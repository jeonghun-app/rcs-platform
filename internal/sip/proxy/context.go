package proxy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// maxQueuedProvisionals bounds the provisional responses of one request that
// wait for a slow upstream peer. Past it new ones are dropped: a provisional
// response carries progress, not state the UAC needs every copy of, and a
// reliable one (RFC 3262) is retransmitted by its UAS. Finals and 2xx are
// never dropped.
const maxQueuedProvisionals = 16

// respContext is the response context of RFC 3261 §16: one request received,
// the branches it was forwarded on, and the final responses gathered from them
// until one is chosen for the upstream transaction (§16.7).
//
// Its state is guarded by mu, which is never held while anything that can block
// runs or while a transaction is called: methods that change the state return
// the actions to take, and the caller runs them once mu is released. Sending a
// request downstream happens on a goroutine per branch, and responses go
// upstream through up, in order, on a goroutine of their own, so a slow peer on
// either side holds up only its own sends.
type respContext struct {
	p      *Proxy
	tx     *transaction.ServerTransaction
	invite bool
	// ctx is what the hooks get. It outlives the request by 64*T1 when a 2xx
	// was forwarded, the time its retransmissions can still arrive (RFC 6026
	// §7.2, Timer M).
	ctx       context.Context
	cancelCtx context.CancelFunc
	// reqCtx is what the Router and a Serve handler get: it also ends when the
	// request is cancelled upstream.
	reqCtx    context.Context
	cancelReq context.CancelFunc
	// handed records that a final response has been handed to the server
	// transaction, by the proxy or by the layer for it: the request is no
	// longer in progress for Drain, even while its context lingers.
	handed atomic.Bool
	// responding is set just before a final response goes to the server
	// transaction, which may then wait for room in a stalled peer's queue
	// (#375).
	responding atomic.Bool
	// replacedFinal records that a final response whose hook panicked was
	// replaced by the proxy's 500 (panicAnswer).
	replacedFinal atomic.Bool
	// unwatch stops watching the server transaction for the layer's own 500
	// (layerAnswered).
	unwatch func() bool
	up      serial
	// reserved is what the context holds of Config.MaxContextBytes.
	reserved int64
	// header is the size of the request's header, which every branch copies.
	header int64

	// Set by run before the first branch starts and not changed after.
	in   *Request
	dec  Decision
	loop string

	mu       sync.Mutex
	branches []*branch
	// groups are the targets of sequential forking still to try, highest Q
	// first.
	groups [][]Target
	// pending counts branches being started and OnBranchFailure calls in
	// progress, either of which can still add a branch.
	pending int
	// routing is set until the Router has decided.
	routing bool
	// cancelled records a CANCEL from upstream (§16.10).
	cancelled bool
	// closed means no new branch may start: after a 2xx, a 6xx (§16.7 step 5) or
	// a CANCEL.
	closed    bool
	finalSent bool
	// forwarded2xx records that a 2xx went upstream, whose retransmissions
	// keep coming for 64*T1.
	forwarded2xx bool
	// abandoned records a branch ended at its Target.Timeout while its
	// transaction still waits for the answer to its CANCEL.
	abandoned bool
	// finals are the final responses kept for choosing the best (§16.7 step 4).
	finals []final
	done   bool
	// uas is set when the Router handed the request to the service.
	uas *UAS
}

type final struct {
	res *sip.Response
	// overload marks a 503 the proxy made up because it or the transport was
	// out of capacity, which is forwarded as a 503 so the client backs off.
	overload bool
	// made marks a response the proxy made up rather than received.
	made bool
	// timeout marks the 408 of a branch whose Target.Timeout passed.
	timeout bool
}

type cancelState int

const (
	cancelNone cancelState = iota
	// cancelWanted waits for a provisional response, before which a CANCEL
	// must not be sent (§9.1).
	cancelWanted
	cancelSent
)

// branch is one forwarded copy of the request and its client transaction.
type branch struct {
	c      *respContext
	target Target

	// Guarded by c.mu.
	tx *transaction.ClientTransaction
	// cancelReq is the CANCEL for an INVITE branch and dst where it goes: the
	// INVITE's destination, over the transport the INVITE actually used (§9.1).
	cancelReq    *sip.Request
	dst          transport.Destination
	provisional  bool
	progress     bool
	final        bool
	cancel       cancelState
	timerC       transaction.Timer
	timerCGen    int
	cancelTimer  transaction.Timer
	timeoutTimer transaction.Timer
	// timedOut records that Target.Timeout ended the branch.
	timedOut bool
	// dialogs holds the To tags of the 2xx the branch has passed upstream:
	// a 2xx with a new one starts a dialog (from the UAS, or a fork further
	// down), a 2xx with a known one is a retransmission.
	dialogs map[string]bool
}

// maxDialogsPerBranch bounds the 2xx dialogs one branch keeps apart; past it a
// 2xx counts as a retransmission, which the UAS sends again until its ACK.
const maxDialogsPerBranch = 16

// newDialog records the dialog of a 2xx on b and reports whether it is new.
// mu must be held.
func (b *branch) newDialog(res *sip.Response) bool {
	to, err := res.Header.To()
	if err != nil {
		return false
	}
	if b.dialogs[to.Tag()] || len(b.dialogs) >= maxDialogsPerBranch {
		return false
	}
	if b.dialogs == nil {
		b.dialogs = map[string]bool{}
	}
	b.dialogs[to.Tag()] = true
	return true
}

func newRespContext(p *Proxy, tx *transaction.ServerTransaction, cost, header int64) *respContext {
	c := &respContext{p: p, tx: tx, invite: tx.Request().Method == "INVITE", routing: true, reserved: cost, header: header}
	c.ctx, c.cancelCtx = context.WithCancel(p.ctx)
	c.reqCtx, c.cancelReq = context.WithCancel(c.ctx)
	c.up.p = p
	c.unwatch = context.AfterFunc(tx.Context(), func() { p.counted(c.layerAnswered) })
	return c
}

// stopped reports whether nothing more may be sent for the request: the proxy
// is closing, or the request was cancelled or answered meanwhile. mu must be
// held.
func (c *respContext) stopped() bool {
	return c.closed || c.finalSent || c.ctx.Err() != nil || c.p.isClosed()
}

// layerAnswered runs when the server transaction's Context ends. If the layer
// answered the request 500 itself, because a Router, Resolver or hook stalled
// past its safety timer (transaction.ErrNoFinalResponse), the client has its
// final response, so the context stops as if it had sent one: the Router and
// hooks see their context cancelled, no branch starts, and the INVITE branches
// still pending, such as one that started just before this ran, are cancelled
// (§16.10), so a call the caller has given up on does not ring on. A
// transaction that ended normally needs nothing, and a 2xx's retransmissions
// keep their context for Timer M.
func (c *respContext) layerAnswered() {
	if !errors.Is(context.Cause(c.tx.Context()), transaction.ErrNoFinalResponse) || c.p.isClosed() {
		return
	}
	c.handed.Store(true)
	c.mu.Lock()
	c.finalSent = true
	acts := c.closeBranches()
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
	// Last, so that whoever sees the context cancelled finds the context
	// stopped and its CANCELs under way.
	c.cancelCtx()
	if h := testHookLayerAnswered.Load(); h != nil {
		(*h)()
	}
}

// testHookLayerAnswered, when set by a test, runs at the end of a
// layerAnswered that stopped a context.
var testHookLayerAnswered atomic.Pointer[func()]

// run validates, preprocesses and routes the request, then starts the first
// fork group. It runs on a goroutine of its own.
func (c *respContext) run() {
	p := c.p
	req := c.tx.Request()
	loop := p.loopHash(req)
	if rej := p.validate(req, loop); rej != nil {
		c.answerWith(rej.code, rej.fields...)
		return
	}
	in, err := p.preprocess(req, c.tx.Source())
	if err != nil {
		c.answerWith(400)
		return
	}
	dec := p.route(c.reqCtx, in)

	c.mu.Lock()
	cancelled := c.cancelled
	// Drain may have answered the request while the Router decided; what
	// the Router decided then starts nothing.
	closing := c.ctx.Err() != nil || p.isClosed() || c.finalSent
	if dec.Serve != nil && !closing {
		// routing stays set while the service answers, so that a CANCEL
		// leaves the answer to it (finish ends the context).
		c.uas = newUAS(c)
		c.dec = Decision{Serve: dec.Serve}
	}
	c.mu.Unlock()
	switch {
	case closing:
		// The proxy is closing, its transactions gone, or the request has
		// its answer from the layer (layerAnswered) or Drain: nothing may be
		// sent.
		c.finish()
		return
	case c.uas != nil:
		c.serve(in)
		return
	case dec.Discard:
		c.discard()
		return
	case cancelled:
		// §9.2: an INVITE cancelled before any branch was sent is answered
		// 487, as a UAS would.
		c.answerWith(487)
		return
	case dec.Response != nil:
		c.answer(dec.Response)
		return
	case dec.Status != 0:
		res, err := p.response(req, dec.Status)
		if err != nil {
			p.log.Error("proxy: Router returned an invalid status", slog.Int("status", dec.Status))
			c.answerWith(500)
			return
		}
		if dec.Reason != "" {
			res.Reason = dec.Reason
		}
		c.answer(res)
		return
	case len(dec.Targets) == 0:
		c.answerWith(480)
		return
	}
	if err := checkRecordRoute(dec.RecordRoute); err != nil {
		p.log.Error("proxy: Router returned an invalid decision", slog.String("error", err.Error()))
		c.answerWith(500)
		return
	}
	groups := groupByQ(dec.Targets)

	c.mu.Lock()
	c.in, c.dec, c.loop = in, dec, loop
	c.routing = false
	c.groups = groups
	acts := c.progress()
	c.mu.Unlock()
	runAll(acts)
}

// answerWith answers the request with a response the proxy makes up.
func (c *respContext) answerWith(code int, fields ...[2]string) {
	res, err := c.p.response(c.tx.Request(), code, fields...)
	if err != nil {
		c.p.log.Error("proxy: building a response", slog.Int("status", code), slog.String("error", err.Error()))
		res = nil
	}
	c.answer(res)
}

// answer sends res as the final response of a request that was not forwarded.
// A nil res sends nothing, which leaves the upstream transaction to its peer's
// timers.
func (c *respContext) answer(res *sip.Response) {
	c.mu.Lock()
	c.routing = false
	// A request Drain answered while its Router ran keeps that answer.
	already := c.finalSent
	c.finalSent = true
	var acts []func()
	if res != nil && !already {
		acts = append(acts, c.forward(res))
	}
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
}

// inProgress reports whether the request still waits for its final
// response: none has been handed to its transaction, a forwarded one queued
// for a slow upstream peer included, and a Serve handler has not sent one
// either (a handler that answered may still wait on its context, for an
// ACK).
//
// Over a *transport.Transport, a final already on its way to the transaction
// is not in progress either: if it waits for room in a stalled peer's
// queue, Drain would wait for it until its own deadline, and
// Transport.Flush, which Drain ends with, waits for it anyway: from the
// start of SendResponse, its connection dialled again to the Via address
// included, as a send under way, then as a sender waiting for room, giving
// up only once it stops getting anywhere (#375). The gap is the transaction
// layer's few lines between taking the response and calling SendResponse:
// a final caught there when Flush looks is not waited for, and Close may
// drop it.
func (c *respContext) inProgress() bool {
	c.mu.Lock()
	uas := c.uas
	c.mu.Unlock()
	flushed := c.p.flushes
	if c.handed.Load() || flushed && c.responding.Load() {
		return false
	}
	return uas == nil || !uas.handedFinal() && !(flushed && uas.hasAnswered())
}

// answerForStop answers a request still without a final response 500 with
// Retry-After, and closes its branches: INVITE branches are cancelled
// (§16.10 does the same for a CANCEL from upstream), and the others end on
// their timers or when the proxy closes. A request whose Router is still
// deciding is answered as well; the Router's decision then starts nothing.
//
// It returns a channel closed once the 500 has been handed to the
// transport, or nil when the request needed no answer.
func (c *respContext) answerForStop(answered *atomic.Int64) <-chan struct{} {
	if !c.inProgress() {
		return nil
	}
	c.mu.Lock()
	uas, cancelled, decided := c.uas, c.cancelled, c.finalSent || c.done
	c.mu.Unlock()
	if decided {
		// Drain's second pass, while the first pass's answer is still
		// queued: DrainAnswer is asked once a request (QA of #436).
		return nil
	}
	if uas != nil {
		// The service answers for itself. It learns of the stop through its
		// context, and serve answers for it if it returns without a final
		// response.
		c.cancelReq()
		return nil
	}
	// The response, and the service's DrainAnswer, are made without the
	// lock, as every hook runs.
	var res *sip.Response
	var err error
	if cancelled {
		// §9.2: what a CANCEL from upstream asked for, as best and serve
		// answer.
		res, err = c.p.response(c.tx.Request(), 487)
	} else {
		res, err = c.p.drainResponse(c.tx.Request())
	}
	if err != nil {
		return nil
	}
	c.mu.Lock()
	switch {
	case c.finalSent || c.done:
		// Answered meanwhile.
		c.mu.Unlock()
		return nil
	case c.uas != nil:
		// The Router handed the request to a Serve handler meanwhile.
		c.mu.Unlock()
		c.cancelReq()
		return nil
	case c.cancelled && !cancelled:
		// Cancelled upstream meanwhile: 487 after all.
		if res, err = c.p.response(c.tx.Request(), 487); err != nil {
			c.mu.Unlock()
			return nil
		}
	}
	c.finalSent = true
	acts := c.closeBranches()
	// The request has its answer: what still prepares or resolves a
	// branch for it, under reqCtx, stops (#382).
	acts = append(acts, c.cancelReq)
	sent := make(chan struct{})
	hook := c.dec.OnResponse
	acts = append(acts, func() {
		c.up.do(func() {
			defer close(sent)
			res := res
			// Drain's Retry-After sends the client to another task, so
			// the 500 in place of a half-changed answer keeps it.
			ra := res.Header.Get("Retry-After")
			if hook != nil && !c.p.hook("OnResponse", func() { hook(c.ctx, res) }) {
				if res = c.panicAnswer(ra); res == nil {
					return
				}
			}
			c.responding.Store(true)
			err := c.tx.Respond(res)
			c.handed.Store(true)
			if err != nil {
				c.p.stats.upstreamErrors.Add(1)
				return
			}
			answered.Add(1)
			c.p.stats.drained.Add(1)
		})
	})
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
	return sent
}

// discard ends the request with a final response the transport never sends
// (silence), so its transaction completes, absorbs retransmissions and ends
// on its timers without a word upstream.
func (c *respContext) discard() {
	res, err := c.p.response(c.tx.Request(), 500)
	if err == nil {
		c.p.silence(c.tx, res)
	}
	c.finish()
}

// finish ends a context that sends nothing more.
func (c *respContext) finish() {
	c.mu.Lock()
	c.routing = false
	c.finalSent = true
	acts := c.progress()
	c.mu.Unlock()
	runAll(acts)
}

// groupByQ splits targets into groups of equal Q, highest first, keeping the
// Router's order within a group.
func groupByQ(targets []Target) [][]Target {
	sorted := slices.Clone(targets)
	slices.SortStableFunc(sorted, func(a, b Target) int { return b.Q - a.Q })
	var groups [][]Target
	for i, t := range sorted {
		if i == 0 || t.Q != sorted[i-1].Q {
			groups = append(groups, nil)
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], t)
	}
	return groups
}

func runAll(acts []func()) {
	for _, a := range acts {
		a()
	}
}

// progress moves the context on once nothing is outstanding: it starts the next
// fork group, or sends the best final response, and ends the context when every
// branch has ended. mu must be held.
func (c *respContext) progress() []func() {
	if c.done || c.routing || c.pending > 0 || !c.allFinal() {
		return nil
	}
	var acts []func()
	for !c.finalSent && !c.closed && len(c.groups) > 0 {
		g := c.groups[0]
		c.groups = c.groups[1:]
		if started := c.startBranches(g); len(started) > 0 {
			return started
		}
	}
	if !c.finalSent {
		c.finalSent = true
		acts = append(acts, c.sendBest()...)
	}
	c.done = true
	// The context is released only once the responses queued before it have
	// gone, so OnResponse never sees a cancelled context for them.
	linger := c.forwarded2xx || c.abandoned
	return append(acts, func() { c.up.do(func() { c.p.release(c, linger) }) })
}

func (c *respContext) allFinal() bool {
	for _, b := range c.branches {
		if !b.final {
			return false
		}
	}
	return true
}

// startBranches starts a branch for each target not tried before, within
// MaxBranches and MaxContextBytes (§16.5 forbids sending to the same target
// twice; RFC 5393 §3 motivates bounding them). Starting one is progress, so
// the layer's safety timer starts again (#156): each fork group and each
// replacement gets its own Timer C or F before the layer answers for the
// proxy. mu must be held.
func (c *respContext) startBranches(targets []Target) []func() {
	var acts []func()
	started := false
	for _, t := range targets {
		if slices.ContainsFunc(c.branches, func(b *branch) bool { return sameTarget(b.target, t) }) {
			continue
		}
		if len(c.branches) >= c.p.maxBranch {
			c.p.stats.targetsDropped.Add(1)
			continue
		}
		b := &branch{c: c, target: t}
		c.branches = append(c.branches, b)
		// Each branch holds a copy of the header (the body is shared) and its
		// CANCEL.
		cost := 2 * c.header
		if !c.p.reserve(cost) {
			c.p.stats.overloaded.Add(1)
			acts = append(acts, c.branchEnded(b, c.failureResponse(errOverload), errOverload)...)
			continue
		}
		c.reserved += cost
		c.pending++
		c.p.stats.branches.Add(1)
		started = true
		acts = append(acts, func() { c.p.spawn(b.start) })
	}
	if started {
		acts = append([]func(){c.tx.Progress}, acts...)
	}
	return acts
}

func sameTarget(a, b Target) bool {
	if !a.URI.Equal(b.URI) || len(a.Routes) != len(b.Routes) || (a.Destination == nil) != (b.Destination == nil) {
		return false
	}
	if a.Destination != nil && *a.Destination != *b.Destination {
		return false
	}
	for i := range a.Routes {
		if a.Routes[i].String() != b.Routes[i].String() {
			return false
		}
	}
	return true
}

// errOverload fails a branch that would take the proxy past MaxContextBytes.
var errOverload = errors.New("proxy: over the memory budget")

// start builds and sends the branch's request (§16.6), on a goroutine of its
// own since resolving, Prepare and the send itself can block.
func (b *branch) start() {
	c, p := b.c, b.c.p
	c.mu.Lock()
	if c.stopped() {
		acts := b.unsent()
		c.mu.Unlock()
		runAll(acts)
		return
	}
	c.mu.Unlock()
	// Under reqCtx, which a CANCEL and Drain's deadline end, so that a
	// stalled Prepare or Resolver, such as pcscf waiting on msrp-relay, does
	// not hold the 487 or the drain's answer back (#382).
	fwd, dst, err := p.buildBranch(c.reqCtx, c.in, &c.dec, b.target, true)
	if err == nil {
		err = b.addVia(fwd, dst)
	}
	{
		// Prepare and the Resolver may have blocked: a 2xx, a 6xx or a CANCEL
		// that came meanwhile means the branch must not be sent after all
		// (§16.7 step 5, §16.10). A response that arrives while the send is
		// under way is handled by the CANCEL that follows its provisional. A
		// Prepare or Resolver the CANCEL cut short (#382) fails for that
		// reason, not the branch's: it is unsent too, not a 500.
		c.mu.Lock()
		stopped := c.stopped()
		c.mu.Unlock()
		if err == nil && stopped || err != nil && c.reqCtx.Err() != nil {
			c.mu.Lock()
			acts := b.unsent()
			c.mu.Unlock()
			runAll(acts)
			return
		}
	}
	var tx *transaction.ClientTransaction
	if err == nil {
		tx, err = p.layer.Request(fwd, dst, b.handle)
	}
	var cancel *sip.Request
	if err == nil && c.invite {
		// Built now, from the request as the transport sent it: the CANCEL
		// needs the Via the transport wrote. The layer owns the INVITE but
		// only reads it from here on.
		cancel, dst = cancelFor(tx.Request(), tx.Network(), dst)
	}

	c.mu.Lock()
	c.pending--
	var acts []func()
	if err != nil {
		acts = c.branchEnded(b, c.failureResponse(err), err)
	} else {
		b.tx, b.cancelReq, b.dst = tx, cancel, dst
		if c.invite && !b.final {
			b.armTimerC()
		}
		if b.target.Timeout > 0 && !b.final {
			b.armTimeout()
		}
		if b.cancel == cancelWanted && b.provisional {
			acts = append(acts, b.sendCancel()...)
		}
	}
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
}

// unsent ends a branch that is never sent: it counts as nothing. mu must be
// held.
func (b *branch) unsent() []func() {
	c := b.c
	b.final = true
	c.pending--
	return c.progress()
}

// addVia adds the proxy's Via. Its branch ID is random in its first part, as
// §8.1.1.7 requires, and carries the loop hash as its second (RFC 5393 §4.2.1).
func (b *branch) addVia(fwd *sip.Request, dst transport.Destination) error {
	id, err := b.c.p.ids.Branch()
	if err != nil {
		return err
	}
	return addVia(fwd, dst, id+"."+b.c.loop)
}

// cancelFor builds the CANCEL for an INVITE sent to dst over network, and where
// it goes: to the same flow, or the same address over the transport the INVITE
// actually used, which differs from dst's when the transport moved a large
// INVITE from UDP to TCP (RFC 3261 §18.1.1). A nil CANCEL means none can be
// built, and the branch is then ended by the 64*T1 timer alone.
func cancelFor(invite *sip.Request, network transport.Network, dst transport.Destination) (*sip.Request, transport.Destination) {
	cancel, err := buildCancel(invite)
	if err != nil {
		return nil, dst
	}
	if dst.Flow == "" && network != "" {
		dst.Network = network
	}
	return cancel, dst
}

// cancelKeeps are the fields a CANCEL copies from its INVITE (§9.1).
var cancelKeeps = map[string]bool{"From": true, "To": true, "Call-ID": true, "Route": true}

// buildCancel builds the CANCEL for an INVITE branch (§9.1): the INVITE's
// Request-URI, top Via, Route, To, From, Call-ID and CSeq number. From, To,
// Call-ID and Route are the INVITE's fields byte for byte, copied rather than
// written again, since a value the parser accepted (an escaped NUL in a display
// name, RFC 4475 §3.1.1.2) is one Header.Add refuses to write.
func buildCancel(invite *sip.Request) (*sip.Request, error) {
	vias, err := invite.Header.Elements("Via")
	if err != nil {
		return nil, err
	}
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	cancel := copyRequest(invite)
	cancel.Method = "CANCEL"
	cancel.Body = nil
	for _, f := range cancel.Header.Fields() {
		if !cancelKeeps[sip.CanonicalName(f.Name)] {
			cancel.Header.Del(f.Name)
		}
	}
	for _, f := range [][2]string{
		{"Via", vias[0]},
		{"Max-Forwards", "70"},
		{"CSeq", sip.CSeq{Seq: cseq.Seq, Method: "CANCEL"}.String()},
	} {
		if err := cancel.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return cancel, nil
}

// failureResponse is the response a branch counts as when sending it failed
// (§16.9). mu must be held.
func (c *respContext) failureResponse(err error) final {
	switch {
	case errors.Is(err, errPrepare):
		return c.made(500)
	case errors.Is(err, transport.ErrNoFlow):
		// RFC 5626 §5.3.1: the flow the target was registered over is gone.
		return c.made(430)
	case errors.Is(err, transport.ErrQueueFull), errors.Is(err, transport.ErrTooManyConnections), errors.Is(err, errOverload):
		// The next hop is reachable but the proxy cannot send to it now: a
		// 503 with Retry-After tells the client to back off, while another
		// branch may still succeed.
		f := c.made(503, [2]string{"Retry-After", overloadRetryAfter})
		f.overload = true
		return f
	}
	return c.made(503)
}

// panicAnswer is the 500 sent in place of a final response whose hook
// panicked (Proxy.hook), which may have half changed it, with retryAfter as
// its Retry-After if not empty; nil if it cannot be built. A 2xx that comes
// again after it is dropped (forwardAs): the transaction has its final.
func (c *respContext) panicAnswer(retryAfter string) *sip.Response {
	c.replacedFinal.Store(true)
	var fields [][2]string
	if retryAfter != "" {
		fields = append(fields, [2]string{"Retry-After", retryAfter})
	}
	res, err := c.p.response(c.tx.Request(), 500, fields...)
	if err != nil {
		c.p.log.Error("proxy: building a response", slog.Int("status", 500), slog.String("error", err.Error()))
		return nil
	}
	return res
}

// made builds a response of the proxy's own to the request received. mu must be
// held.
func (c *respContext) made(code int, fields ...[2]string) final {
	res, err := c.p.response(c.tx.Request(), code, fields...)
	if err != nil {
		c.p.log.Error("proxy: building a response", slog.Int("status", code), slog.String("error", err.Error()))
		return final{}
	}
	return final{res: res, made: true}
}

// handle receives what the branch's client transaction passes up (§16.7). It
// runs on the goroutine that read the response or on a timer, so it only
// changes state and starts what must be sent.
func (b *branch) handle(res *sip.Response, err error) {
	c := b.c
	c.mu.Lock()
	var acts []func()
	if err != nil {
		acts = b.failed(err)
	} else {
		acts = b.received(res)
	}
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
}

// failed handles the error that ends the branch's transaction. mu must be held.
func (b *branch) failed(err error) []func() {
	c := b.c
	if b.final {
		// The proxy terminated a transaction that had already completed.
		return nil
	}
	timedOut := errors.Is(err, transaction.ErrTerminated) || errors.Is(err, transaction.ErrTimeout)
	var f final
	switch {
	case timedOut && b.timedOut:
		f = c.timeoutFinal()
		err = ErrTargetTimeout
	case (timedOut || errors.Is(err, transaction.ErrFlowClosed)) && b.cancel != cancelNone:
		// A branch being cancelled that ends without a final response, its
		// CANCEL unanswered for 64*T1 (§9.1), its timers expired or its flow
		// closed, counts as the 487 the CANCEL asked for: the request was
		// cancelled, not failed for want of the flow.
		f = c.made(487)
	case timedOut:
		// Timer B, F or C, or the target's Timeout, fired without a final
		// response (§16.8, §17.1).
		f = c.made(408)
	default:
		f = c.failureResponse(err)
	}
	return c.branchEnded(b, f, err)
}

// timeoutFinal is what a branch ended by its Target.Timeout counts as. mu must
// be held.
func (c *respContext) timeoutFinal() final {
	f := c.made(408)
	f.timeout = true
	return f
}

// ErrTargetTimeout is the BranchFailure.Err of a branch its Target.Timeout
// ended, which tells it from a 408 the target sent itself: scscf applies an
// application server's default handling on it (TS 24.229 §5.4.3.2).
var ErrTargetTimeout = errors.New("proxy: the target's timeout passed")

// received handles a response on the branch (§16.7 steps 2 to 10). mu must be
// held.
func (b *branch) received(res *sip.Response) []func() {
	c := b.c
	code := res.StatusCode
	if code >= 200 && b.cancelTimer != nil {
		// The INVITE is answered, so its CANCEL needs no deadline.
		b.cancelTimer.Stop()
	}
	// §16.7 step 3: the top Via is the proxy's own.
	if err := res.Header.RemoveFirstElement("Via"); err != nil || !res.Header.Has("Via") {
		// A response must carry every Via of its request (§8.2.6.2). One
		// that lost the upstream ones cannot be forwarded, but a final one
		// still ends the branch, which then counts as a 502 from it.
		if code < 200 {
			return nil
		}
		made := c.made(502)
		if made.res == nil {
			return nil
		}
		res, code = made.res, 502
	}
	if b.final {
		// After the branch ended only 2xx reach here: retransmissions, a 2xx
		// from a fork further down, or the late answer of a branch its
		// Target.Timeout ended. Every 2xx to an INVITE is forwarded (§16.7
		// step 5); one that starts a dialog is a 2xx like the first, which
		// cancels the branches still pending (§16.7 step 10) and is never
		// dropped, while a retransmission may be.
		if !c.invite || code < 200 || code >= 300 {
			return nil
		}
		if !b.newDialog(res) {
			return []func(){c.forwardRetransmission(res)}
		}
		acts := []func(){c.forward(res)}
		c.finalSent = true
		return append(acts, c.closeBranches()...)
	}
	var acts []func()
	switch {
	case code < 200:
		b.provisional = true
		b.progress = b.progress || code > 100
		if c.invite && code > 100 {
			b.armTimerC()
		}
		// Until start has the transaction it sends the CANCEL itself.
		if b.cancel == cancelWanted && b.tx != nil {
			acts = append(acts, b.sendCancel()...)
		}
		// A 100 is hop by hop and never forwarded, and after a final
		// response no provisional is (§16.7 step 5).
		if code > 100 && !c.finalSent {
			acts = append(acts, c.forward(res))
		}
	case code < 300:
		b.end()
		b.newDialog(res)
		if c.invite || !c.finalSent {
			acts = append(acts, c.forward(res))
		}
		c.finalSent = true
		acts = append(acts, c.closeBranches()...)
	default:
		acts = append(acts, c.branchEnded(b, final{res: res}, nil)...)
		if code >= 600 {
			// §16.7 step 5: a 6xx is held back while the other branches are
			// cancelled, so a 2xx racing it can still win, and the 6xx then
			// beats everything but a 2xx.
			acts = append(acts, c.closeBranches()...)
		}
	}
	return acts
}

// branchEnded records a branch's non-2xx final response, received or made up,
// and asks OnBranchFailure what to try instead. mu must be held.
func (c *respContext) branchEnded(b *branch, f final, err error) []func() {
	b.end()
	if f.res == nil {
		return nil
	}
	if !c.finalSent {
		c.finals = append(c.finals, f)
	}
	hook := c.dec.OnBranchFailure
	if hook == nil {
		return nil
	}
	// The hook is told even when its targets can no longer be used, so a
	// service learns of every failed flow; the context waits for it, so its
	// ctx stays valid while it runs.
	c.pending++
	failure := BranchFailure{Target: b.target, Response: f.res.Clone(), Err: err, Provisional: b.provisional, Progress: b.progress}
	return []func(){func() {
		c.p.spawn(func() {
			// A panic leaves the branch failed, with nothing in its place.
			var targets []Target
			c.p.hook("OnBranchFailure", func() { targets = hook(c.ctx, failure) })
			c.mu.Lock()
			c.pending--
			var acts []func()
			if !c.stopped() {
				acts = c.startBranches(targets)
			}
			acts = append(acts, c.progress()...)
			c.mu.Unlock()
			runAll(acts)
		})
	}}
}

// end marks the branch finished and stops its timers. The CANCEL's deadline
// keeps running: a branch its Target.Timeout ended may still wait for the
// answer to its CANCEL, and the deadline ends its transaction (received stops
// it when the INVITE is answered).
func (b *branch) end() {
	b.final = true
	for _, t := range []transaction.Timer{b.timerC, b.timeoutTimer} {
		if t != nil {
			t.Stop()
		}
	}
}

// closeBranches stops the context from starting branches and cancels the INVITE
// branches still pending (§16.7 step 10, §16.10). CANCEL applies to INVITE only
// (§9.1); other requests run to their final response. mu must be held.
func (c *respContext) closeBranches() []func() {
	c.closed = true
	c.groups = nil
	if !c.invite {
		return nil
	}
	var acts []func()
	for _, b := range c.branches {
		if !b.final && b.cancel == cancelNone {
			b.cancel = cancelWanted
			if b.provisional && b.tx != nil {
				acts = append(acts, b.sendCancel()...)
			}
		}
	}
	return acts
}

// cancelUpstream handles a CANCEL for the request (§16.10): it marks the
// request cancelled, so that no branch starts from here on, and returns
// what is to be done for it, the CANCELs of the pending branches and the
// final response if the request has its answer now, which receiveCancel
// runs after the CANCEL's own 200. A branch that ends unsent in between
// sends the final response itself, which may then go before the 200. A request the service is answering itself is the
// service's to end: it learns of the CANCEL through its context, and the
// proxy answers for it only if it returns without a final response.
func (c *respContext) cancelUpstream() (then func()) {
	c.mu.Lock()
	c.cancelled = true
	acts := c.closeBranches()
	acts = append(acts, c.progress()...)
	uas := c.uas
	c.mu.Unlock()
	return func() {
		// A CANCEL after the service's final response has no effect (§9.2).
		if uas == nil || !uas.hasAnswered() {
			c.cancelReq()
		}
		runAll(acts)
	}
}

// sendCancel sends the branch's CANCEL and gives the INVITE 64*T1 to end
// before the proxy terminates it (§9.1). mu must be held.
func (b *branch) sendCancel() []func() {
	p := b.c.p
	b.cancel = cancelSent
	p.stats.cancels.Add(1)
	cancel, dst := b.cancelReq, b.dst
	b.cancelTimer = p.clock.AfterFunc(64*p.t1, func() { b.terminate() })
	if cancel == nil {
		return nil
	}
	// Counted until handed to the transaction layer, so Drain can wait for
	// it before a Close.
	p.cancelsSending.Add(1)
	return []func(){func() {
		p.spawn(func() {
			defer p.cancelsSending.Add(-1)
			// The CANCEL's own transaction ends by itself and its response
			// tells the proxy nothing it acts on. If it cannot be sent, the
			// 64*T1 timer still ends the INVITE.
			_, _ = p.layer.Request(cancel, dst, func(*sip.Response, error) {})
		})
	}}
}

// terminate ends the branch's transaction from a timer; its handler then
// records what the branch counts as, unless the branch has ended already. A
// transaction that has ended is not affected.
func (b *branch) terminate() {
	c := b.c
	if c.p.isClosed() {
		return
	}
	c.mu.Lock()
	tx := b.tx
	c.mu.Unlock()
	if tx != nil {
		tx.Terminate()
	}
}

// armTimeout starts the target's own timer (Target.Timeout). When it fires the
// branch ends at once, counting as a 408, so a replacement can start without
// waiting: an INVITE branch that has a provisional response is cancelled and
// its transaction left to absorb the 487 (a 2xx from it is still forwarded,
// §16.7 step 5), and any other branch's transaction is terminated, unless
// Target.OnTimeout keeps the branch. mu must be held.
func (b *branch) armTimeout() {
	c, p := b.c, b.c.p
	b.timeoutTimer = p.clock.AfterFunc(b.target.Timeout, func() {
		if p.isClosed() {
			return
		}
		keep := b.target.OnTimeout
		if keep == nil {
			b.timeoutNow()
			return
		}
		// It may block, as scscf asks its store, and a timer must not.
		p.spawn(func() {
			// A panic leaves applies true: the timeout ends the branch, as
			// when scscf's store cannot say.
			applies := true
			p.hook("OnTimeout", func() { applies = keep(c.ctx) })
			if applies {
				b.timeoutNow()
				return
			}
			p.stats.targetTimeouts.Add(1)
			p.stats.targetTimeoutsKept.Add(1)
		})
	})
}

// timeoutNow ends the branch on its target's timeout (armTimeout).
func (b *branch) timeoutNow() {
	c, p := b.c, b.c.p
	if p.isClosed() {
		return
	}
	{
		c.mu.Lock()
		if b.final {
			c.mu.Unlock()
			return
		}
		p.stats.targetTimeouts.Add(1)
		b.timedOut = true
		if c.invite && b.provisional {
			var acts []func()
			if b.cancel != cancelSent && b.tx != nil {
				acts = b.sendCancel()
			}
			c.abandoned = true
			acts = append(acts, c.branchEnded(b, c.timeoutFinal(), ErrTargetTimeout)...)
			acts = append(acts, c.progress()...)
			c.mu.Unlock()
			runAll(acts)
			return
		}
		c.mu.Unlock()
		b.terminate()
	}
}

// armTimerC starts or restarts Timer C (§16.6 step 11, §16.7 step 2). mu must
// be held.
func (b *branch) armTimerC() {
	c, p := b.c, b.c.p
	if b.timerC != nil {
		b.timerC.Stop()
	}
	b.timerCGen++
	gen := b.timerCGen
	b.timerC = p.clock.AfterFunc(p.timerC, func() {
		if p.isClosed() {
			return
		}
		c.mu.Lock()
		if b.final || gen != b.timerCGen {
			c.mu.Unlock()
			return
		}
		p.stats.timerC.Add(1)
		var acts []func()
		var terminate *transaction.ClientTransaction
		switch {
		case !b.provisional:
			// §16.8: as if the branch had received 408. The transaction is
			// terminated, and its handler then records the 408.
			terminate = b.tx
		case b.cancel != cancelSent && b.tx != nil:
			// §16.8: cancel it; the 64*T1 that sendCancel allows bounds what
			// remains, so Timer C is not restarted.
			acts = b.sendCancel()
		}
		c.mu.Unlock()
		runAll(acts)
		if terminate != nil {
			terminate.Terminate()
		}
	})
}

// stopTimers stops every timer of the context, for Close.
func (c *respContext) stopTimers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.branches {
		for _, t := range []transaction.Timer{b.timerC, b.cancelTimer, b.timeoutTimer} {
			if t != nil {
				t.Stop()
			}
		}
	}
}

// forward queues res for the upstream transaction (§16.7 step 9). mu must be
// held; the returned action does the queueing, so responses keep the order in
// which they were decided.
func (c *respContext) forward(res *sip.Response) func() { return c.forwardAs(res, false) }

// forwardRetransmission queues a 2xx that came after its branch's final
// response: a retransmission, or a 2xx from a fork further downstream. Like a
// provisional response it is dropped when the upstream peer is not taking
// responses: the UAS retransmits it until the ACK (RFC 6026 §8.1). mu must be
// held.
func (c *respContext) forwardRetransmission(res *sip.Response) func() { return c.forwardAs(res, true) }

func (c *respContext) forwardAs(res *sip.Response, again bool) func() {
	hook := c.dec.OnResponse
	code := res.StatusCode
	if c.invite && code >= 200 && code < 300 {
		c.forwarded2xx = true
	}
	send := func() {
		if again && c.replacedFinal.Load() {
			// The 2xx a 500 replaced, again: the transaction would refuse
			// it, which is no upstream error.
			return
		}
		res := res
		if hook != nil && !c.p.hook("OnResponse", func() { hook(c.ctx, res) }) {
			// The hook may have half changed the response. A provisional
			// response or a 2xx retransmission is dropped; a final
			// response becomes a 500.
			if code < 200 || again {
				return
			}
			if res = c.panicAnswer(""); res == nil {
				return
			}
		}

		// §16.9: a response that cannot be sent is dropped, and the
		// branches are left alone.
		if code >= 200 {
			c.responding.Store(true)
		}
		if err := c.tx.Respond(res); err != nil {
			c.p.stats.upstreamErrors.Add(1)
		}
		if code >= 200 {
			c.handed.Store(true)
		}
	}
	switch {
	case code < 200:
		return func() {
			if !c.up.doUnlessBacklogged(send, maxQueuedProvisionals) {
				c.p.stats.provisionalsDropped.Add(1)
			}
		}
	case again:
		return func() {
			if !c.up.doUnlessBacklogged(send, maxQueuedProvisionals) {
				c.p.stats.retransmissionsDropped.Add(1)
			}
		}
	}
	return func() { c.up.do(send) }
}

// sendBest sends the final response when every branch has failed, or nothing
// for a non-INVITE request that got no response but the proxy's own 408. mu
// must be held.
func (c *respContext) sendBest() []func() {
	f := c.best()
	if f.res == nil {
		return nil
	}
	if !c.invite && f.made && f.res.StatusCode == 408 {
		if !f.timeout {
			// RFC 4320 §4.2: a 408 to a non-INVITE request that timed out
			// comes after the client has given up, so none is sent. The
			// transaction still has to end, so it gets a 408 the proxy's
			// sender never sends.
			return []func(){func() { c.up.do(func() { c.p.silence(c.tx, f.res) }) }}
		}
		// A Target.Timeout ended the request well before the client's Timer
		// F, so it is answered, with 504 rather than the 408 RFC 4320 §4.2
		// forbids, and OnFinal may change that.
		f.res.StatusCode, f.res.Reason = 504, sip.DefaultReason(504)
	}
	res := f.res
	onFinal := c.dec.OnFinal
	hook := c.dec.OnResponse
	return []func(){func() {
		c.up.do(func() {
			res, ok := res, true
			if onFinal != nil {
				ok = c.p.hook("OnFinal", func() { onFinal(c.ctx, res) })
			} else if res.StatusCode == 430 {
				// RFC 5626 §11.5: an endpoint must not see 430, which is
				// for the authoritative proxy. A service that is the edge
				// proxy keeps it with OnFinal.
				res.StatusCode, res.Reason = 480, sip.DefaultReason(480)
			}
			if ok && hook != nil {
				ok = c.p.hook("OnResponse", func() { hook(c.ctx, res) })
			}
			if !ok {
				// A hook may have half changed it.
				if res = c.panicAnswer(""); res == nil {
					return
				}
			}
			// On its way, as the other finals (inProgress; code review of
			// #438).
			c.responding.Store(true)
			if err := c.tx.Respond(res); err != nil {
				c.p.stats.upstreamErrors.Add(1)
			}
		})
	}}
}

// best chooses the final response when every branch has failed (§16.7 steps 6
// and 7). mu must be held.
func (c *respContext) best() final {
	if len(c.finals) == 0 {
		// No branch produced a final response. A request cancelled upstream is
		// answered 487 (§9.2), anything else 408 (§16.7 step 6).
		if c.cancelled {
			return c.made(487)
		}
		return c.made(408)
	}
	chosen := c.finals[0]
	for _, f := range c.finals[1:] {
		if better(f, chosen) {
			chosen = f
		}
	}
	code := chosen.res.StatusCode
	if code == 503 && !chosen.overload {
		// §16.7 step 6: a 503 says the next hop is unavailable, which is not
		// the proxy's own state, so it is not passed on.
		return c.made(500)
	}
	res := chosen.res.Clone()
	if code == 401 || code == 407 {
		for _, f := range c.finals {
			if f == chosen || (f.res.StatusCode != 401 && f.res.StatusCode != 407) {
				continue
			}
			for _, name := range []string{"WWW-Authenticate", "Proxy-Authenticate"} {
				for _, v := range f.res.Header.Values(name) {
					if err := res.Header.Add(name, v); err != nil {
						c.p.log.Error("proxy: aggregating challenges", slog.String("error", err.Error()))
					}
				}
			}
		}
	}
	return final{res: res, overload: chosen.overload, made: chosen.made, timeout: chosen.timeout}
}

// better reports whether a is a better final response than b (§16.7 step 6): any
// 6xx beats every other class, then the lowest class wins. Within 4xx the
// responses that let the client retry with more information are preferred,
// within 5xx anything but a 503; then one received beats one the proxy made up,
// which says less, and otherwise the first received stays.
func better(a, b final) bool {
	ca, cb := a.res.StatusCode/100, b.res.StatusCode/100
	switch {
	case ca == 6 || cb == 6:
		return ca == 6 && cb != 6
	case ca != cb:
		return ca < cb
	case ca == 4 && retryInfo(a.res.StatusCode) != retryInfo(b.res.StatusCode):
		return retryInfo(a.res.StatusCode)
	case ca == 5 && (a.res.StatusCode == 503) != (b.res.StatusCode == 503):
		return b.res.StatusCode == 503
	}
	return b.made && !a.made
}

// retryInfo reports the 4xx responses §16.7 step 6 prefers: those whose
// information lets the client resubmit the request successfully.
func retryInfo(code int) bool {
	switch code {
	case 401, 407, 415, 420, 484:
		return true
	}
	return false
}

// serial runs functions one at a time in the order given, on a goroutine
// started when there is work, like the transaction layer's delivery.
type serial struct {
	p       *Proxy
	mu      sync.Mutex
	queue   []func()
	running bool
}

func (s *serial) do(f func()) { s.doUnlessBacklogged(f, -1) }

// doUnlessBacklogged queues f unless limit or more functions are already
// waiting (limit < 0: no limit), and reports whether it did.
func (s *serial) doUnlessBacklogged(f func(), limit int) bool {
	s.mu.Lock()
	if limit >= 0 && len(s.queue) >= limit {
		s.mu.Unlock()
		return false
	}
	s.queue = append(s.queue, f)
	if s.running {
		s.mu.Unlock()
		return true
	}
	s.running = true
	s.mu.Unlock()
	s.p.spawn(s.drain)
	return true
}

func (s *serial) drain() {
	for {
		s.mu.Lock()
		if len(s.queue) == 0 {
			s.running = false
			s.mu.Unlock()
			return
		}
		f := s.queue[0]
		s.queue = s.queue[1:]
		s.mu.Unlock()
		f()
	}
}
