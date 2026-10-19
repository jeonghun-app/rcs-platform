package proxy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

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
	p         *Proxy
	tx        *transaction.ServerTransaction
	invite    bool
	ctx       context.Context
	cancelCtx context.CancelFunc
	up        serial

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
	// finals are the final responses kept for choosing the best (§16.7 step 4).
	finals []final
	done   bool
}

type final struct {
	res *sip.Response
	// overload marks a 503 the proxy made up because it or the transport was
	// out of capacity, which is forwarded as a 503 so the client backs off.
	overload bool
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
	tx  *transaction.ClientTransaction
	dst transport.Destination
	// cancelReq is the CANCEL for an INVITE branch and dst where it goes: the
	// INVITE's destination, over the transport the INVITE actually used (§9.1).
	cancelReq   *sip.Request
	provisional bool
	final       bool
	cancel      cancelState
	timerC      transaction.Timer
	timerCGen   int
	cancelTimer transaction.Timer
}

func newRespContext(p *Proxy, tx *transaction.ServerTransaction) *respContext {
	c := &respContext{p: p, tx: tx, invite: tx.Request().Method == "INVITE", routing: true}
	c.ctx, c.cancelCtx = context.WithCancel(p.ctx)
	c.up.p = p
	return c
}

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
	dec := p.router.Route(c.ctx, in)

	c.mu.Lock()
	cancelled := c.cancelled
	c.mu.Unlock()
	switch {
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
	c.finalSent = true
	var acts []func()
	if res != nil {
		acts = append(acts, c.forward(res))
	}
	acts = append(acts, c.progress()...)
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
		if res := c.best(); res != nil {
			acts = append(acts, c.forward(res))
		}
	}
	c.done = true
	// The context is released only once the responses queued before it have
	// gone, so OnResponse never sees a cancelled context for them.
	return append(acts, func() { c.up.do(func() { c.p.release(c) }) })
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
// MaxBranches (§16.5 forbids sending to the same target twice; RFC 5393 §3
// motivates bounding them). mu must be held.
func (c *respContext) startBranches(targets []Target) []func() {
	var acts []func()
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
		c.pending++
		c.p.stats.branches.Add(1)
		acts = append(acts, func() { c.p.spawn(b.start) })
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

// start builds and sends the branch's request (§16.6), on a goroutine of its
// own since resolving, Prepare and the send itself can block.
func (b *branch) start() {
	c, p := b.c, b.c.p
	c.mu.Lock()
	if c.closed {
		// A 2xx, a 6xx or a CANCEL came first: the branch is never sent and
		// counts as nothing (§16.7 step 5, §16.10).
		b.final = true
		c.pending--
		acts := c.progress()
		c.mu.Unlock()
		runAll(acts)
		return
	}
	c.mu.Unlock()
	fwd, dst, err := p.buildBranch(c.ctx, c.in, &c.dec, b.target, true)
	if err == nil {
		err = b.addVia(fwd, dst)
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
		cancel, dst = cancelFor(tx.Request(), dst)
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
		if b.cancel == cancelWanted && b.provisional {
			acts = append(acts, b.sendCancel()...)
		}
	}
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
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

// cancelFor builds the CANCEL for an INVITE sent to dst, and where it goes: to
// the same flow, or the same address over the transport the INVITE's Via names,
// which differs from dst's when the transport moved a large INVITE from UDP to
// TCP (RFC 3261 §18.1.1). A nil CANCEL means none can be built, and the branch
// is then ended by the 64*T1 timer alone.
func cancelFor(invite *sip.Request, dst transport.Destination) (*sip.Request, transport.Destination) {
	cancel, err := buildCancel(invite)
	if err != nil {
		return nil, dst
	}
	if vias, err := invite.Header.Via(); err == nil && dst.Flow == "" {
		switch n := transport.Network(strings.ToUpper(vias[0].Transport)); n {
		case transport.UDP, transport.TCP, transport.TLS:
			dst.Network = n
		}
	}
	return cancel, dst
}

// buildCancel builds the CANCEL for an INVITE branch (§9.1): the INVITE's
// Request-URI, top Via, Route, To, From, Call-ID and CSeq number.
func buildCancel(invite *sip.Request) (*sip.Request, error) {
	vias, err := invite.Header.Elements("Via")
	if err != nil {
		return nil, err
	}
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	cancel := &sip.Request{Method: "CANCEL", URI: invite.URI}
	fields := [][2]string{
		{"Via", vias[0]},
		{"Max-Forwards", "70"},
		{"From", invite.Header.Get("From")},
		{"To", invite.Header.Get("To")},
		{"Call-ID", invite.Header.Get("Call-ID")},
		{"CSeq", sip.CSeq{Seq: cseq.Seq, Method: "CANCEL"}.String()},
	}
	for _, r := range invite.Header.Values("Route") {
		fields = append(fields, [2]string{"Route", r})
	}
	for _, f := range fields {
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
	case errors.Is(err, transport.ErrQueueFull), errors.Is(err, transport.ErrTooManyConnections):
		// The next hop is reachable but the proxy cannot send to it now: a
		// 503 with Retry-After tells the client to back off, while another
		// branch may still succeed.
		f := c.made(503, [2]string{"Retry-After", overloadRetryAfter})
		f.overload = true
		return f
	}
	return c.made(503)
}

// made builds a response of the proxy's own to the request received. mu must be
// held.
func (c *respContext) made(code int, fields ...[2]string) final {
	res, err := c.p.response(c.tx.Request(), code, fields...)
	if err != nil {
		c.p.log.Error("proxy: building a response", slog.Int("status", code), slog.String("error", err.Error()))
		return final{}
	}
	return final{res: res}
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
	case timedOut && b.cancel != cancelNone:
		// A branch being cancelled that ends without a final response, its
		// CANCEL unanswered for 64*T1 (§9.1) or its timers expired, counts
		// as the 487 the CANCEL asked for.
		f = c.made(487)
	case timedOut:
		// Timer B, F or C fired without a final response (§16.8, §17.1).
		f = c.made(408)
	default:
		f = c.failureResponse(err)
	}
	return c.branchEnded(b, f, err)
}

// received handles a response on the branch (§16.7 steps 2 to 10). mu must be
// held.
func (b *branch) received(res *sip.Response) []func() {
	c := b.c
	code := res.StatusCode
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
		// After the branch's final response only 2xx retransmissions and 2xx
		// from further forks downstream reach here, and every 2xx to an INVITE
		// is forwarded (§16.7 step 5).
		if c.invite && code >= 200 && code < 300 {
			return []func(){c.forward(res)}
		}
		return nil
	}
	var acts []func()
	switch {
	case code < 200:
		b.provisional = true
		if c.invite && code > 100 {
			b.armTimerC()
		}
		// Until start has the transaction it sends the CANCEL itself.
		if b.cancel == cancelWanted && b.tx != nil {
			acts = append(acts, b.sendCancel()...)
		}
		// A 100 is hop by hop and never forwarded (§16.7 step 5).
		if code > 100 && !c.finalSent {
			acts = append(acts, c.forward(res))
		}
	case code < 300:
		b.end()
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
	failure := BranchFailure{Target: b.target, Response: f.res.Clone(), Err: err}
	return []func(){func() {
		c.p.spawn(func() {
			targets := hook(c.ctx, failure)
			c.mu.Lock()
			c.pending--
			var acts []func()
			if !c.closed && !c.finalSent {
				acts = c.startBranches(targets)
			}
			acts = append(acts, c.progress()...)
			c.mu.Unlock()
			runAll(acts)
		})
	}}
}

// end marks the branch finished and stops its timers. mu must be held.
func (b *branch) end() {
	b.final = true
	if b.timerC != nil {
		b.timerC.Stop()
	}
	if b.cancelTimer != nil {
		b.cancelTimer.Stop()
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

// cancelUpstream handles a CANCEL for the request (§16.10).
func (c *respContext) cancelUpstream() {
	c.mu.Lock()
	c.cancelled = true
	acts := c.closeBranches()
	acts = append(acts, c.progress()...)
	c.mu.Unlock()
	runAll(acts)
}

// sendCancel sends the branch's CANCEL and gives the INVITE 64*T1 to end
// before the proxy terminates it (§9.1). mu must be held.
func (b *branch) sendCancel() []func() {
	c, p := b.c, b.c.p
	b.cancel = cancelSent
	p.stats.cancels.Add(1)
	cancel, dst := b.cancelReq, b.dst
	b.cancelTimer = p.clock.AfterFunc(64*p.t1, func() {
		if p.isClosed() {
			return
		}
		c.mu.Lock()
		tx := b.tx
		live := !b.final && tx != nil
		c.mu.Unlock()
		if live {
			tx.Terminate()
		}
	})
	if cancel == nil {
		return nil
	}
	return []func(){func() {
		p.spawn(func() {
			// The CANCEL's own transaction ends by itself and its response
			// tells the proxy nothing it acts on. If it cannot be sent, the
			// 64*T1 timer still ends the INVITE.
			_, _ = p.layer.Request(cancel, dst, func(*sip.Response, error) {})
		})
	}}
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
		if b.timerC != nil {
			b.timerC.Stop()
		}
		if b.cancelTimer != nil {
			b.cancelTimer.Stop()
		}
	}
}

// forward queues res for the upstream transaction (§16.7 step 9). mu must be
// held; the returned action does the queueing, so responses keep the order in
// which they were decided.
func (c *respContext) forward(res *sip.Response) func() {
	hook := c.dec.OnResponse
	return func() {
		c.up.do(func() {
			if hook != nil {
				hook(c.ctx, res)
			}
			// §16.9: a response that cannot be sent is dropped, and the
			// branches are left alone.
			if err := c.tx.Respond(res); err != nil {
				c.p.stats.upstreamErrors.Add(1)
			}
		})
	}
}

// best chooses the final response when every branch has failed (§16.7 steps 6
// and 7). mu must be held.
func (c *respContext) best() *sip.Response {
	if len(c.finals) == 0 {
		// No branch produced a final response. A request cancelled upstream is
		// answered 487 (§9.2), anything else 408 (§16.7 step 6).
		code := 408
		if c.cancelled {
			code = 487
		}
		return c.made(code).res
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
		return c.made(500).res
	}
	res := chosen.res
	if code == 401 || code == 407 {
		res = res.Clone()
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
	return res
}

// better reports whether a is a better final response than b (§16.7 step 6): any
// 6xx beats every other class, then the lowest class wins. Within 4xx the
// responses that let the client retry with more information are preferred,
// within 5xx anything but a 503, and otherwise the first received stays.
func better(a, b final) bool {
	ca, cb := a.res.StatusCode/100, b.res.StatusCode/100
	switch {
	case ca == 6 || cb == 6:
		return ca == 6 && cb != 6
	case ca != cb:
		return ca < cb
	case ca == 4:
		return retryInfo(a.res.StatusCode) && !retryInfo(b.res.StatusCode)
	case ca == 5:
		return a.res.StatusCode != 503 && b.res.StatusCode == 503
	}
	return false
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

func (s *serial) do(f func()) {
	s.mu.Lock()
	s.queue = append(s.queue, f)
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()
	s.p.spawn(s.drain)
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
