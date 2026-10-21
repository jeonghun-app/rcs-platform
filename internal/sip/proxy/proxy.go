package proxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Defaults for the zero fields of Config.
const (
	// DefaultTimerC is just over the 3 minutes RFC 3261 §16.6 step 11 sets as
	// the least Timer C may be.
	DefaultTimerC = transaction.DefaultTimerC
	// DefaultMaxContexts bounds the requests being forwarded at once. A context
	// lives from the request until every branch has ended, which for an INVITE
	// can be minutes of ringing, so it is sized for the calls a task carries,
	// not for its request rate.
	DefaultMaxContexts = 10000
	// DefaultMaxBranches bounds the branches of one request, every fork group
	// and replacement included. A user has a few devices; a target set larger
	// than this is a misconfiguration or an amplification attempt (RFC 5393 §3).
	DefaultMaxBranches = 16
	// DefaultMaxContextBytes bounds the request bytes all contexts hold
	// together. Each holds its request once, the body shared by its copies,
	// plus a header copy and a CANCEL per branch: a few KiB for a typical
	// request, so the limit bites only when large bodies pile up.
	DefaultMaxContextBytes = 256 << 20
)

// overloadRetryAfter is the Retry-After, in seconds, of a 503 the proxy sends
// because it or its next hop is out of capacity (RFC 3261 §21.5.4).
const overloadRetryAfter = "5"

// Config configures a Proxy. Zero values take the defaults.
type Config struct {
	// Self lists the URIs that name this proxy: the hosts it puts in
	// Record-Route, Path and Service-Route. A URI names the proxy when its host
	// matches one of them, ignoring case, and so does its port, an absent port
	// counting as the default of its scheme and transport. The user part and
	// parameters are not compared, because that is where a proxy carries state
	// to itself, such as a flow token (RFC 5626 §5.2).
	Self []sip.URI
	// Router chooses the targets of each request; nil forwards every request
	// to its Request-URI (Forward).
	Router Router
	// Resolver finds the next hop of a branch; nil is NumericResolver.
	Resolver Resolver
	// Supported lists the option tags a request may name in Proxy-Require;
	// any other is refused with 420 (RFC 3261 §16.3 step 5).
	Supported []string
	// Transaction configures the transaction layer the proxy runs on. Its
	// Clock also runs Timer C, and its T1 times out an unanswered CANCEL (§9.1).
	// DelayTrying is always set, since the proxy forwards provisional responses
	// of its own (§17.2.1). The layer's safety net for a request the proxy
	// never answers must come after the proxy's own deadlines: zero
	// InviteFinalTimeout takes transaction.InviteFinalTimeoutFor(TimerC, T1),
	// and less is refused, as is a NonInviteFinalTimeout under 64*T1 (Timer F)
	// plus transaction.FinalTimeoutMargin.
	Transaction transaction.Config
	// TimerC is how long an INVITE branch may go without a provisional
	// response other than 100 (§16.6 step 11, §16.7 step 2). It must exceed 3
	// minutes.
	TimerC time.Duration
	// MaxContexts bounds the requests in progress at once; a request beyond it
	// is answered 503 with Retry-After. MaxContexts also bounds the ACKs being
	// forwarded at once, beyond which an ACK is dropped and left to the UAS's
	// retransmission of its 2xx (§13.3.1.4).
	MaxContexts int
	// MaxBranches bounds the branches of one request; targets beyond it are
	// dropped and counted.
	MaxBranches int
	// MaxContextBytes bounds the bytes of the requests the contexts hold
	// (see DefaultMaxContextBytes): a request that would take the total past
	// it is answered 503 with Retry-After, and a branch that would fails as a
	// 503 of its own.
	MaxContextBytes int64
	// Rand is the source of branch IDs and of the key behind the proxy's
	// hashes; nil is crypto/rand. Branches start concurrently, so it must be
	// safe for concurrent use.
	Rand io.Reader
	// Logger receives operational events, never message content. Nil discards
	// them.
	Logger *slog.Logger
	// DrainAnswer, if set, chooses the final response Drain gives a request
	// still without one when the stop's time runs out: its status code, 300
	// to 699, and a Retry-After if retryAfter is a second or more. Nil, or a
	// code outside that range, answers 500 with Retry-After: 5. A request
	// cancelled upstream gets 487 whatever it says (§9.2).
	DrainAnswer func(req *sip.Request) (code int, retryAfter time.Duration)
}

// Proxy is the transaction-stateful proxy core of RFC 3261 §16, the transaction
// user of a Layer it owns. Its methods are safe for concurrent use.
type Proxy struct {
	sender    transaction.Sender
	layer     *transaction.Layer
	self      []sip.URI
	router    Router
	resolver  Resolver
	supported map[string]bool
	clock     transaction.Clock
	t1, t2    time.Duration
	timerC    time.Duration
	maxCtx    int
	maxBranch int
	maxBytes  int64
	// bytes is what the contexts hold of maxBytes.
	bytes atomic.Int64
	// silent holds the responses the layer may hand to the sender but that
	// must not be sent (silence).
	silent sync.Map
	ids    sip.IDGenerator
	// drainAns is Config.DrainAnswer.
	drainAns func(*sip.Request) (int, time.Duration)
	// stopping is set once Drain has answered what was left: a request
	// that arrives after that gets the same answer at once, before the
	// Close that follows (QA of #310).
	stopping atomic.Bool
	// cancelsSending counts the CANCELs on their way to the transaction
	// layer, which Drain waits for.
	cancelsSending atomic.Int64
	// key keys the hashes that make the loop-detection part of branch IDs, the
	// branch IDs of ACKs forwarded statelessly and the To tags of responses the
	// proxy makes up, so none of them can be predicted or forged.
	key []byte
	log *slog.Logger
	// ctx is the parent of every request's context; Close cancels it.
	ctx  context.Context
	stop context.CancelFunc

	mu       sync.Mutex
	contexts map[*transaction.ServerTransaction]*respContext
	acks     int
	// awaiting holds the UASs retransmitting a 2xx until its ACK.
	awaiting map[ackKey]*UAS
	closed   bool

	// active counts the goroutines the proxy has started, so Close can wait for
	// them.
	activeMu sync.Mutex
	idle     *sync.Cond
	active   int

	stats counters
}

// New returns a Proxy that sends through s, usually a *transport.Transport,
// whose handler must be the proxy's Receive method:
//
//	var p *proxy.Proxy
//	tr, err := transport.New(tcfg, func(in transport.Inbound) { p.Receive(in) })
//	p, err = proxy.New(tr, proxy.Config{...})
//	tr.Listen(...)
func New(s transaction.Sender, cfg Config) (*Proxy, error) {
	if s == nil {
		return nil, errors.New("proxy: nil sender")
	}
	for _, u := range cfg.Self {
		if !u.IsSIP() || u.Host == "" {
			return nil, errors.New("proxy: Self URIs must be SIP or SIPS URIs with a host")
		}
	}
	if cfg.TimerC == 0 {
		cfg.TimerC = DefaultTimerC
	}
	if cfg.TimerC <= 3*time.Minute {
		return nil, errors.New("proxy: TimerC must be longer than 3 minutes (RFC 3261 §16.6 step 11)")
	}
	if cfg.MaxContexts <= 0 {
		cfg.MaxContexts = DefaultMaxContexts
	}
	if cfg.MaxBranches <= 0 {
		cfg.MaxBranches = DefaultMaxBranches
	}
	if cfg.MaxContextBytes <= 0 {
		cfg.MaxContextBytes = DefaultMaxContextBytes
	}
	if cfg.Router == nil {
		cfg.Router = RouterFunc(func(_ context.Context, r *Request) Decision { return Forward(r) })
	}
	if cfg.Resolver == nil {
		cfg.Resolver = NumericResolver{}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	tcfg := cfg.Transaction
	tcfg.DelayTrying = true
	if tcfg.Clock == nil {
		tcfg.Clock = transaction.SystemClock
	}
	if tcfg.T1 <= 0 {
		tcfg.T1 = transaction.DefaultT1
	}
	if tcfg.T2 <= 0 {
		tcfg.T2 = transaction.DefaultT2
	}
	// The layer answers 500 for a request the proxy has not answered in
	// time; the proxy's own 487 after Timer C and its CANCEL, and its
	// silence after a branch's Timer F (RFC 4320 §4.2), must come first
	// (decided on #156).
	inviteFinal := transaction.InviteFinalTimeoutFor(cfg.TimerC, tcfg.T1)
	if tcfg.InviteFinalTimeout == 0 {
		tcfg.InviteFinalTimeout = inviteFinal
	}
	if tcfg.InviteFinalTimeout < inviteFinal {
		return nil, fmt.Errorf("proxy: Transaction.InviteFinalTimeout %v is under Timer C, 64*T1 and the margin (%v)", tcfg.InviteFinalTimeout, inviteFinal)
	}
	if n := tcfg.NonInviteFinalTimeout; n != 0 && n < 64*tcfg.T1+transaction.FinalTimeoutMargin {
		return nil, fmt.Errorf("proxy: Transaction.NonInviteFinalTimeout %v is under Timer F and the margin (%v)", n, 64*tcfg.T1+transaction.FinalTimeoutMargin)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(cfg.Rand, key); err != nil {
		return nil, fmt.Errorf("proxy: reading the hash key: %w", err)
	}
	p := &Proxy{
		sender:    s,
		self:      cfg.Self,
		router:    cfg.Router,
		resolver:  cfg.Resolver,
		supported: make(map[string]bool),
		clock:     tcfg.Clock,
		t1:        tcfg.T1,
		t2:        tcfg.T2,
		timerC:    cfg.TimerC,
		maxCtx:    cfg.MaxContexts,
		maxBranch: cfg.MaxBranches,
		maxBytes:  cfg.MaxContextBytes,
		ids:       sip.IDGenerator{Rand: cfg.Rand},
		key:       key,
		log:       cfg.Logger,
		drainAns:  cfg.DrainAnswer,
		contexts:  make(map[*transaction.ServerTransaction]*respContext),
		awaiting:  make(map[ackKey]*UAS),
	}
	for _, tag := range cfg.Supported {
		p.supported[strings.ToLower(tag)] = true
	}
	p.idle = sync.NewCond(&p.activeMu)
	p.ctx, p.stop = context.WithCancel(context.Background())
	layer, err := transaction.New(quietSender{s, p}, p, tcfg)
	if err != nil {
		p.stop()
		return nil, err
	}
	p.layer = layer
	return p, nil
}

// quietSender is the transaction layer's sender. It drops the responses silence
// marked, the only way to end a server transaction without sending anything.
type quietSender struct {
	transaction.Sender
	p *Proxy
}

func (q quietSender) SendResponse(res *sip.Response, src transport.Source, opts ...transport.SendOption) error {
	if _, ok := q.p.silent.Load(res); ok {
		return nil
	}
	return q.Sender.SendResponse(res, src, opts...)
}

// silence ends a server transaction without a response (RFC 4320 §4.2, and
// Decision.Discard): the transaction is given res, which quietSender never
// sends, so it completes and absorbs retransmissions as if it had answered.
// The mark is removed once the transaction can no longer resend res: Timer J
// of a non-INVITE one, Timer H of an INVITE one, both 64*T1.
func (p *Proxy) silence(tx *transaction.ServerTransaction, res *sip.Response) {
	p.stats.silenced.Add(1)
	p.silent.Store(res, true)
	_ = tx.Respond(res)
	p.clock.AfterFunc(64*p.t1+time.Second, func() { p.silent.Delete(res) })
}

// reserve takes n bytes of MaxContextBytes, or reports false if they are not
// free.
func (p *Proxy) reserve(n int64) bool {
	for {
		cur := p.bytes.Load()
		if cur+n > p.maxBytes {
			return false
		}
		if p.bytes.CompareAndSwap(cur, cur+n) {
			return true
		}
	}
}

// headerSize estimates the bytes a header takes, as written.
func headerSize(h *sip.Header) int64 {
	var n int64
	for _, f := range h.Fields() {
		n += int64(len(f.Name) + len(f.Value) + 4)
	}
	return n
}

// Receive takes a message from the transport; it is the transport's Handler.
func (p *Proxy) Receive(in transport.Inbound) { p.layer.Receive(in) }

// Layer returns the transaction layer, through which a service sends requests
// of its own as a UAC.
func (p *Proxy) Layer() *transaction.Layer { return p.layer }

// Drain lets the requests in progress finish before a stop, as a service
// does on SIGTERM: it waits until none is left, or until ctx ends, and then
// answers each one still without a final response, 500 with Retry-After
// unless Config.DrainAnswer says otherwise, so its sender tries another
// instance at once instead of waiting 64*T1 for its timers (#281). A request
// a Serve handler is answering is the handler's: its context is cancelled,
// and the handler answers, or the proxy for it once it returns. New
// requests are still served meanwhile: a service's peers keep finding a
// task until its Cloud Map registration and DNS answers age out, and pcscf
// still reaches the clients it has not yet closed. It reports how many
// answers it sent. Call Close after it.
//
// A request that has its final response is not in progress, even while its
// context lingers, after a 2xx to an INVITE to pass retransmissions on or
// while a forked branch waits for the answer to its CANCEL.
func (p *Proxy) Drain(ctx context.Context) int {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if p.inProgress() == 0 {
			// From here on a request is answered as it arrives, as after
			// the deadline: the Close that follows would drop it (QA of
			// #310). The last answers may still sit in the transport's
			// queues.
			p.stopping.Store(true)
			p.flushSender(time.Now().Add(drainSendWait))
			return 0
		}
		select {
		case <-ctx.Done():
			return p.answerForStop()
		case <-tick.C:
		}
	}
}

// inProgress is the number of requests still without a final response.
func (p *Proxy) inProgress() int {
	n := 0
	for _, c := range p.openContexts() {
		if c.inProgress() {
			n++
		}
	}
	return n
}

// openContexts returns the contexts not yet released.
func (p *Proxy) openContexts() []*respContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]*respContext, 0, len(p.contexts))
	for _, c := range p.contexts {
		all = append(all, c)
	}
	return all
}

// DrainSendWait bounds how long Drain waits, after the requests it waited
// for, for the answers and CANCELs to be handed to the transport, which waits
// at most its WriteTimeout for a slow peer, and then written. A service's
// stop margin must leave room for it.
const DrainSendWait = 2 * time.Second

// drainSendWait is DrainSendWait, which a test lengthens to show that
// something else ends the wait.
var drainSendWait = DrainSendWait

// drainFlushStall is how long flushSender waits for any connection with
// output queued to make progress before it gives up on what the queues hold:
// a peer that has stopped reading takes none of it before the Close drops it,
// and would otherwise keep a stop waiting the whole DrainSendWait, most of
// the stop margin (QA of #366). Progress is per connection and per chunk
// written, so neither a long message nor another peer's traffic hides it. The
// kernel takes a full socket's output in steps of about 160 KiB, so this
// keeps waiting for a peer that reads 160 KiB a second or more, however long
// its message; a slower one with that much queued loses the rest at the
// Close, as it did at the end of DrainSendWait. A test lengthens it.
var drainFlushStall = time.Second

// answerForStop answers every request still without a final response, and
// waits until the answers have gone out, so that a Close right after does
// not drop them: handed to the sender, and with a *transport.Transport,
// whose Close drops what its send queues still hold, written as well.
func (p *Proxy) answerForStop() int {
	// From here on a new request is answered as it arrives (Request). One
	// that got its context just before is caught by the second pass.
	p.stopping.Store(true)
	var answered atomic.Int64
	var sent []<-chan struct{}
	for range 2 {
		for _, c := range p.openContexts() {
			if ch := c.answerForStop(&answered); ch != nil {
				sent = append(sent, ch)
			}
		}
	}
	deadline := time.Now().Add(drainSendWait)
	for _, ch := range sent {
		select {
		case <-ch:
		case <-time.After(time.Until(deadline)):
			return int(answered.Load())
		}
	}
	p.flushSender(deadline)
	return int(answered.Load())
}

// flushSender waits, until deadline, for the CANCELs on their way to be
// handed to the transaction layer, and for a *transport.Transport sender to
// write what its send queues hold: its Close drops it. It waits for each
// connection's queue as it was then, the answers still waiting for room in
// it included, and gives up on one whose writer makes no progress for
// drainFlushStall (Transport.Flush).
func (p *Proxy) flushSender(deadline time.Time) {
	for p.cancelsSending.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	tr, ok := p.sender.(*transport.Transport)
	if !ok {
		return
	}
	tr.Flush(deadline, drainFlushStall)
}

// drainResponse is the final response Drain gives req (Config.DrainAnswer).
func (p *Proxy) drainResponse(req *sip.Request) (*sip.Response, error) {
	code, retryAfter := 500, 5*time.Second
	if p.drainAns != nil {
		if c, ra := p.drainAns(req); c >= 300 && c <= 699 {
			code, retryAfter = c, ra
		}
	}
	if retryAfter < time.Second {
		return p.response(req, code)
	}
	return p.response(req, code, [2]string{"Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10)})
}

// FlowClosed tells the proxy that a flow has closed, from the transport's
// OnFlowClosed. A branch sent over it (Target.Destination with Flow) that
// has no final response ends at once and counts as 430 Flow Failed, as a
// send onto the closed flow would (RFC 5626 §5.3), instead of waiting 64*T1
// for Timer B or F.
func (p *Proxy) FlowClosed(id transport.FlowID) { p.layer.FlowClosed(id) }

// Close stops the proxy: every transaction ends without a response, pending
// timers are stopped, and Close returns once the proxy's goroutines have. A
// Router or hook still running sees its context cancelled, and Close waits for
// it to return.
func (p *Proxy) Close() {
	p.mu.Lock()
	p.closed = true
	all := make([]*respContext, 0, len(p.contexts))
	for _, c := range p.contexts {
		all = append(all, c)
	}
	waiting := make([]*UAS, 0, len(p.awaiting))
	for _, u := range p.awaiting {
		waiting = append(waiting, u)
	}
	p.mu.Unlock()
	// The layer closes first, so that nothing a Router or hook does once its
	// context is cancelled can still reach the network.
	p.layer.Close()
	for _, c := range all {
		c.stopTimers()
	}
	for _, u := range waiting {
		u.end()
	}
	p.stop()
	p.wait()
}

func (p *Proxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// spawn runs f on a goroutine of its own, counted for Close.
func (p *Proxy) spawn(f func()) {
	p.activeMu.Lock()
	p.active++
	p.activeMu.Unlock()
	go func() {
		defer func() {
			p.activeMu.Lock()
			p.active--
			if p.active == 0 {
				p.idle.Broadcast()
			}
			p.activeMu.Unlock()
		}()
		f()
	}()
}

// wait returns once no goroutine started by spawn is running.
func (p *Proxy) wait() {
	p.activeMu.Lock()
	for p.active > 0 {
		p.idle.Wait()
	}
	p.activeMu.Unlock()
}

// Request implements transaction.TU. It runs on the goroutine reading the
// network, so everything that can block is started on a goroutine of its own.
// Only an answer to the request just read is sent from here: it goes back where
// the request came from, so it can wait only on a peer that has stopped reading
// what it is sent, and for at most the transport's WriteTimeout.
func (p *Proxy) Request(tx *transaction.ServerTransaction) {
	if tx.Request().Method == "CANCEL" {
		p.receiveCancel(tx)
		return
	}
	if p.stopping.Load() {
		// Drain has answered everything else: this one is answered as they
		// were, statelessly, before the proxy closes.
		if res, err := p.drainResponse(tx.Request()); err == nil {
			if err := tx.Respond(res); err != nil {
				p.stats.upstreamErrors.Add(1)
			}
		}
		return
	}
	c := p.newContext(tx)
	if c == nil {
		// At MaxContexts or MaxContextBytes.
		p.stats.overloaded.Add(1)
		p.reply(tx, 503, [2]string{"Retry-After", overloadRetryAfter})
		return
	}
	p.spawn(c.run)
}

// Stray implements transaction.TU. An ACK for a 2xx is forwarded statelessly
// (§16.11); a response that matches no client transaction is dropped, as RFC
// 6026 §7.3 requires of a transaction-stateful proxy.
func (p *Proxy) Stray(in transport.Inbound) {
	req, ok := in.Message.(*sip.Request)
	if !ok {
		p.stats.strayResponses.Add(1)
		return
	}
	if req.Method == "ACK" {
		p.receiveACK(req, in.Source)
	}
}

// ServerFailed implements transaction.TU. The upstream peer did not take a
// response; it is counted and nothing else is done, so a single bad peer cannot
// cancel the branches of a request (§16.9). The error is not logged: a
// transport error can name the peer's address.
func (p *Proxy) ServerFailed(*transaction.ServerTransaction, error) {
	p.stats.upstreamErrors.Add(1)
}

// newContext registers a response context for tx, or returns nil when
// MaxContexts are in use. It is registered before the request is routed, so a
// CANCEL that arrives meanwhile finds it.
func (p *Proxy) newContext(tx *transaction.ServerTransaction) *respContext {
	req := tx.Request()
	header := headerSize(&req.Header)
	// The request received and the Router's copy of its header; the body is
	// shared.
	cost := int64(len(req.Body)) + 2*header
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.contexts) >= p.maxCtx || !p.reserve(cost) {
		return nil
	}
	c := newRespContext(p, tx, cost, header)
	p.contexts[tx] = c
	return c
}

// release ends a context; its slot comes back at once. With linger, a 2xx went
// upstream, whose retransmissions keep arriving for 64*T1 (Timer M of the
// client transaction, RFC 6026 §7.2) and go through OnResponse, or a branch
// still waits for the answer to its CANCEL, up to 64*T1: the hooks' context
// lives that long, and so does the budget the context's bytes take, because
// the transactions keep the request until then.
func (p *Proxy) release(c *respContext, linger bool) {
	p.mu.Lock()
	delete(p.contexts, c.tx)
	p.mu.Unlock()
	c.unwatch()
	c.mu.Lock()
	n := c.reserved
	c.reserved = 0
	c.mu.Unlock()
	c.cancelReq()
	if linger {
		p.clock.AfterFunc(64*p.t1, func() {
			p.bytes.Add(-n)
			c.cancelCtx()
		})
		return
	}
	p.bytes.Add(-n)
	c.cancelCtx()
}

// receiveCancel answers a CANCEL and cancels the branches of the INVITE it
// refers to (§16.10). A stateful proxy forwards every INVITE through a response
// context, so a CANCEL that matches no INVITE transaction is answered 481 as a
// UAS would (§9.2) rather than forwarded statelessly: its INVITE either never
// came here or has been finished long enough ago for its transaction to go.
func (p *Proxy) receiveCancel(tx *transaction.ServerTransaction) {
	invite, ok := p.layer.InviteFor(tx.Request())
	if !ok {
		p.reply(tx, 481)
		return
	}
	p.mu.Lock()
	c := p.contexts[invite]
	p.mu.Unlock()
	// The request counts as cancelled before its CANCEL is answered, so
	// that no branch whose Prepare or Resolver is still running is sent
	// once the client has the 200 (#361). What the CANCEL sets going here
	// follows the 200; but such a branch, ending unsent meanwhile, may
	// have the INVITE's 487 written before the 200, which RFC 3261 leaves
	// unordered, the two being different transactions.
	var then func()
	if c != nil {
		then = c.cancelUpstream()
	}
	p.reply(tx, 200)
	if then != nil {
		then()
	}
}

// reply answers tx with a response the proxy makes up.
func (p *Proxy) reply(tx *transaction.ServerTransaction, code int, fields ...[2]string) {
	res, err := p.response(tx.Request(), code, fields...)
	if err != nil {
		p.log.Error("proxy: building a response", slog.Int("status", code), slog.String("error", err.Error()))
		return
	}
	if err := tx.Respond(res); err != nil {
		p.stats.upstreamErrors.Add(1)
	}
}

// response builds a response of the proxy's own to req.
//
// sip.NewResponse adds the To tag by writing the To field again, which fails
// for a To the parser accepted but Header.Set refuses to write, such as an
// escaped NUL in the display name (RFC 4475 §3.1.1.2). The response is then
// built with the request's To as it is, without a tag: the client's
// transaction matches it all the same (§17.1.3), and answering beats leaving
// the transaction without a response.
func (p *Proxy) response(req *sip.Request, code int, fields ...[2]string) (*sip.Response, error) {
	if code < 100 || code > 699 {
		return nil, errors.New("proxy: status code outside 100-699")
	}
	res, err := sip.NewResponse(req, code, "", p.toTag(req))
	if err != nil {
		res, err = sip.NewResponse(req, 100, "", "")
		if err != nil {
			return nil, err
		}
		res.Header.Del("Timestamp")
		res.StatusCode, res.Reason = code, sip.DefaultReason(code)
	}
	for _, f := range fields {
		if err := res.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Stats are counters a service exports as metrics.
type Stats struct {
	// Contexts is the number of requests in progress, against MaxContexts,
	// and ContextBytes what they hold, against MaxContextBytes.
	Contexts     int
	ContextBytes int64

	// Counters since New.
	Branches            uint64 // branches started
	TargetsDropped      uint64 // targets refused past MaxBranches
	Cancels             uint64 // CANCELs sent downstream
	TimerC              uint64 // INVITE branches whose Timer C fired
	TargetTimeouts      uint64 // branches whose Target.Timeout fired
	Overloaded          uint64 // requests and branches refused at MaxContexts or MaxContextBytes
	Loops               uint64 // requests answered 482 (RFC 3261 §16.3 step 4)
	Silenced            uint64 // non-INVITE requests left unanswered instead of 408 (RFC 4320 §4.2)
	ProvisionalsDropped uint64 // provisional responses dropped for a slow upstream peer
	// 2xx retransmissions dropped for a slow upstream peer; the UAS sends them
	// again until the ACK.
	RetransmissionsDropped uint64
	StrayResponses         uint64 // responses matching no transaction, dropped (RFC 6026 §7.3)
	ACKsForwarded          uint64 // ACKs for 2xx forwarded statelessly
	ACKsConsumed           uint64 // ACKs for a 2xx a Serve handler sent, delivered to it
	ACKsMissing            uint64 // 2xx a Serve handler sent whose ACK never came
	ACKsDropped            uint64 // ACKs that could not be forwarded
	UpstreamErrors         uint64 // responses the upstream transaction could not send, dropped (§16.9)

	// Drained counts the answers Drain sent to requests that had no final
	// response when the stop's time ran out.
	Drained uint64
}

type counters struct {
	branches, targetsDropped, cancels, timerC, targetTimeouts, overloaded, loops, silenced,
	provisionalsDropped, retransmissionsDropped, strayResponses, acksForwarded, acksConsumed, acksMissing, acksDropped,
	upstreamErrors, drained atomic.Uint64
}

// Stats returns the current gauges and counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	n := len(p.contexts)
	p.mu.Unlock()
	s := &p.stats
	return Stats{
		Contexts:               n,
		ContextBytes:           p.bytes.Load(),
		Branches:               s.branches.Load(),
		TargetsDropped:         s.targetsDropped.Load(),
		Cancels:                s.cancels.Load(),
		TimerC:                 s.timerC.Load(),
		TargetTimeouts:         s.targetTimeouts.Load(),
		Overloaded:             s.overloaded.Load(),
		Loops:                  s.loops.Load(),
		Silenced:               s.silenced.Load(),
		ProvisionalsDropped:    s.provisionalsDropped.Load(),
		RetransmissionsDropped: s.retransmissionsDropped.Load(),
		StrayResponses:         s.strayResponses.Load(),
		ACKsForwarded:          s.acksForwarded.Load(),
		ACKsConsumed:           s.acksConsumed.Load(),
		ACKsMissing:            s.acksMissing.Load(),
		ACKsDropped:            s.acksDropped.Load(),
		UpstreamErrors:         s.upstreamErrors.Load(),

		Drained: s.drained.Load(),
	}
}
