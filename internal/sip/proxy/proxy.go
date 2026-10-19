package proxy

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	DefaultTimerC = 3*time.Minute + time.Second
	// DefaultMaxContexts bounds the requests being forwarded at once. A context
	// lives from the request until every branch has ended, which for an INVITE
	// can be minutes of ringing, so it is sized for the calls a task carries,
	// not for its request rate.
	DefaultMaxContexts = 10000
	// DefaultMaxBranches bounds the branches of one request, every fork group
	// and replacement included. A user has a few devices; a target set larger
	// than this is a misconfiguration or an amplification attempt (RFC 5393 §3).
	DefaultMaxBranches = 16
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
	// of its own (§17.2.1).
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
	// Rand is the source of branch IDs and of the key behind the proxy's
	// hashes; nil is crypto/rand.
	Rand io.Reader
	// Logger receives operational events, never message content. Nil discards
	// them.
	Logger *slog.Logger
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
	t1        time.Duration
	timerC    time.Duration
	maxCtx    int
	maxBranch int
	ids       sip.IDGenerator
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
		timerC:    cfg.TimerC,
		maxCtx:    cfg.MaxContexts,
		maxBranch: cfg.MaxBranches,
		ids:       sip.IDGenerator{Rand: cfg.Rand},
		key:       key,
		log:       cfg.Logger,
		contexts:  make(map[*transaction.ServerTransaction]*respContext),
	}
	for _, tag := range cfg.Supported {
		p.supported[strings.ToLower(tag)] = true
	}
	p.idle = sync.NewCond(&p.activeMu)
	p.ctx, p.stop = context.WithCancel(context.Background())
	p.layer = transaction.New(s, p, tcfg)
	return p, nil
}

// Receive takes a message from the transport; it is the transport's Handler.
func (p *Proxy) Receive(in transport.Inbound) { p.layer.Receive(in) }

// Layer returns the transaction layer, through which a service sends requests
// of its own as a UAC.
func (p *Proxy) Layer() *transaction.Layer { return p.layer }

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
	p.mu.Unlock()
	p.stop()
	for _, c := range all {
		c.stopTimers()
	}
	p.layer.Close()
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
	c := p.newContext(tx)
	if c == nil {
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.contexts) >= p.maxCtx {
		return nil
	}
	c := newRespContext(p, tx)
	p.contexts[tx] = c
	return c
}

func (p *Proxy) release(c *respContext) {
	p.mu.Lock()
	delete(p.contexts, c.tx)
	p.mu.Unlock()
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
	p.reply(tx, 200)
	p.mu.Lock()
	c := p.contexts[invite]
	p.mu.Unlock()
	if c != nil {
		c.cancelUpstream()
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
func (p *Proxy) response(req *sip.Request, code int, fields ...[2]string) (*sip.Response, error) {
	res, err := sip.NewResponse(req, code, "", p.toTag(req))
	if err != nil {
		return nil, err
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
	// Contexts is the number of requests in progress, against MaxContexts.
	Contexts int

	// Counters since New.
	Branches       uint64 // branches started
	TargetsDropped uint64 // targets refused past MaxBranches
	Cancels        uint64 // CANCELs sent downstream
	TimerC         uint64 // INVITE branches whose Timer C fired
	Overloaded     uint64 // requests answered 503 at MaxContexts
	Loops          uint64 // requests answered 482 (RFC 3261 §16.3 step 4)
	StrayResponses uint64 // responses matching no transaction, dropped (RFC 6026 §7.3)
	ACKsForwarded  uint64 // ACKs for 2xx forwarded statelessly
	ACKsDropped    uint64 // ACKs that could not be forwarded
	UpstreamErrors uint64 // responses the upstream transaction could not send, dropped (§16.9)
}

type counters struct {
	branches, targetsDropped, cancels, timerC, overloaded, loops,
	strayResponses, acksForwarded, acksDropped, upstreamErrors atomic.Uint64
}

// Stats returns the current gauges and counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	n := len(p.contexts)
	p.mu.Unlock()
	s := &p.stats
	return Stats{
		Contexts:       n,
		Branches:       s.branches.Load(),
		TargetsDropped: s.targetsDropped.Load(),
		Cancels:        s.cancels.Load(),
		TimerC:         s.timerC.Load(),
		Overloaded:     s.overloaded.Load(),
		Loops:          s.loops.Load(),
		StrayResponses: s.strayResponses.Load(),
		ACKsForwarded:  s.acksForwarded.Load(),
		ACKsDropped:    s.acksDropped.Load(),
		UpstreamErrors: s.upstreamErrors.Load(),
	}
}
