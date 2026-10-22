package msrprelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/panics"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// defaultProxyHeaderTimeout bounds the wait for a PROXY header. The NLB
// writes it with the connection, so only a client that skipped the NLB, or
// one that opened a connection and went quiet, takes this long.
const defaultProxyHeaderTimeout = 5 * time.Second

// expiryRetry is how soon a bridge's binding is looked at again when the
// store could not be read: a DynamoDB hiccup must not cut a running chat.
const expiryRetry = 30 * time.Second

// relayOptions configure a Relay.
type relayOptions struct {
	Store        store.Store
	StoreTimeout time.Duration
	// Public is the client-facing authority bindings were handed out with;
	// a request whose To-Path names another is not for this relay.
	Public        msrp.URI
	ProxyProtocol bool

	MaxConnections          int
	MaxConnectionsPerSource int
	MaxConcurrentBinds      int
	// FailedLookupsPerSource is the per-source lookup budget (see
	// lookupBudget), per minute.
	FailedLookupsPerSource int
	PathWait               time.Duration
	CoreConnectTimeout     time.Duration
	IdleTimeout            time.Duration
	// ProxyHeaderTimeout is the real-time wait for a PROXY header; zero
	// means defaultProxyHeaderTimeout.
	ProxyHeaderTimeout time.Duration
	// FirstBindTimeout is how long a client connection may go without
	// naming a session the first time; zero means
	// msrp.DefaultUnboundTimeout. Once it has carried a bridge, a connection
	// left with none stays for IdleTimeout instead, so the client can reuse
	// it (RFC 4975 §5.4) for its next session.
	FirstBindTimeout time.Duration
	// UserTimeout is TCP_USER_TIMEOUT on client sockets (setUserTimeout);
	// zero leaves the kernel default.
	UserTimeout time.Duration

	// Edge configures client connections and Core the connections toward
	// rcs-as; Clock, Rand and OnEvent are filled in by newRelay.
	Edge, Core msrp.Config
	// Dial opens a connection toward rcs-as; the address has been checked
	// against CoreNetworks only if it is an IP literal, so Dial checks what
	// it actually connects to.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	Clock   msrp.Clock
	Rand    io.Reader
	Log     *slog.Logger
	Metrics *counters
}

// Relay is msrp-relay's data path: passive toward clients, active toward
// rcs-as (ADR 0004). A client connects, sends its first SEND, and the
// session in its To-Path is looked up in the store, claimed, and bridged to
// a session the relay opens toward rcs-as there and then.
type Relay struct {
	o        relayOptions
	instance string
	pool     *msrp.Pool
	binds    chan struct{}
	budget   *lookupBudget
	// ctx ends store calls and core connection attempts when the relay
	// closes.
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	listeners []net.Listener
	// admitted counts connections from accept to close, including those
	// whose PROXY header is still being read.
	admitted int
	sources  map[netip.Prefix]int
	// conns are the client connections, from accept to close, so Close can
	// end them wherever they are, a PROXY header read included.
	conns    map[net.Conn]struct{}
	nextConn uint64
	draining bool
	// drained is closed when admitted reaches zero during a drain.
	drained chan struct{}
	handled sync.WaitGroup
}

// bridge is one bridged session pair.
type bridge struct {
	binding  string
	claimant string
	edge     *msrp.Session

	mu    sync.Mutex
	timer msrp.Timer
	ended bool
}

// logged passes each event to count, and logs the ones that say the relay
// itself is failing, which no metric explains alone: a keep-alive it could
// not build. side is "client" or "core"; an Event carries no identifier.
func logged(log *slog.Logger, side string, count func(msrp.Event)) func(msrp.Event) {
	return func(e msrp.Event) {
		count(e)
		if e.Err == msrp.ErrKeepAliveNotSent {
			log.Error("an MSRP keep-alive could not be sent", slog.String("side", side))
		}
	}
}

func newRelay(o relayOptions) (*Relay, error) {
	instance, err := msrp.NewMessageID(o.Rand)
	if err != nil {
		return nil, err
	}
	if o.ProxyHeaderTimeout <= 0 {
		o.ProxyHeaderTimeout = defaultProxyHeaderTimeout
	}
	if o.FirstBindTimeout <= 0 {
		o.FirstBindTimeout = msrp.DefaultUnboundTimeout
	}
	// internal/msrp's unbound timer runs whenever a connection carries no
	// session: from the start, and again when its last session ends. The
	// first case is FirstBindTimeout's (see handle); for the second, which
	// is a client whose bridge ended from the core side, the connection is
	// kept like any other quiet one.
	o.Edge.UnboundTimeout = o.IdleTimeout
	o.Edge.Clock, o.Edge.Rand, o.Edge.OnEvent = o.Clock, o.Rand, logged(o.Log, "client", o.Metrics.onEvent(mClientPrefix))
	o.Core.Clock, o.Core.Rand, o.Core.OnEvent = o.Clock, o.Rand, logged(o.Log, "core", o.Metrics.onEvent(mCorePrefix))
	// One guard for every connection, both sides, and the goroutines that
	// read a client's PROXY header (handle), so that the log limit holds
	// for all of them (#445).
	guard := panics.New(panics.Config{
		Metric: msrp.MetricCallbackPanics, Message: "msrp-relay: a panic ended a connection's work", Log: o.Log, Metrics: o.Metrics,
	})
	o.Edge.Panics, o.Core.Panics = guard, guard
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{
		o:        o,
		instance: instance,
		binds:    make(chan struct{}, o.MaxConcurrentBinds),
		budget:   newLookupBudget(o.Clock, o.FailedLookupsPerSource),
		ctx:      ctx,
		cancel:   cancel,
		sources:  map[netip.Prefix]int{},
		conns:    map[net.Conn]struct{}{},
	}
	r.pool = &msrp.Pool{Config: o.Core, Dial: r.dialCore}
	return r, nil
}

// dialCore connects toward rcs-as. TLS on that leg is out of scope
// (ADR 0007), and an msrps core_path is refused by the control API already.
func (r *Relay) dialCore(ctx context.Context, to msrp.URI) (net.Conn, error) {
	if to.Secure {
		return nil, errors.New("msrprelay: msrps toward rcs-as is not supported")
	}
	addr, err := to.Addr()
	if err != nil {
		return nil, err
	}
	return r.o.Dial(ctx, "tcp", addr)
}

// coreDialer returns a dialer that connects only to addresses in networks
// and to ports in ports, checked on the resolved address, so a name in the
// namespace cannot be made to point the relay elsewhere. Kernel keep-alive stays on: this side is not
// client-facing (ADR 0003).
func coreDialer(networks []netip.Prefix, ports []uint16, timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !inNetworks(ap.Addr(), networks) || !slices.Contains(ports, ap.Port()) {
				return errCoreNotAllowed
			}
			return nil
		},
	}
	return d.DialContext
}

var errCoreNotAllowed = errors.New("msrprelay: core address outside RELAY_CORE_NETWORKS or RELAY_CORE_PORTS")

// Serve accepts client connections on ln until ln fails or the relay
// drains. Kernel TCP keep-alive must be off on ln (ADR 0003); listen does
// that.
func (r *Relay) Serve(ln net.Listener) error {
	r.mu.Lock()
	if r.draining {
		r.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	r.listeners = append(r.listeners, ln)
	r.mu.Unlock()
	var delay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if r.isDraining() {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of file descriptors and the like: back off as net/http
			// does, rather than spinning or giving up.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			r.o.Log.Warn("accept failed", slog.String("error", pii.Redact(err.Error())))
			time.Sleep(delay)
			continue
		}
		delay = 0
		if reason := r.admit(nc); reason != "" {
			r.o.Metrics.refuse(reason)
			_ = nc.Close()
			continue
		}
		r.handled.Add(1)
		// A panic ends this connection only; handle's deferred calls
		// close it and count it out first.
		go r.o.Edge.Panics.Run("handle", func() { r.handle(nc) })
	}
}

func (r *Relay) isDraining() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.draining
}

// admit counts nc in, or returns the reason it is refused. A connection
// accepted just as the drain began is not a capacity problem, so it is
// counted apart.
func (r *Relay) admit(nc net.Conn) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.draining:
		return reasonDraining
	case r.admitted >= r.o.MaxConnections:
		return reasonConnectionLimit
	}
	r.admitted++
	r.conns[nc] = struct{}{}
	return ""
}

func (r *Relay) leave(nc net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, nc)
	r.admitted--
	if r.admitted == 0 && r.drained != nil {
		close(r.drained)
		r.drained = nil
	}
}

// handle serves one accepted connection to its end.
func (r *Relay) handle(nc net.Conn) {
	defer r.handled.Done()
	defer r.leave(nc)
	defer nc.Close()
	if err := setUserTimeout(nc, r.o.UserTimeout); err != nil {
		r.o.Log.Debug("TCP_USER_TIMEOUT not set", slog.String("error", pii.Redact(err.Error())))
	}
	src, ok := r.source(nc)
	if !ok {
		return
	}
	key := sourceKey(src)
	if !r.enterSource(key) {
		r.o.Metrics.refuse(reasonSourceLimit)
		return
	}
	defer r.leaveSource(key)

	mc := &meteredConn{Conn: nc, idle: r.o.IdleTimeout, in: &r.o.Metrics.bytesIn, out: &r.o.Metrics.bytesOut}
	// The id names the connection in claimed_by, so a claim says which
	// task and connection hold the binding.
	id := r.instance + "/" + strconv.FormatUint(r.nextConnID(), 10)
	b := &binder{r: r, connID: id, source: key}
	c, err := msrp.NewPassiveConn(mc, b, r.o.Edge)
	if err != nil {
		return
	}
	// The active side sends its first SEND at once (RFC 4975 §5.4); a
	// connection that has named no session by now is not going to.
	var unbound atomic.Bool
	first := r.o.Clock.AfterFunc(r.o.FirstBindTimeout, func() {
		if !b.everBound.Load() {
			unbound.Store(true)
			_ = c.Close()
		}
	})
	defer first.Stop()
	r.o.Metrics.conns.Add(1)
	<-c.Done()
	r.o.Metrics.conns.Add(-1)
	// A connection is counted for the reason it ended with. One that a
	// refusal was delivering answers for (internal/msrp, #219) ends with
	// that reason whatever closed it meanwhile, and is counted there
	// alone, not also as unbound or idle.
	switch err := c.Err(); {
	case unbound.Load() && errors.Is(err, msrp.ErrConnClosed):
		r.o.Metrics.add(mUnboundClosed, 1)
	case mc.idled.Load() && errors.Is(err, errIdle):
		r.o.Metrics.add(mIdleClosed, 1)
	}
}

// source returns the client's address: from the PROXY header when one is
// required, from the socket otherwise. It is personal data: a log of it goes
// through pii.ClientIP (#80). A LOCAL header is an NLB health
// check and is closed without a word, as is a connection that sends nothing
// at all, which is what a plain TCP health check does.
func (r *Relay) source(nc net.Conn) (netip.Addr, bool) {
	if !r.o.ProxyProtocol {
		ap, err := netip.ParseAddrPort(nc.RemoteAddr().String())
		if err != nil {
			return netip.Addr{}, false
		}
		return ap.Addr().Unmap(), true
	}
	_ = nc.SetReadDeadline(time.Now().Add(r.o.ProxyHeaderTimeout))
	h, err := proxyproto.Read(nc)
	_ = nc.SetReadDeadline(time.Time{})
	switch {
	case errors.Is(err, io.EOF):
		return netip.Addr{}, false
	case err != nil:
		r.o.Metrics.refuse(reasonProxyHeader)
		return netip.Addr{}, false
	case h.Command == proxyproto.Local:
		r.o.Metrics.add(mHealthChecks, 1)
		return netip.Addr{}, false
	}
	return h.Source.Addr(), true
}

// sourceKey is what the per-source cap counts: the address for IPv4, the
// /64 for IPv6, since a mobile network gives each subscriber bearer a whole
// /64 (RFC 6459 §5.2), and a client could otherwise open the cap's worth of
// connections from every address in it.
func sourceKey(a netip.Addr) netip.Prefix {
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

func (r *Relay) enterSource(key netip.Prefix) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sources[key] >= r.o.MaxConnectionsPerSource {
		return false
	}
	r.sources[key]++
	return true
}

func (r *Relay) leaveSource(key netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sources[key]--; r.sources[key] <= 0 {
		delete(r.sources, key)
	}
}

func (r *Relay) nextConnID() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextConn++
	return r.nextConn
}

// binder looks up the sessions one client connection names.
type binder struct {
	r      *Relay
	connID string
	source netip.Prefix
	// bridges counts the live bridges on this connection; see refuseHard.
	// everBound is set by the first bridge.
	bridges   atomic.Int64
	everBound atomic.Bool
}

// errOverload and errBudget end a connection whose bind found no lookup
// slot, or whose source has used up its lookup budget.
var (
	errOverload = errors.New("msrprelay: too many binds in flight")
	errBudget   = errors.New("msrprelay: source has used up its lookup budget")
)

// bindSlotWait is how long a bind waits for a lookup slot. It absorbs a
// burst of clients arriving together; a store slow enough to keep every
// slot busy for longer is an outage, and waiting longer would only hold
// more client goroutines.
const bindSlotWait = 250 * time.Millisecond

// Bind implements msrp.Binder. It runs on the client connection's reading
// goroutine, so a slow lookup holds up that client alone. What every client
// shares is bounded: store calls in flight (the bind slots, held for the
// lookup and the claim only) and, per source, lookups that find nothing.
func (b *binder) Bind(c *msrp.Conn, to msrp.URI) (*msrp.Session, error) {
	r := b.r
	local := r.o.Public
	local.SessionID = to.SessionID
	// A session id this relay did not issue cannot name a binding, so it
	// is refused before it can cost a store read or a bind slot.
	if !issuedSessionID(to.SessionID) || !local.Equal(to) {
		r.o.Metrics.refuse(reasonUnknownSession)
		return nil, msrp.ErrNoSession
	}
	switch ok, tracked := r.budget.take(b.source); {
	case !ok:
		r.o.Metrics.refuse(reasonSourceBudget)
		return nil, b.refuseHard(c, errBudget)
	case !tracked:
		r.o.Metrics.add(mBudgetUntracked, 1)
	}
	charged := true
	defer func() {
		if !charged {
			r.budget.refund(b.source)
		}
	}()
	if !r.acquire() {
		charged = false
		if r.ctx.Err() != nil {
			r.o.Metrics.refuse(reasonDraining)
		} else {
			r.o.Metrics.refuse(reasonBindOverload)
		}
		return nil, b.refuseHard(c, errOverload)
	}
	// The slot comes back once, even after a panic in a store call (#471
	// code review).
	held := true
	release := func() {
		if held {
			held = false
			r.release()
		}
	}
	defer release()

	id := BindingID(to.SessionID)
	bnd, err := r.awaitComplete(id)
	if err == nil && bnd.ClaimedBy == b.connID {
		// This connection held the binding and its bridge has ended, most
		// likely from the core side; the client, which cannot know, names
		// the session again. Not a second connection: the session is over.
		release()
		charged = false
		r.o.Metrics.refuse(reasonEndedSession)
		return nil, msrp.ErrNoSession
	}
	if err == nil {
		bnd, err = r.claim(id, b.connID)
	}
	// The slot covers the store calls only: connecting to rcs-as happens
	// outside it, so one unreachable rcs-as cannot use up every slot.
	release()
	if err != nil {
		charged = errors.Is(err, store.ErrNotFound)
		return nil, b.refuseBind(c, id, err)
	}
	charged = false
	r.o.Metrics.add(mBindingsClaimed, 1)

	edge, core, err := sessions(local, bnd)
	if err != nil {
		// The control API validated both paths, so this is a corrupt item.
		r.o.Log.Error("binding holds an unusable path", slog.String("binding", id))
		return nil, msrp.ErrNoSession
	}
	if err := msrp.Bridge(edge, core); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.o.CoreConnectTimeout)
	err = r.pool.Open(ctx, core)
	cancel()
	if err != nil {
		_ = edge.Close()
		if r.ctx.Err() != nil {
			r.o.Metrics.refuse(reasonDraining)
			return nil, msrp.ErrNoSession
		}
		r.o.Metrics.refuse(reasonCoreUnreachable)
		r.o.Log.Warn("could not open the session toward rcs-as", slog.String("binding", id), slog.String("error", pii.Redact(err.Error())))
		return nil, msrp.ErrNoSession
	}
	r.startBridge(b, id, edge, bnd.ExpiresAt)
	return edge, nil
}

// issuedSessionID reports whether s has the form msrp.NewSessionID gives:
// 32 characters of lower-case base32.
func issuedSessionID(s string) bool {
	if len(s) != issuedSessionIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || '2' <= c && c <= '7') {
			return false
		}
	}
	return true
}

// issuedSessionIDLen is the length of a 160-bit msrp.NewSessionID.
const issuedSessionIDLen = 32

// acquire takes a bind slot, waiting up to bindSlotWait for one.
func (r *Relay) acquire() bool {
	select {
	case r.binds <- struct{}{}:
		return true
	default:
	}
	expired := make(chan struct{})
	t := r.o.Clock.AfterFunc(bindSlotWait, func() { close(expired) })
	defer t.Stop()
	select {
	case r.binds <- struct{}{}:
		return true
	case <-expired:
	case <-r.ctx.Done():
	}
	return false
}

func (r *Relay) release() { <-r.binds }

// refuseHard refuses a bind for a reason that says nothing about the
// session itself: overload, an exhausted budget, a store failure. MSRP has
// no "try later" (RFC 4975 §10), and every code ends the session for good,
// so on a connection that carries no bridge the connection is closed
// instead: that looks like any transport failure, which the client
// recovers from with a new INVITE, as it would if the task had gone. A
// connection that already carries bridges is kept for their sake (§5.4
// connection reuse), and only the new session is refused, with 481.
func (b *binder) refuseHard(c *msrp.Conn, err error) error {
	if b.bridges.Load() > 0 {
		return msrp.ErrNoSession
	}
	_ = c.Close()
	return err
}

// awaitComplete reads the binding until both paths are known or PathWait
// has passed. Only the second row of ADR 0004's table can find a path
// missing: the client connects as soon as it has answered, and pcscf records
// the client's path from that same answer.
func (r *Relay) awaitComplete(id string) (store.Binding, error) {
	deadline := r.o.Clock.Now().Add(r.o.PathWait)
	delay := 25 * time.Millisecond
	for {
		b, err := r.get(id)
		if err != nil || b.Complete() {
			return b, err
		}
		left := deadline.Sub(r.o.Clock.Now())
		if left <= 0 {
			return store.Binding{}, store.ErrIncomplete
		}
		if err := r.sleep(min(delay, left)); err != nil {
			return store.Binding{}, err
		}
		delay *= 2
	}
}

func (r *Relay) sleep(d time.Duration) error {
	done := make(chan struct{})
	t := r.o.Clock.AfterFunc(d, func() { close(done) })
	select {
	case <-done:
		return nil
	case <-r.ctx.Done():
		t.Stop()
		return r.ctx.Err()
	}
}

func (r *Relay) get(id string) (store.Binding, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.o.StoreTimeout)
	defer cancel()
	return r.o.Store.Get(ctx, id, r.o.Clock.Now())
}

func (r *Relay) claim(id, by string) (store.Binding, error) {
	ctx, cancel := context.WithTimeout(r.ctx, r.o.StoreTimeout)
	defer cancel()
	return r.o.Store.Claim(ctx, id, by, r.o.Clock.Now())
}

// refuseBind answers a bind the store refused or could not serve.
func (b *binder) refuseBind(c *msrp.Conn, id string, err error) error {
	r := b.r
	switch {
	case errors.Is(err, store.ErrNotFound):
		r.o.Metrics.refuse(reasonUnknownSession)
		return msrp.ErrNoSession
	case errors.Is(err, store.ErrIncomplete):
		r.o.Metrics.refuse(reasonIncomplete)
		return msrp.ErrNoSession
	case errors.Is(err, store.ErrClaimed):
		// ADR 0004: one client connection per binding, across tasks; a
		// second is refused with 403 and logged. RFC 4975 §5.4 would say
		// 506, which only fits a session this node already holds.
		r.o.Metrics.refuse(reasonClaimed)
		r.o.Log.Warn("refused a second connection for a claimed binding", slog.String("binding", id))
		return &msrp.StatusError{Code: msrp.StatusForbidden, Comment: msrp.StatusText(msrp.StatusForbidden)}
	case r.ctx.Err() != nil:
		// The relay is closing; a lookup it cut short is not a store fault.
		r.o.Metrics.refuse(reasonDraining)
		return b.refuseHard(c, err)
	}
	r.o.Metrics.refuse(reasonStore)
	r.o.Metrics.add(mStoreErrors, 1)
	r.o.Log.Warn("binding lookup failed", slog.String("binding", id), slog.String("error", pii.Redact(err.Error())))
	return b.refuseHard(c, err)
}

// sessions builds the two sides of a bridge: edge toward the client, named
// by the To-Path it used, and core toward rcs-as.
func sessions(local msrp.URI, b store.Binding) (edge, core *msrp.Session, err error) {
	client, err := msrp.ParseURI(b.ClientEndpointPath)
	if err != nil {
		return nil, nil, err
	}
	as, err := msrp.ParseURI(b.CorePath)
	if err != nil {
		return nil, nil, err
	}
	coreLocal, err := msrp.ParseURI(b.CoreLocal)
	if err != nil {
		return nil, nil, err
	}
	if edge, err = msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{client}}); err != nil {
		return nil, nil, err
	}
	if core, err = msrp.NewSession(msrp.SessionConfig{Local: coreLocal, Remote: []msrp.URI{as}}); err != nil {
		return nil, nil, err
	}
	return edge, core, nil
}

// startBridge tracks a bridge until its client side ends, and checks the
// binding again whenever its expiry comes: pcscf extends it on every session
// refresh, and one it let lapse or released ends the bridge.
func (r *Relay) startBridge(b *binder, id string, edge *msrp.Session, expires time.Time) {
	br := &bridge{binding: id, claimant: b.connID, edge: edge}
	r.o.Metrics.bridges.Add(1)
	b.bridges.Add(1)
	b.everBound.Store(true)
	br.arm(r, expires.Sub(r.o.Clock.Now()))
	go func() {
		<-edge.Done()
		br.mu.Lock()
		br.ended = true
		if br.timer != nil {
			br.timer.Stop()
		}
		br.mu.Unlock()
		b.bridges.Add(-1)
		r.o.Metrics.bridges.Add(-1)
	}()
}

func (br *bridge) arm(r *Relay, after time.Duration) {
	br.mu.Lock()
	defer br.mu.Unlock()
	if br.ended {
		return
	}
	br.timer = r.o.Clock.AfterFunc(max(after, 0), func() { r.checkExpiry(br) })
}

func (r *Relay) checkExpiry(br *bridge) {
	b, err := r.get(br.binding)
	switch {
	case errors.Is(err, store.ErrNotFound), err == nil && b.ClaimedBy != br.claimant:
		r.o.Metrics.add(mBindingsExpired, 1)
		r.o.Log.Debug("bridge ended: its binding expired or was released", slog.String("binding", br.binding))
		_ = br.edge.Close()
	case err != nil:
		if r.ctx.Err() != nil {
			return
		}
		r.o.Metrics.add(mStoreErrors, 1)
		br.arm(r, expiryRetry)
	default:
		br.arm(r, b.ExpiresAt.Sub(r.o.Clock.Now()))
	}
}

// Drain stops accepting, gives the client connections until timeout (on the
// relay's clock) or the end of ctx to finish, and then closes the rest:
// their clients reconnect through a new INVITE, which pcscf anchors on
// another task (ADR 0003). Connections still open halfway through are
// closed one by one over the second half, so their clients do not all
// come back at the same moment, which would turn a rolling update into a
// burst of control calls and claims (ADR 0003 asks the same of pcscf).
func (r *Relay) Drain(ctx context.Context, timeout time.Duration) {
	r.mu.Lock()
	r.draining = true
	lns := r.listeners
	r.listeners = nil
	var drained chan struct{}
	if r.admitted > 0 {
		drained = make(chan struct{})
		r.drained = drained
	}
	r.mu.Unlock()
	for _, ln := range lns {
		_ = ln.Close()
	}
	if drained != nil {
		r.spreadCloses(ctx, drained, timeout)
	}
	r.Close()
}

// spreadCloses waits for the first half of the drain, then closes the
// connections left one at a time at even steps over the second half. It
// returns when they are all gone, the time is up, or ctx ends.
func (r *Relay) spreadCloses(ctx context.Context, drained <-chan struct{}, timeout time.Duration) {
	half := timeout / 2
	if !r.wait(ctx, drained, half) {
		return
	}
	r.mu.Lock()
	conns := make([]net.Conn, 0, len(r.conns))
	for nc := range r.conns {
		conns = append(conns, nc)
	}
	r.mu.Unlock()
	if len(conns) == 0 {
		return
	}
	step := (timeout - half) / time.Duration(len(conns))
	for i, nc := range conns {
		_ = nc.Close()
		if i < len(conns)-1 && !r.wait(ctx, drained, step) {
			return
		}
	}
}

// wait sleeps d on the relay's clock, reporting false if drained closed or
// ctx ended first.
func (r *Relay) wait(ctx context.Context, drained <-chan struct{}, d time.Duration) bool {
	expired := make(chan struct{})
	t := r.o.Clock.AfterFunc(d, func() { close(expired) })
	defer t.Stop()
	select {
	case <-expired:
		return true
	case <-drained:
	case <-ctx.Done():
	}
	return false
}

// Close closes every connection at once and waits for their goroutines.
func (r *Relay) Close() {
	r.mu.Lock()
	r.draining = true
	lns := r.listeners
	r.listeners = nil
	conns := make([]net.Conn, 0, len(r.conns))
	for nc := range r.conns {
		conns = append(conns, nc)
	}
	r.mu.Unlock()
	r.cancel()
	for _, ln := range lns {
		_ = ln.Close()
	}
	// Closing the socket ends the msrp.Conn on it, and with it every
	// session and bridge it carries.
	for _, nc := range conns {
		_ = nc.Close()
	}
	_ = r.pool.Close()
	r.handled.Wait()
}

// meteredConn counts what crosses a client connection and closes it after
// IdleTimeout without a byte in either direction (ADR 0003). Traffic toward
// the client counts too: rcs-as may send with Failure-Report no or partial,
// which the client does not answer (RFC 4975 §7.1.2), and the relay
// forwards that header as it is, so a client that only receives would
// otherwise be cut while chatting. A dead client is still caught, by the
// write timeout and the unanswered keep-alive. The NLB's idle timer works
// the same way. The deadline is real time: the operating system enforces
// it.
type meteredConn struct {
	net.Conn
	idle    time.Duration
	in, out *atomic.Int64
	idled   atomic.Bool
}

// errIdle replaces the deadline error, which internal/msrp would otherwise
// report as a write timeout, the only deadline it sets itself.
var errIdle = errors.New("msrprelay: client connection idle")

func (c *meteredConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Read(p)
	c.in.Add(int64(n))
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		c.idled.Store(true)
		return n, errIdle
	}
	return n, err
}

// CloseWrite half-closes the connection, which internal/msrp does to
// deliver the answers it owes before it closes (#219).
func (c *meteredConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	if n > 0 && c.idle > 0 {
		// A deadline set while a Read waits applies to that Read.
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return n, err
}
