package msrprelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// proxyHeaderTimeout bounds the wait for a PROXY header. The NLB writes it
// with the connection, so only a client that skipped the NLB, or one that
// opened a connection and went quiet, takes this long.
const proxyHeaderTimeout = 5 * time.Second

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
	PathWait                time.Duration
	CoreConnectTimeout      time.Duration
	IdleTimeout             time.Duration

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

func newRelay(o relayOptions) (*Relay, error) {
	instance, err := msrp.NewMessageID(o.Rand)
	if err != nil {
		return nil, err
	}
	o.Edge.Clock, o.Edge.Rand, o.Edge.OnEvent = o.Clock, o.Rand, o.Metrics.onEvent(mClientPrefix)
	o.Core.Clock, o.Core.Rand, o.Core.OnEvent = o.Clock, o.Rand, o.Metrics.onEvent(mCorePrefix)
	ctx, cancel := context.WithCancel(context.Background())
	r := &Relay{
		o:        o,
		instance: instance,
		binds:    make(chan struct{}, o.MaxConcurrentBinds),
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

// coreDialer returns a dialer that connects only to addresses in networks,
// checked on the resolved address, so a name in the namespace cannot be made
// to point the relay elsewhere. Kernel keep-alive stays on: this side is not
// client-facing (ADR 0003).
func coreDialer(networks []netip.Prefix, timeout time.Duration) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !inNetworks(ap.Addr(), networks) {
				return errCoreNotAllowed
			}
			return nil
		},
	}
	return d.DialContext
}

var errCoreNotAllowed = errors.New("msrprelay: core address outside RELAY_CORE_NETWORKS")

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
		if !r.admit(nc) {
			r.o.Metrics.refuse(reasonConnectionLimit)
			_ = nc.Close()
			continue
		}
		r.handled.Add(1)
		go r.handle(nc)
	}
}

func (r *Relay) isDraining() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.draining
}

func (r *Relay) admit(nc net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.draining || r.admitted >= r.o.MaxConnections {
		return false
	}
	r.admitted++
	r.conns[nc] = struct{}{}
	return true
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
	c, err := msrp.NewPassiveConn(mc, &binder{r: r, connID: id}, r.o.Edge)
	if err != nil {
		return
	}
	r.o.Metrics.conns.Add(1)
	<-c.Done()
	r.o.Metrics.conns.Add(-1)
	if mc.idled.Load() {
		r.o.Metrics.add(mIdleClosed, 1)
	}
}

// source returns the client's address: from the PROXY header when one is
// required, from the socket otherwise. A LOCAL header is an NLB health
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
	_ = nc.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
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
}

// errOverload ends a connection whose bind found no lookup slot.
var errOverload = errors.New("msrprelay: too many binds in flight")

// Bind implements msrp.Binder. It runs on the client connection's reading
// goroutine, so a slow lookup holds up that client alone; the number of
// lookups in flight is bounded all the same, since each is a store call.
func (b *binder) Bind(c *msrp.Conn, to msrp.URI) (*msrp.Session, error) {
	r := b.r
	local := r.o.Public
	local.SessionID = to.SessionID
	if to.SessionID == "" || !local.Equal(to) {
		r.o.Metrics.refuse(reasonUnknownSession)
		return nil, msrp.ErrNoSession
	}
	select {
	case r.binds <- struct{}{}:
	default:
		// MSRP has no "try later" (RFC 4975 §10): every code refuses the
		// session for good. Closing the connection instead looks like any
		// transport failure, which the client recovers from with a new
		// INVITE, as it would if the task had gone.
		r.o.Metrics.refuse(reasonBindOverload)
		_ = c.Close()
		return nil, errOverload
	}
	defer func() { <-r.binds }()

	id := BindingID(to.SessionID)
	bnd, err := r.awaitComplete(id)
	if err == nil {
		bnd, err = r.claim(id, b.connID)
	}
	if err != nil {
		return nil, r.refuseBind(c, id, err)
	}
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
		r.o.Metrics.refuse(reasonCoreUnreachable)
		r.o.Log.Warn("could not open the session toward rcs-as", slog.String("binding", id), slog.String("error", pii.Redact(err.Error())))
		return nil, msrp.ErrNoSession
	}
	r.startBridge(id, b.connID, edge, bnd.ExpiresAt)
	return edge, nil
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
func (r *Relay) refuseBind(c *msrp.Conn, id string, err error) error {
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
	}
	// The binding may well exist; refusing it with 481 would end the
	// session for good. A closed connection is what an unreachable relay
	// looks like, and the client recovers from it the same way.
	r.o.Metrics.refuse(reasonStore)
	r.o.Metrics.add(mStoreErrors, 1)
	r.o.Log.Warn("binding lookup failed", slog.String("binding", id), slog.String("error", pii.Redact(err.Error())))
	_ = c.Close()
	return err
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
func (r *Relay) startBridge(id, claimant string, edge *msrp.Session, expires time.Time) {
	br := &bridge{binding: id, claimant: claimant, edge: edge}
	r.o.Metrics.bridges.Add(1)
	br.arm(r, expires.Sub(r.o.Clock.Now()))
	go func() {
		<-edge.Done()
		br.mu.Lock()
		br.ended = true
		if br.timer != nil {
			br.timer.Stop()
		}
		br.mu.Unlock()
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
// another task (ADR 0003).
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
		expired := make(chan struct{})
		t := r.o.Clock.AfterFunc(timeout, func() { close(expired) })
		select {
		case <-drained:
		case <-expired:
		case <-ctx.Done():
		}
		t.Stop()
	}
	r.Close()
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
// IdleTimeout without a byte from the client (ADR 0003). The deadline is
// real time: the operating system enforces it.
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

func (c *meteredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.out.Add(int64(n))
	return n, err
}
