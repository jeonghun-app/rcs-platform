package cxclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range
// (.github/allowed-test-identifiers.txt).
const (
	realm     = "ims.mnc001.mcc001.3gppnetwork.org"
	impi1     = "001010000000001@" + realm
	impu1     = "sip:+15550100001@" + realm
	scscfName = "sip:scscf.rcs.local"
	hssName   = "hss.rcs.local"
	thisHost  = "scscf-0a1b2c.rcs.local"
)

// realWait guards against hangs; no protocol timer depends on it.
const realWait = 10 * time.Second

// pipeListener hands one end of a net.Pipe to Node.Serve per dial.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// network routes the client's dials to in-process listeners by address.
type network struct {
	mu    sync.Mutex
	hosts map[string]*pipeListener
	dials map[string]int
}

func newNetwork() *network {
	return &network{hosts: map[string]*pipeListener{}, dials: map[string]int{}}
}

func (n *network) add(addr string, l *pipeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hosts[netip.AddrPortFrom(netip.MustParseAddr(addr), DefaultPort).String()] = l
}

func (n *network) dial(ctx context.Context, _, address string) (net.Conn, error) {
	n.mu.Lock()
	l := n.hosts[address]
	n.dials[address]++
	n.mu.Unlock()
	if l == nil {
		return nil, errors.New("connection refused")
	}
	return l.dial(ctx)
}

func (n *network) dialsTo(addr string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dials[netip.AddrPortFrom(netip.MustParseAddr(addr), DefaultPort).String()]
}

// resolver answers with the addresses set last, or err.
type resolver struct {
	mu    sync.Mutex
	addrs []netip.Addr
	err   error
}

func (r *resolver) set(err error, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
	r.addrs = nil
	for _, a := range addrs {
		r.addrs = append(r.addrs, netip.MustParseAddr(a))
	}
}

func (r *resolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if network != "ip" || host != hssName {
		return nil, errors.New("unexpected lookup")
	}
	return r.addrs, r.err
}

func dictionary(t *testing.T) *diameter.Dictionary {
	t.Helper()
	d, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// received is one request a fake HSS task got.
type received struct {
	code      uint32
	sessionID string
	endToEnd  uint32
	flags     diameter.CommandFlags
	msg       *diameter.Message
}

// fakeHSS is an HSS task: a Diameter node that answers Cx with whatever its
// answer function says, success by default, and records what it gets.
type fakeHSS struct {
	t    *testing.T
	host string
	node *diameter.Node
	ln   *pipeListener

	mu  sync.Mutex
	got []received
	// answer, if set, decides the answer to each request; nil answers
	// success.
	answer func(code uint32, req *diameter.Message) (*diameter.Message, error)
}

func startHSS(t *testing.T, net *network, addr, host string) *fakeHSS {
	t.Helper()
	h := &fakeHSS{t: t, host: host, ln: newPipeListener()}
	n, err := diameter.NewNode(diameter.Config{
		OriginHost: host, OriginRealm: realm,
		HostIPAddresses:    []netip.Addr{netip.MustParseAddr(addr)},
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dictionary(t),
		Accept:             []diameter.PeerRule{{HostPattern: "scscf-*.rcs.local"}},
		Logger:             slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.node = n
	n.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	for _, code := range []uint32{cx.CodeUserAuthorization, cx.CodeLocationInfo, cx.CodeMultimediaAuth, cx.CodeServerAssignment} {
		n.HandleFunc(cx.ApplicationID, code, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
			sid, _ := req.SessionID()
			h.mu.Lock()
			h.got = append(h.got, received{code: code, sessionID: sid, endToEnd: req.EndToEnd, flags: req.Flags, msg: req})
			answer := h.answer
			h.mu.Unlock()
			if answer != nil {
				return answer(code, req)
			}
			return h.success(code, req)
		})
	}
	go func() { _ = n.Serve(h.ln) }()
	net.add(addr, h.ln)
	t.Cleanup(h.stop)
	return h
}

func (h *fakeHSS) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()
	_ = h.node.Shutdown(ctx)
	_ = h.ln.Close()
}

// kill drops the task's connections without a DPR, as a task that dies does.
func (h *fakeHSS) kill() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h.node.Shutdown(ctx)
	_ = h.ln.Close()
}

func (h *fakeHSS) setAnswer(f func(code uint32, req *diameter.Message) (*diameter.Message, error)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answer = f
}

func (h *fakeHSS) requests() []received {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]received(nil), h.got...)
}

func (h *fakeHSS) success(code uint32, req *diameter.Message) (*diameter.Message, error) {
	return h.result(code, req, cx.ExperimentalResult(cx.FirstRegistration))
}

// result answers req with res in the command's own answer format.
func (h *fakeHSS) result(code uint32, req *diameter.Message, res cx.Result) (*diameter.Message, error) {
	a := cx.Answer{Result: res}
	switch code {
	case cx.CodeUserAuthorization:
		return (&cx.UAA{Answer: a, ServerName: scscfName}).Message(h.node, req)
	case cx.CodeLocationInfo:
		return (&cx.LIA{Answer: a, ServerName: scscfName}).Message(h.node, req)
	case cx.CodeMultimediaAuth:
		if !res.IsSuccess() {
			return (&cx.MAA{Answer: a}).Message(h.node, req)
		}
		mar, err := cx.ParseMAR(req)
		if err != nil {
			return nil, err
		}
		return (&cx.MAA{Answer: cx.Answer{Result: cx.ResultCode(diameter.ResultSuccess)}, UserName: mar.UserName,
			PublicIdentity: mar.PublicIdentity, NumberAuthItems: 1,
			AuthDataItems: []cx.AuthDataItem{{Scheme: mar.AuthDataItem.Scheme, Authenticate: []byte("challenge")}}}).Message(h.node, req)
	case cx.CodeServerAssignment:
		if res.IsSuccess() {
			a.Result = cx.ResultCode(diameter.ResultSuccess)
		}
		return (&cx.SAA{Answer: a, UserData: []byte("<IMSSubscription/>")}).Message(h.node, req)
	}
	return nil, errors.New("unexpected command")
}

// busy answers DIAMETER_TOO_BUSY, a protocol error the node builds.
func busy(uint32, *diameter.Message) (*diameter.Message, error) {
	return nil, &diameter.Error{ResultCode: diameter.ResultTooBusy}
}

// recordingMetrics records counts by name.
type recordingMetrics struct {
	mu     sync.Mutex
	counts map[string]int64
	timed  map[string]int
}

func (m *recordingMetrics) Count(name string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int64{}
	}
	m.counts[name] += n
}

func (m *recordingMetrics) Timing(name string, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timed == nil {
		m.timed = map[string]int{}
	}
	m.timed[name]++
}

func (m *recordingMetrics) count(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

// env is a client and the HSS tasks it can reach.
type env struct {
	t       *testing.T
	net     *network
	dns     *resolver
	metrics *recordingMetrics
	client  *Client
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	e := &env{t: t, net: newNetwork(), dns: &resolver{}, metrics: &recordingMetrics{}}
	cfg := Config{
		OriginHost: thisHost, OriginRealm: realm, DestinationRealm: realm, ServerName: scscfName,
		HSS: hssName, Resolver: e.dns,
		// The loop resolves once at start; the tests call Refresh.
		ResolveInterval: time.Hour,
		RequestTimeout:  2 * time.Second,
		Node: diameter.Config{
			Dial: e.net.dial, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 50 * time.Millisecond,
			HostIPAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.100")},
		},
		Metrics: e.metrics,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.client = c
	// The first resolution, which New starts, finds no address yet; waiting
	// for it keeps it from landing in the middle of a test.
	eventually(t, "the first resolution", func() bool { return e.metrics.count("cxclient.resolve.error") == 1 })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = c.Close(ctx)
	})
	return e
}

// refresh resolves now and waits until exactly the addresses given are
// connected and available.
func (e *env) refresh(addrs ...string) {
	e.t.Helper()
	e.dns.set(nil, addrs...)
	if err := e.client.Refresh(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.waitAvailable(addrs...)
}

func (e *env) waitAvailable(addrs ...string) {
	e.t.Helper()
	eventually(e.t, "the peers to be available", func() bool {
		ps := e.client.Peers()
		if len(ps) != len(addrs) {
			return false
		}
		for i, p := range ps {
			if !p.Available || p.Address != netip.MustParseAddr(addrs[i]) {
				return false
			}
		}
		return true
	})
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), realWait)
	t.Cleanup(cancel)
	return c
}

func uar() *cx.UAR {
	return &cx.UAR{UserName: impi1, PublicIdentity: impu1, VisitedNetworkIdentifier: []byte(realm)}
}
