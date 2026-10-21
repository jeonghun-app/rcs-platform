package proxy

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// fakeClock runs timers only when advanced, in deadline order, on the calling
// goroutine.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Duration
	seq    int
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Duration
	seq  int
	f    func()
	done bool
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) transaction.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := &fakeTimer{c: c, at: c.now + d, seq: c.seq, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// advance moves the clock forward by d, firing every timer that falls due,
// including timers those firings start.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	end := c.now + d
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.done && t.at <= end && (next == nil || t.at < next.at || t.at == next.at && t.seq < next.seq) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.done = true
		c.now = next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = end
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool { return t.done })
	c.mu.Unlock()
}

// fakeNet is the transport: it records what the proxy and its transaction
// layer send, and can make sends fail.
type fakeNet struct {
	mu       sync.Mutex
	requests []sentRequest
	upstream []*sip.Response
	// fail, if set, decides the error of each request send.
	fail func(req *sip.Request, dst transport.Destination) error
	// failUpstream, if set, is the error of every response send.
	failUpstream error
	// stallUpstream, if set, blocks every response send until it is
	// closed, to stand for an upstream peer that does not read.
	stallUpstream chan struct{}
	// held, if set, stops the sends it matches until released, to stand for a
	// peer whose connection has no room.
	held *hold
	// moveToTCP makes INVITEs meant for UDP go over TCP, as the transport does
	// with a large one (RFC 3261 §18.1.1), rewriting the Via to match.
	moveToTCP bool
}

type hold struct {
	match   func(*sip.Request) bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// holdSends makes the request sends match selects wait until release is
// called; entered is closed when the first of them starts waiting.
func (n *fakeNet) holdSends(match func(*sip.Request) bool) (entered <-chan struct{}, release func()) {
	h := &hold{match: match, entered: make(chan struct{}), release: make(chan struct{})}
	n.mu.Lock()
	n.held = h
	n.mu.Unlock()
	var once sync.Once
	return h.entered, func() { once.Do(func() { close(h.release) }) }
}

type sentRequest struct {
	req *sip.Request
	dst transport.Destination
}

func (n *fakeNet) SendRequest(req *sip.Request, dst transport.Destination, _ ...transport.SendOption) (transport.Network, error) {
	n.mu.Lock()
	fail, held := n.fail, n.held
	n.mu.Unlock()
	if held != nil && held.match(req) {
		held.once.Do(func() { close(held.entered) })
		<-held.release
	}
	if fail != nil {
		if err := fail(req, dst); err != nil {
			return "", err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.moveToTCP && req.Method == "INVITE" && dst.Network == transport.UDP {
		vias, _ := req.Header.Via()
		v := vias[0]
		v.Transport = "TCP"
		if err := req.Header.ReplaceFirstElement("Via", v.String()); err != nil {
			return "", err
		}
		dst.Network = transport.TCP
	}
	// The transaction layer owns req and may resend it; keep a copy.
	n.requests = append(n.requests, sentRequest{req.Clone(), dst})
	if dst.Network == "" {
		return transport.TCP, nil
	}
	return dst.Network, nil
}

func (n *fakeNet) SendResponse(res *sip.Response, _ transport.Source, _ ...transport.SendOption) error {
	n.mu.Lock()
	stall := n.stallUpstream
	n.mu.Unlock()
	if stall != nil {
		<-stall
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failUpstream != nil {
		return n.failUpstream
	}
	n.upstream = append(n.upstream, res.Clone())
	return nil
}

func (n *fakeNet) setFail(f func(*sip.Request, transport.Destination) error) {
	n.mu.Lock()
	n.fail = f
	n.mu.Unlock()
}

// harness is a Proxy wired to the fakes.
type harness struct {
	t     *testing.T
	clock *fakeClock
	net   *fakeNet
	p     *Proxy

	mu     sync.Mutex
	router func(ctx context.Context, r *Request) Decision
	seen   []*Request
}

var (
	upstreamSource   = transport.Source{Flow: "up", Network: transport.TCP, Listener: "core"}
	downstreamSource = transport.Source{Flow: "down", Network: transport.TCP}
	selfURI          = mustURI("sip:proxy.example.net;lr")
)

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, clock: &fakeClock{}, net: &fakeNet{}}
	cfg.Transaction.Clock = h.clock
	if cfg.Self == nil {
		cfg.Self = []sip.URI{selfURI}
	}
	if cfg.Rand == nil {
		cfg.Rand = &lockedReader{r: rand.NewChaCha8([32]byte{1})}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = fakeResolver{}
	}
	if cfg.Router == nil {
		cfg.Router = RouterFunc(func(ctx context.Context, r *Request) Decision {
			h.mu.Lock()
			h.seen = append(h.seen, r)
			route := h.router
			h.mu.Unlock()
			if route == nil {
				return Forward(r)
			}
			return route(ctx, r)
		})
	}
	p, err := New(h.net, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	t.Cleanup(p.Close)
	return h
}

// lockedReader makes a seeded reader safe for the concurrent branch starts,
// as Config.Rand must be.
type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (l *lockedReader) Read(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(b)
}

// fakeResolver resolves any host to a TCP destination named after it, so tests
// can tell next hops apart without addresses.
type fakeResolver struct{}

func (fakeResolver) Resolve(_ context.Context, u sip.URI) (transport.Destination, error) {
	return transport.Destination{Network: transport.TCP, ServerName: u.Host}, nil
}

func (h *harness) route(f func(ctx context.Context, r *Request) Decision) {
	h.mu.Lock()
	h.router = f
	h.mu.Unlock()
}

// decide makes the Router answer every request with d.
func (h *harness) decide(d Decision) {
	h.route(func(context.Context, *Request) Decision { return d })
}

func (h *harness) lastSeen() *Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) == 0 {
		h.t.Fatal("the Router saw no request")
	}
	return h.seen[len(h.seen)-1]
}

// settle waits until every goroutine the proxy started has returned.
func (h *harness) settle() { h.p.wait() }

// receive delivers a message from upstream and lets the proxy act on it.
func (h *harness) receive(m sip.Message) {
	h.p.Receive(transport.Inbound{Message: m, Source: upstreamSource})
	h.settle()
}

// reply delivers a downstream response to a request the proxy sent.
func (h *harness) reply(req *sip.Request, code int, extra ...string) {
	h.t.Helper()
	h.p.Receive(transport.Inbound{Message: responseTo(h.t, req, code, extra...), Source: downstreamSource})
	h.settle()
}

func (h *harness) advance(d time.Duration) {
	h.clock.advance(d)
	h.settle()
}

// sent returns the requests sent downstream since the last call.
func (h *harness) sent() []sentRequest {
	h.net.mu.Lock()
	defer h.net.mu.Unlock()
	r := h.net.requests
	h.net.requests = nil
	return r
}

// sentMethods returns "METHOD request-uri" for each request sent since the last
// call, sorted, since parallel branches go out in no fixed order.
func (h *harness) sentMethods() []string {
	var out []string
	for _, s := range h.sent() {
		out = append(out, s.req.Method+" "+s.req.URI.String())
	}
	slices.Sort(out)
	return out
}

// upstream returns the status codes sent upstream since the last call.
func (h *harness) upstream() []int {
	h.net.mu.Lock()
	defer h.net.mu.Unlock()
	var out []int
	for _, r := range h.net.upstream {
		out = append(out, r.StatusCode)
	}
	h.net.upstream = nil
	return out
}

// upstreamResponses returns the responses sent upstream since the last call.
func (h *harness) upstreamResponses() []*sip.Response {
	h.net.mu.Lock()
	defer h.net.mu.Unlock()
	r := h.net.upstream
	h.net.upstream = nil
	return r
}

// one returns the single request sent since the last call.
func (h *harness) one() *sip.Request {
	h.t.Helper()
	s := h.sent()
	if len(s) != 1 {
		h.t.Fatalf("sent %d requests, want 1", len(s))
	}
	return s[0].req
}

// byURI picks from sent the request whose Request-URI is uri.
func byURI(t *testing.T, sent []sentRequest, method, uri string) *sip.Request {
	t.Helper()
	for _, s := range sent {
		if s.req.Method == method && s.req.URI.String() == uri {
			return s.req
		}
	}
	t.Fatalf("no %s to %s among %d sent", method, uri, len(sent))
	return nil
}

func mustURI(s string) sip.URI {
	u, err := sip.ParseURI(s)
	if err != nil {
		panic(err)
	}
	return u
}

func mustAddr(s string) sip.Address {
	a, err := sip.ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

func target(uri string) Target { return Target{URI: mustURI(uri)} }

// request builds a request in wire form and parses it, as the transport would
// deliver it. extra lines replace the default field of the same name.
func request(t *testing.T, method, uri string, extra ...string) *sip.Request {
	t.Helper()
	fields := []string{
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-" + method,
		"Max-Forwards: 70",
		"To: <sip:bob@example.com>",
		"From: <sip:alice@example.com>;tag=a1",
		"Call-ID: call-1@192.0.2.10",
		"CSeq: 1 " + method,
	}
	lines := append([]string{method + " " + uri + " SIP/2.0"}, override(fields, extra)...)
	lines = append(lines, extra...)
	lines = append(lines, "Content-Length: 0")
	m, err := sip.ParseMessage([]byte(strings.Join(lines, "\r\n") + "\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

// override returns the fields whose name no line of extra has.
func override(fields, extra []string) []string {
	name := func(f string) string { return strings.ToLower(f[:strings.IndexByte(f, ':')]) }
	return slices.DeleteFunc(slices.Clone(fields), func(f string) bool {
		return slices.ContainsFunc(extra, func(e string) bool { return name(e) == name(f) })
	})
}

// invite is the INVITE most tests forward.
func invite(t *testing.T, extra ...string) *sip.Request {
	t.Helper()
	return request(t, "INVITE", "sip:bob@example.com", extra...)
}

// uacCancel builds the CANCEL a UAC sends for req (§9.1).
func uacCancel(t *testing.T, req *sip.Request) *sip.Request {
	t.Helper()
	return request(t, "CANCEL", req.URI.String(), "Via: "+req.Header.Get("Via"), "CSeq: 1 CANCEL")
}

// responseTo builds the response a downstream element sends to req, with a To
// tag naming the element, and parses it back as the transport would deliver it.
func responseTo(t *testing.T, req *sip.Request, code int, extra ...string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", "tag-"+strings.ReplaceAll(req.URI.Host, ".", "-"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		i := strings.IndexByte(e, ':')
		if err := res.Header.Add(e[:i], strings.TrimSpace(e[i+1:])); err != nil {
			t.Fatal(err)
		}
	}
	b, err := res.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m, err := sip.ParseMessage(b)
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Response)
}

// contextT shortens hook signatures in test tables.
type contextT = context.Context

var errTest = errors.New("test failure")

// inboundFrom is a message arriving on the named flow.
func inboundFrom(m sip.Message, flow string) transport.Inbound {
	return transport.Inbound{Message: m, Source: transport.Source{Flow: transport.FlowID(flow), Network: transport.TCP}}
}

func check[T comparable](t *testing.T, what string, got, want []T) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func codes(cs ...int) []int { return cs }

func transactionConfig(t1 time.Duration) transaction.Config { return transaction.Config{T1: t1} }

func itoa(n int) string { return strconv.Itoa(n) }
