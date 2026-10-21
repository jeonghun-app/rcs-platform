package icscf

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// These tests run the Router inside the proxy core, for the parts of the
// mapping table the proxy carries out: the 504 of a silent S-CSCF, the 487
// of a request cancelled while the HSS is asked, the 416 of a pres: URI, and
// the 480 with Retry-After as the client receives it.

// realWait bounds a wait for the proxy's goroutines; no protocol timer
// depends on it, those run on the fake clock.
const realWait = 10 * time.Second

// fakeClock fires timers only when advanced.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	at   time.Duration
	f    func()
	done bool
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) transaction.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now + d, f: f}
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

// advance moves the clock by d, firing the timers that fall due in order.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	end := c.now + d
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.done && t.at <= end && (next == nil || t.at < next.at) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.done, c.now = true, next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = end
	c.mu.Unlock()
}

// fakeNet records what the proxy sends.
type fakeNet struct {
	mu       sync.Mutex
	requests []*sip.Request
	// networks are the networks the requests were sent over, in order.
	networks []transport.Network
	upstream []*sip.Response
	// fail, if set, is what sending a request downstream returns.
	fail error
	// up, if set, takes the responses sent upstream instead of recording
	// them: the proxy before icscf in a chain.
	up func(*sip.Response)
}

func (n *fakeNet) SendRequest(req *sip.Request, dst transport.Destination, _ ...transport.SendOption) (transport.Network, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail != nil {
		return "", n.fail
	}
	n.requests = append(n.requests, req.Clone())
	network := dst.Network
	if network == "" {
		network = transport.TCP
	}
	n.networks = append(n.networks, network)
	return network, nil
}

func (n *fakeNet) SendResponse(res *sip.Response, _ transport.Source, _ ...transport.SendOption) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.up != nil {
		go n.up(res.Clone())
		return nil
	}
	n.upstream = append(n.upstream, res.Clone())
	return nil
}

func (n *fakeNet) sent() []*sip.Request {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.requests)
}

// responses returns "status method" for every response sent upstream.
func (n *fakeNet) responses() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for _, r := range n.upstream {
		cseq, _ := r.Header.CSeq()
		out = append(out, strconv.Itoa(r.StatusCode)+" "+cseq.Method)
	}
	return out
}

func (n *fakeNet) response(t *testing.T, status int) *sip.Response {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, r := range n.upstream {
		if r.StatusCode == status {
			return r
		}
	}
	t.Fatalf("no %d among the responses", status)
	return nil
}

type resolver struct{}

func (resolver) Resolve(context.Context, sip.URI) (transport.Destination, error) {
	return transport.Destination{Network: transport.TCP}, nil
}

// proxied is a proxy.Proxy whose Router is an icscf Router.
type proxied struct {
	*rig
	clock *fakeClock
	net   *fakeNet
	p     *proxy.Proxy
}

func newProxied(t *testing.T, mutate ...func(*Config)) *proxied {
	t.Helper()
	return newProxiedWith(t, resolver{}, mutate...)
}

// newProxiedWith is newProxied with the proxy's Resolver res.
func newProxiedWith(t *testing.T, res proxy.Resolver, mutate ...func(*Config)) *proxied {
	t.Helper()
	g := &proxied{rig: newRig(t, mutate...), clock: &fakeClock{}, net: &fakeNet{}}
	p, err := proxy.New(g.net, proxy.Config{
		Self:        []sip.URI{mustURI("sip:icscf.rcs.local;lr")},
		Router:      g.r,
		Resolver:    res,
		Transaction: transaction.Config{Clock: g.clock},
		Rand:        &lockedReader{r: rand.NewChaCha8([32]byte{1})},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.p = p
	t.Cleanup(p.Close)
	return g
}

func (g *proxied) receive(m sip.Message) {
	g.p.Receive(transport.Inbound{Message: m, Source: transport.Source{Flow: "pcscf", Network: transport.TCP, Listener: "core"}})
}

// waitFor polls until cond holds, for what the proxy does on goroutines of
// its own.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRegisterReachesTheSCSCFWithItsURIAsTheRequestURI(t *testing.T) {
	g := newProxied(t)
	g.receive(register(t))
	waitFor(t, "the REGISTER downstream", func() bool { return len(g.net.sent()) == 1 })
	fwd := g.net.sent()[0]
	if fwd.Method != "REGISTER" || fwd.URI.String() != scscfURI || fwd.Header.Has("Route") {
		t.Errorf("forwarded %s %s with Route %q", fwd.Method, fwd.URI.String(), fwd.Header.Get("Route"))
	}
}

// TS 24.229 §5.3.1.3: an S-CSCF that does not answer the REGISTER gets the
// client a 504, before the client's own Timer F.
func TestRegisterTheSCSCFDoesNotAnswerGets504(t *testing.T) {
	g := newProxied(t)
	g.receive(register(t))
	waitFor(t, "the REGISTER downstream", func() bool { return len(g.net.sent()) > 0 })
	g.clock.advance(DefaultRegisterTimeout - time.Millisecond)
	if got := g.net.responses(); len(got) != 0 {
		t.Fatalf("answered %v before the timeout", got)
	}
	g.clock.advance(time.Millisecond)
	waitFor(t, "the 504", func() bool { return slices.Contains(g.net.responses(), "504 REGISTER") })
}

func TestTerminatingInviteReachesTheSCSCFAsItsTopmostRoute(t *testing.T) {
	g := newProxied(t)
	g.receive(invite(t, "sip:+15550100001@"+home+";user=phone", "Route: <sip:icscf.rcs.local;lr>"))
	waitFor(t, "the INVITE downstream", func() bool { return len(g.net.sent()) == 1 })
	fwd := g.net.sent()[0]
	routes, err := fwd.Header.Route()
	if err != nil || len(routes) != 1 || routes[0].URI.String() != scscfURI+";lr" {
		t.Errorf("Route = %v (%v), want only <%s;lr>", routes, err, scscfURI)
	}
	if fwd.URI.String() != tel1 {
		t.Errorf("Request-URI = %s, want %s", fwd.URI.String(), tel1)
	}
	if got := g.hss.lastLIR(t).PublicIdentity; got != tel1 {
		t.Errorf("LIR for %s, want %s", got, tel1)
	}
}

// TS 24.229 §5.3.2.2: a CANCEL while the LIR is pending is answered 200 and
// the INVITE 487, and the LIR's ctx ends.
func TestCancelWhileTheHSSIsAskedAnswersTheInvite487(t *testing.T) {
	g := newProxied(t)
	g.hss.block = true
	entered := make(chan struct{})
	g.hss.entered = entered
	inv := invite(t, impu1)
	g.receive(inv)
	select {
	case <-entered:
	case <-time.After(realWait):
		t.Fatal("the LIR was not sent")
	}
	g.receive(request(t, "CANCEL", inv.URI.String(), "Via: "+inv.Header.Get("Via"), "To: <"+impu1+">", "CSeq: 1 CANCEL"))
	waitFor(t, "the 487", func() bool { return slices.Contains(g.net.responses(), "487 INVITE") })
	if got := g.net.responses(); !slices.Contains(got, "200 CANCEL") {
		t.Errorf("responses = %v, want a 200 to the CANCEL", got)
	}
	if n := len(g.net.sent()); n != 0 {
		t.Errorf("forwarded %d requests after the CANCEL", n)
	}
}

func TestHSSFailureReachesTheClientAs480WithRetryAfter(t *testing.T) {
	g := newProxied(t)
	g.hss.err = cxclient.ErrNoPeer
	g.receive(register(t))
	waitFor(t, "the 480", func() bool { return slices.Contains(g.net.responses(), "480 REGISTER") })
	if got := g.net.response(t, 480).Header.Get("Retry-After"); got != "10" {
		t.Errorf("Retry-After = %q, want 10", got)
	}
}

// §5.3.2.1 step 1 a) is not implemented; the proxy refuses the scheme.
func TestPresURIIsRefused416WithoutAnLIR(t *testing.T) {
	g := newProxied(t)
	g.receive(request(t, "SUBSCRIBE", "pres:user1@"+home, "To: <pres:user1@"+home+">", "Event: presence"))
	waitFor(t, "the 416", func() bool { return slices.Contains(g.net.responses(), "416 SUBSCRIBE") })
	if n := g.hss.calls(); n != 0 {
		t.Errorf("the HSS got %d requests", n)
	}
}

func TestNegativeUAAReachesTheClientAs403(t *testing.T) {
	g := newProxied(t)
	g.hss.uaa = uaa(experimental(cx.ErrorUserUnknown), "", nil)
	g.receive(register(t))
	waitFor(t, "the 403", func() bool { return slices.Contains(g.net.responses(), "403 REGISTER") })
}

// lockedReader makes a seeded reader safe for the proxy's concurrent use.
type lockedReader struct {
	mu sync.Mutex
	r  *rand.ChaCha8
}

func (l *lockedReader) Read(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.r.Read(b)
}

// upstreamNet links the proxy before icscf to it: its requests go to
// icscf, its responses to the caller, which records them.
type upstreamNet struct {
	icscf *proxy.Proxy
	fakeNet
}

func (n *upstreamNet) SendRequest(req *sip.Request, _ transport.Destination, _ ...transport.SendOption) (transport.Network, error) {
	go n.icscf.Receive(transport.Inbound{Message: req.Clone(), Source: transport.Source{Flow: "scscf-orig", Network: transport.TCP, Listener: "core"}})
	return transport.TCP, nil
}

// Decided on #274: a terminating request whose S-CSCF cannot be sent to
// reaches the caller, through the proxy before icscf (the originating
// S-CSCF, which runs the same proxy core), as 500 with Retry-After. A 503
// would have been turned into a 500 there, its Retry-After dropped.
func TestTerminatingRequestToAnUnreachableSCSCFReachesTheCallerAs500WithRetryAfter(t *testing.T) {
	g := newProxied(t)
	g.net.mu.Lock()
	g.net.fail = errors.New("connection refused")
	g.net.mu.Unlock()
	un := &upstreamNet{icscf: g.p}
	up, err := proxy.New(un, proxy.Config{
		Self:        []sip.URI{mustURI("sip:scscf-orig.rcs.local;lr")},
		Router:      proxy.RouterFunc(func(_ context.Context, r *proxy.Request) proxy.Decision { return proxy.Forward(r) }),
		Resolver:    resolver{},
		Transaction: transaction.Config{Clock: &fakeClock{}},
		Rand:        &lockedReader{r: rand.NewChaCha8([32]byte{2})},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Close)
	g.net.mu.Lock()
	g.net.up = func(res *sip.Response) {
		up.Receive(transport.Inbound{Message: res, Source: transport.Source{Flow: "icscf", Network: transport.TCP}})
	}
	g.net.mu.Unlock()
	up.Receive(transport.Inbound{Message: request(t, "MESSAGE", impu1), Source: transport.Source{Flow: "caller", Network: transport.TCP}})
	waitFor(t, "the caller's final response", func() bool { return len(un.responses()) > 0 })
	res := un.response(t, 500)
	if got := res.Header.Get("Retry-After"); got != "10" {
		t.Errorf("the caller got 500 with Retry-After %q, want 10", got)
	}
	if got := g.metrics.counts["icscf.scscf.unreachable"]; got != 1 {
		t.Errorf("unreachable counted %d", got)
	}
}

// Review of #274: the HSS names the S-CSCF as sip:scscf.<namespace>,
// without the transport; the REGISTER still leaves over the configured
// TCP, which the resolver reads from the configured URI. Routed as the HSS
// wrote it, it would have left over UDP, which icscf has no listener for.
func TestARegisterToTheProductionFormOfANameLeavesOverTCP(t *testing.T) {
	g := newProxiedWith(t, proxy.NumericResolver{}, func(c *Config) {
		c.SCSCFs = []SCSCF{{URI: mustURI("sip:192.0.2.30:5060;transport=tcp")}}
	})
	g.hss.uaa = uaa(experimental(cx.SubsequentRegistration), "sip:192.0.2.30", nil)
	g.receive(register(t))
	waitFor(t, "the REGISTER downstream", func() bool { return len(g.net.sent()) == 1 })
	g.net.mu.Lock()
	network := g.net.networks[0]
	g.net.mu.Unlock()
	if fwd := g.net.sent()[0]; network != transport.TCP || fwd.URI.String() != "sip:192.0.2.30:5060;transport=tcp" {
		t.Errorf("the REGISTER left over %s to %s, want TCP to the configured URI", network, fwd.URI.String())
	}
}

// Code review of #311, scaled down: with a 4 MiB layer bound and the proxy
// limits proxyLimits gives, 300 KiB MESSAGEs held at the S-CSCF are refused
// by the transaction layer, whose refusals #56's alarm counts, and never by
// the proxy's own byte bound.
func TestTheLayerRefusesLargeRequestsBeforeTheProxy(t *testing.T) {
	g := &proxied{rig: newRig(t), clock: &fakeClock{}, net: &fakeNet{}}
	tcfg, contexts, bytes := proxyLimits(ServiceConfig{MaxServerTransactions: 20000, MaxServerTransactionBytes: 4 << 20})
	tcfg.Clock = g.clock
	p, err := proxy.New(g.net, proxy.Config{
		Self:            []sip.URI{mustURI("sip:icscf.rcs.local;lr")},
		Router:          g.r,
		Resolver:        resolver{},
		Transaction:     tcfg,
		MaxContexts:     contexts,
		MaxContextBytes: bytes,
		Rand:            &lockedReader{r: rand.NewChaCha8([32]byte{1})},
	})
	if err != nil {
		t.Fatal(err)
	}
	g.p = p
	t.Cleanup(p.Close)
	for i := range 20 {
		m := request(t, "MESSAGE", impu1, fmt.Sprintf("Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKbig%d", i), fmt.Sprintf("Call-ID: big-%d@192.0.2.10", i))
		m.Body = make([]byte, 300<<10)
		g.receive(m)
	}
	waitFor(t, "a refusal", func() bool { return slices.Contains(g.net.responses(), "503 MESSAGE") })
	if ls, ps := p.Layer().Stats(), p.Stats(); ls.ServerTransactionsRejected == 0 || ps.Overloaded != 0 {
		t.Fatalf("layer %+v, proxy %+v: the proxy refused first", ls, ps)
	}
}
