package icscf

import (
	"context"
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
	upstream []*sip.Response
}

func (n *fakeNet) SendRequest(req *sip.Request, dst transport.Destination, _ ...transport.SendOption) (transport.Network, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.requests = append(n.requests, req.Clone())
	return transport.TCP, nil
}

func (n *fakeNet) SendResponse(res *sip.Response, _ transport.Source, _ ...transport.SendOption) error {
	n.mu.Lock()
	defer n.mu.Unlock()
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
	g := &proxied{rig: newRig(t, mutate...), clock: &fakeClock{}, net: &fakeNet{}}
	p, err := proxy.New(g.net, proxy.Config{
		Self:        []sip.URI{mustURI("sip:icscf.rcs.local;lr")},
		Router:      g.r,
		Resolver:    resolver{},
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
