package pcscf

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// panicOnceResolver panics on its first Resolve, as a bug in a resolver
// would, inside a reg-event subscription's background work.
type panicOnceResolver struct {
	proxy.Resolver
	n atomic.Int32
}

func (r *panicOnceResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	if r.n.Add(1) == 1 {
		panic("resolve")
	}
	return r.Resolver.Resolve(ctx, u)
}

// subsUnlocked reports whether the subscriptions' lock is free.
func subsUnlocked(p *pcscf) bool {
	if !p.subs.mu.TryLock() {
		return false
	}
	p.subs.mu.Unlock()
	return true
}

// A panic while a SUBSCRIBE is made fails the subscription as an error
// does: it is set up again after resubscribeAfter, and nothing stays
// locked (#471 code review).
func TestAPanicMakingASubscribeLetsItBeTriedAgain(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	p.resolve = &panicOnceResolver{Resolver: p.resolve}
	registerKept(t, p, "FLOW-A")
	if got := f.take(p); len(got) != 0 {
		t.Fatal("sent")
	}
	if !subsUnlocked(p) {
		t.Fatal("the subscriptions stay locked")
	}
	clock.t = clock.t.Add(resubscribeAfter)
	p.reconcileSubscriptions()
	f.one(t, p)
}

// A panic in the send itself, with the lock no longer held across it,
// leaves the process running and the subscription to be tried again.
func TestAPanicSendingASubscribeLetsItBeTriedAgain(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	var sends atomic.Int32
	p.send = func(req *sip.Request, dst transport.Destination, h transaction.ResponseHandler) error {
		if sends.Add(1) == 1 {
			panic("send")
		}
		return f.send(req, dst, h)
	}
	registerKept(t, p, "FLOW-A")
	if got := f.take(p); len(got) != 0 {
		t.Fatal("sent")
	}
	if !subsUnlocked(p) {
		t.Fatal("the subscriptions stay locked")
	}
	clock.t = clock.t.Add(resubscribeAfter)
	p.reconcileSubscriptions()
	f.one(t, p)
}

// panicReader panics when read, as a broken random source would.
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("rand") }

// A panic while a refresh is made under the lock releases the lock and
// leaves the subscription for the sweep to refresh.
func TestAPanicMakingARefreshReleasesTheLock(t *testing.T) {
	p, clock, f := newSubscribingPcscf(t)
	registerKept(t, p, "FLOW-A")
	s := f.one(t, p)
	respond(t, s, 200, "Expires: 1800")
	if code := notify(t, p, notifyFor(t, s.req, 1, "active;expires=1800", nil)); code != 200 {
		t.Fatalf("first NOTIFY: %d", code)
	}
	ids := p.ids
	p.ids = sip.IDGenerator{Rand: panicReader{}}
	clock.t = clock.t.Add(1800*time.Second - refreshLead)
	p.reconcileSubscriptions()
	if got := f.take(p); len(got) != 0 {
		t.Fatalf("%d sent", len(got))
	}
	if !subsUnlocked(p) {
		t.Fatal("the subscriptions stay locked")
	}
	p.subs.mu.Lock()
	busy := 0
	for _, sub := range p.subs.byKey {
		if sub.busy {
			busy++
		}
	}
	p.subs.mu.Unlock()
	if busy != 0 {
		t.Fatalf("%d subscriptions left busy", busy)
	}
	p.ids = ids
	for range 10 {
		clock.t = clock.t.Add(resubscribeAfter)
		p.reconcileSubscriptions()
		if got := f.take(p); len(got) == 1 {
			return
		}
	}
	t.Fatal("never refreshed after the panic")
}

// panicRoundTripper panics for one method, after block if set, and passes
// the rest on.
type panicRoundTripper struct {
	next   http.RoundTripper
	method string
	block  chan struct{}
	n      atomic.Int32
}

func (rt *panicRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == rt.method && rt.n.Add(1) == 1 {
		if rt.block != nil {
			<-rt.block
		}
		panic("relay")
	}
	return rt.next.RoundTrip(r)
}

// A panic in a binding create answers the caller at once, rather than at
// the end of its context; once the caller has gone, the share it left to
// the work comes back (#471 code review).
func TestAPanicInABindingCreateGivesItsShareBack(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	client := a.p.msrp.relay.client
	client.Transport = &panicRoundTripper{next: client.Transport, method: http.MethodPost}
	sh := share{flow: "FLOW-A"}
	// Bounded only so that a create that waits for it fails with a
	// message (#471 QA).
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if _, err := a.p.create(ctx, sh, relayPaths{ExpiresIn: bindingExpiresIn}); !errors.Is(err, errRelayPanicked) {
		t.Fatalf("create: %v, want errRelayPanicked", err)
	}

	block := make(chan struct{})
	client.Transport = &panicRoundTripper{next: client.Transport, method: http.MethodPost, block: block}
	if _, err := a.p.msrp.limit.take(sh, 1); err != nil {
		t.Fatal(err)
	}
	gone, stop := context.WithCancel(context.Background())
	stop()
	if _, err := a.p.create(gone, sh, relayPaths{ExpiresIn: bindingExpiresIn}); !errors.Is(err, errCreateAbandoned) {
		t.Fatalf("create: %v, want errCreateAbandoned", err)
	}
	close(block)
	a.settle()
	if n := a.p.msrp.limit.held(); n != 0 {
		t.Fatalf("%d bindings held after the panic", n)
	}
}

// A panic in an extension lets the next sweep extend the session.
func TestAPanicExtendingLetsTheNextSweepExtend(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.settle()
	// After the answer's own update of the binding.
	before := a.relay.count(http.MethodPatch)
	client := a.p.msrp.relay.client
	client.Transport = &panicRoundTripper{next: client.Transport, method: http.MethodPatch}
	a.clock.t = a.clock.t.Add(15 * time.Minute)
	a.p.sweepMSRP()
	a.settle()
	if n := a.relay.count(http.MethodPatch) - before; n != 0 {
		t.Fatalf("%d extensions reached the relay", n)
	}
	a.clock.t = a.clock.t.Add(30 * time.Second)
	a.p.sweepMSRP()
	a.settle()
	if n := a.relay.count(http.MethodPatch) - before; n != 1 {
		t.Fatalf("%d extensions after the panic, want the next sweep's", n)
	}
}

// run gives the reg-event subscriptions and the MSRP anchor their guard:
// a panic in either's background work is counted in the service's metrics
// and logged with the work's name (#471 QA).
func TestRunGuardsTheBackgroundWork(t *testing.T) {
	got := make(chan *pcscf, 1)
	s := start(t, testConfig(), deps{started: func(pc *pcscf) { got <- pc }})
	pc := <-got
	pc.subs.goRun(func(context.Context) { panic("subscription") })
	pc.msrp.goRun(func(context.Context) { panic("anchor") })
	pc.subs.wait()
	pc.msrp.wait()
	if v, ok := s.h.Metric(metricBackgroundPanics); !ok || v != 2 {
		t.Errorf("%s = %v (%v), want 2", metricBackgroundPanics, v, ok)
	}
	for _, name := range []string{`"name":"regevent"`, `"name":"msrp"`} {
		if !strings.Contains(s.h.Output(), name) {
			t.Errorf("the log lacks %s", name)
		}
	}
}
