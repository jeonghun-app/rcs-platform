package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The layer's safety net (#156) answers 500 for a request the proxy has not
// answered in time. It must come after every deadline of the proxy's own, so
// that only a stalled Router or hook ever meets it.

// A callee that rang and then went away never answers the CANCEL Timer C
// sends: the proxy gives the CANCEL 64*T1 and answers 487 itself, before the
// layer would.
func TestTheProxys487ComesBeforeItsLayers500(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	a := h.one()
	h.reply(a, 180)
	check(t, "upstream after the 180", h.upstream(), codes(180))
	h.advance(DefaultTimerC)
	check(t, "sent at Timer C", h.sentMethods(), []string{"CANCEL sip:bob@example.com"})
	h.advance(64 * transaction.DefaultT1)
	check(t, "upstream", h.upstream(), codes(487))
	h.advance(time.Hour)
	check(t, "upstream later", h.upstream(), nil)
	if s := h.p.Layer().Stats(); s.ServerTransactionsTimedOut != 0 || s.LateFinalResponses != 0 {
		t.Fatalf("the layer answered for the proxy: %+v", s)
	}
}

// The layer takes its INVITE timeout from the proxy's Timer C, so a longer one
// still forwards the callee's late 2xx (§16.7 step 5).
func TestALongerTimerCIsWhatTheLayerWaitsFor(t *testing.T) {
	h := newHarness(t, Config{TimerC: 5 * time.Minute})
	h.receive(invite(t))
	a := h.one()
	h.reply(a, 180)
	check(t, "upstream after the 180", h.upstream(), codes(180))
	h.advance(4 * time.Minute)
	h.reply(a, 200)
	check(t, "upstream", h.upstream(), codes(200))
	if s := h.p.Layer().Stats(); s.ServerTransactionsTimedOut != 0 {
		t.Fatalf("the layer answered for the proxy: %+v", s)
	}
}

// A safety net shorter than the proxy's own deadlines is refused.
func TestASafetyNetBeforeTheProxysDeadlinesIsRefused(t *testing.T) {
	// Timer C, 64*T1 for the CANCEL's 487 and the 5 s margin; Timer F (64*T1)
	// and the margin.
	invite := 5*time.Minute + 32*time.Second + 5*time.Second
	nonInvite := 32*time.Second + 5*time.Second
	for _, tc := range []struct {
		tcfg transaction.Config
		ok   bool
	}{
		{transaction.Config{InviteFinalTimeout: invite - time.Millisecond}, false},
		{transaction.Config{InviteFinalTimeout: invite}, true},
		{transaction.Config{NonInviteFinalTimeout: nonInvite - time.Millisecond}, false},
		{transaction.Config{NonInviteFinalTimeout: nonInvite}, true},
		{transaction.Config{T1: time.Second, NonInviteFinalTimeout: 64*time.Second + 5*time.Second - time.Millisecond}, false},
		{transaction.Config{T1: time.Second, NonInviteFinalTimeout: 64*time.Second + 5*time.Second}, true},
	} {
		tc.tcfg.Clock = &fakeClock{}
		p, err := New(&fakeNet{}, Config{TimerC: 5 * time.Minute, Transaction: tc.tcfg})
		if (err == nil) != tc.ok {
			t.Errorf("%+v: err %v, want ok %v", tc.tcfg, err, tc.ok)
		}
		if p != nil {
			p.Close()
		}
	}
}

// Each fork group gets its own Timer F before the layer answers: starting one
// starts the safety timer again, so a MESSAGE whose groups all time out still
// gets no late response (RFC 4320 §4.2).
func TestNonInviteForkGroupsThatTimeOutStaySilent(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{
		{URI: mustURI("sip:high@192.0.2.1"), Q: 1000},
		{URI: mustURI("sip:mid@192.0.2.2"), Q: 500},
		{URI: mustURI("sip:low@192.0.2.3"), Q: 100},
	}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.advance(32 * time.Second)
	check(t, "second group", h.sentMethods(), []string{"MESSAGE sip:mid@192.0.2.2"})
	h.advance(32 * time.Second)
	check(t, "third group", h.sentMethods(), []string{"MESSAGE sip:low@192.0.2.3"})
	// Each step lets the proxy act before the clock moves on, as real time
	// does in the 32 s between its deadline and the layer's.
	h.advance(32 * time.Second)
	if s := h.p.Stats(); s.Silenced != 1 {
		t.Fatalf("the last group's Timer F did not end the request: %+v", s)
	}
	h.advance(time.Hour)
	check(t, "upstream", h.upstream(), nil)
	if s := h.p.Layer().Stats(); s.ServerTransactionsTimedOut != 0 {
		t.Fatalf("the layer answered for the proxy: %+v", s)
	}
}

// So does a replacement OnBranchFailure starts.
func TestANonInviteReplacementThatTimesOutStaysSilent(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{target("sip:first@192.0.2.1")},
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target {
			if f.Target.URI.User == "first" {
				return []Target{target("sip:second@192.0.2.2")}
			}
			return nil
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.advance(32 * time.Second)
	check(t, "replacement", h.sentMethods(), []string{"MESSAGE sip:second@192.0.2.2"})
	h.advance(32 * time.Second)
	if s := h.p.Stats(); s.Silenced != 1 {
		t.Fatalf("the replacement's Timer F did not end the request: %+v", s)
	}
	h.advance(time.Hour)
	check(t, "upstream", h.upstream(), nil)
	if s := h.p.Layer().Stats(); s.ServerTransactionsTimedOut != 0 {
		t.Fatalf("the layer answered for the proxy: %+v", s)
	}
}

// stall blocks until released, ignoring its context as a stuck Router or hook
// would, and hands that context to the test.
type stall struct {
	ctxs    chan context.Context
	release chan struct{}
}

func newStall() *stall {
	return &stall{ctxs: make(chan context.Context, 1), release: make(chan struct{})}
}

func (s *stall) wait(ctx context.Context) {
	s.ctxs <- ctx
	<-s.release
}

// entered returns the stalled context once the stall is reached.
func (s *stall) entered(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-s.ctxs:
		return ctx
	case <-time.After(10 * time.Second):
		t.Fatal("the stall was never reached")
		return nil
	}
}

// stallResolver stalls before it resolves.
type stallResolver struct{ s *stall }

func (r stallResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	r.s.wait(ctx)
	return fakeResolver{}.Resolve(ctx, u)
}

// A Router, Resolver or hook that stalls past the layer's 500 learns of it
// through its context, and when it comes back nothing more goes downstream or
// upstream: the caller has its answer, and a call it gave up on must not ring
// (#156 AC 2).
func TestAStallPastTheLayers500SendsNothingAfterIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		// start sends the request and anything before the stall.
		start func(h *harness)
	}{
		{"Router", func(h *harness) { h.p.Receive(inboundFrom(invite(h.t), "up")) }},
		{"Resolver", func(h *harness) { h.p.Receive(inboundFrom(invite(h.t), "up")) }},
		{"OnBranchFailure", func(h *harness) {
			h.receive(invite(h.t))
			a := h.one()
			h.p.Receive(transport.Inbound{Message: responseTo(h.t, a, 486), Source: downstreamSource})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStall()
			cfg := Config{}
			if tc.name == "Resolver" {
				cfg.Resolver = stallResolver{s}
			}
			h := newHarness(t, cfg)
			switch tc.name {
			case "Router":
				h.route(func(ctx context.Context, r *Request) Decision { s.wait(ctx); return Forward(r) })
			case "OnBranchFailure":
				h.decide(Decision{
					Targets: []Target{target("sip:first@192.0.2.1")},
					OnBranchFailure: func(ctx context.Context, _ BranchFailure) []Target {
						s.wait(ctx)
						return []Target{target("sip:second@192.0.2.2")}
					},
				})
			}
			tc.start(h)
			ctx := s.entered(t)
			h.sent() // the first branch and its ACK, if any
			h.clock.advance(4 * time.Minute)
			check(t, "upstream", h.upstream(), codes(100, 500))
			select {
			case <-ctx.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("the stalled call's context was not cancelled")
			}
			close(s.release)
			h.settle()
			check(t, "sent after the 500", h.sentMethods(), nil)
			h.advance(time.Hour)
			check(t, "upstream after the 500", h.upstream(), nil)
			if ps, ls := h.p.Stats(), h.p.Layer().Stats(); ps.Contexts != 0 || ps.ContextBytes != 0 ||
				ls.ServerTransactionsTimedOut != 1 || ls.LateFinalResponses != 0 || ps.UpstreamErrors != 0 {
				t.Fatalf("proxy %+v, layer %+v", ps, ls)
			}
		})
	}
}

// A ringing branch whose 180 never reached the client, held by a stalled
// OnResponse hook, keeps the proxy's Timer C running past the layer's 500: the
// branch is then cancelled, so the callee stops ringing for a caller who has
// its answer.
func TestTheLayers500CancelsTheBranchesStillRinging(t *testing.T) {
	h := newHarness(t, Config{})
	s := newStall()
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.1")},
		OnResponse: func(ctx context.Context, res *sip.Response) {
			if res.StatusCode == 180 {
				s.wait(ctx)
			}
		},
	})
	h.receive(invite(t))
	a := h.one()
	// A 100 stops Timer B and is not forwarded; the 180 comes a minute later.
	h.reply(a, 100)
	h.advance(time.Minute)
	check(t, "upstream", h.upstream(), codes(100))
	h.p.Receive(transport.Inbound{Message: responseTo(t, a, 180), Source: downstreamSource})
	ctx := s.entered(t)
	// The safety timer runs from the branch's start; Timer C from the 180.
	h.clock.advance(2*time.Minute + 40*time.Second)
	check(t, "upstream", h.upstream(), codes(500))
	select {
	case <-ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the hook's context was not cancelled")
	}
	close(s.release)
	h.settle()
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@192.0.2.1"})
	if st := h.p.Stats(); st.TimerC != 0 {
		t.Fatalf("Timer C fired first: %+v", st)
	}
}

// A server transaction that ends otherwise, here because the upstream peer
// did not take a provisional response, is not the layer's answer: the
// branches are left alone (§16.9).
func TestOnlyTheLayers500StopsTheBranches(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	a := h.one()
	h.net.mu.Lock()
	h.net.failUpstream = errTest
	h.net.mu.Unlock()
	h.reply(a, 180)
	// What the server transaction's end would start runs on a goroutine of
	// its own; give it time to act.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := h.sentMethods(); got != nil {
			t.Fatalf("sent %q after the upstream failure", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s := h.p.Stats(); s.UpstreamErrors != 1 || s.Cancels != 0 {
		t.Fatalf("stats %+v", s)
	}
}
