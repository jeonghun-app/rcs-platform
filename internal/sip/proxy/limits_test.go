package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// secondInvite is another call from the same UAC.
func secondInvite(t *testing.T) *sip.Request {
	t.Helper()
	return invite(t, "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-2", "Call-ID: call-2@192.0.2.10")
}

func TestARequestBeyondMaxContextsIsAnswered503WithRetryAfter(t *testing.T) {
	h := newHarness(t, Config{MaxContexts: 1})
	h.receive(invite(t))
	first := h.one()
	h.receive(secondInvite(t))
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 503 || res[0].Header.Get("Retry-After") == "" {
		t.Fatalf("upstream = %v, want 503 with Retry-After", labels(res))
	}
	check(t, "sent", h.sentMethods(), nil)
	if n := h.p.Stats().Overloaded; n != 1 {
		t.Errorf("Overloaded = %d, want 1", n)
	}

	// The slot comes back once the first request has ended.
	h.reply(first, 486)
	h.sent()
	h.upstream()
	h.receive(invite(t, "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-3", "Call-ID: call-3@192.0.2.10"))
	check(t, "sent", h.sentMethods(), []string{"INVITE sip:bob@example.com"})
}

func TestAContextLastsUntilEveryBranchHasEnded(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	h.reply(byURI(t, sent, "MESSAGE", "sip:a@192.0.2.1"), 200)
	if n := h.p.Stats().Contexts; n != 1 {
		t.Errorf("Contexts = %d with a branch pending, want 1", n)
	}
	h.reply(byURI(t, sent, "MESSAGE", "sip:b@192.0.2.2"), 500)
	if n := h.p.Stats().Contexts; n != 0 {
		t.Errorf("Contexts = %d after the last branch, want 0", n)
	}
}

// TestASlowNextHopDoesNotHoldTheReadingGoroutine holds every downstream send:
// Receive, which runs on the goroutine reading the upstream connection, still
// returns, and another upstream request still gets an answer.
func TestASlowNextHopDoesNotHoldTheReadingGoroutine(t *testing.T) {
	h := newHarness(t, Config{MaxContexts: 1})
	entered, release := h.net.holdSends(func(*sip.Request) bool { return true })
	defer release()
	returned := make(chan struct{})
	go func() {
		h.p.Receive(inboundFrom(invite(t), "up"))
		<-entered
		h.p.Receive(inboundFrom(secondInvite(t), "up"))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("Receive blocked behind a held send")
	}
	check(t, "upstream", h.upstream(), codes(503))
	release()
	h.settle()
	check(t, "sent", h.sentMethods(), []string{"INVITE sip:bob@example.com"})
}

func TestARouterThatBlocksDoesNotHoldTheReadingGoroutine(t *testing.T) {
	h := newHarness(t, Config{})
	release := make(chan struct{})
	h.route(func(ctx context.Context, r *Request) Decision {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return Forward(r)
	})
	done := make(chan struct{})
	go func() {
		h.p.Receive(inboundFrom(invite(t), "up"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Receive waited for the Router")
	}
	close(release)
	h.settle()
}

func TestCloseCancelsARunningRouterAndWaitsForIt(t *testing.T) {
	h := newHarness(t, Config{})
	entered := make(chan struct{})
	var routerErr error
	h.route(func(ctx context.Context, r *Request) Decision {
		close(entered)
		<-ctx.Done()
		routerErr = ctx.Err()
		return Forward(r)
	})
	h.p.Receive(inboundFrom(invite(t), "up"))
	<-entered
	h.p.Close()
	if !errors.Is(routerErr, context.Canceled) {
		t.Errorf("the Router's context ended with %v, want Canceled", routerErr)
	}
	check(t, "sent", h.sentMethods(), nil)
}

func TestCloseStopsTimerC(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	h.reply(h.one(), 180)
	h.p.Close()
	h.advance(DefaultTimerC)
	check(t, "sent after Close", h.sentMethods(), nil)
	h.receive(invite(t))
	check(t, "sent for a request after Close", h.sentMethods(), nil)
}

func TestACKsBeyondMaxContextsAreDropped(t *testing.T) {
	h := newHarness(t, Config{MaxContexts: 1})
	entered, release := h.net.holdSends(func(r *sip.Request) bool { return r.Method == "ACK" })
	defer release()
	h.p.Receive(inboundFrom(ackFor2xx(t), "up"))
	<-entered
	h.p.Receive(inboundFrom(ackFor2xx(t, "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKack-2"), "up"))
	release()
	h.settle()
	if s := h.p.Stats(); s.ACKsForwarded != 1 || s.ACKsDropped != 1 {
		t.Errorf("ACKs forwarded %d, dropped %d; want 1 and 1", s.ACKsForwarded, s.ACKsDropped)
	}
}

func TestNewRefusesABadConfig(t *testing.T) {
	tests := []struct {
		name string
		s    *fakeNet
		cfg  Config
	}{
		{"no sender", nil, Config{}},
		{"a Self URI that is not SIP", &fakeNet{}, Config{Self: []sip.URI{mustURI("tel:+15550100001")}}},
		{"no randomness", &fakeNet{}, Config{Rand: failingReader{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s transportSender
			if tt.s != nil {
				s = tt.s
			}
			if _, err := New(s, tt.cfg); err == nil {
				t.Error("New accepted it")
			}
		})
	}
}

type transportSender interface {
	SendRequest(*sip.Request, transport.Destination, ...transport.SendOption) (transport.Network, error)
	SendResponse(*sip.Response, transport.Source, ...transport.SendOption) error
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errTest }

func TestAnUpstreamPeerThatNeverACKsIsCountedNotActedOn(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	h.reply(h.one(), 486)
	h.sent()
	// Timer H: 64*T1 without the ACK for the 486.
	h.advance(64 * t1)
	if n := h.p.Stats().UpstreamErrors; n != 1 {
		t.Errorf("UpstreamErrors = %d, want 1", n)
	}
	check(t, "sent", h.sentMethods(), nil)
}

func TestATargetWithAnInvalidRouteFailsItsBranch(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{
		{URI: mustURI("sip:a@192.0.2.1"), Routes: []sip.Address{{}}},
		{URI: mustURI("sip:a@192.0.2.1"), Routes: []sip.Address{mustAddr("<sip:edge.example.net;lr>")}},
	}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	// The two targets differ by their Route, so both are tried.
	sent := h.sent()
	if len(sent) != 1 || sent[0].dst.ServerName != "edge.example.net" {
		t.Fatalf("sent %v, want the branch with the valid Route", methodsOf(sent))
	}
	h.reply(sent[0].req, 486)
	check(t, "upstream", h.upstream(), codes(486))
}
