package proxy

import (
	"context"
	"testing"
	"time"
)

// drainFor runs Drain with a deadline d away and returns its result.
func drainFor(h *harness, d time.Duration) chan int {
	out := make(chan int, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		out <- h.p.Drain(ctx)
	}()
	return out
}

func TestDrainWithNothingInProgressReturnsAtOnce(t *testing.T) {
	h := newHarness(t, Config{})
	select {
	case n := <-drainFor(h, time.Hour):
		if n != 0 {
			t.Fatalf("answered %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain waited with nothing in progress")
	}
}

// #281: a request in progress at the stop finishes with its own answer.
func TestDrainLetsARequestInProgressFinish(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	fwd := h.one()
	done := drainFor(h, time.Hour)
	h.reply(fwd, 200)
	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("Drain answered %d itself", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return once the request finished")
	}
	check(t, "upstream", h.upstream(), codes(200))
}

// #281: what is left when the stop's time runs out is answered 500 with
// Retry-After (decided on #281), so its sender tries another instance.
func TestDrainAnswersWhatIsLeftAtTheDeadline500WithRetryAfter(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	if n := <-drainFor(h, 100*time.Millisecond); n != 1 {
		t.Fatalf("Drain answered %d, want 1", n)
	}
	// Already sent when Drain returns, so a Close right after keeps it.
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Get("Retry-After") == "" {
		t.Fatalf("upstream got %v, want one 500 with Retry-After", res)
	}
	if s := h.p.Stats(); s.Drained != 1 {
		t.Errorf("Drained = %d", s.Drained)
	}
}

// A ringing INVITE left at the deadline is answered 500 and its branch
// cancelled.
func TestDrainCancelsTheBranchesOfARingingInvite(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(invite(t))
	fwd := h.one()
	h.reply(fwd, 180)
	h.upstream()
	<-drainFor(h, 100*time.Millisecond)
	h.settle()
	check(t, "upstream", h.upstream(), codes(500))
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@192.0.2.2"})
}

// A request whose Router is still deciding at the deadline is answered,
// and what the Router then decides sends nothing.
func TestDrainAnswersARequestTheRouterStillDecides(t *testing.T) {
	h := newHarness(t, Config{})
	release := make(chan struct{})
	entered := make(chan struct{})
	h.route(func(context.Context, *Request) Decision {
		close(entered)
		<-release
		return Decision{Targets: []Target{target("sip:bob@192.0.2.2")}}
	})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	<-entered
	if n := <-drainFor(h, 100*time.Millisecond); n != 1 {
		t.Fatalf("Drain answered %d, want 1", n)
	}
	close(release)
	h.settle()
	check(t, "upstream", h.upstream(), codes(500))
	check(t, "sent", h.sentMethods(), nil)
}

// New requests are still served while Drain waits: peers find the task
// until its registration and DNS answers age out (decided on #281).
func TestDrainStillServesNewRequests(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	first := h.one()
	done := drainFor(h, time.Hour)
	second := request(t, "MESSAGE", "sip:bob@example.com", "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-second", "Call-ID: call-2@192.0.2.10")
	h.receive(second)
	fwd := h.one()
	h.reply(fwd, 200)
	h.reply(first, 200)
	<-done
	check(t, "upstream", h.upstream(), codes(200, 200))
}

// A Router that comes back with an answer of its own after Drain answered
// does not send a second final response.
func TestDrainKeepsItsAnswerOverALateRouterAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	release := make(chan struct{})
	entered := make(chan struct{})
	h.route(func(context.Context, *Request) Decision {
		close(entered)
		<-release
		return Decision{Status: 404}
	})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	<-entered
	if n := <-drainFor(h, 100*time.Millisecond); n != 1 {
		t.Fatalf("Drain answered %d, want 1", n)
	}
	close(release)
	h.settle()
	check(t, "upstream", h.upstream(), codes(500))
	if s := h.p.Stats(); s.UpstreamErrors != 0 {
		t.Errorf("a second final response was tried: %+v", s)
	}
}

// A request that has its final response, here an INVITE whose 200 went up
// while another branch waits for the answer to its CANCEL, is not answered
// again.
func TestDrainLeavesAnAnsweredRequestAlone(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2"), target("sip:bob@192.0.2.3")}})
	h.receive(invite(t))
	sent := h.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d branches", len(sent))
	}
	h.reply(sent[1].req, 180)
	h.reply(sent[0].req, 200)
	check(t, "upstream", h.upstream(), codes(180, 200))
	if n := <-drainFor(h, 100*time.Millisecond); n != 0 {
		t.Fatalf("Drain answered %d, want 0", n)
	}
	h.settle()
	check(t, "upstream after Drain", h.upstream(), nil)
}
