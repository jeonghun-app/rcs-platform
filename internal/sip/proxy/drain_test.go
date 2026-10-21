package proxy

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
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
// again, and is not waited for either.
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
	select {
	case n := <-drainFor(h, time.Hour):
		if n != 0 {
			t.Fatalf("Drain answered %d, want 0", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain waited for a request that has its final response")
	}
	h.settle()
	check(t, "upstream after Drain", h.upstream(), nil)
}

// The service chooses the answer per request (Config.DrainAnswer); a code it
// cannot use falls back to 500 with Retry-After: 5.
func TestDrainTakesItsAnswerFromTheService(t *testing.T) {
	h := newHarness(t, Config{DrainAnswer: func(req *sip.Request) (int, time.Duration) {
		if req.Method == "REGISTER" {
			return 503, 7 * time.Second
		}
		return 200, 0
	}})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "REGISTER", "sip:example.com"))
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-msg", "Call-ID: call-msg@192.0.2.10"))
	if n := <-drainFor(h, 100*time.Millisecond); n != 2 {
		t.Fatalf("Drain answered %d, want 2", n)
	}
	got := map[string]string{}
	for _, res := range h.upstreamResponses() {
		cseq, _ := res.Header.CSeq()
		got[cseq.Method] = strconv.Itoa(res.StatusCode) + " " + res.Header.Get("Retry-After")
	}
	if got["REGISTER"] != "503 7" || got["MESSAGE"] != "500 5" {
		t.Fatalf("answers = %v, want REGISTER 503 with 7 and MESSAGE 500 with 5", got)
	}
}

// An INVITE the caller cancelled gets the 487 its CANCEL asked for (§9.2),
// not the 500, while its branch still waits for its own 487.
func TestDrainAnswersACancelledInvite487(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	req := invite(t)
	h.receive(req)
	h.reply(h.one(), 180)
	h.receive(uacCancel(t, req))
	check(t, "upstream", h.upstream(), codes(180, 200))
	<-drainFor(h, 100*time.Millisecond)
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 487 || res[0].Header.Has("Retry-After") {
		t.Fatalf("upstream got %v, want one 487", res)
	}
}

// A request a Serve handler answers stays the handler's: Drain cancels its
// context and sends nothing itself; the handler, returning without an
// answer, leaves it to serve's own 500.
func TestDrainLeavesAServedRequestToItsHandler(t *testing.T) {
	h := newHarness(t, Config{})
	entered := make(chan context.Context, 1)
	h.decide(Decision{Serve: func(ctx context.Context, _ *UAS) {
		entered <- ctx
		<-ctx.Done()
	}})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	ctx := <-entered
	if n := <-drainFor(h, 100*time.Millisecond); n != 0 {
		t.Fatalf("Drain answered %d itself", n)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's context was not cancelled")
	}
	h.settle()
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Has("Retry-After") {
		t.Fatalf("upstream got %v, want serve's 500", res)
	}
	if s := h.p.Stats(); s.Drained != 0 || s.UpstreamErrors != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// A Router that hands the request to a Serve handler after Drain answered
// it runs no handler.
func TestDrainDropsALateServeDecision(t *testing.T) {
	h := newHarness(t, Config{})
	release, entered := make(chan struct{}), make(chan struct{})
	served := make(chan struct{}, 1)
	h.route(func(context.Context, *Request) Decision {
		close(entered)
		<-release
		return Decision{Serve: func(context.Context, *UAS) { served <- struct{}{} }}
	})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	<-entered
	if n := <-drainFor(h, 100*time.Millisecond); n != 1 {
		t.Fatalf("Drain answered %d, want 1", n)
	}
	close(release)
	h.settle()
	select {
	case <-served:
		t.Fatal("a Serve handler ran for a request Drain had answered")
	default:
	}
	check(t, "upstream", h.upstream(), codes(500))
}

// Only answers that went out count: one the upstream peer did not take is
// an upstream error, not a drained request.
func TestDrainCountsOnlyTheAnswersSent(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.net.mu.Lock()
	h.net.failUpstream = errTest
	h.net.mu.Unlock()
	if n := <-drainFor(h, 100*time.Millisecond); n != 0 {
		t.Fatalf("Drain reported %d answers, want 0", n)
	}
	if s := h.p.Stats(); s.Drained != 0 || s.UpstreamErrors != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// A handler that has sent its final response and still waits on its
// context, as rcs-as does for the ACK of its 2xx, is not in progress: Drain
// returns at once and leaves its context alone.
func TestDrainLeavesAHandlerThatAnsweredAlone(t *testing.T) {
	h := newHarness(t, Config{})
	answered := make(chan context.Context, 1)
	release := make(chan struct{})
	h.decide(Decision{Serve: func(ctx context.Context, u *UAS) {
		res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1")
		if err == nil {
			err = u.Respond(res)
		}
		if err != nil {
			t.Error(err)
		}
		answered <- ctx
		select {
		case <-ctx.Done():
		case <-release:
		}
	}})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	ctx := <-answered
	select {
	case n := <-drainFor(h, time.Hour):
		if n != 0 {
			t.Fatalf("Drain answered %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain waited for a handler that had answered")
	}
	if ctx.Err() != nil {
		t.Fatal("Drain cancelled the context of a handler that had answered")
	}
	close(release)
	h.settle()
	check(t, "upstream", h.upstream(), codes(200))
}

// A Router that hands the request to a Serve handler while DrainAnswer runs
// leaves the request to the handler: Drain cancels its context instead of
// answering (code review of #310).
func TestDrainLeavesARequestServedWhileItsAnswerWasMade(t *testing.T) {
	inHook, releaseHook := make(chan struct{}), make(chan struct{})
	h := newHarness(t, Config{DrainAnswer: func(*sip.Request) (int, time.Duration) {
		close(inHook)
		<-releaseHook
		return 500, 5 * time.Second
	}})
	routing, releaseRouter := make(chan struct{}), make(chan struct{})
	serving := make(chan context.Context, 1)
	h.route(func(context.Context, *Request) Decision {
		close(routing)
		<-releaseRouter
		return Decision{Serve: func(ctx context.Context, _ *UAS) {
			serving <- ctx
			<-ctx.Done()
		}}
	})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	<-routing
	done := drainFor(h, 100*time.Millisecond)
	<-inHook
	close(releaseRouter)
	ctx := <-serving
	close(releaseHook)
	if n := <-done; n != 0 {
		t.Fatalf("Drain answered %d itself", n)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's context was not cancelled")
	}
	h.settle()
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Has("Retry-After") {
		t.Fatalf("upstream got %v, want serve's own 500 alone", res)
	}
}

// An INVITE cancelled upstream while DrainAnswer runs gets the 487.
func TestDrainAnswers487ToAnInviteCancelledWhileItsAnswerWasMade(t *testing.T) {
	inHook, releaseHook := make(chan struct{}), make(chan struct{})
	h := newHarness(t, Config{DrainAnswer: func(*sip.Request) (int, time.Duration) {
		close(inHook)
		<-releaseHook
		return 500, 5 * time.Second
	}})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	req := invite(t)
	h.receive(req)
	h.reply(h.one(), 180)
	h.upstream()
	done := drainFor(h, 100*time.Millisecond)
	<-inHook
	h.receive(uacCancel(t, req))
	close(releaseHook)
	<-done
	h.settle()
	var finals []int
	for _, res := range h.upstreamResponses() {
		if cseq, _ := res.Header.CSeq(); cseq.Method == "INVITE" {
			finals = append(finals, res.StatusCode)
		}
	}
	check(t, "INVITE finals", finals, codes(487))
}

// A final response forwarded but still queued for the upstream peer, here
// held by its OnResponse hook, keeps the request in progress: Drain waits
// until it has been handed over, so a Close right after does not drop it.
func TestDrainWaitsForAForwardedAnswerStillQueued(t *testing.T) {
	h := newHarness(t, Config{})
	holding, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.2")},
		OnResponse: func(_ context.Context, res *sip.Response) {
			if res.StatusCode == 200 {
				close(holding)
				<-release
			}
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	fwd := h.one()
	done := drainFor(h, time.Hour)
	h.p.Receive(transport.Inbound{Message: responseTo(t, fwd, 200), Source: downstreamSource})
	select {
	case <-holding:
	case <-time.After(5 * time.Second):
		t.Fatal("the 200 never reached OnResponse")
	}
	select {
	case <-done:
		t.Fatal("Drain returned while the 200 was still queued")
	case <-time.After(300 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return once the 200 was handed over")
	}
	check(t, "upstream", h.upstream(), codes(200))
}

// A request that arrives once Drain has answered what was left gets the
// same answer at once, rather than nothing when the proxy closes right
// after (QA of #310).
func TestARequestAfterDrainHasAnsweredGetsItsAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	if n := <-drainFor(h, 50*time.Millisecond); n != 1 {
		t.Fatalf("Drain answered %d, want 1", n)
	}
	h.upstream()
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-late", "Call-ID: call-late@192.0.2.10"))
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Get("Retry-After") != "5" {
		t.Fatalf("a request after the drain got %v, want 500 with Retry-After 5", res)
	}
	check(t, "sent", h.sentMethods(), nil)
}

// However many answers cannot go out, Drain gives them DrainSendWait in all,
// not each (QA of #310).
func TestDrainWaitsForItsAnswersForDrainSendWaitInAll(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	for i := range 5 {
		h.receive(request(t, "MESSAGE", "sip:bob@example.com", fmt.Sprintf("Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-stall%d", i), fmt.Sprintf("Call-ID: stall-%d@192.0.2.10", i)))
	}
	h.sent()
	stall := make(chan struct{})
	h.net.mu.Lock()
	h.net.stallUpstream = stall
	h.net.mu.Unlock()
	t.Cleanup(func() { close(stall) })
	start := time.Now()
	<-drainFor(h, 50*time.Millisecond)
	if took := time.Since(start); took < DrainSendWait || took > DrainSendWait+time.Second {
		t.Fatalf("Drain returned after %v, want about %v after its 50 ms", took, DrainSendWait)
	}
}

// A request that arrives after Drain found nothing in progress gets the
// drain's answer at once too, rather than nothing when the proxy closes
// right after (QA of #310).
func TestARequestAfterAnEarlyDrainGetsItsAnswer(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.2")}})
	if n := <-drainFor(h, time.Hour); n != 0 {
		t.Fatalf("Drain answered %d", n)
	}
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 500 || res[0].Header.Get("Retry-After") != "5" {
		t.Fatalf("a request after the drain got %v, want 500 with Retry-After 5", res)
	}
	check(t, "sent", h.sentMethods(), nil)
}

// A Serve handler's final response that the upstream peer has not taken yet
// keeps the request in progress, as the proxy's own does (QA of #310): Drain
// waits until it has been handed over.
func TestDrainWaitsForAHandlersAnswerStillOnItsWay(t *testing.T) {
	h := newHarness(t, Config{})
	stall := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(stall) }) })
	responding := make(chan struct{})
	h.decide(Decision{Serve: func(_ context.Context, u *UAS) {
		res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1")
		if err != nil {
			t.Error(err)
			return
		}
		h.net.mu.Lock()
		h.net.stallUpstream = stall
		h.net.mu.Unlock()
		close(responding)
		_ = u.Respond(res)
	}})
	h.p.Receive(inboundFrom(request(t, "MESSAGE", "sip:bob@example.com"), "up"))
	<-responding
	done := drainFor(h, time.Hour)
	select {
	case <-done:
		t.Fatal("Drain returned while the handler's 200 was still on its way")
	case <-time.After(300 * time.Millisecond):
	}
	once.Do(func() { close(stall) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return once the 200 was handed over")
	}
	check(t, "upstream", h.upstream(), codes(200))
}
