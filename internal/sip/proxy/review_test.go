package proxy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// withBody returns req with body as its SDP.
func withBody(t *testing.T, method, uri, body string, extra ...string) *sip.Request {
	t.Helper()
	req := request(t, method, uri, append(extra, "Content-Type: application/sdp")...)
	req.Body = []byte(body)
	return req
}

func TestOnResponseMayReplaceTheBodyOfEveryResponseItForwards(t *testing.T) {
	h := newHarness(t, Config{})
	var mu sync.Mutex
	var ctxErrs []error
	var hookCtx context.Context
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.30")},
		OnResponse: func(ctx context.Context, res *sip.Response) {
			mu.Lock()
			ctxErrs = append(ctxErrs, ctx.Err())
			hookCtx = ctx
			mu.Unlock()
			if len(res.Body) > 0 {
				// An application level gateway anchors the media (ADR 0004).
				res.Body = []byte(strings.ReplaceAll(string(res.Body), "192.0.2.30", "198.51.100.7"))
			}
		},
	})
	h.receive(withBody(t, "INVITE", "sip:bob@example.com", "c=IN IP4 192.0.2.10\r\n"))
	a := h.one()
	sdp := "c=IN IP4 192.0.2.30\r\n"
	for _, code := range []int{183, 200, 200} {
		res := responseTo(t, a, code, "Content-Type: application/sdp")
		res.Body = []byte(sdp)
		h.p.Receive(inboundFrom(res, "down"))
		h.settle()
	}
	got := h.upstreamResponses()
	if len(got) != 3 {
		t.Fatalf("upstream = %v, want 183 and two 200s", labels(got))
	}
	for _, res := range got {
		if string(res.Body) != "c=IN IP4 198.51.100.7\r\n" {
			t.Errorf("the %d went upstream with %q", res.StatusCode, res.Body)
		}
	}
	mu.Lock()
	for i, err := range ctxErrs {
		if err != nil {
			t.Errorf("call %d of OnResponse had a cancelled context", i)
		}
	}
	mu.Unlock()
	// The context lives for the 64*T1 that 2xx retransmissions can come.
	h.advance(64*t1 - time.Millisecond)
	if hookCtx.Err() != nil {
		t.Fatal("the hooks' context ended before 64*T1")
	}
	h.advance(time.Millisecond)
	if hookCtx.Err() == nil {
		t.Error("the hooks' context outlived 64*T1")
	}
}

func TestBranchCopiesShareTheRequestBody(t *testing.T) {
	h := newHarness(t, Config{})
	var mu sync.Mutex
	var bodies []*byte
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		Prepare: func(_ context.Context, _ Target, req *sip.Request) error {
			mu.Lock()
			bodies = append(bodies, &req.Body[0])
			mu.Unlock()
			return nil
		},
	})
	h.receive(withBody(t, "MESSAGE", "sip:bob@example.com", strings.Repeat("x", 4096)))
	routed := &h.lastSeen().Message.Body[0]
	if len(bodies) != 2 || bodies[0] != routed || bodies[1] != routed {
		t.Fatal("a branch copied the body")
	}
}

func TestRequestsBeyondMaxContextBytesAreAnswered503(t *testing.T) {
	h := newHarness(t, Config{MaxContextBytes: 4096})
	h.receive(withBody(t, "MESSAGE", "sip:bob@example.com", strings.Repeat("x", 8192)))
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].StatusCode != 503 || res[0].Header.Get("Retry-After") == "" {
		t.Fatalf("upstream = %v, want 503 with Retry-After", labels(res))
	}
	h.receive(withBody(t, "MESSAGE", "sip:bob@example.com", "small", "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-2"))
	out := h.one()
	if h.p.Stats().ContextBytes <= int64(len("small")) {
		t.Errorf("ContextBytes = %d while a request is held", h.p.Stats().ContextBytes)
	}
	h.reply(out, 200)
	if n := h.p.Stats().ContextBytes; n != 0 {
		t.Errorf("ContextBytes = %d once the request ended, want 0", n)
	}
}

func TestABranchOverMaxContextBytesFailsAs503(t *testing.T) {
	req := request(t, "MESSAGE", "sip:bob@example.com")
	// Room for the request and one branch.
	budget := 4 * headerSize(&req.Header)
	h := newHarness(t, Config{MaxContextBytes: budget + 64})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(req)
	a := h.one()
	h.reply(a, 486)
	check(t, "upstream", h.upstream(), codes(486))
	if h.p.Stats().Overloaded != 1 {
		t.Errorf("Overloaded = %d, want the second branch", h.p.Stats().Overloaded)
	}
}

// TestANonInviteThatTimesOutIsNotAnswered408 is RFC 4320 §4.2: a 408 to a
// non-INVITE request would reach a client that has given up, so the proxy sends
// none, and the transaction still ends and absorbs the request's
// retransmissions without answering.
func TestANonInviteThatTimesOutIsNotAnswered408(t *testing.T) {
	h := newHarness(t, Config{})
	msg := request(t, "MESSAGE", "sip:bob@example.com", "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKup-udp")
	// Over UDP, where the client retransmits and Timer J absorbs it.
	fromUDP := transport.Inbound{Message: msg, Source: transport.Source{Network: transport.UDP, Flow: "udp"}}
	h.p.Receive(fromUDP)
	h.settle()
	h.one()
	h.advance(64 * t1)
	check(t, "upstream", h.upstream(), nil)
	if n := h.p.Stats().Silenced; n != 1 {
		t.Errorf("Silenced = %d, want 1", n)
	}
	h.p.Receive(fromUDP)
	h.settle()
	check(t, "upstream after a retransmission", h.upstream(), nil)
	check(t, "sent after a retransmission", h.sentMethods(), nil)
	if _, servers := h.p.Layer().Len(); servers != 1 {
		t.Errorf("%d server transactions, want the silenced one absorbing", servers)
	}
	h.advance(64*t1 + time.Second)
	if _, servers := h.p.Layer().Len(); servers != 0 {
		t.Errorf("%d server transactions left", servers)
	}
}

func TestAReceivedResponseBeatsATimeoutTheProxyMadeUp(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:a@192.0.2.1"), Timeout: time.Second}, target("sip:b@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	h.advance(time.Second)
	h.reply(byURI(t, sent, "MESSAGE", "sip:b@192.0.2.2"), 486)
	check(t, "upstream", h.upstream(), codes(486))
}

func TestANonInviteForwardsA408ItReceived(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.reply(h.one(), 408)
	check(t, "upstream", h.upstream(), codes(408))
}

func TestOnFinalDecidesWhatAnAll430ResultBecomes(t *testing.T) {
	noFlow := func(*sip.Request, transport.Destination) error { return transport.ErrNoFlow }
	h := newHarness(t, Config{})
	h.net.setFail(noFlow)
	h.receive(invite(t))
	check(t, "upstream without OnFinal", h.upstream(), codes(480))

	edge := newHarness(t, Config{})
	edge.net.setFail(noFlow)
	var seen []int
	edge.decide(Decision{
		Targets: []Target{target("sip:alice@192.0.2.10")},
		// The edge proxy keeps 430 for the authoritative proxy.
		OnFinal: func(_ context.Context, res *sip.Response) { seen = append(seen, res.StatusCode) },
	})
	edge.receive(invite(t))
	check(t, "upstream with OnFinal", edge.upstream(), codes(430))
	check(t, "OnFinal saw", seen, codes(430))
}

func TestOnFinalCanChangeTheStatusSentUpstream(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.30")},
		OnFinal: func(_ context.Context, res *sip.Response) {
			res.StatusCode, res.Reason = 480, "Temporarily Unavailable"
		},
	})
	h.receive(invite(t))
	h.reply(h.one(), 486)
	check(t, "upstream", h.upstream(), codes(480))
}

func TestATargetTimeoutEndsItsBranchInTimeForAnotherTarget(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:as@192.0.2.40"), Timeout: 2 * time.Second}},
		// The application server's default handling continues the session.
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target {
			if f.Target.URI.User == "as" && f.Response.StatusCode == 408 {
				return []Target{target("sip:bob@192.0.2.30")}
			}
			return nil
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	check(t, "sent", h.sentMethods(), []string{"MESSAGE sip:as@192.0.2.40"})
	h.advance(2*time.Second - time.Millisecond)
	check(t, "sent before the timeout", h.sentMethods(), nil)
	h.advance(time.Millisecond)
	sent := h.sent()
	check(t, "sent at the timeout", methodsOf(sent), []string{"MESSAGE sip:bob@192.0.2.30"})
	h.reply(sent[0].req, 200)
	check(t, "upstream", h.upstream(), codes(200))
	if n := h.p.Stats().TargetTimeouts; n != 1 {
		t.Errorf("TargetTimeouts = %d", n)
	}
}

// TestATargetTimeoutEndsARingingInviteBranchAtOnce: the branch is cancelled
// and counts as a 408 when the timeout passes, without waiting for the 487,
// so a replacement starts at once; the late 487 is absorbed.
func TestATargetTimeoutEndsARingingInviteBranchAtOnce(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:as@192.0.2.40"), Timeout: 2 * time.Second}},
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target {
			if f.Target.URI.User == "as" && errors.Is(f.Err, ErrTargetTimeout) {
				return []Target{target("sip:bob@192.0.2.30")}
			}
			return nil
		},
	})
	h.receive(invite(t))
	as := h.one()
	h.reply(as, 100)
	h.advance(2 * time.Second)
	sent := h.sent()
	check(t, "sent at the timeout", methodsOf(sent), []string{"CANCEL sip:as@192.0.2.40", "INVITE sip:bob@192.0.2.30"})
	h.reply(as, 487)
	// Only the server transaction's own 100 Trying, at 200 ms.
	check(t, "upstream after the late 487", h.upstream(), codes(100))
	h.reply(byURI(t, sent, "INVITE", "sip:bob@192.0.2.30"), 200)
	check(t, "upstream", h.upstream(), codes(200))
}

// TestALateFirst2xxOfATimedOutBranchCancelsTheReplacement: the AS answers
// after its timeout, while the replacement rings. Its 200 starts a dialog
// like any first 2xx: it goes upstream, never dropped, and the replacement is
// cancelled (§16.7 step 10); its retransmission goes upstream too.
func TestALateFirst2xxOfATimedOutBranchCancelsTheReplacement(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:as@192.0.2.40"), Timeout: 2 * time.Second}},
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target {
			if errors.Is(f.Err, ErrTargetTimeout) {
				return []Target{target("sip:bob@192.0.2.30")}
			}
			return nil
		},
	})
	h.receive(invite(t))
	as := h.one()
	h.reply(as, 100)
	h.advance(2 * time.Second)
	bob := byURI(t, h.sent(), "INVITE", "sip:bob@192.0.2.30")
	h.reply(bob, 180)
	h.upstream()
	h.reply(as, 200)
	check(t, "sent after the late 200", h.sentMethods(), []string{"CANCEL sip:bob@192.0.2.30"})
	h.reply(as, 200)
	h.reply(bob, 487)
	got := h.upstreamResponses()
	var tags []string
	for _, r := range got {
		to, _ := r.Header.To()
		tags = append(tags, itoa(r.StatusCode)+" "+to.Tag())
	}
	check(t, "upstream", tags, []string{"200 tag-192-0-2-40", "200 tag-192-0-2-40"})
	if n := h.p.Stats().RetransmissionsDropped; n != 0 {
		t.Errorf("RetransmissionsDropped = %d", n)
	}
}

// TestAnAbandonedBranchKeepsTheBudgetAndHookContextFor64T1: a branch its
// Target.Timeout ended still waits for the answer to its CANCEL, and its
// transaction holds the request, so the context's bytes and hook context stay
// for 64*T1 after the final went upstream.
func TestAnAbandonedBranchKeepsTheBudgetAndHookContextFor64T1(t *testing.T) {
	h := newHarness(t, Config{})
	var hookCtx context.Context
	h.decide(Decision{
		Targets:    []Target{{URI: mustURI("sip:bob@192.0.2.30"), Timeout: time.Second}},
		OnResponse: func(ctx context.Context, _ *sip.Response) { hookCtx = ctx },
	})
	h.receive(withBody(t, "INVITE", "sip:bob@example.com", strings.Repeat("x", 4096)))
	h.reply(h.one(), 180)
	h.advance(time.Second)
	check(t, "upstream", h.upstream(), codes(180, 408))
	if n := h.p.Stats().Contexts; n != 0 {
		t.Fatalf("Contexts = %d", n)
	}
	if n := h.p.Stats().ContextBytes; n < 4096 {
		t.Errorf("ContextBytes = %d while the abandoned branch's transaction lives", n)
	}
	h.advance(64*t1 - time.Millisecond)
	if hookCtx.Err() != nil {
		t.Error("the hooks' context ended before 64*T1")
	}
	h.advance(time.Millisecond)
	if n := h.p.Stats().ContextBytes; n != 0 || hookCtx.Err() == nil {
		t.Errorf("after 64*T1: ContextBytes %d, context %v", n, hookCtx.Err())
	}
}

// TestAnAbandonedBranchThatAnswers2xxIsNotTerminatedByItsCancelDeadline: once
// the abandoned branch's INVITE is answered, the CANCEL's 64*T1 deadline no
// longer applies, so the transaction lives out Timer M and the 2xx's
// retransmissions still reach the proxy rather than turning stray.
func TestAnAbandonedBranchThatAnswers2xxIsNotTerminatedByItsCancelDeadline(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:bob@192.0.2.30"), Timeout: 2 * time.Second}},
		// A replacement rings, so no final goes upstream before the late 200.
		OnBranchFailure: func(context.Context, BranchFailure) []Target { return []Target{target("sip:bob2@192.0.2.31")} },
	})
	h.receive(invite(t))
	b := h.one()
	h.reply(b, 180)
	h.advance(2 * time.Second) // CANCEL sent; its deadline is at 2 s + 64*T1
	h.reply(byURI(t, h.sent(), "INVITE", "sip:bob2@192.0.2.31"), 180)
	h.advance(time.Second)
	h.reply(b, 200) // Timer M runs to 3 s + 64*T1
	h.upstream()
	h.advance(64*t1 - 500*time.Millisecond) // past the CANCEL's deadline
	h.reply(b, 200)
	check(t, "a retransmission after the CANCEL's deadline", h.upstream(), codes(200))
	if n := h.p.Stats().StrayResponses; n != 0 {
		t.Errorf("StrayResponses = %d", n)
	}
}

// TestANonInviteBranchEndedByItsTimeoutReportsErrTargetTimeout: the branch is
// ended by terminating its transaction, and the hook learns why.
func TestANonInviteBranchEndedByItsTimeoutReportsErrTargetTimeout(t *testing.T) {
	h := newHarness(t, Config{})
	var got []error
	h.decide(Decision{
		Targets:         []Target{{URI: mustURI("sip:as@192.0.2.40"), Timeout: time.Second}},
		OnBranchFailure: func(_ context.Context, f BranchFailure) []Target { got = append(got, f.Err); return nil },
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.advance(time.Second)
	if len(got) != 1 || !errors.Is(got[0], ErrTargetTimeout) {
		t.Fatalf("OnBranchFailure got %v, want ErrTargetTimeout", got)
	}
}

func TestATargetTimeoutWithoutReplacementAnswersAnInvite408(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:bob@192.0.2.30"), Timeout: 5 * time.Second}}})
	h.receive(invite(t))
	b := h.one()
	h.reply(b, 180)
	h.advance(5 * time.Second)
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@192.0.2.30"})
	check(t, "upstream", h.upstream(), codes(180, 408))
	// Its CANCEL unanswered, the transaction still ends at 64*T1.
	h.advance(64 * t1)
	if clients, _ := h.p.Layer().Len(); clients != 0 {
		t.Errorf("%d client transactions left", clients)
	}
}

func TestATargetTimeoutOnANonInviteIsAnswered504ThroughOnFinal(t *testing.T) {
	h := newHarness(t, Config{})
	var seen []int
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:as@192.0.2.40"), Timeout: 2 * time.Second}},
		OnFinal: func(_ context.Context, res *sip.Response) { seen = append(seen, res.StatusCode) },
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.advance(2 * time.Second)
	check(t, "upstream", h.upstream(), codes(504))
	check(t, "OnFinal saw", seen, codes(504))
	if n := h.p.Stats().Silenced; n != 0 {
		t.Errorf("Silenced = %d", n)
	}
}

func TestTheByteBudgetIsHeldWhileA2xxCanStillBeRetransmitted(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(withBody(t, "INVITE", "sip:bob@example.com", strings.Repeat("x", 4096)))
	h.reply(h.one(), 200)
	if n := h.p.Stats().Contexts; n != 0 {
		t.Fatalf("Contexts = %d", n)
	}
	if n := h.p.Stats().ContextBytes; n < 4096 {
		t.Errorf("ContextBytes = %d right after the 2xx; the transactions still hold the body", n)
	}
	h.advance(64 * t1)
	if n := h.p.Stats().ContextBytes; n != 0 {
		t.Errorf("ContextBytes = %d after 64*T1", n)
	}
}

func TestOnResponseSeesTheChosenFinalOfAFork(t *testing.T) {
	h := newHarness(t, Config{})
	var seen []int
	h.decide(Decision{
		Targets:    []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		OnResponse: func(_ context.Context, res *sip.Response) { seen = append(seen, res.StatusCode) },
	})
	h.receive(request(t, "REGISTER", "sip:example.com"))
	sent := h.sent()
	h.reply(byURI(t, sent, "REGISTER", "sip:a@192.0.2.1"), 401, `WWW-Authenticate: Digest realm="example.com", nonce="n"`)
	h.reply(byURI(t, sent, "REGISTER", "sip:b@192.0.2.2"), 404)
	check(t, "OnResponse saw", seen, codes(401))
	check(t, "upstream", h.upstream(), codes(401))
}

func TestAServiceThatReturnsAfterACancelWithoutAnsweringGets487(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	s := serve(t, h, inv)
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	s.release()
	h.settle()
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 CANCEL", "487 INVITE"})
}

func Test2xxRetransmissionsQueuedForASlowUpstreamAreBounded(t *testing.T) {
	net := &stalledUp{fakeNet: &fakeNet{}, block: make(chan struct{})}
	p, err := New(net, Config{Self: []sip.URI{selfURI}, Resolver: fakeResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			close(net.block)
		}
		p.Close()
	}()
	p.Receive(inboundFrom(invite(t), "up"))
	var a *sip.Request
	for a == nil {
		net.mu.Lock()
		if len(net.requests) > 0 {
			a = net.requests[0].req
		}
		net.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	var c *respContext
	p.mu.Lock()
	for _, x := range p.contexts {
		c = x
	}
	p.mu.Unlock()
	wire, err := responseTo(t, a, 200).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for range 2000 {
		m, err := sip.ParseMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		p.Receive(inboundFrom(m, "down"))
	}
	c.up.mu.Lock()
	queued := len(c.up.queue)
	c.up.mu.Unlock()
	// The first 2xx, at most 16 retransmissions and the context's release.
	if queued > maxQueuedProvisionals+2 {
		t.Errorf("%d responses queued for one slow upstream transaction", queued)
	}
	if p.Stats().RetransmissionsDropped == 0 {
		t.Error("no retransmission was counted as dropped")
	}
	close(net.block)
	released = true
	p.wait()
}

// A CANCEL that arrives while Prepare runs is answered 200; the INVITE must
// then never be sent (§16.10), and the request is answered 487 (§9.2).
func TestAnInviteCancelledDuringPrepareIsNotSent(t *testing.T) {
	h := newHarness(t, Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.20")},
		Prepare: func(context.Context, Target, *sip.Request) error {
			close(entered)
			<-release
			return nil
		},
	})
	inv := invite(t)
	h.p.Receive(inboundFrom(inv, "up"))
	<-entered
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	close(release)
	h.settle()
	check(t, "sent after the CANCEL", h.sentMethods(), nil)
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 CANCEL", "487 INVITE"})
}

// Same with a sibling branch's 2xx (§16.7 step 10).
func TestABranchStillInPrepareIsNotSentAfterA2xx(t *testing.T) {
	h := newHarness(t, Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		Prepare: func(_ context.Context, tg Target, _ *sip.Request) error {
			if tg.URI.User == "b" {
				close(entered)
				<-release
			}
			return nil
		},
	})
	h.p.Receive(inboundFrom(invite(t), "up"))
	<-entered
	var a *sip.Request
	for a == nil {
		h.net.mu.Lock()
		if len(h.net.requests) > 0 {
			a = h.net.requests[0].req
		}
		h.net.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	h.sent()
	h.p.Receive(inboundFrom(responseTo(t, a, 200), "down"))
	close(release)
	h.settle()
	check(t, "sent after the 2xx", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(200))
}

// stalledUp never completes a send upstream until released, as a peer whose
// connection has no room makes SendResponse wait (WriteTimeout per send in the
// real transport).
type stalledUp struct {
	*fakeNet
	block chan struct{}
}

func (s *stalledUp) SendResponse(res *sip.Response, src transport.Source, o ...transport.SendOption) error {
	if res.StatusCode != 100 {
		<-s.block
	}
	return s.fakeNet.SendResponse(res, src, o...)
}

func TestProvisionalsQueuedForASlowUpstreamAreBounded(t *testing.T) {
	net := &stalledUp{fakeNet: &fakeNet{}, block: make(chan struct{})}
	p, err := New(net, Config{Self: []sip.URI{selfURI}, Resolver: fakeResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			close(net.block)
		}
		p.Close()
	}()
	p.Receive(inboundFrom(invite(t), "up"))
	var a *sip.Request
	for a == nil {
		net.mu.Lock()
		if len(net.requests) > 0 {
			a = net.requests[0].req
		}
		net.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	for range 200 {
		p.Receive(inboundFrom(responseTo(t, a, 180), "down"))
	}
	p.Receive(inboundFrom(responseTo(t, a, 200), "down"))
	p.mu.Lock()
	var queued int
	for _, c := range p.contexts {
		c.up.mu.Lock()
		queued = len(c.up.queue)
		c.up.mu.Unlock()
	}
	p.mu.Unlock()
	// The provisionals, the 200 and the context's release.
	if queued > maxQueuedProvisionals+2 {
		t.Errorf("%d responses queued for one slow upstream transaction", queued)
	}
	close(net.block)
	released = true
	p.wait()
	net.mu.Lock()
	defer net.mu.Unlock()
	if last := net.upstream[len(net.upstream)-1]; last.StatusCode != 200 {
		t.Errorf("the 2xx was dropped: last upstream %d", last.StatusCode)
	}
	if p.Stats().ProvisionalsDropped == 0 {
		t.Error("no provisional was counted as dropped")
	}
}

func TestOnBranchFailureSeesItsContextEndWhenTheProxyCloses(t *testing.T) {
	h := newHarness(t, Config{})
	entered := make(chan struct{})
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1")},
		OnBranchFailure: func(ctx context.Context, _ BranchFailure) []Target {
			close(entered)
			<-ctx.Done()
			return nil
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.p.Receive(inboundFrom(responseTo(t, h.one(), 486), "down"))
	<-entered
	closed := make(chan struct{})
	go func() {
		h.p.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(realWait):
		t.Fatal("Close did not end the hook's context")
	}
}

func TestANonInviteBranchWithAProvisionalIsNotCancelled(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	b := byURI(t, sent, "MESSAGE", "sip:b@192.0.2.2")
	h.reply(b, 100)
	h.reply(byURI(t, sent, "MESSAGE", "sip:a@192.0.2.1"), 200)
	h.advance(64 * t1)
	check(t, "sent", h.sentMethods(), nil)
	if n := h.p.Stats().Cancels; n != 0 {
		t.Errorf("Cancels = %d for a MESSAGE", n)
	}
}

func TestNoProvisionalGoesUpstreamAfterTheFinal(t *testing.T) {
	h := newHarness(t, Config{})
	var seen []int
	h.decide(Decision{
		Targets:    []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		OnResponse: func(_ context.Context, res *sip.Response) { seen = append(seen, res.StatusCode) },
	})
	h.receive(invite(t))
	sent := h.sent()
	h.reply(byURI(t, sent, "INVITE", "sip:a@192.0.2.1"), 200)
	h.reply(byURI(t, sent, "INVITE", "sip:b@192.0.2.2"), 180)
	check(t, "OnResponse saw", seen, codes(200))
}

// escapedNUL is a display name the parser accepts (RFC 4475 §3.1.1.2) and
// Header.Add refuses to write.
const escapedNUL = "\"a\\\x00b\" "

func TestACancelIsSentForAnInviteWithAnEscapedNULInFrom(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t, "From: "+escapedNUL+"<sip:alice@example.com>;tag=a1")
	h.receive(inv)
	b := h.one()
	h.reply(b, 180)
	h.receive(uacCancel(t, inv))
	cancels := h.sent()
	if len(cancels) != 1 || cancels[0].req.Method != "CANCEL" {
		t.Fatalf("sent %v, want the CANCEL", methodsOf(cancels))
	}
	if got := cancels[0].req.Header.Get("From"); got != b.Header.Get("From") {
		t.Errorf("CANCEL From = %q, want the INVITE's", got)
	}
}

func TestAResponseIsSentForARequestWithAnEscapedNULInTo(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Status: 404})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "To: "+escapedNUL+"<sip:bob@example.com>"))
	check(t, "upstream", h.upstream(), codes(404))
}

// served is a request handed to Serve, which waits until release so the test
// can drive the UAS. Until then the test delivers messages with p.Receive, not
// with the harness helpers, which wait for every goroutine.
type served struct {
	u       *UAS
	ctx     context.Context
	release func()
}

// serve hands req to a Serve handler and returns it.
func serve(t *testing.T, h *harness, req *sip.Request) served {
	t.Helper()
	got := make(chan served, 1)
	h.decide(Decision{Serve: func(ctx context.Context, u *UAS) {
		done := make(chan struct{})
		var once sync.Once
		got <- served{u: u, ctx: ctx, release: func() { once.Do(func() { close(done) }) }}
		<-done
	}})
	h.p.Receive(inboundFrom(req, "up"))
	s := <-got
	t.Cleanup(s.release)
	return s
}

func answer(t *testing.T, s served, code int) {
	t.Helper()
	res, err := sip.NewResponse(s.u.Request().Message, code, "", "uas-tag")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.u.Respond(res); err != nil {
		t.Fatal(err)
	}
}

func TestAServedInviteHasIts2xxRetransmittedUntilTheACK(t *testing.T) {
	h := newHarness(t, Config{})
	uases := make(chan *UAS, 1)
	h.decide(Decision{Serve: func(_ context.Context, u *UAS) {
		res, err := sip.NewResponse(u.Request().Message, 200, "", "uas-tag")
		if err != nil {
			t.Error(err)
			return
		}
		if err := u.Respond(res); err != nil {
			t.Error(err)
		}
		uases <- u
	}})
	inv := invite(t)
	h.receive(inv)
	u := <-uases
	check(t, "sent downstream", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(200))
	h.advance(t1)
	check(t, "after T1", h.upstream(), codes(200))
	h.advance(2 * t1)
	check(t, "after 2*T1 more", h.upstream(), codes(200))

	ack := request(t, "ACK", inv.URI.String(), "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKack-1",
		"To: <sip:bob@example.com>;tag=uas-tag", "CSeq: 1 ACK")
	h.receive(ack)
	got, err := u.ACK(ctx(t))
	if err != nil || got.Header.Get("Via") != ack.Header.Get("Via") {
		t.Fatalf("ACK = %v, %v", got, err)
	}
	check(t, "the ACK was not forwarded", h.sentMethods(), nil)
	h.advance(64 * t1)
	check(t, "upstream after the ACK", h.upstream(), nil)
	if s := h.p.Stats(); s.ACKsConsumed != 1 || s.ACKsForwarded != 0 {
		t.Errorf("ACKs consumed %d, forwarded %d", s.ACKsConsumed, s.ACKsForwarded)
	}
}

func TestAServed2xxWithoutAnACKIsReportedAfter64T1(t *testing.T) {
	h := newHarness(t, Config{})
	s := serve(t, h, invite(t))
	answer(t, s, 200)
	s.release()
	h.settle()
	// In steps, so each retransmission is sent before the next timer fires.
	for range 64 {
		h.advance(t1)
	}
	if _, err := s.u.ACK(ctx(t)); !errors.Is(err, ErrNoACK) {
		t.Fatalf("ACK error = %v, want ErrNoACK", err)
	}
	if n := h.p.Stats().ACKsMissing; n != 1 {
		t.Errorf("ACKsMissing = %d", n)
	}
	// The first and its retransmissions at T1 doubling to T2 within 64*T1:
	// 0.5, 1.5, 3.5, 7.5 s, then every 4 s to 31.5 s.
	if n := len(h.upstream()); n != 11 {
		t.Errorf("%d 2xx sent in 64*T1", n)
	}
}

func TestACancelReachesTheServingServiceThroughItsContext(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	s := serve(t, h, inv)
	answer(t, s, 180)
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	if s.ctx.Err() == nil {
		t.Fatal("the service was not told of the CANCEL")
	}
	answer(t, s, 487)
	s.release()
	h.settle()
	check(t, "upstream", labels(h.upstreamResponses()), []string{"180 INVITE", "200 CANCEL", "487 INVITE"})
}

func TestACancelAfterTheServicesAnswerLeavesItsContextAlone(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	s := serve(t, h, inv)
	answer(t, s, 200)
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	if s.ctx.Err() != nil {
		t.Error("a CANCEL after the 2xx reached the service")
	}
	s.release()
	h.settle()
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 INVITE", "200 CANCEL"})
}

func TestTheProxyAnswersForAServiceThatReturnsWithoutAnswering(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Serve: func(context.Context, *UAS) {}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	check(t, "upstream", h.upstream(), codes(500))
	if n := h.p.Stats().Contexts; n != 0 {
		t.Errorf("Contexts = %d", n)
	}
}

func TestAServedMessageHasNoACK(t *testing.T) {
	h := newHarness(t, Config{})
	s := serve(t, h, request(t, "MESSAGE", "sip:bob@example.com"))
	answer(t, s, 200)
	if _, err := s.u.ACK(ctx(t)); !errors.Is(err, ErrNotAccepted) {
		t.Errorf("ACK error = %v, want ErrNotAccepted", err)
	}
	res, _ := sip.NewResponse(s.u.Request().Message, 200, "", "uas-tag")
	if err := s.u.Respond(res); !errors.Is(err, transaction.ErrState) {
		t.Errorf("a second final: %v, want ErrState", err)
	}
	s.release()
	h.settle()
	check(t, "upstream", h.upstream(), codes(200))
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), realWait)
	t.Cleanup(cancel)
	return c
}

const realWait = 10 * time.Second

// startStalled forwards an INVITE through a proxy whose upstream sends are
// held, and returns the branch's request and its context.
func startStalled(t *testing.T) (*Proxy, *stalledUp, *sip.Request, *respContext) {
	t.Helper()
	net := &stalledUp{fakeNet: &fakeNet{}, block: make(chan struct{})}
	p, err := New(net, Config{Self: []sip.URI{selfURI}, Resolver: fakeResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	p.Receive(inboundFrom(invite(t), "up"))
	var a *sip.Request
	for a == nil {
		net.mu.Lock()
		if len(net.requests) > 0 {
			a = net.requests[0].req
		}
		net.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	var c *respContext
	p.mu.Lock()
	for _, x := range p.contexts {
		c = x
	}
	p.mu.Unlock()
	return p, net, a, c
}

func ok2xx(t *testing.T, req *sip.Request, tag string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, 200, "", tag)
	if err != nil {
		t.Fatal(err)
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

// From QA: a downstream that sends each 2xx with a new To tag cannot grow the
// upstream queue without bound either; past maxDialogsPerBranch dialogs a 2xx
// counts as a retransmission.
func TestA2xxFloodWithNewToTagsQueuedForASlowUpstreamIsBounded(t *testing.T) {
	p, net, a, c := startStalled(t)
	defer func() { close(net.block); p.Close() }()
	for i := range 20000 {
		p.Receive(inboundFrom(ok2xx(t, a, fmt.Sprintf("t%d", i)), "down"))
	}
	c.up.mu.Lock()
	queued := len(c.up.queue)
	c.up.mu.Unlock()
	// Each new dialog, the bounded retransmissions, and the release.
	if queued > maxDialogsPerBranch+maxQueuedProvisionals+1 {
		t.Errorf("%d responses queued for one slow upstream transaction", queued)
	}
}

// TestANewDialog2xxIsNeverDropped: however many retransmissions fill the
// upstream queue, a 2xx that starts another dialog is queued and goes up.
func TestANewDialog2xxIsNeverDropped(t *testing.T) {
	p, net, a, _ := startStalled(t)
	defer p.Close()
	for range 200 {
		p.Receive(inboundFrom(ok2xx(t, a, "first"), "down"))
	}
	p.Receive(inboundFrom(ok2xx(t, a, "second"), "down"))
	if p.Stats().RetransmissionsDropped == 0 {
		t.Fatal("the queue never filled")
	}
	close(net.block)
	p.wait()
	net.mu.Lock()
	defer net.mu.Unlock()
	seen := map[string]bool{}
	for _, res := range net.upstream {
		to, _ := res.Header.To()
		seen[to.Tag()] = true
	}
	if !seen["first"] || !seen["second"] {
		t.Errorf("dialogs upstream %v, want both", seen)
	}
}
