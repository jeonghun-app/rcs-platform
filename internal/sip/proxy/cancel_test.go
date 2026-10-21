package proxy

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const t1 = 500 * time.Millisecond

func TestAnUpstreamCancelIsAnswered200AndCancelsEveryPendingBranch(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	inv := invite(t)
	h.receive(inv)
	sent := h.sent()
	a := byURI(t, sent, "INVITE", "sip:a@192.0.2.1")
	b := byURI(t, sent, "INVITE", "sip:b@192.0.2.2")
	h.reply(a, 180)

	h.receive(uacCancel(t, inv))
	check(t, "upstream", labels(h.upstreamResponses()), []string{"180 INVITE", "200 CANCEL"})
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:a@192.0.2.1"})

	// b is cancelled once it shows it has the INVITE (§9.1).
	h.reply(b, 100)
	cancels := h.sent()
	check(t, "sent after b's 100", methodsOf(cancels), []string{"CANCEL sip:b@192.0.2.2"})
	checkCancelMatches(t, cancels[0].req, b)

	h.reply(a, 487)
	h.reply(b, 487)
	check(t, "upstream", labels(h.upstreamResponses()), []string{"487 INVITE"})
}

// checkCancelMatches checks a CANCEL against the INVITE it cancels (§9.1).
func checkCancelMatches(t *testing.T, cancel, inv *sip.Request) {
	t.Helper()
	if cancel.URI.String() != inv.URI.String() {
		t.Errorf("CANCEL Request-URI = %s, want %s", cancel.URI.String(), inv.URI.String())
	}
	if topBranch(t, cancel) != topBranch(t, inv) {
		t.Error("CANCEL branch differs from the INVITE's")
	}
	if n := len(cancel.Header.Values("Via")); n != 1 {
		t.Errorf("CANCEL has %d Via fields, want only the proxy's", n)
	}
	for _, name := range []string{"From", "To", "Call-ID"} {
		if cancel.Header.Get(name) != inv.Header.Get(name) {
			t.Errorf("CANCEL %s = %q, want %q", name, cancel.Header.Get(name), inv.Header.Get(name))
		}
	}
	cc, _ := cancel.Header.CSeq()
	ic, _ := inv.Header.CSeq()
	if cc.Seq != ic.Seq || cc.Method != "CANCEL" {
		t.Errorf("CANCEL CSeq = %v, want %d CANCEL", cc, ic.Seq)
	}
	check(t, "CANCEL Route", cancel.Header.Values("Route"), inv.Header.Values("Route"))
}

func TestACancelCarriesTheRouteOfItsInvite(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:a@192.0.2.1"), Routes: []sip.Address{mustAddr("<sip:edge.example.net;lr>")}}}})
	inv := invite(t)
	h.receive(inv)
	a := h.one()
	h.reply(a, 180)
	h.receive(uacCancel(t, inv))
	checkCancelMatches(t, h.one(), a)
}

func TestACancelMatchingNoInviteIsAnswered481(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(uacCancel(t, invite(t)))
	check(t, "upstream", labels(h.upstreamResponses()), []string{"481 CANCEL"})
	check(t, "sent", h.sentMethods(), nil)
}

func TestACancelAfterTheFinalResponseIsAnswered200AndChangesNothing(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	h.receive(inv)
	h.reply(h.one(), 486)
	h.sent()
	h.receive(uacCancel(t, inv))
	check(t, "upstream", labels(h.upstreamResponses()), []string{"486 INVITE", "200 CANCEL"})
	check(t, "sent", h.sentMethods(), nil)
}

func TestACancelWhileTheRouterRunsAnswers487AndForwardsNothing(t *testing.T) {
	h := newHarness(t, Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	h.route(func(_ contextT, r *Request) Decision {
		close(entered)
		<-release
		return Forward(r)
	})
	inv := invite(t)
	h.p.Receive(inboundFrom(inv, "up"))
	<-entered
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	close(release)
	h.settle()
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 CANCEL", "487 INVITE"})
	check(t, "sent", h.sentMethods(), nil)
}

// #361: a CANCEL that comes while a branch's Prepare runs is answered 200
// only once the request counts as cancelled, so that the branch, prepared
// once the client has its 200, is never sent: the INVITE gets its 487 at
// once, not after a downstream that may never send a provisional, which a
// CANCEL waits for (§9.1), runs out Timer B (§16.10). Prepare returns from
// the 200's send, the earliest the client can have it, and the 200 waits
// for the branch to be sent or dropped. The 487 may come before the 200:
// they are two transactions, which RFC 3261 does not order.
func TestACancelDuringPrepareIsAnswered200OnlyOnceTheRequestIsCancelled(t *testing.T) {
	h := newHarness(t, Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.route(func(_ contextT, r *Request) Decision {
		d := Forward(r)
		d.Prepare = func(contextT, Target, *sip.Request) error {
			once.Do(func() { close(entered) })
			<-release
			return nil
		}
		return d
	})
	var cancelledFirst []bool
	h.net.mu.Lock()
	h.net.onResponse = func(res *sip.Response) {
		if cseq, _ := res.Header.CSeq(); res.StatusCode != 200 || cseq.Method != "CANCEL" {
			return
		}
		h.p.mu.Lock()
		var ctxs []*respContext
		for _, c := range h.p.contexts {
			ctxs = append(ctxs, c)
		}
		h.p.mu.Unlock()
		for _, c := range ctxs {
			c.mu.Lock()
			cancelledFirst = append(cancelledFirst, c.cancelled && c.closed)
			c.mu.Unlock()
		}
		// Prepare returns, and the 200 waits until the branch has decided,
		// sent or not: whatever the proxy does after the 200 cannot help it.
		close(release)
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			sent := 0
			h.net.mu.Lock()
			sent = len(h.net.requests)
			h.net.mu.Unlock()
			ctxs[0].mu.Lock()
			decided := ctxs[0].pending == 0
			ctxs[0].mu.Unlock()
			if sent > 0 || decided {
				return
			}
		}
		t.Error("the branch never decided")
	}
	h.net.mu.Unlock()
	inv := invite(t)
	h.p.Receive(inboundFrom(inv, "up"))
	<-entered
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	h.settle()
	check(t, "cancelled before the 200", cancelledFirst, []bool{true})
	check(t, "sent", h.sentMethods(), nil)
	got := labels(h.upstreamResponses())
	slices.Sort(got)
	check(t, "upstream", got, []string{"200 CANCEL", "487 INVITE"})
}

// TestACancelWhileTheInviteIsBeingSentWaitsForItsProvisional holds the branch
// in its send while the CANCEL arrives: the INVITE still goes, and is cancelled
// once it is known to have arrived.
func TestACancelWhileTheInviteIsBeingSentWaitsForItsProvisional(t *testing.T) {
	h := newHarness(t, Config{})
	entered, release := h.net.holdSends(func(r *sip.Request) bool { return r.Method == "INVITE" })
	defer release()
	inv := invite(t)
	h.p.Receive(inboundFrom(inv, "up"))
	<-entered
	h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
	release()
	h.settle()
	a := h.one()
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 CANCEL"})

	h.reply(a, 180)
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@example.com"})
	// Until a final response is sent, provisional ones still go upstream
	// (§16.7 step 5), CANCEL or not.
	check(t, "upstream", h.upstream(), codes(180))
	h.reply(a, 487)
	check(t, "upstream", labels(h.upstreamResponses()), []string{"487 INVITE"})
}

// TestACancelRacingA2xxNeverYieldsTwoFinals delivers an upstream CANCEL and a
// downstream 200 at once, many times: whichever wins, the UAC gets the 2xx and
// no 487.
func TestACancelRacingA2xxNeverYieldsTwoFinals(t *testing.T) {
	for range 50 {
		h := newHarness(t, Config{})
		inv := invite(t)
		h.receive(inv)
		a := h.one()
		h.reply(a, 180)
		h.upstream()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			h.p.Receive(inboundFrom(uacCancel(t, inv), "up"))
		}()
		go func() {
			defer wg.Done()
			h.p.Receive(inboundFrom(responseTo(t, a, 200), "down"))
		}()
		wg.Wait()
		h.settle()
		var finals []string
		for _, l := range labels(h.upstreamResponses()) {
			if l != "200 CANCEL" {
				finals = append(finals, l)
			}
		}
		check(t, "INVITE finals", finals, []string{"200 INVITE"})
		h.p.Close()
	}
}

func TestAnUnansweredCancelEndsTheBranchAfter64T1(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	h.receive(inv)
	a := h.one()
	h.reply(a, 180)
	h.receive(uacCancel(t, inv))
	h.sent()
	h.upstream()
	h.advance(64*t1 - time.Millisecond)
	check(t, "upstream before 64*T1", h.upstream(), nil)
	h.advance(time.Millisecond)
	check(t, "upstream", h.upstream(), codes(487))
	if n := h.p.Stats().Contexts; n != 0 {
		t.Errorf("Contexts = %d, want 0", n)
	}
}

func TestTimerCCancelsABranchThatHadAProvisional(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	a := h.one()
	h.reply(a, 180)
	h.advance(DefaultTimerC - time.Millisecond)
	check(t, "sent before Timer C", h.sentMethods(), nil)
	h.advance(time.Millisecond)
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@example.com"})
	h.reply(a, 487)
	check(t, "upstream", h.upstream(), codes(180, 487))
	if n := h.p.Stats().TimerC; n != 1 {
		t.Errorf("TimerC = %d, want 1", n)
	}
}

func TestEveryProvisionalButA100RestartsTimerC(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	a := h.one()
	h.reply(a, 180)
	h.advance(170 * time.Second)
	h.reply(a, 183)
	h.advance(170 * time.Second)
	check(t, "sent 170 s after the 183", h.sentMethods(), nil)
	h.reply(a, 100)
	h.advance(11 * time.Second)
	check(t, "sent", h.sentMethods(), []string{"CANCEL sip:bob@example.com"})
}

func TestTimerCWithoutAProvisionalCountsAs408(t *testing.T) {
	// T1 long enough for Timer B (64*T1) to come after Timer C.
	h := newHarness(t, Config{Transaction: transactionConfig(4 * time.Second)})
	h.receive(invite(t))
	h.one()
	h.advance(DefaultTimerC)
	check(t, "sent", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(100, 408))
}

func TestTimerCRunsOnlyForInvite(t *testing.T) {
	h := newHarness(t, Config{Transaction: transactionConfig(4 * time.Second)})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.reply(h.one(), 100)
	h.advance(DefaultTimerC)
	if n := h.p.Stats().TimerC; n != 0 {
		t.Errorf("TimerC fired %d times for a MESSAGE", n)
	}
}

func TestTimerCMustExceedThreeMinutes(t *testing.T) {
	if _, err := New(&fakeNet{}, Config{TimerC: 3 * time.Minute}); err == nil {
		t.Error("New accepted a Timer C of 3 minutes")
	}
}

func TestACancelledBranchThatNeverAnswersCountsAs487(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	h.receive(inv)
	h.one()
	h.receive(uacCancel(t, inv))
	// No provisional, so no CANCEL was sent; Timer B ends the branch.
	check(t, "sent", h.sentMethods(), nil)
	h.advance(64 * t1)
	// The 100 is the server transaction's own, 200 ms after the INVITE.
	check(t, "upstream", labels(h.upstreamResponses()), []string{"200 CANCEL", "100 INVITE", "487 INVITE"})
}

// TestACancelFollowsItsInviteOntoTCP has the transport move the INVITE from UDP
// to TCP: the CANCEL must reach the same server transaction, so it goes the
// same way, with the Via the transport wrote.
func TestACancelFollowsItsInviteOntoTCP(t *testing.T) {
	h := newHarness(t, Config{Resolver: NumericResolver{}})
	h.net.moveToTCP = true
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.30")}})
	inv := invite(t)
	h.receive(inv)
	sent := h.sent()
	if len(sent) != 1 || sent[0].dst.Network != transport.TCP {
		t.Fatalf("sent %v", methodsOf(sent))
	}
	h.reply(sent[0].req, 180)
	h.receive(uacCancel(t, inv))
	cancels := h.sent()
	if len(cancels) != 1 || cancels[0].dst.Network != transport.TCP {
		t.Fatalf("CANCEL sent %v over %v, want TCP", methodsOf(cancels), cancels)
	}
	checkCancelMatches(t, cancels[0].req, sent[0].req)
	if got := cancels[0].req.Header.Get("Via"); got != sent[0].req.Header.Values("Via")[0] {
		t.Errorf("CANCEL Via = %q, want the INVITE's %q", got, sent[0].req.Header.Values("Via")[0])
	}
}
