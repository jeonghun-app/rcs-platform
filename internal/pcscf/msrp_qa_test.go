package pcscf

// QA's tests on #315 (F1 to F5 and the gaps it measured), as QA wrote
// them.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// QA's round 3 tests are at the end: F6, F7 and the unanchored dialog's
// declined line.

// declinedAnswer is the client's answer to an offer whose MSRP line pcscf
// declined: the line at port 0.
var declinedAnswer = strings.Replace(clientAnswer, "m=message 9 ", "m=message 0 ", 1)

// F1a: two forks each send a reliable 183 with an offer to an offerless
// INVITE. b1's is anchored, b2's goes on declined. The client PRACKs b2
// first (its answer declines the line), then b1 with the real answer.
func TestQAForkPRACKOfOtherForkTakesTheAnchoredExchange(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "", "Supported: 100rel")
	for _, tag := range []string{"b1", "b2"} {
		e := answered(t, c.req, 183, tag, rcsAsOffer)
		_ = e.Header.Set("Require", "100rel")
		_ = e.Header.Set("RSeq", "1")
		c.respond(e)
	}
	pr2 := inCall(t, c, "PRACK", "b2", 2, declinedAnswer)
	if d := a.p.Route(context.Background(), pr2); len(d.Targets) == 1 {
		_ = d.Prepare(context.Background(), d.Targets[0], pr2.Message.Clone())
	}
	pr1 := inCall(t, c, "PRACK", "b1", 3, clientAnswer)
	d := a.p.Route(context.Background(), pr1)
	if len(d.Targets) != 1 {
		t.Fatalf("b1's PRACK with the real answer refused: status %d", d.Status)
	}
	fwd := pr1.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
	a.settle()
	if a.p.msrp.limit.held() != 1 || a.relay.count(http.MethodDelete) != 0 {
		t.Errorf("b1's binding: held %d calls %q", a.p.msrp.limit.held(), a.relay.log())
	}
}

// F1b: the same with two 2xx; the client ACKs b2 (declined) before b1.
func TestQAForkACKOfOtherForkTakesTheAnchoredExchange(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "")
	ok1 := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
	ok2 := c.respond(answered(t, c.req, 200, "b2", rcsAsOffer))
	ack2 := ackFor(t, c, ok2)
	_ = ack2.Message.Header.Set("Content-Type", "application/sdp")
	ack2.Message.Body = []byte(declinedAnswer)
	if d := a.p.Route(context.Background(), ack2); len(d.Targets) == 1 {
		_ = d.Prepare(context.Background(), d.Targets[0], ack2.Message.Clone())
	}
	a.settle()
	a.sent.take(a.p) // b2's two BYEs, as expected
	ack1 := ackFor(t, c, ok1)
	_ = ack1.Message.Header.Set("Content-Type", "application/sdp")
	ack1.Message.Body = []byte(clientAnswer)
	d := a.p.Route(context.Background(), ack1)
	if len(d.Targets) != 1 {
		t.Fatalf("b1's ACK with the real answer dropped: status %d", d.Status)
	}
	fwd := ack1.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
	a.settle()
	if a.p.msrp.limit.held() != 1 || a.relay.count(http.MethodDelete) != 0 {
		t.Errorf("b1's session: held %d calls %q", a.p.msrp.limit.held(), a.relay.log())
	}
}

// F2: an offerless re-INVITE whose ACK carries no answer (rcs-as goes on
// as it was, sipas/session.go:843-845). The next refresh must not be 491.
func TestQARefreshAfterAnACKWithoutAnswer(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", rcsAsOffer))
	a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 2, ""))
	next := reInvite(t, a, c, "UPDATE", 3, clientChatOffer)
	if next.d.Status != 0 {
		t.Errorf("next refresh with an offer: %d", next.d.Status)
	}
	// rcs-as answers the UPDATE before the next offer: one offer at a time
	// (RFC 3311 §5.2), as the developer changed this test.
	next.d.OnResponse(context.Background(), answered(t, next.req, 200, "b1", rcsAsAnswer))
	if next := reInvite(t, a, c, "INVITE", 4, ""); next.d.Status != 0 {
		t.Errorf("next offerless re-INVITE: %d", next.d.Status)
	}
}

// F3: rcs-as retransmits its refresh 2xx (ACK late), the client ACKs it
// again with the same answer: docs/pcscf.md says it is rewritten the same.
func TestQARetransmittedRefreshACKIsRewrittenTheSame(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	offer := strings.Replace(rcsAsOffer, "3913000002 3913000002", "3913000002 3913000003", 1)
	re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", offer))
	ack := inCall(t, c, "ACK", "b1", 2, clientAnswer)
	d := a.p.Route(context.Background(), ack)
	fwd := ack.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", offer))
	ack2 := inCall(t, c, "ACK", "b1", 2, clientAnswer)
	d = a.p.Route(context.Background(), ack2)
	if len(d.Targets) != 1 {
		t.Fatalf("the retransmitted ACK was dropped: status %d", d.Status)
	}
	fwd2 := ack2.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd2); err != nil || string(fwd2.Body) != string(fwd.Body) {
		t.Errorf("retransmitted ACK: %v\n%s", err, fwd2.Body)
	}
}

// F4: the client answers rcs-as's offer with an MSRP line of its own at an
// index the relay's offer declined: its path reaches rcs-as.
func TestQAClientAnswerToALineTheOfferDeclined(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, rcsAsOffer)
	ans := strings.Replace(clientAnswer, "m=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
		"m=message 9 TCP/TLS/MSRP *\r\na=path:msrps://192.0.2.10:9/leak1;tcp\r\na=setup:passive\r\n", 1)
	ok := c.respond(clientAnswered(t, c.req, 200, ans))
	if strings.Contains(string(ok.Body), "leak1") {
		t.Errorf("a client path reached rcs-as:\n%s", ok.Body)
	}
}

// QA decision 1 (part 2), initial: an offer in the 2xx to an offerless
// INVITE that the relay fails to anchor goes on declined, and the dialog
// ends with a 503 BYE once the ACK passes; nothing held.
func TestQAOfferIn2xxRelayFails(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	a.relay.fail = func(m string, _ int) int {
		if m == http.MethodPost {
			return 503
		}
		return 0
	}
	c := a.invite(t, "chat-1", "", "")
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
	mediaOf(t, ok.Body, "m=message 0 ")
	if privateAddr(ok.Body) != "" {
		t.Errorf("core address to client:\n%s", ok.Body)
	}
	ack := ackFor(t, c, ok)
	_ = ack.Message.Header.Set("Content-Type", "application/sdp")
	ack.Message.Body = []byte(declinedAnswer)
	d := a.p.Route(context.Background(), ack)
	t.Logf("ACK status %d targets %d", d.Status, len(d.Targets))
	a.settle()
	checkEnd(t, a, "b1", reasonRelayUnavailable)
	if a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
		t.Errorf("held %d sessions %d", a.p.msrp.limit.held(), len(a.p.msrp.all()))
	}
}

// QA decision 1 (part 2), refresh: rcs-as's 2xx to an offerless re-INVITE
// moves its path: a new binding (POST core_path), the client's answer in
// the ACK PATCHes it, and the old binding goes. With the relay failing,
// the offer goes on declined and the session ends with a 503 BYE.
func TestQARefreshOfferInResponseMovesThePath(t *testing.T) {
	moved := strings.Replace(rcsAsOffer, "as9f2c1", "moved7", 1)
	for _, failing := range []bool{false, true} {
		a := newAnchoring(t, 16, 100)
		c := confirmedChat(t, a)
		if failing {
			a.relay.fail = func(m string, _ int) int {
				if m == http.MethodPost {
					return 503
				}
				return 0
			}
		}
		re := reInvite(t, a, c, "INVITE", 2, "")
		ok := answered(t, re.req, 200, "b1", moved)
		re.d.OnResponse(context.Background(), ok)
		if failing {
			mediaOf(t, ok.Body, "m=message 0 ")
		} else {
			mediaOf(t, ok.Body, "a=path:"+clientPathFor(2))
		}
		ackBody := clientAnswer
		if failing {
			ackBody = declinedAnswer
		}
		ack := inCall(t, c, "ACK", "b1", 2, ackBody)
		d := a.p.Route(context.Background(), ack)
		if len(d.Targets) == 1 {
			fwd := ack.Message.Clone()
			_ = d.Prepare(context.Background(), d.Targets[0], fwd)
			if !failing {
				mediaOf(t, fwd.Body, "a=path:"+corePathFor(2))
			}
		} else {
			t.Logf("failing=%v ACK status %d", failing, d.Status)
		}
		a.settle()
		calls := a.relay.log()
		t.Logf("failing=%v calls %q held %d", failing, calls, a.p.msrp.limit.held())
		if failing {
			checkEndSeq(t, a, "b1", reasonRelayUnavailable, "3 BYE")
			if a.p.msrp.limit.held() != 0 {
				t.Errorf("held %d", a.p.msrp.limit.held())
			}
			continue
		}
		if a.relay.count(http.MethodPost) != 2 || calls[len(calls)-1] != "DELETE /v1/bindings/"+bindingIDFor(1) || a.p.msrp.limit.held() != 1 {
			t.Errorf("moved: calls %q held %d", calls, a.p.msrp.limit.held())
		}
		if len(a.sent.take(a.p)) != 0 {
			t.Errorf("ended")
		}
	}
}

// QA: a moved-path refresh offer in a request when the relay fails: the
// re-INVITE is 503 with Retry-After and the old binding stays.
func TestQAMovedRefreshWithRelayFailing(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	a.relay.fail = func(m string, _ int) int {
		if m == http.MethodPost {
			return 503
		}
		return 0
	}
	r := inCall(t, c, "INVITE", "b1", 2, strings.Replace(clientChatOffer, "s7d2k8f", "m0v3d9x", 1))
	d := a.p.Route(context.Background(), r)
	req := r.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], req); err == nil {
		t.Fatal("anchored")
	}
	res, _ := sip.NewResponse(r.Message, 500, "", "")
	d.OnFinal(context.Background(), res)
	d.OnResponse(context.Background(), res)
	a.settle()
	if res.StatusCode != 503 || res.Header.Get("Retry-After") == "" || a.p.msrp.limit.held() != 1 || a.relay.count(http.MethodDelete) != 0 {
		t.Errorf("%d %q held %d calls %q", res.StatusCode, res.Header.Get("Retry-After"), a.p.msrp.limit.held(), a.relay.log())
	}
	// The session is still usable: a refresh that keeps the path.
	a.relay.fail = nil
	re := reInvite(t, a, c, "UPDATE", 3, clientChatOffer)
	if re.req == nil {
		t.Fatalf("next refresh: %d", re.d.Status)
	}
}

// QA: a 2xx to a refresh offer with no answer at all ends the session (503
// BYE after ACK) and returns the fresh binding.
func TestQARefresh2xxWithoutAnswer(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, strings.Replace(clientChatOffer, "s7d2k8f", "m0v3d9x", 1))
	res := answered(t, re.req, 200, "b1", "")
	re.d.OnResponse(context.Background(), res)
	a.settle()
	a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 2, ""))
	checkEndSeq(t, a, "b1", reasonRelayUnavailable, "3 BYE")
	if a.p.msrp.limit.held() != 0 {
		t.Errorf("held %d", a.p.msrp.limit.held())
	}
}

// QA AC 5 for sessions rcs-as starts: non-2xx final, CANCEL (487), flow
// loss during ringing and after, and a setup no final response ended.
func TestQATerminatingReleases(t *testing.T) {
	for _, tc := range []string{"486", "487", "flow-ringing", "flow-confirmed", "stale", "bye-from-core"} {
		a := newAnchoring(t, 16, 100)
		c := a.coreInvite(t, rcsAsOffer)
		if a.p.msrp.limit.held() != 1 {
			t.Fatalf("%s: held %d", tc, a.p.msrp.limit.held())
		}
		switch tc {
		case "486", "487":
			code := 486
			if tc == "487" {
				code = 487
			}
			c.respond(clientAnswered(t, c.req, 180, ""))
			c.respond(clientAnswered(t, c.req, code, ""))
		case "flow-ringing":
			c.respond(clientAnswered(t, c.req, 180, ""))
			a.p.msrpFlowClosed("FLOW-A")
		case "flow-confirmed":
			c.respond(clientAnswered(t, c.req, 200, clientAnswer))
			a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
			a.p.msrpFlowClosed("FLOW-A")
		case "stale":
			c.respond(clientAnswered(t, c.req, 180, ""))
			a.clock.t = a.clock.t.Add(maxSetupTime + time.Second)
			a.p.sweepMSRP()
		case "bye-from-core":
			c.respond(clientAnswered(t, c.req, 200, clientAnswer))
			a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
			a.p.Route(context.Background(), fromCoreInCall(t, a, c, "BYE", "b1", 2, ""))
		}
		a.settle()
		if a.p.msrp.limit.held() != 0 || a.relay.count(http.MethodDelete) != 1 || len(a.p.msrp.all()) != 0 {
			t.Errorf("%s: held %d calls %q sessions %d", tc, a.p.msrp.limit.held(), a.relay.log(), len(a.p.msrp.all()))
		}
	}
}

// QA: rcs-as's INVITE without an offer: the client's offer in the 2xx is
// anchored (client_endpoint_path), rcs-as's answer in the ACK completes
// it (core_path).
func TestQACoreOfferlessInvite(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, "")
	ok := c.respond(clientAnswered(t, c.req, 200, clientChatOffer))
	mediaOf(t, ok.Body, "a=path:"+corePathFor(1))
	mediaOf(t, ok.Body, "a=setup:active")
	ack := fromCoreInCall(t, a, c, "ACK", "b1", 1, rcsAsAnswer)
	d := a.p.Route(context.Background(), ack)
	if len(d.Targets) != 1 {
		t.Fatalf("ACK %d", d.Status)
	}
	fwd := ack.Message.Clone()
	_ = d.Prepare(context.Background(), d.Targets[0], fwd)
	mediaOf(t, fwd.Body, "a=path:"+clientPathFor(1))
	mediaOf(t, fwd.Body, "a=setup:passive")
	if privateAddr(fwd.Body) != "" {
		t.Errorf("core address:\n%s", fwd.Body)
	}
	a.settle()
	if a.relay.count(http.MethodPatch) != 1 || fmt.Sprint(a.relay.bodies[1]["core_path"]) != "[msrp://10.0.1.20:2855/as9f2c1;tcp]" || len(a.sent.take(a.p)) != 0 {
		t.Errorf("calls %q %v", a.relay.log(), a.relay.bodies)
	}
}

// QA: a session rcs-as set up, refreshed by the client with an offer
// (re-INVITE and UPDATE), keeps the binding both ways; then an offerless
// re-INVITE from the client gets rcs-as's offer again.
func TestQATerminatingSessionClientRefreshes(t *testing.T) {
	for _, method := range []string{"INVITE", "UPDATE"} {
		a := newAnchoring(t, 16, 100)
		c := a.coreInvite(t, rcsAsOffer)
		c.respond(clientAnswered(t, c.req, 200, clientAnswer))
		a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
		calls := len(a.relay.log())
		// alice's refresh, From tag a1, To tag b1.
		r := inCall(t, c, method, "b1", 2, clientAnswer)
		_ = r.Message.Header.Set("From", "<"+aliceIMPU+">;tag=a1")
		d := a.p.Route(context.Background(), r)
		if len(d.Targets) != 1 {
			t.Fatalf("%s refresh refused: %d", method, d.Status)
		}
		req := r.Message.Clone()
		if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
			t.Fatal(err)
		}
		mediaOf(t, req.Body, "a=path:"+corePathFor(1))
		res := answered(t, req, 200, "b1", rcsAsAnswer)
		d.OnResponse(context.Background(), res)
		mediaOf(t, res.Body, "a=path:"+clientPathFor(1))
		a.settle()
		if len(a.relay.log()) != calls || a.p.msrp.limit.held() != 1 || len(a.sent.take(a.p)) != 0 {
			t.Errorf("%s: calls %q held %d", method, a.relay.log(), a.p.msrp.limit.held())
		}
		if method == "INVITE" {
			ack := inCall(t, c, "ACK", "b1", 2, "")
			_ = ack.Message.Header.Set("From", "<"+aliceIMPU+">;tag=a1")
			a.p.Route(context.Background(), ack)
			// offerless re-INVITE
			r := inCall(t, c, "INVITE", "b1", 3, "")
			_ = r.Message.Header.Set("From", "<"+aliceIMPU+">;tag=a1")
			d := a.p.Route(context.Background(), r)
			if len(d.Targets) != 1 {
				t.Fatalf("offerless refused: %d", d.Status)
			}
			req := r.Message.Clone()
			_ = d.Prepare(context.Background(), d.Targets[0], req)
			ok := answered(t, req, 200, "b1", rcsAsOffer)
			d.OnResponse(context.Background(), ok)
			mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
			mediaOf(t, ok.Body, "a=setup:actpass")
			ack = inCall(t, c, "ACK", "b1", 3, clientAnswer)
			_ = ack.Message.Header.Set("From", "<"+aliceIMPU+">;tag=a1")
			d = a.p.Route(context.Background(), ack)
			if len(d.Targets) != 1 {
				t.Fatalf("ACK dropped %d", d.Status)
			}
			fwd := ack.Message.Clone()
			_ = d.Prepare(context.Background(), d.Targets[0], fwd)
			mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
			a.settle()
			if len(a.relay.log()) != calls || len(a.sent.take(a.p)) != 0 {
				t.Errorf("offerless: calls %q", a.relay.log())
			}
		}
	}
}

// QA kill M1/M11: another fork's 2xx with the same offer goes on declined
// and is ended; before the first is confirmed (b1 in a reliable 183) it
// also releases the bindings.
func TestQAOtherForksOfferIn2xx(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "", "Supported: 100rel")
	e := answered(t, c.req, 183, "b1", rcsAsOffer)
	_ = e.Header.Set("Require", "100rel")
	_ = e.Header.Set("RSeq", "1")
	c.respond(e)
	ok2 := c.respond(answered(t, c.req, 200, "b2", rcsAsOffer))
	mediaOf(t, ok2.Body, "m=message 0 ")
	if strings.Contains(string(ok2.Body), clientPathFor(1)) {
		t.Errorf("fork b2 got b1's relay path")
	}
	a.settle()
	if a.p.msrp.limit.held() != 0 {
		t.Errorf("b1's early bindings held %d after b2's 2xx", a.p.msrp.limit.held())
	}
}

// QA kill M13: rcs-as's refresh offer pcscf refuses ends the session only
// once the ACK has passed.
func TestQARefusedRefreshOfferWaitsForTheACK(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	ok := answered(t, re.req, 200, "b1", strings.Replace(rcsAsOffer, "a=setup:actpass", "a=setup:active", 1))
	re.d.OnResponse(context.Background(), ok)
	a.settle()
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Fatalf("ended before the ACK: %d", len(got))
	}
}

// QA kill M14: an offerless re-INVITE whose reliable 183 offer was anchored
// and whose final is a failure gives the exchange up: the next refresh is
// not 491.
func TestQAFailedOfferlessReInviteGivesTheExchangeUp(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	e := answered(t, re.req, 183, "b1", rcsAsOffer)
	_ = e.Header.Set("Require", "100rel")
	_ = e.Header.Set("RSeq", "1")
	re.d.OnResponse(context.Background(), e)
	mediaOf(t, e.Body, "a=path:"+clientPathFor(1))
	re.d.OnResponse(context.Background(), answered(t, re.req, 500, "b1", ""))
	if next := reInvite(t, a, c, "UPDATE", 3, clientChatOffer); next.d.Status != 0 {
		t.Errorf("next refresh: %d", next.d.Status)
	}
}

// QA kill M6/M20: in an offerless re-INVITE, an unreliable 1xx offer is
// declined, and a later different offer after the anchored one is
// declined.
func TestQAOfferlessReInviteOtherOffersDeclined(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	p := answered(t, re.req, 183, "b1", rcsAsOffer)
	re.d.OnResponse(context.Background(), p)
	mediaOf(t, p.Body, "m=message 0 ")
	ok := answered(t, re.req, 200, "b1", rcsAsOffer)
	re.d.OnResponse(context.Background(), ok)
	mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
	other := answered(t, re.req, 200, "b1", strings.Replace(rcsAsOffer, "3913000002 3913000002", "3913000002 3913000009", 1))
	re.d.OnResponse(context.Background(), other)
	mediaOf(t, other.Body, "m=message 0 ")
}

// QA: with #293 merged, rcs-as's MSRP INVITE ringing toward a client whose
// flow closes: the core gets 430 at once, and the binding is released.
func TestQAE2ETerminatingMSRPInviteFlowCloses(t *testing.T) {
	for i := 0; i < 5; i++ {
		relay := &scriptedRelay{bodies: map[int]map[string]any{}}
		srv := httptest.NewServer(relay)
		t.Cleanup(srv.Close)
		icscf := startCoreNode(t, echo200)
		cfg := testConfig()
		cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
		cfg.RelayURL, _ = url.Parse(srv.URL)
		cfg.RelayToken = relayToken{testRelayToken}
		cfg.RelayTimeout = 5 * time.Second
		var pc *pcscf
		s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }})
		c, path := registered(t, s, icscf)
		core := dial(t, s.core, nil)
		inv := coreRequest("INVITE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("qa-msrp-%d", requests.Add(1)), "", 1, "Route: <"+path+">")
		inv = strings.Replace(inv, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(rcsAsOffer), rcsAsOffer), 1)
		core.write(inv)
		got := c.nextRequest()
		if !strings.Contains(string(got.Body), "a=setup:actpass") || !strings.Contains(string(got.Body), clientPathFor(1)) {
			t.Fatalf("offer to the client:\n%s", got.Body)
		}
		_ = c.nc.Close()
		// 430 only comes from the flow's close (see finalWithin).
		if code, err := finalWithin(core); err != nil || code != 430 {
			t.Errorf("%d (%v), want 430", code, err)
		}
		deadline := time.Now().Add(waitFor)
		for time.Now().Before(deadline) {
			pc.msrp.wait()
			if pc.msrp.limit.held() == 0 && len(pc.msrp.all()) == 0 && relay.count(http.MethodDelete) == 1 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if pc.msrp.limit.held() != 0 || len(pc.msrp.all()) != 0 || relay.count(http.MethodDelete) != 1 {
			t.Errorf("held %d sessions %d calls %q", pc.msrp.limit.held(), len(pc.msrp.all()), relay.log())
		}
	}
}

// R3-5 (F6): a PRACK without a description that acknowledges another
// reliable 1xx than the one with the offer (an earlier 180, RSeq 1; or the
// right RSeq with another CSeq) gives nothing up: the offer's own PRACK then
// carries the answer and is anchored.
func TestQAR3PRACKOfAnotherReliableResponseGivesNothingUp(t *testing.T) {
	for _, rack := range []string{"1 1 INVITE", "2 9 INVITE"} {
		a := newAnchoring(t, 16, 100)
		c := a.invite(t, "chat-1", "", "", "Supported: 100rel")
		e := answered(t, c.req, 183, "b1", rcsAsOffer)
		_ = e.Header.Set("Require", "100rel")
		_ = e.Header.Set("RSeq", "2")
		e = c.respond(e)
		mediaOf(t, e.Body, "a=path:"+clientPathFor(1))
		other := inCall(t, c, "PRACK", "b1", 2, "")
		_ = other.Message.Header.Set("RAck", rack)
		a.p.Route(context.Background(), other)
		pr := inCall(t, c, "PRACK", "b1", 3, clientAnswer)
		_ = pr.Message.Header.Set("RAck", "2 1 INVITE")
		d := a.p.Route(context.Background(), pr)
		if len(d.Targets) != 1 {
			t.Errorf("RAck %q: the offer's PRACK refused: %d", rack, d.Status)
			continue
		}
		fwd := pr.Message.Clone()
		_ = d.Prepare(context.Background(), d.Targets[0], fwd)
		mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
		a.settle()
		if a.p.msrp.limit.held() != 1 || a.relay.count(http.MethodDelete) != 0 {
			t.Errorf("RAck %q: held %d calls %q", rack, a.p.msrp.limit.held(), a.relay.log())
		}
	}
}

// R3-6 (F7): run applies PCSCF_MAX_CORE_OFFER_BINDINGS_PER_FLOW: with 1,
// rcs-as's second chat toward alice is 503 while her own chat is still
// anchored.
func TestQAR3RunAppliesTheCoreOfferShare(t *testing.T) {
	relay := &scriptedRelay{bodies: map[int]map[string]any{}}
	srv := httptest.NewServer(relay)
	t.Cleanup(srv.Close)
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.RelayURL, _ = url.Parse(srv.URL)
	cfg.RelayToken = relayToken{testRelayToken}
	cfg.RelayTimeout = 5 * time.Second
	cfg.MaxCoreOfferBindingsPerFlow = 1
	var pc *pcscf
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }})
	_, path := registered(t, s, icscf)
	core := dial(t, s.core, nil)
	codes := []int{}
	for i := 0; i < 2; i++ {
		inv := coreRequest("INVITE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("qa-share-%d", requests.Add(1)), "", 1, "Route: <"+path+">")
		inv = strings.Replace(inv, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(rcsAsOffer), rcsAsOffer), 1)
		core.write(inv)
	}
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		pc.msrp.wait()
		if relay.count(http.MethodPost) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = core.nc.SetDeadline(time.Now().Add(10 * time.Second))
	for len(codes) < 1 {
		m, err := core.r.ReadMessage()
		if err != nil {
			break
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			codes = append(codes, res.StatusCode)
		}
	}
	if len(codes) != 1 || codes[0] != 503 || relay.count(http.MethodPost) != 1 {
		t.Errorf("finals %v, POSTs %d", codes, relay.count(http.MethodPost))
	}
}

// R3-4: in a dialog pcscf does not anchor, a client's UPDATE whose MSRP
// line is declined (port 0) carries no a=path to the core (QA round 3's
// probe, made an assertion with the fix).
func TestQAR3UnanchoredDialogDeclinedLineKeepsNoPath(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	audio := strings.Split(clientChatOffer, "m=message")[0]
	c := a.invite(t, "call-1", "application/sdp", audio)
	c.respond(answered(t, c.req, 200, "b1", strings.Split(rcsAsAnswer, "m=message")[0]))
	r := inCall(t, c, "UPDATE", "b1", 2, strings.Replace(clientChatOffer, "m=message 9 ", "m=message 0 ", 1))
	d := a.p.Route(context.Background(), r)
	if len(d.Targets) != 1 {
		t.Fatalf("status %d", d.Status)
	}
	fwd := r.Message.Clone()
	if d.Prepare != nil {
		_ = d.Prepare(context.Background(), d.Targets[0], fwd)
	}
	if strings.Contains(string(fwd.Body), "s7d2k8f") || !strings.Contains(string(fwd.Body), "m=message 0 ") {
		t.Errorf("client path reaches the core in an unanchored dialog:\n%s", fwd.Body)
	}
}
