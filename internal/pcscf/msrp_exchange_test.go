package pcscf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// rcsAsOffer is rcs-as's offer of a chat it sets up, actpass on its MSRP
// port (ADR 0004, second row), and clientAnswer the client's answer to the
// relay's offer, active.
var (
	rcsAsOffer   = strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:actpass", 1)
	clientAnswer = strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:active", 1)
)

// coreInvite is rcs-as's INVITE through scscf to alice over FLOW-A, with
// body as its offer if any, and its decision; req is the INVITE as it went
// to the client.
func (a *anchoring) coreInvite(t *testing.T, body string) call {
	t.Helper()
	c, err := a.coreInviteIn(t, "", body)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// coreInviteIn is coreInvite with Call-ID callID, unless empty; it returns
// the error of a decision that does not forward the INVITE or whose
// Prepare fails.
func (a *anchoring) coreInviteIn(t *testing.T, callID, body string) (call, error) {
	t.Helper()
	r := fromCore(t, "INVITE", false, []string{pathEntry}, "Contact: <sip:rcs-as@10.0.1.20:5060;transport=tcp>",
		"Record-Route: <sip:scscf.rcs.internal;transport=tcp;lr>", "P-Called-Party-ID: <"+aliceIMPU+">")
	if callID != "" {
		_ = r.Message.Header.Set("Call-ID", callID)
	}
	if body != "" {
		_ = r.Message.Header.Set("Content-Type", "application/sdp")
		r.Message.Body = []byte(body)
	}
	d := a.p.Route(context.Background(), r)
	if len(d.Targets) != 1 {
		return call{r: r, d: d}, fmt.Errorf("not forwarded: %+v", d)
	}
	req := r.Message.Clone()
	for i := len(d.RecordRoute) - 1; i >= 0; i-- {
		_ = req.Header.Prepend("Record-Route", d.RecordRoute[i].String())
	}
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		return call{r: r, d: d}, fmt.Errorf("Prepare: %w", err)
	}
	return call{r: r, d: d, req: req}, nil
}

// clientAnswered is alice's response with code to req, with tag a1, her
// Contact, req's Record-Route and body as its description if any.
func clientAnswered(t *testing.T, req *sip.Request, code int, body string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", "a1")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Header.Add("Contact", "<"+aliceContact+">")
	for _, v := range req.Header.Values("Record-Route") {
		_ = res.Header.Add("Record-Route", v)
	}
	if body != "" {
		_ = res.Header.Set("Content-Type", "application/sdp")
		res.Body = []byte(body)
	}
	return res
}

// checkEndOfCoreSession checks the two BYEs that end a dialog rcs-as set
// up: one to the client over its flow, as from rcs-as, and one to the core
// along the INVITE's Record-Route, as from the client; both with reason.
func checkEndOfCoreSession(t *testing.T, a *anchoring, reason string) {
	t.Helper()
	sent := a.sent.take(a.p)
	if len(sent) != 2 {
		t.Fatalf("%d requests sent, want two BYEs", len(sent))
	}
	for _, s := range sent {
		f, _ := s.req.Header.From()
		to, _ := s.req.Header.To()
		if s.req.Method != "BYE" || s.req.Header.Get("Reason") != reason {
			t.Errorf("%s with Reason %q", s.req.Method, s.req.Header.Get("Reason"))
		}
		if s.dst.Flow == "FLOW-A" {
			if s.req.URI.String() != aliceContact || f.Tag() != "b1" || to.Tag() != "a1" || s.req.Header.Has("Route") {
				t.Errorf("BYE to the client: %s From %q To %q Route %q", s.req.URI, s.req.Header.Get("From"), s.req.Header.Get("To"), s.req.Header.Values("Route"))
			}
			continue
		}
		if s.req.URI.String() != "sip:rcs-as@10.0.1.20:5060;transport=tcp" || f.Tag() != "a1" || to.Tag() != "b1" ||
			strings.Join(s.req.Header.Values("Route"), ",") != "<sip:scscf.rcs.internal;transport=tcp;lr>" || s.dst.Addr != netip.MustParseAddrPort("10.0.4.4:5060") {
			t.Errorf("BYE to the core: %s From %q To %q Route %q to %+v", s.req.URI, s.req.Header.Get("From"), s.req.Header.Get("To"), s.req.Header.Values("Route"), s.dst)
		}
	}
}

// A chat rcs-as sets up is anchored (ADR 0004, second row): a binding for
// rcs-as's path, the offer to the client with the relay's client path,
// actpass, and nothing of the core; the client's answer, active, completes
// the binding, and rcs-as gets the relay's core-side path, active, so that
// the relay connects to it. The client's BYE releases the binding.
func TestARcsAsChatIsAnchoredThroughTheRelay(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, rcsAsOffer)
	if calls := a.relay.log(); len(calls) != 1 || fmt.Sprint(a.relay.bodies[0]["core_path"]) != "[msrp://10.0.1.20:2855/as9f2c1;tcp]" {
		t.Fatalf("relay calls %q %v", calls, a.relay.bodies)
	}
	mediaOf(t, c.req.Body, "a=path:"+clientPathFor(1))
	mediaOf(t, c.req.Body, "a=setup:actpass")
	mediaOf(t, c.req.Body, "c=IN IP4 msrp.example.net")
	if addr := privateAddr(c.req.Body); addr != "" {
		t.Errorf("%s reached the client:\n%s", addr, c.req.Body)
	}
	ok := c.respond(clientAnswered(t, c.req, 200, clientAnswer))
	mediaOf(t, ok.Body, "a=path:"+corePathFor(1))
	mediaOf(t, ok.Body, "a=setup:active")
	if calls := a.relay.log(); len(calls) != 2 || calls[1] != "PATCH /v1/bindings/"+bindingIDFor(1) ||
		fmt.Sprint(a.relay.bodies[1]["client_endpoint_path"]) != "[msrps://192.0.2.10:9/s7d2k8f;tcp]" {
		t.Fatalf("relay calls %q %v", calls, a.relay.bodies)
	}
	// A retransmission goes the same and asks nothing more.
	if again := c.respond(clientAnswered(t, c.req, 200, clientAnswer)); string(again.Body) != string(ok.Body) || len(a.relay.log()) != 2 {
		t.Errorf("retransmission:\n%s", again.Body)
	}
	a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
	a.settle()
	if len(a.sent.take(a.p)) != 0 {
		t.Fatal("ended")
	}
	bye := inCall(t, c, "BYE", "b1", 1, "")
	if d := a.p.Route(context.Background(), bye); len(d.Targets) != 1 {
		t.Fatalf("BYE: %+v", d)
	}
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
		t.Errorf("after BYE: calls %q", a.relay.log())
	}
}

// A client that answers rcs-as's offer passive would have the relay dial
// it, which it never does (ADR 0004): the binding is released before the
// 2xx goes on, rcs-as gets the MSRP lines declined, and once rcs-as's ACK
// has passed both sides get a BYE with cause 488 (#136 AC 4). An answer
// without a=setup is passive (RFC 4145 §4).
func TestAClientAnsweringPassiveIsEnded(t *testing.T) {
	for name, answer := range map[string]string{
		"passive": strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1),
		"none":    strings.Replace(clientChatOffer, "a=setup:actpass\r\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			c := a.coreInvite(t, rcsAsOffer)
			ok := c.respond(clientAnswered(t, c.req, 200, answer))
			mediaOf(t, ok.Body, "m=message 0 ")
			if strings.Contains(string(ok.Body), "192.0.2.10:9/") || a.relay.count(http.MethodDelete) != 1 || a.relay.count(http.MethodPatch) != 0 {
				t.Errorf("calls %q, body\n%s", a.relay.log(), ok.Body)
			}
			a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
			checkEndOfCoreSession(t, a, reasonDirection)
			if a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
				t.Errorf("held %d", a.p.msrp.limit.held())
			}
		})
	}
}

// An offer of rcs-as's that the relay could not serve is refused, 488:
// active, which would have the relay listen toward rcs-as; and without a
// relay, or past the limits, the INVITE is 503 with Retry-After.
func TestARcsAsOfferPcscfCannotAnchorIsRefused(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	r := fromCore(t, "INVITE", false, []string{pathEntry}, "Contact: <sip:rcs-as@10.0.1.20:5060;transport=tcp>", "Content-Type: application/sdp")
	r.Message.Body = []byte(strings.Replace(rcsAsOffer, "a=setup:actpass", "a=setup:active", 1))
	if d := a.p.Route(context.Background(), r); d.Status != 488 || len(a.relay.log()) != 0 {
		t.Errorf("active: %+v", d)
	}
	a.relay.fail = func(m string, _ int) int { return 503 }
	r = fromCore(t, "INVITE", false, []string{pathEntry}, "Contact: <sip:rcs-as@10.0.1.20:5060;transport=tcp>", "Content-Type: application/sdp")
	r.Message.Body = []byte(rcsAsOffer)
	d := a.p.Route(context.Background(), r)
	if err := d.Prepare(context.Background(), d.Targets[0], r.Message.Clone()); err == nil {
		t.Fatal("anchored with the relay failing")
	}
	res, _ := sip.NewResponse(r.Message, 500, "", "p1")
	d.OnFinal(context.Background(), res)
	d.OnResponse(context.Background(), res)
	if res.StatusCode != 503 || res.Header.Get("Retry-After") != "1" || a.p.msrp.limit.held() != 0 {
		t.Errorf("relay failing: %d %q held %d", res.StatusCode, res.Header.Get("Retry-After"), a.p.msrp.limit.held())
	}
	// A 430 from a lost flow still reaches scscf as it is (RFC 5626 §11.5).
	lost, _ := sip.NewResponse(r.Message, statusFlowFailed, "", "p1")
	a.relay.fail = nil
	c := a.coreInvite(t, rcsAsOffer)
	c.d.OnFinal(context.Background(), lost)
	if lost.StatusCode != statusFlowFailed {
		t.Errorf("430 became %d", lost.StatusCode)
	}
}

// An INVITE without an offer gets one in its 2xx (RFC 3261 §13.2.1): the
// client's, from rcs-as, is anchored there, a binding made for rcs-as's
// path, the client getting the relay's client path, actpass, and its
// answer in the ACK completes the binding, rcs-as getting the relay's
// core-side path, active. A retransmitted 2xx and its ACK go the same.
func TestAnOfferInA2xxIsAnchored(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "")
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
	mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
	mediaOf(t, ok.Body, "a=setup:actpass")
	if addr := privateAddr(ok.Body); addr != "" || a.relay.count(http.MethodPost) != 1 {
		t.Fatalf("%s reached the client, calls %q:\n%s", addr, a.relay.log(), ok.Body)
	}
	ack := ackFor(t, c, ok)
	_ = ack.Message.Header.Set("Content-Type", "application/sdp")
	ack.Message.Body = []byte(clientAnswer)
	d := a.p.Route(context.Background(), ack)
	if len(d.Targets) != 1 {
		t.Fatalf("ACK: %+v", d)
	}
	fwd := ack.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
	mediaOf(t, fwd.Body, "a=setup:active")
	if strings.Contains(string(fwd.Body), "192.0.2.10:9/") || a.relay.count(http.MethodPatch) != 1 {
		t.Errorf("calls %q, ACK\n%s", a.relay.log(), fwd.Body)
	}
	again := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
	ack2 := ackFor(t, c, again)
	_ = ack2.Message.Header.Set("Content-Type", "application/sdp")
	ack2.Message.Body = []byte(clientAnswer)
	d = a.p.Route(context.Background(), ack2)
	fwd2 := ack2.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd2); err != nil || string(fwd2.Body) != string(fwd.Body) ||
		string(again.Body) != string(ok.Body) || len(a.relay.log()) != 2 {
		t.Errorf("retransmissions: %v, calls %q", err, a.relay.log())
	}
	a.settle()
	if len(a.sent.take(a.p)) != 0 || a.p.msrp.limit.held() != 1 {
		t.Errorf("held %d", a.p.msrp.limit.held())
	}
}

// An offer in a reliable 183 is anchored, its answer in the PRACK; an
// unreliable 1xx with one goes on declined, and a PRACK with an offer of
// its own is 488, as pcscf does not anchor one there.
func TestAnOfferInAReliableProvisionalIsAnchored(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "", "Supported: 100rel", "Require: 100rel")
	if c.req.Header.Get("Supported") != "100rel" || c.req.Header.Get("Require") != "100rel" {
		t.Errorf("100rel taken out: Supported %q, Require %q", c.req.Header.Get("Supported"), c.req.Header.Get("Require"))
	}
	preview := c.respond(answered(t, c.req, 180, "b1", rcsAsOffer))
	mediaOf(t, preview.Body, "m=message 0 ")
	early := answered(t, c.req, 183, "b1", rcsAsOffer)
	_ = early.Header.Set("Require", "100rel")
	_ = early.Header.Set("RSeq", "1")
	early = c.respond(early)
	mediaOf(t, early.Body, "a=path:"+clientPathFor(1))
	prack := inCall(t, c, "PRACK", "b1", 2, clientAnswer)
	d := a.p.Route(context.Background(), prack)
	if len(d.Targets) != 1 {
		t.Fatalf("PRACK: %+v", d)
	}
	fwd := prack.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
	c.respond(answered(t, c.req, 200, "b1", ""))
	if a.relay.count(http.MethodPatch) != 1 || a.relay.count(http.MethodDelete) != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
	if d := a.p.Route(context.Background(), inCall(t, c, "PRACK", "b1", 3, clientChatOffer)); d.Status != 488 {
		t.Errorf("an offer in a PRACK: %+v", d)
	}
}

// reInvite is alice's re-INVITE in c's dialog with b1, with body as its
// offer if any, run through its decision as the proxy does; it returns the
// decision and the request as it went.
func reInvite(t *testing.T, a *anchoring, c call, method string, seq int, body string) call {
	t.Helper()
	r := inCall(t, c, method, "b1", seq, body)
	d := a.p.Route(context.Background(), r)
	if len(d.Targets) != 1 {
		return call{r: r, d: d}
	}
	req := r.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return call{r: r, d: d, req: req}
}

// confirmedChat is a chat alice set up and rcs-as answered, its ACK sent.
func confirmedChat(t *testing.T, a *anchoring) call {
	t.Helper()
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	return c
}

// A re-INVITE or UPDATE whose offer keeps the client's path keeps the
// binding: rcs-as gets its core-side path again, and the client the relay's
// client path in the answer, without a call to the relay (#136 AC 7).
func TestARefreshThatKeepsThePathKeepsTheBinding(t *testing.T) {
	for _, method := range []string{"INVITE", "UPDATE"} {
		a := newAnchoring(t, 16, 100)
		c := confirmedChat(t, a)
		calls := len(a.relay.log())
		re := reInvite(t, a, c, method, 2, clientChatOffer)
		if re.req == nil {
			t.Fatalf("%s: %+v", method, re.d)
		}
		mediaOf(t, re.req.Body, "a=path:"+corePathFor(1))
		res := answered(t, re.req, 200, "b1", rcsAsAnswer)
		re.d.OnResponse(context.Background(), res)
		mediaOf(t, res.Body, "a=path:"+clientPathFor(1))
		if len(a.relay.log()) != calls || a.p.msrp.limit.held() != 1 {
			t.Errorf("%s: calls %q", method, a.relay.log())
		}
	}
}

// rcs-as answers a re-INVITE without an offer with its last description,
// actpass, as the offer (#252): the client gets the relay's client path,
// and its answer in the ACK, active, goes to rcs-as with the relay's
// core-side path, active, the relay keeping its connection; nothing is
// asked of the relay.
func TestRcsAsRefreshOfferIsAnsweredActive(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	calls := len(a.relay.log())
	re := reInvite(t, a, c, "INVITE", 2, "")
	ok := answered(t, re.req, 200, "b1", strings.Replace(rcsAsOffer, "3913000002 3913000002", "3913000002 3913000003", 1))
	re.d.OnResponse(context.Background(), ok)
	mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
	mediaOf(t, ok.Body, "a=setup:actpass")
	ack := inCall(t, c, "ACK", "b1", 2, clientAnswer)
	d := a.p.Route(context.Background(), ack)
	fwd := ack.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "a=path:"+corePathFor(1))
	mediaOf(t, fwd.Body, "a=setup:active")
	a.settle()
	if len(a.relay.log()) != calls || len(a.sent.take(a.p)) != 0 || a.p.msrp.limit.held() != 1 {
		t.Errorf("calls %q", a.relay.log())
	}
}

// A refresh whose offer moves the client's path gets a new binding: once
// rcs-as answers it, the old one goes; when rcs-as refuses it, the new one
// goes and the old one stays (#136 AC 7, RFC 3261 §14.1).
func TestARefreshThatMovesThePathReallocates(t *testing.T) {
	moved := strings.Replace(clientChatOffer, "s7d2k8f", "m0v3d9x", 1)
	for _, code := range []int{200, 488} {
		a := newAnchoring(t, 16, 100)
		c := confirmedChat(t, a)
		re := reInvite(t, a, c, "INVITE", 2, moved)
		mediaOf(t, re.req.Body, "a=path:"+corePathFor(2))
		res := answered(t, re.req, code, "b1", "")
		if code == 200 {
			res = answered(t, re.req, 200, "b1", rcsAsAnswer)
		} else if re.d.OnFinal != nil {
			re.d.OnFinal(context.Background(), res)
		}
		re.d.OnResponse(context.Background(), res)
		a.settle()
		want := "DELETE /v1/bindings/" + bindingIDFor(1)
		if code != 200 {
			want = "DELETE /v1/bindings/" + bindingIDFor(2)
		}
		calls := a.relay.log()
		if a.relay.count(http.MethodDelete) != 1 || calls[len(calls)-1] != want || a.p.msrp.limit.held() != 1 {
			t.Errorf("%d: calls %q, held %d", code, calls, a.p.msrp.limit.held())
		}
	}
}

// One offer at a time: another while one is under way is 491 (RFC 3261
// §14.2); and a refresh offer pcscf cannot anchor is 488.
func TestOneOfferAtATime(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	reInvite(t, a, c, "INVITE", 2, clientChatOffer)
	if re := reInvite(t, a, c, "UPDATE", 3, clientChatOffer); re.d.Status != 491 {
		t.Errorf("a second offer: %+v", re.d)
	}
	if re := reInvite(t, a, c, "INVITE", 4, ""); re.d.Status != 491 {
		t.Errorf("an INVITE without an offer: %+v", re.d)
	}
	a = newAnchoring(t, 16, 100)
	c = confirmedChat(t, a)
	if re := reInvite(t, a, c, "UPDATE", 2, strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1)); re.d.Status != 488 {
		t.Errorf("a passive refresh offer: %+v", re.d)
	}
}

// A client that answers a refresh offer passive ends the session, as one
// answering the first would (#136 part 2, question 3).
func TestAPassiveAnswerToARefreshEndsTheSession(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, rcsAsOffer)
	ok := c.respond(clientAnswered(t, c.req, 200, clientAnswer))
	_ = ok
	a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
	// rcs-as's re-INVITE with an offer, which the client answers passive.
	re := fromCoreInCall(t, a, c, "INVITE", "b1", 2, rcsAsOffer)
	d := a.p.Route(context.Background(), re)
	if len(d.Targets) != 1 {
		t.Fatalf("re-INVITE: %+v", d)
	}
	req := re.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatal(err)
	}
	res := clientAnswered(t, req, 200, strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1))
	d.OnResponse(context.Background(), res)
	mediaOf(t, res.Body, "m=message 0 ")
	a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 2, ""))
	checkEndOfCoreSession(t, a, reasonDirection)
	if a.p.msrp.limit.held() != 0 {
		t.Errorf("held %d", a.p.msrp.limit.held())
	}
}

// A dialog set up without MSRP cannot have it added: an offer with an MSRP
// line inside it is 488, and an MSRP offer in a response to an INVITE
// without one goes on declined.
func TestADialogWithoutMSRPGetsNone(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	audio := strings.Split(clientChatOffer, "m=message")[0]
	c := a.invite(t, "call-1", "application/sdp", audio)
	c.respond(answered(t, c.req, 200, "b1", strings.Split(rcsAsAnswer, "m=message")[0]))
	if d := a.p.Route(context.Background(), inCall(t, c, "INVITE", "b1", 2, clientChatOffer)); d.Status != 488 {
		t.Errorf("an MSRP offer: %+v", d)
	}
	re := reInvite(t, a, c, "INVITE", 3, "")
	res := answered(t, re.req, 200, "b1", rcsAsOffer)
	re.d.OnResponse(context.Background(), res)
	mediaOf(t, res.Body, "m=message 0 ")
	if len(a.relay.log()) != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
}

// A refresh whose answer gives a kept binding another path of rcs-as's,
// which the relay does not change, cannot be served: the session ends once
// the re-INVITE's ACK has passed.
func TestARefreshAnswerThatMovesAKeptPathEndsTheSession(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, clientChatOffer)
	res := answered(t, re.req, 200, "b1", strings.Replace(rcsAsAnswer, "as9f2c1", "moved1", 1))
	re.d.OnResponse(context.Background(), res)
	if strings.Contains(string(res.Body), "10.0.1.20") {
		t.Errorf("rcs-as's path reached the client:\n%s", res.Body)
	}
	a.settle()
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Fatalf("ended before the ACK: %d", len(got))
	}
	ack := inCall(t, c, "ACK", "b1", 2, "")
	a.p.Route(context.Background(), ack)
	// Past the re-INVITE's CSeq.
	checkEndSeq(t, a, "b1", reasonRelayUnavailable, "3 BYE")
}

// A refresh that moves the path and whose answer cannot be served gives
// the new binding back at once, before its ACK ends the session.
func TestAFailedRefreshGivesItsBindingBack(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, strings.Replace(clientChatOffer, "s7d2k8f", "m0v3d9x", 1))
	res := answered(t, re.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1))
	re.d.OnResponse(context.Background(), res)
	a.settle()
	if calls := a.relay.log(); a.relay.count(http.MethodDelete) != 1 || calls[len(calls)-1] != "DELETE /v1/bindings/"+bindingIDFor(2) {
		t.Errorf("calls %q", calls)
	}
}

// An end waits for the ACK of the side that sends it: rcs-as's, for the 2xx
// of a client that answered passive, not the client's.
func TestAnEndWaitsForTheRightACK(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, rcsAsOffer)
	c.respond(clientAnswered(t, c.req, 200, strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1)))
	a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 1, ""))
	a.settle()
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Fatalf("the client's ACK ended it: %d", len(got))
	}
	a.p.Route(context.Background(), fromCoreInCall(t, a, c, "ACK", "b1", 1, ""))
	checkEndOfCoreSession(t, a, reasonDirection)
}

// A session rcs-as set up is the client's tag's, which its first response
// gave: an offer in a request with another tag is in no dialog pcscf
// anchors, and is refused.
func TestASessionRcsAsSetUpIsTheClientsTags(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.coreInvite(t, rcsAsOffer)
	c.respond(clientAnswered(t, c.req, 200, clientAnswer))
	re := inCall(t, c, "INVITE", "b1", 2, clientAnswer)
	_ = re.Message.Header.Set("From", "<"+aliceIMPU+">;tag=other")
	if d := a.p.Route(context.Background(), re); d.Status != 488 || len(a.relay.log()) != 2 {
		t.Errorf("another tag's offer: %+v, calls %q", d, a.relay.log())
	}
}

// An answer in the ACK that pcscf cannot serve, a client's passive one,
// ends the session once the ACK has gone.
func TestAPassiveAnswerInTheACKEndsTheSession(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "")
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
	ack := ackFor(t, c, ok)
	_ = ack.Message.Header.Set("Content-Type", "application/sdp")
	ack.Message.Body = []byte(strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1))
	d := a.p.Route(context.Background(), ack)
	fwd := ack.Message.Clone()
	if err := d.Prepare(context.Background(), d.Targets[0], fwd); err != nil {
		t.Fatal(err)
	}
	mediaOf(t, fwd.Body, "m=message 0 ")
	checkEnd(t, a, "b1", reasonDirection)
	if a.p.msrp.limit.held() != 0 {
		t.Errorf("held %d", a.p.msrp.limit.held())
	}
}

// A 183 that asks for 100rel without an RSeq is not reliable (RFC 3262
// §3): its offer goes on declined.
func TestAProvisionalWithoutRSeqIsNotReliable(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "", "")
	early := answered(t, c.req, 183, "b1", rcsAsOffer)
	_ = early.Header.Set("Require", "100rel")
	early = c.respond(early)
	mediaOf(t, early.Body, "m=message 0 ")
	if len(a.relay.log()) != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
}

// rcs-as's refresh offer is rewritten the same when its 2xx is
// retransmitted; one pcscf cannot anchor goes on declined, and its 2xx
// ends the session once the ACK has passed.
func TestRcsAsRefreshOffersRetransmittedOrRefused(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	re := reInvite(t, a, c, "INVITE", 2, "")
	ok := answered(t, re.req, 200, "b1", rcsAsOffer)
	re.d.OnResponse(context.Background(), ok)
	again := answered(t, re.req, 200, "b1", rcsAsOffer)
	re.d.OnResponse(context.Background(), again)
	if string(again.Body) != string(ok.Body) {
		t.Errorf("the retransmission:\n%s", again.Body)
	}

	a = newAnchoring(t, 16, 100)
	out := a.recordMetrics()
	c = confirmedChat(t, a)
	re = reInvite(t, a, c, "INVITE", 2, "")
	ok = answered(t, re.req, 200, "b1", strings.Replace(rcsAsOffer, "a=setup:actpass", "a=setup:active", 1))
	re.d.OnResponse(context.Background(), ok)
	mediaOf(t, ok.Body, "m=message 0 ")
	a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 2, ""))
	checkEndSeq(t, a, "b1", reasonOfferRefused, "3 BYE")
	// Counted as the offer it is, not as the relay failing (#315 code
	// review 4).
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricEndedOffer+`":1`) || strings.Contains(out.String(), metricEndedRelay) {
		t.Errorf("metrics %s", out.String())
	}
}

// recordMetrics has a's pcscf write its metrics to the returned builder.
func (a *anchoring) recordMetrics() *strings.Builder {
	out := &strings.Builder{}
	a.p.metrics = runtime.NewMetrics(out, "RCS", "pcscf", a.clock.now, a.p.log)
	return out
}

// #315 code review 2: the sessions rcs-as starts toward a flow take from a
// share of their own. With that share full, alice still starts her own
// chat, and only the next session coming in is refused, 503.
func TestIncomingSessionsLeaveTheClientItsOwnShare(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	for i := range 16 {
		if _, err := a.coreInviteIn(t, fmt.Sprintf("term-%d", i), rcsAsOffer); err != nil {
			t.Fatalf("incoming session %d: %v", i, err)
		}
	}
	c := a.invite(t, "chat-own", "application/sdp", clientChatOffer)
	mediaOf(t, c.req.Body, "a=path:"+corePathFor(17))
	if a.p.msrp.limit.held() != 17 {
		t.Fatalf("held %d", a.p.msrp.limit.held())
	}
	if _, err := a.coreInviteIn(t, "term-16", rcsAsOffer); !errors.Is(err, errBindingLimit) {
		t.Fatalf("a 17th incoming session: %v", err)
	}
}

// #315 code review 1: rcsjta, as the refresher, sends a re-INVITE without
// an offer, and acknowledges the offer rcs-as makes in the 2xx (#252) with
// an ACK without an answer (SessionTimerManager). The exchange is given
// up: the session goes on with its binding, and neither the next refresh
// nor an offer is 491. An ACK of an earlier 2xx, sent again, gives up
// nothing.
func TestAnACKWithoutTheAnswerToARefreshOfferGivesItUp(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	calls := len(a.relay.log())
	for seq := 2; seq <= 3; seq++ {
		re := reInvite(t, a, c, "INVITE", seq, "")
		if re.req == nil {
			t.Fatalf("refresh %d: %+v", seq, re.d)
		}
		ok := answered(t, re.req, 200, "b1", rcsAsOffer)
		re.d.OnResponse(context.Background(), ok)
		mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
		if seq == 3 {
			a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 1, ""))
			if d := a.p.Route(context.Background(), inCall(t, c, "UPDATE", "b1", 4, clientChatOffer)); d.Status != 491 {
				t.Fatalf("an offer before the refresh's ACK: %+v", d)
			}
		}
		a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", seq, ""))
	}
	if re := reInvite(t, a, c, "INVITE", 5, clientChatOffer); re.req == nil {
		t.Fatalf("an offer after the refreshes: %+v", re.d)
	}
	a.settle()
	if len(a.sent.take(a.p)) != 0 || a.p.msrp.limit.held() != 1 || len(a.relay.log()) != calls {
		t.Errorf("held %d, calls %q", a.p.msrp.limit.held(), a.relay.log())
	}
}

// An offer in a 2xx that made a binding, as one that moves rcs-as's path,
// leaves the relay without the client's path for it: an ACK without the
// answer ends the session with BYE 488, and its bindings go. So does the
// ACK to the offer in the 2xx of an INVITE without one.
func TestAnACKWithoutTheAnswerToANewBindingEndsTheSession(t *testing.T) {
	moved := strings.Replace(rcsAsOffer, "as9f2c1", "m0v3d9x", 1)
	t.Run("refresh", func(t *testing.T) {
		a := newAnchoring(t, 16, 100)
		out := a.recordMetrics()
		c := confirmedChat(t, a)
		re := reInvite(t, a, c, "INVITE", 2, "")
		re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", moved))
		if a.relay.count(http.MethodPost) != 2 {
			t.Fatalf("calls %q", a.relay.log())
		}
		a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 2, ""))
		a.settle()
		checkEndSeq(t, a, "b1", reasonNoAnswer, "3 BYE")
		a.p.metrics.Flush()
		if a.p.msrp.limit.held() != 0 || a.relay.count(http.MethodDelete) != 2 || !strings.Contains(out.String(), `"`+metricEndedNoAnswer+`":1`) {
			t.Errorf("held %d, calls %q, metrics %s", a.p.msrp.limit.held(), a.relay.log(), out.String())
		}
	})
	t.Run("setup", func(t *testing.T) {
		a := newAnchoring(t, 16, 100)
		c := a.invite(t, "chat-1", "", "")
		ok := c.respond(answered(t, c.req, 200, "b1", rcsAsOffer))
		a.p.Route(context.Background(), ackFor(t, c, ok))
		a.settle()
		checkEnd(t, a, "b1", reasonNoAnswer)
		if a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
			t.Errorf("held %d", a.p.msrp.limit.held())
		}
	})
}

// #315 code review 3: rcs-as's offer in a reliable 183 to a re-INVITE
// without one, which the client answers passive in the PRACK, ends the
// session with BYE 488 after the 2xx (#136 part 2, decision 3); so does a
// PRACK without the answer to one that made a binding.
func TestAPRACKThatCannotServeARefreshOfferEndsTheSession(t *testing.T) {
	for name, tc := range map[string]struct{ offer, prack, reason string }{
		"passive":   {rcsAsOffer, strings.Replace(clientAnswer, "a=setup:active", "a=setup:passive", 1), reasonDirection},
		"no answer": {strings.Replace(rcsAsOffer, "as9f2c1", "m0v3d9x", 1), "", reasonNoAnswer},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			c := confirmedChat(t, a)
			re := reInvite(t, a, c, "INVITE", 2, "")
			early := answered(t, re.req, 183, "b1", tc.offer)
			_ = early.Header.Set("Require", "100rel")
			_ = early.Header.Set("RSeq", "1")
			re.d.OnResponse(context.Background(), early)
			prack := inCall(t, c, "PRACK", "b1", 3, tc.prack)
			_ = prack.Message.Header.Set("RAck", "1 2 INVITE")
			d := a.p.Route(context.Background(), prack)
			if len(d.Targets) != 1 {
				t.Fatalf("PRACK: %+v", d)
			}
			if d.Prepare != nil {
				if err := d.Prepare(context.Background(), d.Targets[0], prack.Message.Clone()); err != nil {
					t.Fatal(err)
				}
			}
			re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", ""))
			a.settle()
			if sent := a.sent.take(a.p); len(sent) != 0 {
				t.Fatalf("%d sent before the ACK", len(sent))
			}
			a.p.Route(context.Background(), inCall(t, c, "ACK", "b1", 2, ""))
			a.settle()
			checkEndSeq(t, a, "b1", tc.reason, "4 BYE")
			if a.p.msrp.limit.held() != 0 {
				t.Errorf("held %d", a.p.msrp.limit.held())
			}
		})
	}
}

// #315 code review 5: a refresh offer that declines the MSRP line (port 0,
// RFC 3264 §8.2) goes to rcs-as without the client's path, and the line's
// binding goes once rcs-as answers. An INVITE whose MSRP line is declined
// goes without it too.
func TestADeclinedLineGoesWithoutItsPathAndReleasesItsBinding(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := confirmedChat(t, a)
	declined := strings.Replace(clientChatOffer, "m=message 9 ", "m=message 0 ", 1)
	re := reInvite(t, a, c, "INVITE", 2, declined)
	if re.req == nil {
		t.Fatalf("refresh: %+v", re.d)
	}
	if strings.Contains(string(re.req.Body), "a=path:") {
		t.Errorf("the client's path went to rcs-as:\n%s", re.req.Body)
	}
	if a.relay.count(http.MethodDelete) != 0 {
		t.Fatalf("released before the answer: %q", a.relay.log())
	}
	re.d.OnResponse(context.Background(), answered(t, re.req, 200, "b1", strings.Replace(rcsAsAnswer, "m=message 2855 ", "m=message 0 ", 1)))
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 {
		t.Errorf("held %d, calls %q", a.p.msrp.limit.held(), a.relay.log())
	}
	if len(a.sent.take(a.p)) != 0 {
		t.Error("the session was ended")
	}

	b := newAnchoring(t, 16, 100)
	in := b.invite(t, "chat-2", "application/sdp", declined)
	if strings.Contains(string(in.req.Body), "a=path:") || !strings.Contains(string(in.req.Body), "m=message 0 ") || len(b.relay.log()) != 0 {
		t.Errorf("calls %q, INVITE to rcs-as:\n%s", b.relay.log(), in.req.Body)
	}
}
