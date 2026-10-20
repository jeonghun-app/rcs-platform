package pcscf

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// inCall is alice's request of method inside the dialog of c's INVITE that
// the To tag names, with CSeq seq and body as its description, if any.
func inCall(t *testing.T, c call, method, tag string, seq int, body string) *proxy.Request {
	t.Helper()
	callID := c.req.Header.Get("Call-ID")
	r := inDialogFrom(t, []string{clientEnt, "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr"}, "sip:rcs-as@10.0.1.20:5060", "Route: "+scscfRoute)
	r.Message.Method = method
	_ = r.Message.Header.Set("CSeq", fmt.Sprintf("%d %s", seq, method))
	_ = r.Message.Header.Set("Call-ID", callID)
	_ = r.Message.Header.Set("To", "<"+bobIMPU+">;tag="+tag)
	r.Routed[1].URI.Params.Set(dialogParam, testPcscfMAC("FLOW-A", callID, ""))
	if body != "" {
		_ = r.Message.Header.Set("Content-Type", "application/sdp")
		r.Message.Body = []byte(body)
	}
	return r
}

// fromCoreInCall is the core's request of method inside that dialog.
func fromCoreInCall(t *testing.T, a *anchoring, c call, method, tag string, seq int, body string) *proxy.Request {
	t.Helper()
	callID := c.req.Header.Get("Call-ID")
	r := fromCore(t, method, true, []string{"sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;dlg=" + a.p.dialogMAC("FLOW-A", callID, ""), "sip:" + publicHost + ":5060;transport=tcp;lr"})
	_ = r.Message.Header.Set("From", "<"+bobIMPU+">;tag="+tag)
	_ = r.Message.Header.Set("To", "<"+aliceIMPU+">;tag=a1")
	_ = r.Message.Header.Set("Call-ID", callID)
	_ = r.Message.Header.Set("CSeq", fmt.Sprintf("%d %s", seq, method))
	if body != "" {
		_ = r.Message.Header.Set("Content-Type", "application/sdp")
		r.Message.Body = []byte(body)
	}
	return r
}

// An offer whose MSRP lines pcscf could not have the relay serve is 488
// before anything is allocated: more than two lines, holdconn, which pcscf
// cannot answer in kind (RFC 4145 §4), or a path the relay refuses. active,
// actpass and none at all are anchored, active toward the core.
func TestAnOfferTheRelayCouldNotServeIsRefused(t *testing.T) {
	second := lines("m=message 9 TCP/TLS/MSRP *", "a=setup:active", "a=path:msrps://192.0.2.10:9/second;tcp")
	for name, offer := range map[string]string{
		"three lines":              clientChatOffer + second + strings.Replace(second, "second", "third", 1),
		"holdconn":                 strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:holdconn", 1),
		"holdconn for all":         strings.Replace(strings.Replace(clientChatOffer, "a=setup:actpass\r\n", "", 1), "t=0 0\r\n", "t=0 0\r\na=setup:holdconn\r\n", 1),
		"a path without a port":    strings.Replace(clientChatOffer, "192.0.2.10:9/s7d2k8f;tcp", "alice.example.net/s7d2k8f;tcp", 1),
		"a path over websocket":    strings.Replace(clientChatOffer, "s7d2k8f;tcp", "s7d2k8f;ws", 1),
		"a path without a session": strings.Replace(clientChatOffer, "192.0.2.10:9/s7d2k8f;tcp", "192.0.2.10:9;tcp", 1),
	} {
		t.Run(name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			d := a.p.Route(context.Background(), clientRequest(t, inviteWith("chat-1", "application/sdp", offer), "FLOW-A"))
			if d.Status != 488 || len(a.relay.log()) != 0 {
				t.Errorf("%+v, relay calls %q", d, a.relay.log())
			}
		})
	}
	// Two lines a flow could never hold.
	a := newAnchoring(t, 1, 100)
	two := clientChatOffer + second
	if d := a.p.Route(context.Background(), clientRequest(t, inviteWith("chat-1", "application/sdp", two), "FLOW-A")); d.Status != 488 {
		t.Errorf("two lines past the flow's limit: %+v", d)
	}
	for _, setup := range []string{"active", "actpass", ""} {
		a = newAnchoring(t, 16, 100)
		offer := strings.Replace(clientChatOffer, "a=setup:actpass\r\n", "", 1)
		if setup != "" {
			offer = strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:"+setup, 1)
		}
		c := a.invite(t, "chat-1", "application/sdp", offer)
		mediaOf(t, c.req.Body, "a=setup:active")
	}
}

// An INVITE pcscf anchors, or watches for a late offer, asks for no
// reliable provisional response, whose offer would be answered in a PRACK
// pcscf does not anchor (RFC 3262).
func TestAnchoredInvitesAskForNoReliableResponses(t *testing.T) {
	for _, tt := range []struct{ ct, body string }{{"application/sdp", clientChatOffer}, {"", ""}} {
		a := newAnchoring(t, 16, 100)
		r := clientRequest(t, inviteWith("chat-1", tt.ct, tt.body, "Supported: 100rel, timer", "Require: 100rel", "Require: precondition"), "FLOW-A")
		d := a.p.Route(context.Background(), r)
		req := r.Message.Clone()
		if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Values("Supported"); !slices.Equal(got, []string{"timer"}) {
			t.Errorf("Supported %q", got)
		}
		if got := req.Header.Values("Require"); !slices.Equal(got, []string{"precondition"}) {
			t.Errorf("Require %q", got)
		}
	}
}

// pcscf keeps no Record-Route a client writes on an initial request, and
// the BYE it sends the core follows only what the core recorded below
// pcscf's own values (#248 security review): it still goes to scscf. A
// route set without pcscf's values is not followed.
func TestTheCoresByeFollowsOnlyTheCoresRoute(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	a.relay.fail = func(m string, _ int) int {
		if m == http.MethodPatch {
			return 503
		}
		return 0
	}
	r := clientRequest(t, inviteWith("chat-1", "application/sdp", clientChatOffer, "Record-Route: <sip:192.0.2.99;lr>"), "FLOW-A")
	d := a.p.Route(context.Background(), r)
	req := r.Message.Clone()
	for _, rr := range slices.Backward(d.RecordRoute) {
		_ = req.Header.Prepend("Record-Route", rr.String())
	}
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, rr := range d.RecordRoute {
		want = append(want, rr.String())
	}
	if got := req.Header.Values("Record-Route"); !slices.Equal(got, want) {
		t.Fatalf("Record-Route %q, want pcscf's %q", got, want)
	}
	c := call{r: r, d: d, req: req}
	res := answered(t, req, 200, "b1", rcsAsAnswer)
	// Whatever is below pcscf's values is not the core's.
	_ = res.Header.Add("Record-Route", "<sip:192.0.2.98;lr>")
	ok := c.respond(res)
	a.p.Route(context.Background(), ackFor(t, c, ok))
	checkEnd(t, a, "b1", reasonRelayUnavailable)

	// Without pcscf's values, only the client's BYE goes.
	a = newAnchoring(t, 16, 100)
	var out strings.Builder
	a.p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", a.clock.now, a.p.log)
	c = a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	res = answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1))
	res.Header.Del("Record-Route")
	_ = res.Header.Add("Record-Route", "<sip:scscf.rcs.internal;transport=tcp;lr>")
	ok = c.respond(res)
	a.p.Route(context.Background(), ackFor(t, c, ok))
	if sent := a.sent.take(a.p); len(sent) != 1 || sent[0].dst.Flow != "FLOW-A" {
		t.Errorf("%d requests sent", len(sent))
	}
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricByeFailed+`":1`) {
		t.Errorf("metrics %s", out.String())
	}
}

// Inside a dialog pcscf anchors nothing yet (#136's second change), so it
// refuses what would need it: an INVITE without an offer, from either side,
// whose 2xx would bring one, and an MSRP description in a PRACK; an ACK
// with one is not passed on, though it still ends what it acknowledges. An
// UPDATE without one goes on.
func TestInDialogOffersPcscfDoesNotAnchorAreRefused(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	if d := a.p.Route(context.Background(), inCall(t, c, "INVITE", "b1", 2, "")); d.Status != 488 {
		t.Errorf("re-INVITE without an offer: %+v", d)
	}
	if d := a.p.Route(context.Background(), fromCoreInCall(t, a, c, "INVITE", "b1", 1, "")); d.Status != 488 {
		t.Errorf("the core's re-INVITE without an offer: %+v", d)
	}
	answer := strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1)
	if d := a.p.Route(context.Background(), inCall(t, c, "PRACK", "b1", 3, answer)); d.Status != 488 {
		t.Errorf("PRACK with an MSRP answer: %+v", d)
	}
	if d := a.p.Route(context.Background(), inCall(t, c, "UPDATE", "b1", 4, "")); len(d.Targets) != 1 {
		t.Errorf("UPDATE: %+v", d)
	}
	if d := a.p.Route(context.Background(), fromCore(t, "INVITE", false, []string{pathEntry})); d.Status != 488 {
		t.Errorf("an INVITE from the core without an offer: %+v", d)
	}

	// The late offer's 2xx is answered in the ACK.
	a = newAnchoring(t, 16, 100)
	c = a.invite(t, "chat-2", "", "")
	ok := c.respond(answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:actpass", 1)))
	ack := ackFor(t, c, ok)
	_ = ack.Message.Header.Set("Content-Type", "application/sdp")
	ack.Message.Body = []byte(answer)
	if d := a.p.Route(context.Background(), ack); len(d.Targets) != 0 {
		t.Errorf("ACK with an MSRP answer: %+v", d)
	}
	checkEnd(t, a, "b1", reasonLateOffer)
}

// A 2xx the proxy passes on after the session ended, as a late one after
// Timer C's 408, gets no path of the released bindings and its dialog is
// ended with Reason 503 (QA of #248).
func TestA2xxAfterTheSessionEndedIsEnded(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 408, "z9", ""))
	a.settle()
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	if strings.Contains(string(ok.Body), clientPathFor(1)) || strings.Contains(string(ok.Body), "10.0.1.20") {
		t.Errorf("the late 2xx:\n%s", ok.Body)
	}
	mediaOf(t, ok.Body, "m=message 0 TCP/MSRP *")
	if a.relay.count(http.MethodPatch) != 0 {
		t.Errorf("a released binding was completed: %q", a.relay.log())
	}
	a.p.Route(context.Background(), ackFor(t, c, ok))
	checkEnd(t, a, "b1", reasonRelayUnavailable)
	if len(a.p.msrp.all()) != 0 || a.p.msrp.limit.held() != 0 {
		t.Errorf("%d sessions, held %d", len(a.p.msrp.all()), a.p.msrp.limit.held())
	}
}

// An extension the relay fails is tried again at the next sweep, not 15
// minutes on, when the binding is gone; one the relay answers 404 ends the
// session as one it cannot serve, with a BYE each way (#248 code review 1).
// Each BYE's CSeq is past the requests its side sent in the dialog.
func TestAFailedExtensionIsTriedAgainAndALostBindingEndsTheSession(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	failures := map[int]int{}
	a.relay.fail = func(m string, n int) int { return failures[n] }
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	a.p.Route(context.Background(), inCall(t, c, "UPDATE", "b1", 5, ""))
	a.p.Route(context.Background(), fromCoreInCall(t, a, c, "INFO", "b1", 7, ""))
	failures[3] = 503 // the first extension
	a.clock.t = a.clock.t.Add(15 * time.Minute)
	a.p.sweepMSRP()
	a.settle()
	a.clock.t = a.clock.t.Add(30 * time.Second)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodPatch) != 3 {
		t.Fatalf("not tried again: %q", a.relay.log())
	}
	// Extended now: the next is 15 minutes on.
	a.clock.t = a.clock.t.Add(15*time.Minute - time.Second)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodPatch) != 3 {
		t.Fatalf("extended early: %q", a.relay.log())
	}
	if len(a.sent.take(a.p)) != 0 {
		t.Fatal("ended for a failed extension")
	}
	failures[5] = 404
	a.clock.t = a.clock.t.Add(time.Second)
	a.p.sweepMSRP()
	a.settle()
	sent := a.sent.take(a.p)
	if len(sent) != 2 || a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
		t.Fatalf("%d sent, held %d, calls %q", len(sent), a.p.msrp.limit.held(), a.relay.log())
	}
	for _, s := range sent {
		want := "8 BYE" // past the core's INFO
		if s.dst.Flow == "" {
			want = "6 BYE" // past the client's UPDATE
		}
		if s.req.Header.Get("CSeq") != want || s.req.Header.Get("Reason") != reasonRelayUnavailable {
			t.Errorf("BYE to %+v: CSeq %q, Reason %q", s.dst, s.req.Header.Get("CSeq"), s.req.Header.Get("Reason"))
		}
	}
	a.clock.t = a.clock.t.Add(time.Hour)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodPatch) != 4 || len(a.sent.take(a.p)) != 0 {
		t.Errorf("after the end: %q", a.relay.log())
	}
}

// A BYE of another fork's dialog ends that dialog alone: the first keeps
// its binding, and the other's end is not sent again (#248 code review 4).
func TestAByeOfAnotherForksDialogEndsThatDialogAlone(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	c.respond(answered(t, c.req, 200, "B2", strings.Replace(rcsAsAnswer, "as9f2c1", "other1", 1)))
	if d := a.p.Route(context.Background(), inCall(t, c, "BYE", "b2", 2, "")); len(d.Targets) != 1 {
		t.Fatalf("BYE: %+v", d)
	}
	a.clock.t = a.clock.t.Add(32 * time.Second)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodDelete) != 0 || len(a.p.msrp.all()) != 1 || len(a.sent.take(a.p)) != 0 {
		t.Errorf("calls %q, %d sessions", a.relay.log(), len(a.p.msrp.all()))
	}
	a.p.Route(context.Background(), inCall(t, c, "BYE", "B1", 2, ""))
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || len(a.p.msrp.all()) != 0 {
		t.Errorf("the first dialog's BYE: calls %q", a.relay.log())
	}
}

// A flow that closes, and the sweep, never wait for the relay: neither is
// held up while the relay is completing an answer's binding (#248 code
// review 5). What the relay completed then serves nothing, and the client
// gets no path of it.
func TestAFlowClosingNeverWaitsForTheRelay(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	a.p.msrp.relay = newRelayClient(a.base, testRelayToken, time.Minute, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	a.relay.fail = func(m string, _ int) int {
		if m == http.MethodPatch {
			close(entered)
			a.relay.mu.Unlock()
			<-release
			a.relay.mu.Lock()
		}
		return 0
	}
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	res := answered(t, c.req, 200, "b1", rcsAsAnswer)
	answered := make(chan struct{})
	go func() {
		defer close(answered)
		c.respond(res)
	}()
	<-entered
	done := make(chan struct{})
	a.alive["FLOW-A"] = false
	go func() {
		defer close(done)
		a.p.sweepMSRP()
		a.p.msrpFlowClosed("FLOW-A")
	}()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Error("the flow's closing waited for the relay")
	}
	close(release)
	<-answered
	<-done
	a.p.sweepMSRP()
	a.settle()
	if strings.Contains(string(res.Body), clientPathFor(1)) || a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 || a.relay.count(http.MethodDelete) != 1 {
		t.Errorf("held %d, calls %q, body\n%s", a.p.msrp.limit.held(), a.relay.log(), res.Body)
	}
}

// A late offer's 2xx retransmitted after its ACK ends nothing again (#248
// code review 6); a 1xx with one is declined too, and ends nothing.
func TestALateOfferIsEndedOnce(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	var out strings.Builder
	a.p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", a.clock.now, a.p.log)
	c := a.invite(t, "chat-1", "", "")
	offer := strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:actpass", 1)
	early := c.respond(answered(t, c.req, 183, "b1", offer))
	mediaOf(t, early.Body, "m=message 0 TCP/MSRP *")
	ok := c.respond(answered(t, c.req, 200, "b1", offer))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	checkEnd(t, a, "b1", reasonLateOffer)
	again := c.respond(answered(t, c.req, 200, "b1", offer))
	if string(again.Body) != string(ok.Body) {
		t.Errorf("the retransmission:\n%s", again.Body)
	}
	a.p.Route(context.Background(), ackFor(t, c, again))
	a.clock.t = a.clock.t.Add(32 * time.Second)
	a.p.sweepMSRP()
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Errorf("%d more requests", len(got))
	}
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricEndedLateOffer+`":1,`) && !strings.Contains(out.String(), `"`+metricEndedLateOffer+`":1}`) {
		t.Errorf("metrics %s", out.String())
	}
}

// privateAddr finds an address of the core's, private or loopback, in an
// SDP body.
var addrLike = regexp.MustCompile(`[0-9A-Fa-f:.]{3,}`)

func privateAddr(body []byte) string {
	for _, m := range addrLike.FindAllString(string(body), -1) {
		if a, err := netip.ParseAddr(strings.Trim(m, ":.")); err == nil && (a.IsPrivate() || a.IsLoopback()) {
			return m
		}
	}
	return ""
}

// No address of the core, RFC 1918 or ULA, reaches the client in any
// description pcscf lets through: the o= and session c= show the relay, or
// pcscf when no binding serves, and a line other than an anchored one is
// declined bare (ADR 0004).
func TestNoCoreAddressReachesTheClient(t *testing.T) {
	audio := strings.Replace(rcsAsAnswer, "m=audio 0 RTP/AVP 0", "m=audio 49000 RTP/AVP 0\r\nc=IN IP6 fd00::20\r\na=rtcp:49001 IN IP4 10.0.1.20", 1)
	declined := strings.Replace(rcsAsAnswer, "m=message 2855", "m=message 0", 1)
	active := strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1)
	for name, tt := range map[string]struct {
		patch  int
		bodies []string // to the INVITE: 183 b1, then 200s with their tags
		late   bool
	}{
		"an answer":                 {bodies: []string{"b1", rcsAsAnswer}},
		"an answer accepting audio": {bodies: []string{"b1", audio}},
		"every line declined":       {bodies: []string{"b1", declined}},
		"the relay failing":         {patch: 503, bodies: []string{"b1", rcsAsAnswer}},
		"an answer pcscf refuses":   {bodies: []string{"b1", active}},
		"a second answer":           {bodies: []string{"b1", rcsAsAnswer, "b2", audio}},
		"an early answer":           {bodies: []string{"b1", audio, "b1", ""}},
		"a late offer":              {late: true, bodies: []string{"b1", audio}},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			a.relay.fail = func(m string, _ int) int {
				if m == http.MethodPatch {
					return tt.patch
				}
				return 0
			}
			var c call
			if tt.late {
				c = a.invite(t, "chat-1", "", "")
			} else {
				c = a.invite(t, "chat-1", "application/sdp", clientChatOffer)
			}
			code := 200
			if name == "an early answer" {
				code = 183
			}
			for i := 0; i < len(tt.bodies); i += 2 {
				res := c.respond(answered(t, c.req, code, tt.bodies[i], tt.bodies[i+1]))
				code = 200
				if addr := privateAddr(res.Body); addr != "" {
					t.Errorf("%s reached the client in\n%s", addr, res.Body)
				}
				if res.Body != nil && !strings.Contains(string(res.Body), "c=IN IP4 msrp.example.net") && !strings.Contains(string(res.Body), "c=IN IP4 "+publicHost) {
					t.Errorf("session c= not the relay's:\n%s", res.Body)
				}
			}
		})
	}
}

// The BYEs that end a dialog are counted as failed when one cannot be
// sent or is refused, and logged without naming anyone.
func TestAByeThatFailsIsCounted(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	var out strings.Builder
	a.p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", a.clock.now, a.p.log)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	ok := c.respond(answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1)))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	sent := a.sent.take(a.p)
	if len(sent) != 2 {
		t.Fatalf("%d sent", len(sent))
	}
	refused, _ := sip.NewResponse(sent[0].req, 500, "", "x1")
	sent[0].h(refused, nil)
	gone, _ := sip.NewResponse(sent[1].req, 481, "", "x1")
	sent[1].h(gone, nil)
	a.sent.err = errors.New("no flow")
	c = a.invite(t, "chat-2", "application/sdp", clientChatOffer)
	ok = c.respond(answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1)))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	a.settle()
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricByeFailed+`":3`) {
		t.Errorf("metrics %s", out.String())
	}
}

// A 3xx ends the session like any final failure: no BYE, nothing held.
// An answer without a=setup is passive (RFC 4145 §4) and anchored.
func TestARedirectEndsTheSessionAndAnAnswerWithoutSetupIsPassive(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 302, "b1", ""))
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 || len(a.sent.take(a.p)) != 0 {
		t.Errorf("302: calls %q", a.relay.log())
	}
	a = newAnchoring(t, 16, 100)
	c = a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	ok := c.respond(answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive\r\n", "", 1)))
	a.p.Route(context.Background(), ackFor(t, c, ok))
	a.clock.t = a.clock.t.Add(32 * time.Second)
	a.p.sweepMSRP()
	if a.relay.count(http.MethodPatch) != 1 || a.relay.count(http.MethodDelete) != 0 || len(a.sent.take(a.p)) != 0 {
		t.Errorf("no setup: calls %q", a.relay.log())
	}
	mediaOf(t, ok.Body, "a=setup:passive")
}

// A description of up to 16 KiB is read; a longer one is refused.
func TestADescriptionOfUpTo16KiBIsRead(t *testing.T) {
	pad := func(n int) string {
		offer := clientChatOffer + "a=x-pad:"
		return offer + strings.Repeat("p", n-len(offer)-2) + "\r\n"
	}
	if _, _, err := msrpLines([]byte(pad(16<<10)), true); err != nil {
		t.Errorf("16 KiB: %v", err)
	}
	a := newAnchoring(t, 16, 100)
	if d := a.p.Route(context.Background(), clientRequest(t, inviteWith("chat-1", "application/sdp", pad(16<<10+1)), "FLOW-A")); d.Status != 488 {
		t.Errorf("16 KiB and one: %+v", d)
	}
}

// A flow that closes while the relay is asked leaves nothing: the session
// made for it is released as soon as it is added, and the INVITE does not
// go on.
func TestAFlowClosedDuringAllocationLeavesNothing(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	r := clientRequest(t, inviteWith("chat-1", "application/sdp", clientChatOffer), "FLOW-A")
	d := a.p.Route(context.Background(), r)
	a.alive["FLOW-A"] = false
	if err := d.Prepare(context.Background(), d.Targets[0], r.Message.Clone()); !errors.Is(err, errFlowClosed) {
		t.Fatalf("Prepare: %v", err)
	}
	a.settle()
	if len(a.p.msrp.all()) != 0 || a.p.msrp.limit.held() != 0 || a.relay.count(http.MethodDelete) != 1 {
		t.Errorf("calls %q, held %d", a.relay.log(), a.p.msrp.limit.held())
	}
}

// An extension under way is not started again by the next sweep, and a
// session whose bindings are released is not extended, though it waits to
// end another dialog.
func TestTheSweepExtendsOnceAndOnlyWhatIsHeld(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	entered, release := make(chan struct{}), make(chan struct{})
	a.relay.fail = func(m string, n int) int {
		if m == http.MethodPatch && n == 3 {
			close(entered)
			a.relay.mu.Unlock()
			<-release
			a.relay.mu.Lock()
		}
		return 0
	}
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.clock.t = a.clock.t.Add(15 * time.Minute)
	a.p.sweepMSRP()
	<-entered
	a.clock.t = a.clock.t.Add(30 * time.Second)
	a.p.sweepMSRP()
	close(release)
	a.settle()
	if a.relay.count(http.MethodPatch) != 2 {
		t.Errorf("extended twice at once: %q", a.relay.log())
	}

	a = newAnchoring(t, 16, 100)
	c = a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	c.respond(answered(t, c.req, 200, "b2", strings.Replace(rcsAsAnswer, "as9f2c1", "other1", 1)))
	a.p.Route(context.Background(), inCall(t, c, "BYE", "b1", 2, ""))
	a.settle()
	if len(a.p.msrp.all()) != 1 || a.relay.count(http.MethodDelete) != 1 {
		t.Fatalf("the other dialog's end is not waited for: %q", a.relay.log())
	}
	a.clock.t = a.clock.t.Add(15 * time.Minute)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodPatch) != 1 || len(a.sent.take(a.p)) != 2 || len(a.p.msrp.all()) != 0 {
		t.Errorf("calls %q, %d sessions", a.relay.log(), len(a.p.msrp.all()))
	}
}

// A flow that closes takes its count of bindings created with it, and the
// sweep drops the counts that have filled again.
func TestTheCountsOfBindingsCreatedGo(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 486, "b1", ""))
	a.p.msrpFlowClosed("FLOW-A")
	if len(a.p.msrp.limit.created) != 0 {
		t.Errorf("a closed flow's count stayed")
	}
	a.invite(t, "chat-2", "application/sdp", clientChatOffer)
	a.p.sweepMSRP()
	if len(a.p.msrp.limit.created) != 1 {
		t.Fatalf("a count not full again was dropped")
	}
	a.clock.t = a.clock.t.Add(time.Minute)
	a.p.sweepMSRP()
	if len(a.p.msrp.limit.created) != 0 {
		t.Errorf("a full count stayed")
	}
}

// A message whose body has two Content-Type fields cannot be read in one
// way only, so it is refused as an offer pcscf cannot read, inside a dialog
// and from the core too, and an answer or a late offer with two reaches
// the client without its body. text/plain comes first, as the field a
// reader of the first alone would take.
func TestTwoContentTypesAreRefused(t *testing.T) {
	twoTypes := func(h *sip.Header) {
		h.Del("Content-Type")
		_ = h.Add("Content-Type", "text/plain")
		_ = h.Add("Content-Type", "application/sdp")
	}
	for _, order := range [][2]string{{"text/plain", "application/sdp"}, {"application/sdp", "text/plain"}} {
		a := newAnchoring(t, 16, 100)
		text := strings.Replace(inviteWith("chat-1", "application/sdp", clientChatOffer), "Content-Type: application/sdp", "Content-Type: "+order[0]+"\r\nContent-Type: "+order[1], 1)
		if d := a.p.Route(context.Background(), clientRequest(t, text, "FLOW-A")); d.Status != 488 || len(a.relay.log()) != 0 {
			t.Errorf("INVITE %v: %+v, relay %q", order, d, a.relay.log())
		}
	}
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	update := inCall(t, c, "UPDATE", "b1", 2, clientChatOffer)
	twoTypes(&update.Message.Header)
	if d := a.p.Route(context.Background(), update); d.Status != 488 {
		t.Errorf("UPDATE: %+v", d)
	}
	core := fromCore(t, "INVITE", false, []string{pathEntry})
	core.Message.Body = []byte(clientChatOffer)
	twoTypes(&core.Message.Header)
	if d := a.p.Route(context.Background(), core); d.Status != 488 {
		t.Errorf("an INVITE from the core: %+v", d)
	}
	res := answered(t, c.req, 200, "b1", rcsAsAnswer)
	twoTypes(&res.Header)
	ok := c.respond(res)
	if len(ok.Body) != 0 || a.relay.count(http.MethodPatch) != 0 {
		t.Errorf("an answer with two Content-Types:\n%s", ok.Body)
	}

	a = newAnchoring(t, 16, 100)
	late := a.invite(t, "chat-2", "", "")
	res = answered(t, late.req, 200, "b1", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:actpass", 1))
	twoTypes(&res.Header)
	ok = late.respond(res)
	if len(ok.Body) != 0 {
		t.Errorf("a late offer with two Content-Types:\n%s", ok.Body)
	}
	a.p.Route(context.Background(), ackFor(t, late, ok))
	checkEnd(t, a, "b1", reasonLateOffer)
}
