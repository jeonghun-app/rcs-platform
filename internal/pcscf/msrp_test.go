package pcscf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// scriptedRelay is msrp-relay's control API as the anchoring tests need it:
// it hands out numbered bindings, records every call, and fails the calls
// fail says to.
type scriptedRelay struct {
	mu    sync.Mutex
	n     int
	calls []string
	// bodies holds the JSON body of each call, by its index in calls.
	bodies map[int]map[string]any
	fail   func(method string, n int) int
}

func (s *scriptedRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := r.Method + " " + r.URL.Path
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		s.bodies[len(s.calls)] = m
	}
	s.calls = append(s.calls, call)
	if s.fail != nil {
		if code := s.fail(r.Method, len(s.calls)); code != 0 {
			w.WriteHeader(code)
			return
		}
	}
	switch r.Method {
	case http.MethodPost:
		s.n++
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"id":"%s","client_path":"%s","core_path_local":"%s"}`, bindingIDFor(s.n), clientPathFor(s.n), corePathFor(s.n))
	case http.MethodPatch:
		fmt.Fprintf(w, `{"id":"x","expires_at":"2026-01-02T03:34:05.000Z"}`)
	default:
		w.WriteHeader(204)
	}
}

func (s *scriptedRelay) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

// count counts the calls of method.
func (s *scriptedRelay) count(method string) int {
	n := 0
	for _, c := range s.log() {
		if strings.HasPrefix(c, method+" ") {
			n++
		}
	}
	return n
}

func bindingIDFor(n int) string { return strings.Repeat("a", 51) + string(rune('a'+n)) }
func clientPathFor(n int) string {
	return fmt.Sprintf("msrps://msrp.example.net:2856/%sclient%d;tcp", strings.Repeat("c", 24), n)
}
func corePathFor(n int) string {
	return fmt.Sprintf("msrp://10.0.2.9:9/%score%d;tcp", strings.Repeat("r", 24), n)
}

// anchoring is a pcscf that anchors MSRP through a scripted relay and sends
// its own requests through a fakeSender, with alice registered over FLOW-A.
type anchoring struct {
	p     *pcscf
	clock *testClock
	relay *scriptedRelay
	base  *url.URL
	sent  *fakeSender
	alive map[transport.FlowID]bool
}

func newAnchoring(t *testing.T, perFlow, total int) *anchoring {
	t.Helper()
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	relay := &scriptedRelay{bodies: map[int]map[string]any{}}
	srv := httptest.NewServer(relay)
	t.Cleanup(srv.Close)
	base, _ := url.Parse(srv.URL)
	a := &anchoring{p: p, clock: clock, relay: relay, base: base, sent: &fakeSender{}, alive: map[transport.FlowID]bool{"FLOW-A": true}}
	// The relay's answers are timed by the test, never by the client: a
	// loaded host may take more than a second for one (make race).
	p.msrp = newMSRPAnchor(context.Background(), newRelayClient(base, testRelayToken, waitFor, nil), newBindingLimit(perFlow, total, DefaultBindingsPerMinute, clock.now))
	p.send = a.sent.send
	var mu sync.Mutex
	p.clientFlow = func(id transport.FlowID) bool { mu.Lock(); defer mu.Unlock(); return a.alive[id] }
	// For an hour, as a client that keeps its flow alive.
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute, "P-Associated-URI: <"+aliceIMPU+">", "Require: outbound")
	return a
}

// settle waits for the relay calls and requests pcscf made in the
// background.
func (a *anchoring) settle() { a.p.msrp.wait() }

// clientContact is alice's Contact in her INVITEs.
const clientContact = "sip:alice@192.0.2.10:40000;transport=tcp;ob"

// inviteWith is alice's INVITE to bob in call call with a body of
// contentType.
func inviteWith(call, contentType, body string, extra ...string) string {
	text := initialText("INVITE", append([]string{"Contact: <" + clientContact + ">"}, extra...)...)
	text = strings.Replace(text, "Call-ID: orig-1", "Call-ID: "+call, 1)
	if contentType == "" {
		return text
	}
	return strings.Replace(text, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, len(body), body), 1)
}

// rcsAsAnswer is rcs-as's answer to the relay's offer: passive, on its
// MSRP port.
var rcsAsAnswer = lines(
	"v=0",
	"o=rcs-as 3913000002 3913000002 IN IP4 10.0.1.20",
	"s=-",
	"c=IN IP4 10.0.1.20",
	"t=0 0",
	"m=audio 0 RTP/AVP 0",
	"m=message 2855 TCP/MSRP *",
	"a=accept-types:message/cpim application/im-iscomposing+xml",
	"a=path:msrp://10.0.1.20:2855/as9f2c1;tcp",
	"a=setup:passive",
	"a=sendrecv",
)

// answered is the core's response with code to req, as rcs-as and scscf
// send it: To tag, Contact, the request's Record-Route below scscf's, and
// body as an SDP answer if any.
func answered(t *testing.T, req *sip.Request, code int, tag, body string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range [][2]string{{"Contact", "<sip:rcs-as@10.0.1.20:5060;transport=tcp>"}, {"Record-Route", "<sip:scscf.rcs.internal;transport=tcp;lr>"}} {
		_ = res.Header.Add(f[0], f[1])
	}
	for _, v := range req.Header.Values("Record-Route") {
		_ = res.Header.Add("Record-Route", v)
	}
	if body != "" {
		_ = res.Header.Set("Content-Type", "application/sdp")
		res.Body = []byte(body)
	}
	return res
}

// call is a client's INVITE through pcscf: its decision and the INVITE as
// it went to the core.
type call struct {
	r   *proxy.Request
	d   proxy.Decision
	req *sip.Request
}

func (a *anchoring) invite(t *testing.T, callID, contentType, body string, extra ...string) call {
	t.Helper()
	r := clientRequest(t, inviteWith(callID, contentType, body, extra...), "FLOW-A")
	d := a.p.Route(context.Background(), r)
	if len(d.Targets) != 1 {
		t.Fatalf("not forwarded: %+v", d)
	}
	req := r.Message.Clone()
	for _, rr := range d.RecordRoute {
		_ = req.Header.Add("Record-Route", rr.String())
	}
	if err := d.Prepare(context.Background(), d.Targets[0], req); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return call{r: r, d: d, req: req}
}

// respond runs res through c's hooks as the proxy does and returns it.
func (c call) respond(res *sip.Response) *sip.Response {
	if res.StatusCode >= 300 && c.d.OnFinal != nil {
		c.d.OnFinal(context.Background(), res)
	}
	c.d.OnResponse(context.Background(), res)
	return res
}

// clientMSRP is the MSRP media line of a description toward the client.
func mediaOf(t *testing.T, body []byte, want string) {
	t.Helper()
	if !strings.Contains(string(body), want) {
		t.Errorf("body\n%s\nlacks %q", body, want)
	}
}

// A client's chat INVITE is anchored (ADR 0004, first row): a binding for
// the client's path, the offer to the core with the relay's core-side path,
// active, port 9, and the answer to the client with the relay's client
// path, passive, once the binding has rcs-as's path; the rest of both
// descriptions is untouched. The client's BYE releases the binding.
func TestAClientsChatIsAnchoredThroughTheRelay(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	got := string(c.req.Body)
	want := strings.NewReplacer(
		"m=message 9 TCP/TLS/MSRP *", "m=message 9 TCP/MSRP *\r\nc=IN IP4 10.0.2.9",
		"a=setup:actpass", "a=setup:active",
		"a=path:msrps://192.0.2.10:9/s7d2k8f;tcp", "a=path:"+corePathFor(1),
	).Replace(clientChatOffer)
	if got != want {
		t.Errorf("offer to the core:\n%s\nwant:\n%s", got, want)
	}
	if calls := a.relay.log(); len(calls) != 1 || calls[0] != "POST /v1/bindings" ||
		fmt.Sprint(a.relay.bodies[0]["client_endpoint_path"]) != "[msrps://192.0.2.10:9/s7d2k8f;tcp]" || a.relay.bodies[0]["expires_in"] != 1800.0 {
		t.Fatalf("relay calls %q %v", calls, a.relay.bodies)
	}
	if a.p.msrp.limit.held() != 1 {
		t.Errorf("held %d", a.p.msrp.limit.held())
	}

	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	mediaOf(t, ok.Body, "m=message 2856 TCP/TLS/MSRP *\r\n")
	mediaOf(t, ok.Body, "c=IN IP4 msrp.example.net\r\n")
	mediaOf(t, ok.Body, "o=rcs-as 3913000002 3913000002 IN IP4 msrp.example.net\r\n")
	mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
	mediaOf(t, ok.Body, "a=setup:passive")
	mediaOf(t, ok.Body, "m=audio 0 RTP/AVP 0\r\n")
	if strings.Contains(string(ok.Body), "10.0.1.20:2855") {
		t.Errorf("rcs-as's path reached the client:\n%s", ok.Body)
	}
	if calls := a.relay.log(); len(calls) != 2 || calls[1] != "PATCH /v1/bindings/"+bindingIDFor(1) ||
		fmt.Sprint(a.relay.bodies[1]["core_path"]) != "[msrp://10.0.1.20:2855/as9f2c1;tcp]" {
		t.Fatalf("relay calls %q %v", calls, a.relay.bodies)
	}
	// A retransmission is rewritten the same, and asks nothing more.
	again := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	if string(again.Body) != string(ok.Body) || len(a.relay.log()) != 2 {
		t.Errorf("retransmission:\n%s\ncalls %q", again.Body, a.relay.log())
	}

	bye := inDialogFrom(t, []string{clientEnt, "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr"}, "sip:rcs-as@10.0.1.20:5060", "Route: "+scscfRoute)
	bye.Message.Header.Set("Call-ID", "chat-1")
	bye.Routed[1].URI.Params.Set(dialogParam, testPcscfMAC("FLOW-A", "chat-1", ""))
	if d := a.p.Route(context.Background(), bye); len(d.Targets) != 1 {
		t.Fatalf("BYE: %+v", d)
	}
	a.settle()
	if calls := a.relay.log(); len(calls) != 3 || calls[2] != "DELETE /v1/bindings/"+bindingIDFor(1) || a.p.msrp.limit.held() != 0 {
		t.Errorf("after BYE: calls %q, held %d", calls, a.p.msrp.limit.held())
	}
}

// An offer pcscf will not anchor is refused before anything is allocated:
// a=setup:passive (RFC 6135 §4.2.2), a path through relays (RFC 4976), a
// description or body it cannot read; without a relay token, 503.
func TestAnOfferPcscfWillNotAnchorIsRefused(t *testing.T) {
	multipart := "--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b1--"
	for _, tt := range []struct {
		name, ct, body string
	}{
		{"passive", "application/sdp", strings.Replace(clientChatOffer, "a=setup:actpass", "a=setup:passive", 1)},
		{"relays in the path", "application/sdp", strings.Replace(clientChatOffer, "s7d2k8f;tcp", "s7d2k8f;tcp msrp://192.0.2.99:2855/r;tcp", 1)},
		{"a broken description", "application/sdp", strings.Replace(clientChatOffer, "t=0 0", "t=zero", 1)},
		{"two descriptions", "multipart/mixed;boundary=b1", multipart},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			d := a.p.Route(context.Background(), clientRequest(t, inviteWith("chat-1", tt.ct, tt.body), "FLOW-A"))
			if d.Status != 488 || len(a.relay.log()) != 0 {
				t.Errorf("%+v, relay calls %q", d, a.relay.log())
			}
		})
	}
	a := newAnchoring(t, 16, 100)
	a.p.msrp.relay = nil
	d := a.p.Route(context.Background(), clientRequest(t, inviteWith("chat-1", "application/sdp", clientChatOffer), "FLOW-A"))
	if d.Response == nil || d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1" {
		t.Errorf("without a relay: %+v", d)
	}
	// An INVITE with no MSRP line, or no body, goes as it is.
	audio := strings.Split(clientChatOffer, "m=message")[0]
	if c := a.invite(t, "call-1", "application/sdp", audio); string(c.req.Body) != audio {
		t.Errorf("an offer without MSRP was changed:\n%s", c.req.Body)
	}
}

// Past the flow's or the task's binding limit, past the bindings a flow
// may create in a minute, or when the relay fails, the INVITE is answered
// 503 with Retry-After and holds nothing: a binding already made for it is
// released (#136 decisions 4 and 5). A path the relay refuses, which
// waiting will not change, is 488.
func TestAnUnanchoredOfferIs503(t *testing.T) {
	twoLines := clientChatOffer + lines("m=message 9 TCP/TLS/MSRP *", "a=setup:active", "a=path:msrps://192.0.2.10:9/second;tcp")
	for _, tt := range []struct {
		name       string
		setup      func(a *anchoring)
		fail       func(method string, n int) int
		status     int
		retryAfter string
		deletes    int
	}{
		{"past the flow's limit", func(a *anchoring) {
			a.p.msrp.limit = newBindingLimit(2, 100, 32, a.clock.now)
			_, _ = a.p.msrp.limit.take(share{flow: "FLOW-A"}, 1)
		}, nil, 503, "1", 0},
		{"past the task's limit", func(a *anchoring) {
			a.p.msrp.limit = newBindingLimit(16, 2, 32, a.clock.now)
			_, _ = a.p.msrp.limit.take(share{flow: "FLOW-B"}, 1)
		}, nil, 503, "1", 0},
		// Two a minute: the one taken comes back in 30 s.
		{"past the flow's rate", func(a *anchoring) {
			a.p.msrp.limit = newBindingLimit(16, 100, 2, a.clock.now)
			_, _ = a.p.msrp.limit.take(share{flow: "FLOW-A"}, 1)
			a.p.msrp.limit.give(share{flow: "FLOW-A"}, 1)
		}, nil, 503, "30", 0},
		{"the relay refusing", nil, func(m string, _ int) int {
			if m == http.MethodPost {
				return 503
			}
			return 0
		}, 503, "1", 0},
		{"the relay failing the second", nil, func(m string, n int) int {
			if m == http.MethodPost && n == 2 {
				return 500
			}
			return 0
		}, 503, "1", 1},
		{"the relay refusing the path", nil, func(m string, n int) int {
			if m == http.MethodPost && n == 2 {
				return 400
			}
			return 0
		}, 488, "", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			if tt.setup != nil {
				tt.setup(a)
			}
			held := a.p.msrp.limit.held()
			a.relay.fail = tt.fail
			r := clientRequest(t, inviteWith("chat-1", "application/sdp", twoLines), "FLOW-A")
			d := a.p.Route(context.Background(), r)
			if len(d.Targets) != 1 {
				t.Fatalf("not forwarded: %+v", d)
			}
			req := r.Message.Clone()
			if err := d.Prepare(context.Background(), d.Targets[0], req); err == nil {
				t.Fatal("Prepare anchored it")
			}
			res, _ := sip.NewResponse(r.Message, 500, "", "p1")
			d.OnFinal(context.Background(), res)
			d.OnResponse(context.Background(), res)
			a.settle()
			if res.StatusCode != tt.status || res.Header.Get("Retry-After") != tt.retryAfter {
				t.Errorf("answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
			}
			if a.p.msrp.limit.held() != held || a.relay.count(http.MethodDelete) != tt.deletes || len(a.p.msrp.all()) != 0 {
				t.Errorf("held %d, calls %q", a.p.msrp.limit.held(), a.relay.log())
			}
		})
	}
}

// A failure response, a CANCEL's 487 included, releases the bindings.
func TestAFailedSetupReleasesTheBinding(t *testing.T) {
	for _, code := range []int{486, 487, 408, 503} {
		a := newAnchoring(t, 16, 100)
		c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
		c.respond(answered(t, c.req, 180, "b1", ""))
		c.respond(answered(t, c.req, code, "b1", ""))
		a.settle()
		if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 || len(a.p.msrp.all()) != 0 {
			t.Errorf("%d: calls %q, held %d", code, a.relay.log(), a.p.msrp.limit.held())
		}
	}
}

// The first answer, in a 183 here, completes the binding; the 2xx after
// it, without a description, keeps it.
func TestAnAnswerInAProvisionalResponseCompletesTheBinding(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	early := c.respond(answered(t, c.req, 183, "b1", rcsAsAnswer))
	mediaOf(t, early.Body, "a=path:"+clientPathFor(1))
	c.respond(answered(t, c.req, 200, "b1", ""))
	a.settle()
	if a.relay.count(http.MethodPatch) != 1 || a.relay.count(http.MethodDelete) != 0 || len(a.sent.take(a.p)) != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
}

// ackFor is alice's ACK of res, a 2xx to c's INVITE.
func ackFor(t *testing.T, c call, res *sip.Response) *proxy.Request {
	t.Helper()
	to, _ := res.Header.To()
	r := inDialogFrom(t, []string{clientEnt, "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr"}, "sip:rcs-as@10.0.1.20:5060", "Route: "+scscfRoute)
	r.Message.Method = "ACK"
	_ = r.Message.Header.Set("CSeq", "1 ACK")
	_ = r.Message.Header.Set("Call-ID", c.req.Header.Get("Call-ID"))
	_ = r.Message.Header.Set("To", to.String())
	r.Routed[1].URI.Params.Set(dialogParam, testPcscfMAC("FLOW-A", c.req.Header.Get("Call-ID"), ""))
	return r
}

// checkEnd checks the two BYEs that end a dialog: one to the client over
// its flow, as from the far end, and one to the core along the dialog's
// route past pcscf's own values, as from the client; both with reason.
func checkEnd(t *testing.T, a *anchoring, toTag, reason string) {
	t.Helper()
	checkEndSeq(t, a, toTag, reason, "2 BYE")
}

// checkEndSeq is checkEnd with the CSeq the BYE to the core has, past the
// client's requests in the dialog.
func checkEndSeq(t *testing.T, a *anchoring, toTag, reason, cseq string) {
	t.Helper()
	sent := a.sent.take(a.p)
	if len(sent) != 2 {
		t.Fatalf("%d requests sent, want two BYEs", len(sent))
	}
	var client, core *sentRequest
	for i := range sent {
		if sent[i].dst.Flow == "FLOW-A" {
			client = &sent[i]
		} else {
			core = &sent[i]
		}
	}
	if client == nil || core == nil {
		t.Fatalf("BYEs to %+v and %+v", sent[0].dst, sent[1].dst)
	}
	cf, _ := client.req.Header.From()
	ct, _ := client.req.Header.To()
	if client.req.Method != "BYE" || client.req.URI.String() != clientContact || cf.Tag() != toTag || ct.Tag() != "a1" ||
		client.req.Header.Get("Reason") != reason || client.req.Header.Has("Route") {
		t.Errorf("BYE to the client: %s %s From %q To %q Reason %q Route %q", client.req.Method, client.req.URI,
			client.req.Header.Get("From"), client.req.Header.Get("To"), client.req.Header.Get("Reason"), client.req.Header.Values("Route"))
	}
	kf, _ := core.req.Header.From()
	kt, _ := core.req.Header.To()
	if core.req.Method != "BYE" || core.req.URI.String() != "sip:rcs-as@10.0.1.20:5060;transport=tcp" || kf.Tag() != "a1" || kt.Tag() != toTag ||
		core.req.Header.Get("Reason") != reason || strings.Join(core.req.Header.Values("Route"), ",") != "<sip:scscf.rcs.internal;transport=tcp;lr>" ||
		core.req.Header.Get("CSeq") != cseq || core.dst.Addr != netip.MustParseAddrPort("10.0.4.4:5060") {
		t.Errorf("BYE to the core: %s %s From %q To %q Reason %q Route %q CSeq %q to %+v", core.req.Method, core.req.URI,
			core.req.Header.Get("From"), core.req.Header.Get("To"), core.req.Header.Get("Reason"), core.req.Header.Values("Route"), core.req.Header.Get("CSeq"), core.dst)
	}
}

// When the relay cannot complete the binding at answer time the 2xx still
// goes to the client, never with rcs-as's path, the binding is released
// before it goes, and the ACK sends a BYE each way with Reason 503 (#136
// decision 6).
func TestARelayFailureAtTheAnswerEndsTheSession(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	var out strings.Builder
	a.p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", a.clock.now, a.p.log)
	a.relay.fail = func(m string, _ int) int {
		if m == http.MethodPatch {
			return 503
		}
		return 0
	}
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	ok := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	mediaOf(t, ok.Body, "a=path:"+clientPathFor(1))
	if strings.Contains(string(ok.Body), "10.0.1.20") {
		t.Errorf("rcs-as's address reached the client:\n%s", ok.Body)
	}
	// Released before the 2xx went on, not in the background.
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 {
		t.Fatalf("not released before the 2xx: %q", a.relay.log())
	}
	a.settle()
	if d := a.p.Route(context.Background(), ackFor(t, c, ok)); len(d.Targets) != 1 {
		t.Fatalf("ACK: %+v", d)
	}
	checkEnd(t, a, "b1", reasonRelayUnavailable)
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricEndedRelay+`":1`) || !strings.Contains(out.String(), `"`+metricRelayErrors+`":1`) {
		t.Errorf("metrics %s", out.String())
	}
	if len(a.p.msrp.all()) != 0 {
		t.Error("the session stayed")
	}
}

// A 2xx of another fork, or another answer, goes to the client with its
// MSRP lines declined, and its dialog is ended; the first dialog keeps its
// binding (#136 decision 3).
func TestASecondAnswerIsEnded(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	other := c.respond(answered(t, c.req, 200, "b2", strings.Replace(rcsAsAnswer, "as9f2c1", "other1", 1)))
	mediaOf(t, other.Body, "m=message 0 TCP/MSRP *")
	if strings.Contains(string(other.Body), "a=path") {
		t.Errorf("the second answer keeps a path:\n%s", other.Body)
	}
	if d := a.p.Route(context.Background(), ackFor(t, c, other)); len(d.Targets) != 1 {
		t.Fatalf("ACK: %+v", d)
	}
	a.settle()
	checkEnd(t, a, "b2", reasonSecondAnswer)
	if len(a.p.msrp.all()) != 1 || a.relay.count(http.MethodDelete) != 0 {
		t.Errorf("the first dialog lost its binding: %q", a.relay.log())
	}
	// Without its ACK, the sweep ends a dialog after 64*T1, 32 s.
	third := c.respond(answered(t, c.req, 200, "b3", strings.Replace(rcsAsAnswer, "as9f2c1", "third1", 1)))
	_ = third
	a.clock.t = a.clock.t.Add(32*time.Second - time.Second)
	a.p.sweepMSRP()
	a.settle()
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Fatalf("ended before 32 s: %d", len(got))
	}
	a.clock.t = a.clock.t.Add(time.Second)
	a.p.sweepMSRP()
	a.settle()
	checkEnd(t, a, "b3", reasonSecondAnswer)
}

// A confirmed session's bindings are extended every 15 minutes; a
// session whose flow has gone, or whose setup never ended, is released.
func TestTheSweepKeepsLiveSessionsAndEndsTheRest(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.clock.t = a.clock.t.Add(15*time.Minute - time.Second)
	a.p.sweepMSRP()
	a.settle()
	if a.relay.count(http.MethodPatch) != 1 {
		t.Fatalf("extended early: %q", a.relay.log())
	}
	a.clock.t = a.clock.t.Add(time.Second)
	a.p.sweepMSRP()
	a.settle()
	calls := a.relay.log()
	if a.relay.count(http.MethodPatch) != 2 || a.relay.bodies[len(calls)-1]["expires_in"] != 1800.0 {
		t.Fatalf("not extended: %q %v", calls, a.relay.bodies)
	}

	stuck := a.invite(t, "chat-2", "application/sdp", clientChatOffer)
	_ = stuck
	a.clock.t = a.clock.t.Add(10 * time.Minute)
	a.p.sweepMSRP()
	a.settle()
	if len(a.p.msrp.all()) != 1 || a.relay.count(http.MethodDelete) != 1 {
		t.Fatalf("a setup that never ended stayed: %q", a.relay.log())
	}
	a.alive["FLOW-A"] = false
	a.p.sweepMSRP()
	a.settle()
	if len(a.p.msrp.all()) != 0 || a.relay.count(http.MethodDelete) != 2 || a.p.msrp.limit.held() != 0 {
		t.Errorf("a session of a gone flow stayed: %q", a.relay.log())
	}
}

// A closed flow's sessions are released at once (RFC 5626 §5.3).
func TestAClosedFlowReleasesItsSessions(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
	a.p.msrpFlowClosed("FLOW-B")
	a.p.msrpFlowClosed("FLOW-A")
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
}

// A chat INVITE carrying its first message is multipart: its description
// is anchored and the message part goes as it was.
func TestAMultipartOfferIsAnchored(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	cpim := "From: <sip:anonymous@anonymous.invalid>\r\n\r\nContent-Type: text/plain\r\n\r\nhi"
	body := "--b1\r\nContent-Type: application/sdp\r\n\r\n" + clientChatOffer + "\r\n--b1\r\nContent-Type: message/cpim\r\n\r\n" + cpim + "\r\n--b1--\r\n"
	c := a.invite(t, "chat-1", "multipart/mixed;boundary=b1", body)
	got := string(c.req.Body)
	if !strings.Contains(got, "a=path:"+corePathFor(1)) || !strings.HasSuffix(got, "\r\n--b1\r\nContent-Type: message/cpim\r\n\r\n"+cpim+"\r\n--b1--\r\n") ||
		!strings.HasPrefix(got, "--b1\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n") {
		t.Errorf("body:\n%s", got)
	}
}

// An answer pcscf cannot read reaches the client without its description,
// never as rcs-as wrote it, and its 2xx ends the dialog; so does a 2xx
// that brings no answer at all.
func TestAnAnswerPcscfCannotServeEndsTheDialog(t *testing.T) {
	for name, tt := range map[string]struct{ ct, answer string }{
		"unreadable":          {"application/sdp", strings.Replace(rcsAsAnswer, "t=0 0", "t=zero", 1)},
		"a body unsplittable": {"multipart/mixed;boundary=b1", "--b1\r\nContent-Type: application/sdp\r\n\r\n" + rcsAsAnswer},
		"none":                {"", ""},
		// The relay offered active: rcs-as must listen (RFC 6135 §4.2.2).
		"active": {"application/sdp", strings.Replace(rcsAsAnswer, "a=setup:passive", "a=setup:active", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAnchoring(t, 16, 100)
			c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
			res := answered(t, c.req, 200, "b1", tt.answer)
			if tt.ct != "" {
				_ = res.Header.Set("Content-Type", tt.ct)
			}
			ok := c.respond(res)
			if strings.Contains(string(ok.Body), "10.0.1.20") {
				t.Errorf("rcs-as's address reached the client: %q", ok.Body)
			}
			if a.relay.count(http.MethodDelete) != 1 {
				t.Errorf("not released: %q", a.relay.log())
			}
			a.p.Route(context.Background(), ackFor(t, c, ok))
			checkEnd(t, a, "b1", reasonRelayUnavailable)
		})
	}
}

// A line rcs-as declines, with port 0, gives back its binding; the session
// goes on with the others.
func TestADeclinedLineReleasesItsBinding(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	c.respond(answered(t, c.req, 200, "b1", strings.Replace(rcsAsAnswer, "m=message 2855", "m=message 0", 1)))
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.relay.count(http.MethodPatch) != 0 {
		t.Errorf("calls %q", a.relay.log())
	}
	if got := a.sent.take(a.p); len(got) != 0 {
		t.Errorf("%d requests sent", len(got))
	}
}

// A 2xx of another fork after the first answer came in a 183 is ended, and
// releases the bindings at once: they served the first fork's early dialog,
// which that 2xx ends (RFC 3261 §13.2.2.4). A 2xx of the first fork after
// it gets no path of theirs and is ended too.
func TestAnotherForksAnswerReleasesTheFirstForksBindings(t *testing.T) {
	for _, body := range []string{"", strings.Replace(rcsAsAnswer, "as9f2c1", "other1", 1)} {
		a := newAnchoring(t, 16, 100)
		c := a.invite(t, "chat-1", "application/sdp", clientChatOffer)
		c.respond(answered(t, c.req, 183, "b1", rcsAsAnswer))
		other := c.respond(answered(t, c.req, 200, "b2", body))
		a.settle()
		if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 0 {
			t.Fatalf("not released: calls %q, held %d", a.relay.log(), a.p.msrp.limit.held())
		}
		if strings.Contains(string(other.Body), "a=path") {
			t.Errorf("the other fork's 2xx has a path:\n%s", other.Body)
		}
		a.p.Route(context.Background(), ackFor(t, c, other))
		checkEnd(t, a, "b2", reasonSecondAnswer)
		if len(a.p.msrp.all()) != 0 {
			t.Error("the session stayed")
		}
		late := c.respond(answered(t, c.req, 200, "b1", rcsAsAnswer))
		if strings.Contains(string(late.Body), clientPathFor(1)) || strings.Contains(string(late.Body), "10.0.1.20") {
			t.Errorf("the first fork's late 2xx:\n%s", late.Body)
		}
		a.p.Route(context.Background(), ackFor(t, c, late))
		checkEnd(t, a, "b1", reasonRelayUnavailable)
		for range 4 * 60 * 2 { // two hours of sweeps
			a.clock.t = a.clock.t.Add(30 * time.Second)
			a.p.sweepMSRP()
		}
		a.settle()
		if a.relay.count(http.MethodDelete) != 1 || len(a.relay.log()) != 3 || len(a.p.msrp.all()) != 0 || len(a.sent.take(a.p)) != 0 {
			t.Errorf("after two hours: calls %q, %d sessions", a.relay.log(), len(a.p.msrp.all()))
		}
	}
}

// A new INVITE with the Call-ID and tag of a session that lives ends that
// session, so its bindings are not left behind.
func TestASessionReplacedReleasesTheOld(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	a.settle()
	if a.relay.count(http.MethodDelete) != 1 || a.p.msrp.limit.held() != 1 || len(a.p.msrp.all()) != 1 {
		t.Errorf("calls %q, held %d", a.relay.log(), a.p.msrp.limit.held())
	}
}

// The sweep reports the bindings held.
func TestTheSweepReportsTheBindingsHeld(t *testing.T) {
	a := newAnchoring(t, 16, 100)
	var out strings.Builder
	a.p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", a.clock.now, a.p.log)
	a.invite(t, "chat-1", "application/sdp", clientChatOffer)
	a.p.sweepMSRP()
	a.p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricBindings+`":1`) {
		t.Errorf("metrics %s", out.String())
	}
}
