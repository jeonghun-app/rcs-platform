package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// TestRouteProcessing runs requests through the proxy with the default Router,
// which forwards to the Request-URI, and checks what leaves: the Request-URI,
// the Route, and the next hop resolved. The §16.12 cases follow the examples of
// RFC 3261 §16.12.1, one hop at a time, written for this proxy.
func TestRouteProcessing(t *testing.T) {
	tests := []struct {
		name   string
		self   []string
		uri    string
		routes []string
		// want is the request sent: its Request-URI, then its Route values.
		wantURI    string
		wantRoutes []string
		wantHop    string
		wantRouted []string
	}{
		{
			name:    "a request without Route goes to its Request-URI",
			self:    []string{"sip:p1.example.com"},
			uri:     "sip:callee@domain.com",
			wantURI: "sip:callee@domain.com", wantHop: "domain.com",
		},
		{
			name:       "§16.12.1.1: P1 removes its own Route and sends to P2",
			self:       []string{"sip:p1.example.com"},
			uri:        "sip:callee@u2.domain.com",
			routes:     []string{"<sip:p1.example.com;lr>", "<sip:p2.domain.com;lr>"},
			wantURI:    "sip:callee@u2.domain.com",
			wantRoutes: []string{"<sip:p2.domain.com;lr>"},
			wantHop:    "p2.domain.com",
			wantRouted: []string{"<sip:p1.example.com;lr>"},
		},
		{
			name:       "§16.12.1.1: P2 removes the last Route and sends to the Request-URI",
			self:       []string{"sip:p2.domain.com"},
			uri:        "sip:callee@u2.domain.com",
			routes:     []string{"<sip:p2.domain.com;lr>"},
			wantURI:    "sip:callee@u2.domain.com",
			wantHop:    "u2.domain.com",
			wantRouted: []string{"<sip:p2.domain.com;lr>"},
		},
		{
			name:   "§16.12.1.2: P4 reformats the request for the strict router P3",
			self:   []string{"sip:p4.domain.com"},
			uri:    "sip:caller@u1.example.com",
			routes: []string{"<sip:p4.domain.com;lr>", "<sip:p3.middle.com>", "<sip:p2.example.com;lr>", "<sip:p1.example.com;lr>"},
			// The Request-URI becomes the strict router and moves to the end.
			wantURI:    "sip:p3.middle.com",
			wantRoutes: []string{"<sip:p2.example.com;lr>", "<sip:p1.example.com;lr>", "<sip:caller@u1.example.com>"},
			wantHop:    "p3.middle.com",
			wantRouted: []string{"<sip:p4.domain.com;lr>"},
		},
		{
			name:   "§16.12.1.2: P2 restores the Request-URI a strict router replaced with its Record-Route",
			self:   []string{"sip:p2.example.com"},
			uri:    "sip:p2.example.com;lr",
			routes: []string{"<sip:p1.example.com;lr>", "<sip:caller@u1.example.com>"},
			// The last Route was the Request-URI; P1 is next.
			wantURI:    "sip:caller@u1.example.com",
			wantRoutes: []string{"<sip:p1.example.com;lr>"},
			wantHop:    "p1.example.com",
			wantRouted: []string{"<sip:p2.example.com;lr>"},
		},
		{
			name:       "§16.12.1.2: P1 removes its Route and sends to the Request-URI",
			self:       []string{"sip:p1.example.com"},
			uri:        "sip:caller@u1.example.com",
			routes:     []string{"<sip:p1.example.com;lr>"},
			wantURI:    "sip:caller@u1.example.com",
			wantHop:    "u1.example.com",
			wantRouted: []string{"<sip:p1.example.com;lr>"},
		},
		{
			name:       "RFC 5658 §5: both Routes of a double Record-Route are removed",
			self:       []string{"sip:pcscf.example.net", "sip:198.51.100.7:5070"},
			uri:        "sip:alice@192.0.2.10:5060",
			routes:     []string{"<sip:pcscf.example.net;lr>", "<sip:flow-token@198.51.100.7:5070;lr>", "<sip:scscf.example.net;lr>"},
			wantURI:    "sip:alice@192.0.2.10:5060",
			wantRoutes: []string{"<sip:scscf.example.net;lr>"},
			wantHop:    "scscf.example.net",
			wantRouted: []string{"<sip:pcscf.example.net;lr>", "<sip:flow-token@198.51.100.7:5070;lr>"},
		},
		{
			name:       "an absent port matches the default port",
			self:       []string{"sip:proxy.example.net"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:PROXY.example.net:5060;lr>"},
			wantURI:    "sip:bob@example.com",
			wantHop:    "example.com",
			wantRouted: []string{"<sip:PROXY.example.net:5060;lr>"},
		},
		{
			name:       "a SIPS URI defaults to port 5061",
			self:       []string{"sip:proxy.example.net:5061"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sips:proxy.example.net;lr>"},
			wantURI:    "sip:bob@example.com",
			wantHop:    "example.com",
			wantRouted: []string{"<sips:proxy.example.net;lr>"},
		},
		{
			// An address written another way is still this proxy's
			// (review of #208): IPv4-mapped, bracketed, case, trailing dot.
			name:       "an IPv4-mapped form of its address is this proxy",
			self:       []string{"sip:10.0.2.9:5070"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:[::ffff:10.0.2.9]:5070;transport=tcp;lr>"},
			wantURI:    "sip:bob@example.com",
			wantHop:    "example.com",
			wantRouted: []string{"<sip:[::ffff:10.0.2.9]:5070;transport=tcp;lr>"},
		},
		{
			name:       "another spelling of its IPv6 address is this proxy",
			self:       []string{"sip:[fd00:0:0::9]:5070"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:[FD00::9]:5070;lr>"},
			wantURI:    "sip:bob@example.com",
			wantHop:    "example.com",
			wantRouted: []string{"<sip:[FD00::9]:5070;lr>"},
		},
		{
			name:       "a name with a trailing dot is this proxy",
			self:       []string{"sip:proxy.example.net"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:PROXY.example.net.:5060;lr>"},
			wantURI:    "sip:bob@example.com",
			wantHop:    "example.com",
			wantRouted: []string{"<sip:PROXY.example.net.:5060;lr>"},
		},
		{
			name:       "another port of the same host is another element",
			self:       []string{"sip:proxy.example.net"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:proxy.example.net:5070;lr>"},
			wantURI:    "sip:bob@example.com",
			wantRoutes: []string{"<sip:proxy.example.net:5070;lr>"},
			wantHop:    "proxy.example.net",
		},
		{
			name:       "a Route naming this proxy below another is left for later",
			self:       []string{"sip:proxy.example.net"},
			uri:        "sip:bob@example.com",
			routes:     []string{"<sip:as.example.net;lr>", "<sip:proxy.example.net;lr;odi=1>"},
			wantURI:    "sip:bob@example.com",
			wantRoutes: []string{"<sip:as.example.net;lr>", "<sip:proxy.example.net;lr;odi=1>"},
			wantHop:    "as.example.net",
		},
		{
			name:    "a Request-URI naming this proxy without a Route is not a strict router's doing",
			self:    []string{"sip:proxy.example.net"},
			uri:     "sip:proxy.example.net;lr",
			wantURI: "sip:proxy.example.net;lr", wantHop: "proxy.example.net",
		},
		{
			name:       "a Request-URI naming this proxy without lr is not a Record-Route of ours",
			self:       []string{"sip:proxy.example.net"},
			uri:        "sip:conference@proxy.example.net",
			routes:     []string{"<sip:as.example.net;lr>"},
			wantURI:    "sip:conference@proxy.example.net",
			wantRoutes: []string{"<sip:as.example.net;lr>"},
			wantHop:    "as.example.net",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var self []sip.URI
			for _, s := range tt.self {
				self = append(self, mustURI(s))
			}
			h := newHarness(t, Config{Self: self})
			var extra []string
			for _, r := range tt.routes {
				extra = append(extra, "Route: "+r)
			}
			h.receive(request(t, "BYE", tt.uri, extra...))
			sent := h.sent()
			if len(sent) != 1 {
				t.Fatalf("sent %d requests, want 1", len(sent))
			}
			got := sent[0].req
			if got.URI.String() != tt.wantURI {
				t.Errorf("Request-URI = %s, want %s", got.URI.String(), tt.wantURI)
			}
			routes, err := got.Header.Elements("Route")
			if err != nil {
				t.Fatal(err)
			}
			check(t, "Route", routes, tt.wantRoutes)
			if sent[0].dst.ServerName != tt.wantHop {
				t.Errorf("next hop = %s, want %s", sent[0].dst.ServerName, tt.wantHop)
			}
			var routed []string
			for _, a := range h.lastSeen().Routed {
				routed = append(routed, a.String())
			}
			check(t, "Routed", routed, tt.wantRouted)
		})
	}
}

// TestRouteEditsKeepOtherFieldsByteForByte checks that removing the proxy's own
// Route leaves the other Route lines, and every other field, as received.
func TestRouteEditsKeepOtherFieldsByteForByte(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(request(t, "BYE", "sip:bob@example.com",
		"Route: <sip:proxy.example.net;lr>",
		"Route: <sip:NEXT.example.net;lr>;x=\"y\"",
		"X-Custom: kept  as   is"))
	got := h.one()
	check(t, "Route lines", got.Header.Values("Route"), []string{`<sip:NEXT.example.net;lr>;x="y"`})
	check(t, "X-Custom", got.Header.Values("X-Custom"), []string{"kept  as   is"})
}

func TestTargetRoutesArePushedOnTopOfTheRoute(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{
		URI:    mustURI("sip:alice@192.0.2.20"),
		Routes: []sip.Address{mustAddr("<sip:pcscf.example.net;lr>"), mustAddr("<sip:edge.example.net;lr>")},
	}}})
	h.receive(request(t, "MESSAGE", "sip:alice@example.com", "Route: <sip:proxy.example.net;lr>", "Route: <sip:later.example.net;lr>"))
	sent := h.sent()
	routes, _ := sent[0].req.Header.Elements("Route")
	check(t, "Route", routes, []string{"<sip:pcscf.example.net;lr>", "<sip:edge.example.net;lr>", "<sip:later.example.net;lr>"})
	if sent[0].dst.ServerName != "pcscf.example.net" {
		t.Errorf("next hop = %s, want the first pushed Route", sent[0].dst.ServerName)
	}
}

func TestRecordRouteValuesAreInsertedTopmostFirst(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{target("sip:bob@192.0.2.30")},
		// RFC 5658 §5: the outgoing interface on top, the incoming below.
		RecordRoute: []sip.Address{mustAddr("<sip:pcscf.example.net;lr>"), mustAddr("<sip:flow@198.51.100.7;lr>")},
	})
	h.receive(invite(t, "Record-Route: <sip:upstream.example.net;lr>"))
	got := h.one()
	rr, _ := got.Header.Elements("Record-Route")
	check(t, "Record-Route", rr, []string{"<sip:pcscf.example.net;lr>", "<sip:flow@198.51.100.7;lr>", "<sip:upstream.example.net;lr>"})
}

func TestARecordRouteWithoutLRIsRefusedAsARouterError(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets:     []Target{target("sip:bob@192.0.2.30")},
		RecordRoute: []sip.Address{mustAddr("<sip:pcscf.example.net>")},
	})
	h.receive(invite(t))
	check(t, "sent", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(500))
}

func TestForwardedRequestGetsANewViaAndOneLessMaxForwards(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Max-Forwards: 9"))
	got := h.one()
	vias, err := got.Header.Via()
	if err != nil {
		t.Fatal(err)
	}
	if len(vias) != 2 || vias[1].Branch() != "z9hG4bKup-MESSAGE" {
		t.Fatalf("Via = %v, want the proxy's above the received one", got.Header.Values("Via"))
	}
	if !vias[0].HasMagicCookie() || !strings.Contains(vias[0].Branch(), ".") {
		t.Errorf("branch %q lacks the magic cookie or the loop part", vias[0].Branch())
	}
	if mf, _ := got.Header.MaxForwards(); mf != 8 {
		t.Errorf("Max-Forwards = %d, want 8", mf)
	}
}

func TestMissingMaxForwardsIsSetTo70(t *testing.T) {
	h := newHarness(t, Config{})
	req := request(t, "MESSAGE", "sip:bob@example.com")
	req.Header.Del("Max-Forwards")
	h.receive(req)
	if mf, _ := h.one().Header.MaxForwards(); mf != 70 {
		t.Errorf("Max-Forwards = %d, want 70", mf)
	}
}

func TestBranchesOfOneRequestShareTheLoopPartButNotTheRandomPart(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")}})
	h.receive(invite(t))
	sent := h.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d, want 2", len(sent))
	}
	b0 := topBranch(t, sent[0].req)
	b1 := topBranch(t, sent[1].req)
	if b0 == b1 {
		t.Fatal("two branches share a branch ID")
	}
	if b0[strings.LastIndexByte(b0, '.'):] != b1[strings.LastIndexByte(b1, '.'):] {
		t.Errorf("loop parts differ: %s %s", b0, b1)
	}
}

func topBranch(t *testing.T, req *sip.Request) string {
	t.Helper()
	vias, err := req.Header.Via()
	if err != nil || len(vias) == 0 {
		t.Fatal("no Via")
	}
	return vias[0].Branch()
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name   string
		req    func(t *testing.T) *sip.Request
		code   int
		header [2]string
	}{
		{"Max-Forwards 0 is answered 483", func(t *testing.T) *sip.Request {
			return request(t, "MESSAGE", "sip:bob@example.com", "Max-Forwards: 0")
		}, 483, [2]string{}},
		{"Max-Forwards 0 on OPTIONS is answered 483 too", func(t *testing.T) *sip.Request {
			return request(t, "OPTIONS", "sip:bob@example.com", "Max-Forwards: 0")
		}, 483, [2]string{}},
		{"an unknown URI scheme is answered 416", func(t *testing.T) *sip.Request {
			return request(t, "MESSAGE", "urn:example:thing")
		}, 416, [2]string{}},
		{"an unsupported Proxy-Require is answered 420 naming it", func(t *testing.T) *sip.Request {
			return request(t, "MESSAGE", "sip:bob@example.com", "Proxy-Require: sec-agree, foo")
		}, 420, [2]string{"Unsupported", "foo"}},
		{"a malformed Route is answered 400", func(t *testing.T) *sip.Request {
			return request(t, "MESSAGE", "sip:bob@example.com", "Route: sip:bare.example.net")
		}, 400, [2]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Config{Supported: []string{"Sec-Agree"}})
			h.receive(tt.req(t))
			check(t, "sent", h.sentMethods(), nil)
			res := h.upstreamResponses()
			if len(res) != 1 || res[0].StatusCode != tt.code {
				t.Fatalf("upstream = %v, want %d", res, tt.code)
			}
			if tt.header[0] != "" && res[0].Header.Get(tt.header[0]) != tt.header[1] {
				t.Errorf("%s = %q, want %q", tt.header[0], res[0].Header.Get(tt.header[0]), tt.header[1])
			}
		})
	}
}

func TestTelRequestURIIsRouted(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.30")}})
	h.receive(request(t, "MESSAGE", "tel:+15550100001"))
	check(t, "sent", h.sentMethods(), []string{"MESSAGE sip:bob@192.0.2.30"})
}

// TestARequestThatComesBackUnchangedIsALoop sends the proxy's own output back
// to it: the same Request-URI and Route is a loop (482), while one whose Route
// changed, as after an application server, is a spiral and is forwarded.
func TestARequestThatComesBackUnchangedIsALoop(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	out := h.one()

	back := out.Clone()
	h.p.Receive(inboundFrom(back, "loop"))
	h.settle()
	check(t, "sent", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(482))
	if h.p.Stats().Loops != 1 {
		t.Errorf("Loops = %d, want 1", h.p.Stats().Loops)
	}

	spiral := out.Clone()
	if err := spiral.Header.Add("Route", "<sip:proxy.example.net;lr;odi=2>"); err != nil {
		t.Fatal(err)
	}
	h.p.Receive(inboundFrom(spiral, "spiral"))
	h.settle()
	check(t, "sent", h.sentMethods(), []string{"MESSAGE sip:bob@example.com"})
}

func TestRouterAnswers(t *testing.T) {
	tests := []struct {
		name string
		dec  func(r *Request) Decision
		want int
	}{
		{"an empty target set is answered 480", func(*Request) Decision { return Decision{} }, 480},
		{"a status is answered", func(*Request) Decision { return Decision{Status: 404} }, 404},
		{"a response is sent as built", func(r *Request) Decision {
			res, err := sip.NewResponse(r.Message, 200, "", "uas-tag")
			if err != nil {
				panic(err)
			}
			return Decision{Response: res}
		}, 200},
		{"an invalid status is a Router error", func(*Request) Decision { return Decision{Status: 1000} }, 500},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.route(func(_ contextT, r *Request) Decision { return tt.dec(r) })
			h.receive(request(t, "REGISTER", "sip:example.com"))
			check(t, "sent", h.sentMethods(), nil)
			check(t, "upstream", h.upstream(), codes(tt.want))
			if n := h.p.Stats().Contexts; n != 0 {
				t.Errorf("Contexts = %d after the answer, want 0", n)
			}
		})
	}
}

func TestStatusAnswerCarriesTheRoutersReason(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Status: 403, Reason: "Not Here"})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	res := h.upstreamResponses()
	if len(res) != 1 || res[0].Reason != "Not Here" {
		t.Fatalf("upstream = %v, want 403 Not Here", res)
	}
	if to, _ := res[0].Header.To(); to.Tag() == "" {
		t.Error("a 403 the proxy made has no To tag")
	}
}

func TestInitialTellsDialogCreatingRequestsApart(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(invite(t))
	if !h.lastSeen().Initial() {
		t.Error("an INVITE without a To tag is not Initial")
	}
	h.receive(request(t, "BYE", "sip:bob@192.0.2.30", "To: <sip:bob@example.com>;tag=b1"))
	if h.lastSeen().Initial() {
		t.Error("a BYE with a To tag is Initial")
	}
}

func TestPrepareChangesEachBranchCopy(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1"), target("sip:b@192.0.2.2")},
		Prepare: func(_ contextT, tg Target, req *sip.Request) error {
			req.Header.Del("P-Secret")
			return req.Header.Add("X-Branch", tg.URI.User)
		},
	})
	h.receive(invite(t, "P-Secret: internal"))
	for _, s := range h.sent() {
		if s.req.Header.Has("P-Secret") {
			t.Error("Prepare's removal did not reach the request sent")
		}
		if got := s.req.Header.Get("X-Branch"); got != s.req.URI.User {
			t.Errorf("X-Branch = %q on the branch to %s", got, s.req.URI.User)
		}
	}
	if !h.lastSeen().Message.Header.Has("P-Secret") {
		t.Error("Prepare changed the request the Router saw")
	}
}

func TestPrepareErrorFailsTheBranchWith500(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{
		Targets: []Target{target("sip:a@192.0.2.1")},
		Prepare: func(contextT, Target, *sip.Request) error { return errTest },
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	check(t, "sent", h.sentMethods(), nil)
	check(t, "upstream", h.upstream(), codes(500))
}

// A discarded request gets no response at all, not even a 100 Trying, and
// its retransmission is absorbed (TS 24.229 §5.2.6.3.2A).
func TestADiscardedRequestGetsNoResponse(t *testing.T) {
	for _, method := range []string{"MESSAGE", "INVITE"} {
		t.Run(method, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.decide(Decision{Discard: true, Status: 403})
			req := request(t, method, "sip:bob@example.com")
			h.receive(req)
			h.advance(time.Second)
			h.receive(req)
			h.advance(time.Second)
			check(t, "sent", h.sentMethods(), nil)
			check(t, "upstream", h.upstream(), nil)
			if n := h.p.Stats().Contexts; n != 0 {
				t.Errorf("Contexts = %d after the discard, want 0", n)
			}
		})
	}
}
