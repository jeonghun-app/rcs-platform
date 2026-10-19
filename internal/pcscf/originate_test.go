package pcscf

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	bobIMPU  = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
	carolTel = "tel:+15550100003"
	// scscfRoute is the Service-Route the tests' registrations receive.
	scscfRoute = "<sip:orig@10.0.4.4:5060;transport=tcp;lr>"
)

// initialText is a request from alice to bob outside a dialog; extra fields
// are written as they are.
func initialText(method string, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, bobIMPU)
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-orig-1\r\n")
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=a1\r\n")
	b.WriteString("To: <" + bobIMPU + ">\r\n")
	fmt.Fprintf(&b, "Call-ID: orig-1\r\nCSeq: 1 %s\r\n", method)
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// inDialogText is initialText inside the dialog: To has bob's tag.
func inDialogText(method string, extra ...string) string {
	return strings.Replace(initialText(method, extra...), "To: <"+bobIMPU+">", "To: <"+bobIMPU+">;tag=b1", 1)
}

// registerAlice registers alice over flow from 192.0.2.10, with the 200's
// extra fields.
func registerAlice(t *testing.T, p *pcscf, flow transport.FlowID, extra ...string) {
	t.Helper()
	d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact, "Supported: outbound"), flow))
	d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600", extra...)))
	if _, ok := p.registry.lookup(flow, aorKey(mustURI(t, aliceIMPU))); !ok {
		t.Fatal("not registered")
	}
}

// A request outside a dialog goes along the registration's Service-Route in
// place of the client's Route, with the default public identity asserted and
// the registration's tel URI beside it, a new charging identifier, and two
// Record-Route values: the core's naming the flow, the client's the public
// name (TS 24.229 §5.2.6.3.3, RFC 3325 §9.1, RFC 5658).
func TestAnInitialRequestGoesAlongTheServiceRouteAsTheDefaultIdentity(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute+", <sip:term@10.0.4.5;lr>",
		"P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">")
	r := clientRequest(t, initialText("INVITE", "Route: <sip:10.0.9.9;lr>"), "FLOW-A")
	d := p.Route(context.Background(), r)
	if d.Targets[0].URI.String() != bobIMPU {
		t.Errorf("target %v", d.Targets[0].URI)
	}
	var rr []string
	for _, a := range d.RecordRoute {
		rr = append(rr, a.String())
	}
	if want := []string{"<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr>", "<sip:" + publicHost + ":5060;transport=tcp;lr>"}; !slices.Equal(rr, want) {
		t.Errorf("Record-Route %q, want %q", rr, want)
	}
	req := prepared(t, d, r)
	if got := req.Header.Values("Route"); !slices.Equal(got, []string{scscfRoute, "<sip:term@10.0.4.5;lr>"}) {
		t.Errorf("Route %q, want the Service-Route alone", got)
	}
	if got := req.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ">", "<" + aliceTel + ">"}) {
		t.Errorf("P-Asserted-Identity %q", got)
	}
	first := req.Header.Get("P-Charging-Vector")
	if !icidValue.MatchString(first) {
		t.Errorf("P-Charging-Vector %q", first)
	}
	// P-Visited-Network-ID is for REGISTER (§5.2.2.1), not these.
	if req.Header.Has("P-Visited-Network-ID") {
		t.Errorf("P-Visited-Network-ID %q", req.Header.Get("P-Visited-Network-ID"))
	}
	if strings.Contains(r.Message.Header.Get("Route"), "orig") || r.Message.Header.Has("P-Asserted-Identity") {
		t.Error("Prepare changed the shared request")
	}
	// A client using outbound for the dialog has ob on the flow's entry
	// (TS 24.229 §5.2.6.3.3 5)).
	ob := p.Route(context.Background(), clientRequest(t, initialText("INVITE", "Contact: <sip:alice@192.0.2.10:40000;transport=tcp;ob>"), "FLOW-A"))
	if got := ob.RecordRoute[0].String(); got != "<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob>" || ob.RecordRoute[1].URI.Params.Has("ob") {
		t.Errorf("Record-Route %q, %q with an ob Contact", got, ob.RecordRoute[1].String())
	}
	// Each request is charged on its own.
	r = clientRequest(t, initialText("MESSAGE"), "FLOW-A")
	if again := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Charging-Vector"); again == first || !icidValue.MatchString(again) {
		t.Errorf("second P-Charging-Vector %q after %q", again, first)
	}
}

// pcscf asserts the identity the client prefers if a registration over its
// flow lists it, and sends the request under that registration; otherwise
// the default public identity of the first registration (TS 24.229
// §5.2.6.3.3, #16 question 5).
func TestTheAssertedIdentityIsAPreferredOneTheFlowRegistered(t *testing.T) {
	addrs := func(t *testing.T, uris ...string) []sip.Address {
		var out []sip.Address
		for _, u := range uris {
			out = append(out, sip.Address{URI: mustURI(t, u)})
		}
		return out
	}
	alice := &registration{uri: mustURI(t, aliceIMPU), seq: 1,
		associated: addrs(t, aliceIMPU+";user=phone;sos", aliceTel, "sip:alice@ims.mnc001.mcc001.3gppnetwork.org")}
	bob := &registration{uri: mustURI(t, bobIMPU), seq: 2, associated: addrs(t, bobIMPU)}
	carol := &registration{uri: mustURI(t, carolTel), seq: 3, associated: addrs(t, carolTel)}
	unlisted := &registration{uri: mustURI(t, bobIMPU+";user=phone"), seq: 4}
	regs := []*registration{alice, bob, carol}
	for _, tt := range []struct {
		name      string
		regs      []*registration
		preferred []string
		reg       *registration
		ids       []string
	}{
		{"none", regs, nil, alice, []string{"<" + aliceIMPU + ";user=phone>", "<" + aliceTel + ">"}},
		{"the default", regs, []string{"<" + aliceIMPU + ">"}, alice, []string{"<" + aliceIMPU + ";user=phone>", "<" + aliceTel + ">"}},
		{"another SIP URI", regs, []string{"<sip:alice@IMS.mnc001.mcc001.3gppnetwork.org>"}, alice, []string{"<sip:alice@ims.mnc001.mcc001.3gppnetwork.org>", "<" + aliceTel + ">"}},
		{"a tel URI", regs, []string{"<" + aliceTel + ">"}, alice, []string{"<" + aliceTel + ">"}},
		{"another registration", regs, []string{"<" + bobIMPU + ">"}, bob, []string{"<" + bobIMPU + ">"}},
		{"another registration's tel URI", regs, []string{"<" + carolTel + ">"}, carol, []string{"<" + carolTel + ">"}},
		{"the first listed", regs, []string{"<sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>", "<" + bobIMPU + ">", "<" + aliceTel + ">"}, bob, []string{"<" + bobIMPU + ">"}},
		{"unknown", regs, []string{"<sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>"}, alice, []string{"<" + aliceIMPU + ";user=phone>", "<" + aliceTel + ">"}},
		{"malformed", regs, []string{"<<"}, alice, []string{"<" + aliceIMPU + ";user=phone>", "<" + aliceTel + ">"}},
		{"no P-Associated-URI", []*registration{unlisted}, nil, unlisted, []string{"<" + bobIMPU + ";user=phone>"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var extra []string
			for _, v := range tt.preferred {
				extra = append(extra, "P-Preferred-Identity: "+v)
			}
			reg, ids := assertedIdentity(tt.regs, parseRequest(t, initialText("MESSAGE", extra...)))
			var got []string
			for _, a := range ids {
				got = append(got, a.String())
			}
			if reg != tt.reg || !slices.Equal(got, tt.ids) {
				t.Errorf("registration %v, identities %q; want %v, %q", reg.uri, got, tt.reg.uri, tt.ids)
			}
		})
	}
}

// The registration a preferred identity chooses decides the Service-Route,
// and P-Preferred-Identity goes (TS 24.229 §5.2.6.3.3).
func TestThePreferredIdentitysRegistrationGivesTheRoute(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute, "P-Associated-URI: <"+aliceIMPU+">")
	other := &registration{flow: "FLOW-A", uri: mustURI(t, bobIMPU), aor: aorKey(mustURI(t, bobIMPU)), expires: clock.t.Add(time.Hour),
		serviceRoute: []sip.Address{{URI: mustURI(t, "sip:orig@10.0.4.7;lr")}}, associated: []sip.Address{{URI: mustURI(t, bobIMPU)}}}
	if err := p.registry.save(other); err != nil {
		t.Fatal(err)
	}
	r := clientRequest(t, initialText("MESSAGE", "P-Preferred-Identity: <"+bobIMPU+">"), "FLOW-A")
	req := prepared(t, p.Route(context.Background(), r), r)
	if req.Header.Get("Route") != "<sip:orig@10.0.4.7;lr>" || req.Header.Get("P-Asserted-Identity") != "<"+bobIMPU+">" || req.Header.Has("P-Preferred-Identity") {
		t.Errorf("Route %q, P-Asserted-Identity %q, P-Preferred-Identity %q",
			req.Header.Get("Route"), req.Header.Get("P-Asserted-Identity"), req.Header.Get("P-Preferred-Identity"))
	}
	// Without one, the first registration over the flow is the default,
	// however often it is refreshed.
	for i := range 2 {
		r = clientRequest(t, initialText("MESSAGE"), "FLOW-A")
		if req := prepared(t, p.Route(context.Background(), r), r); req.Header.Get("Route") != scscfRoute {
			t.Errorf("default route %q after %d refreshes", req.Header.Get("Route"), i)
		}
		registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute, "P-Associated-URI: <"+aliceIMPU+">")
	}
}

// Only a flow with a live registration may send requests outside a dialog,
// and only along a Service-Route.
func TestAnInitialRequestNeedsARegistrationOverItsFlow(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); d.Status != 403 {
		t.Errorf("unregistered: %+v", d)
	}
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-B")); d.Status != 403 {
		t.Errorf("another flow: %+v", d)
	}
	clock.t = clock.t.Add(time.Hour)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); d.Status != 403 {
		t.Errorf("expired: %+v", d)
	}

	p, _ = newTestPcscf(clock)
	registerAlice(t, p, "FLOW-A")
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); d.Status != 500 || d.Targets != nil {
		t.Errorf("no Service-Route: %+v", d)
	}
}

// A client's requests outside a dialog beyond the rate are answered 503 with
// Retry-After; another client is not held up (#16 question 1).
func TestInitialRequestsPastTheRateAreRefused(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.initials = newLimiter(1, 2, clock.now)
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute)
	for i := range 3 {
		d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A"))
		if refused := d.Response != nil; refused != (i == 2) {
			t.Fatalf("request %d refused %v", i, refused)
		}
		if d.Response != nil && (d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1") {
			t.Fatalf("refusal %d %q", d.Response.StatusCode, d.Response.Header.Get("Retry-After"))
		}
	}
	// REGISTERs and requests inside a dialog have their own limits.
	if d := p.Route(context.Background(), clientRequest(t, registerText(outboundContact), "FLOW-A")); d.Response != nil {
		t.Error("a REGISTER was refused")
	}
	other := clientRequest(t, initialText("MESSAGE"), "FLOW-B")
	other.Source.Addr = netip.MustParseAddrPort("192.0.2.11:40000")
	if d := p.Route(context.Background(), other); d.Status != 403 {
		t.Errorf("another client was limited: %+v", d)
	}
	clock.t = clock.t.Add(time.Second)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); d.Response != nil {
		t.Fatal("the bucket did not refill")
	}
}

// A request inside a dialog is forwarded only along a route set this pcscf
// put itself in for the flow it came on, to a private next hop; anything
// else is 403 (#16 question 6).
func TestAnInDialogRequestMustFollowThisPcscfsRouteForItsFlow(t *testing.T) {
	core := "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr"
	client := "sip:" + publicHost + ":5060;transport=tcp;lr"
	for _, tt := range []struct {
		name   string
		routed []string
		extra  []string
		ok     bool
	}{
		{"both, to scscf", []string{client, core}, []string{"Route: " + scscfRoute}, true},
		{"both, to the remote target", []string{client, core}, nil, false},
		{"the NLB's address", []string{"sip:203.0.113.10:5060;transport=tcp;lr", core}, []string{"Route: " + scscfRoute}, true},
		{"another flow", []string{client, "sip:FLOW-B@10.0.2.9:5070;transport=tcp;lr"}, []string{"Route: " + scscfRoute}, false},
		{"another task", []string{client, "sip:FLOW-A@10.0.2.8:5070;transport=tcp;lr"}, []string{"Route: " + scscfRoute}, false},
		{"another port", []string{client, "sip:FLOW-A@10.0.2.9:5060;transport=tcp;lr"}, []string{"Route: " + scscfRoute}, false},
		{"the core's only", []string{core}, []string{"Route: " + scscfRoute}, false},
		{"the client's only", []string{client}, []string{"Route: " + scscfRoute}, false},
		{"none", nil, []string{"Route: " + scscfRoute}, false},
		{"a public next hop", []string{client, core}, []string{"Route: <sip:198.51.100.7;lr>"}, false},
		// Not even looked up: outside the service namespace (ADR 0007 §5).
		{"a name outside the namespace", []string{client, core}, []string{"Route: <sip:scscf.example.net;lr>"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
			p.cfg.PublicAddrs = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
			r := clientRequest(t, inDialogText("BYE", tt.extra...), "FLOW-A")
			r.Message.URI = mustURI(t, "sip:bob@198.51.100.20:5060;transport=tcp")
			for _, u := range tt.routed {
				r.Routed = append(r.Routed, sip.Address{URI: mustURI(t, u)})
			}
			d := p.Route(context.Background(), r)
			if tt.ok {
				if d.Status != 0 || len(d.Targets) != 1 || d.Targets[0].URI.String() != r.Message.URI.String() || d.Prepare != nil || d.RecordRoute != nil {
					t.Errorf("not forwarded as it is: %+v", d)
				}
			} else if d.Status != 403 {
				t.Errorf("decision %+v, want 403", d)
			}
		})
	}
}
