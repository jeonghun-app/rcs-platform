package pcscf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	bobIMPU  = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
	carolTel = "tel:+15550100003"
	daveTel  = "tel:+15550100004"
	// daveIMPUPhone is the SIP URI of dave's second number.
	daveIMPUPhone = "sip:+15550100004@ims.mnc001.mcc001.3gppnetwork.org;user=phone"
	// scscfRoute is the Service-Route the tests' registrations receive.
	scscfRoute = "<sip:orig@scscf.rcs.internal;transport=tcp;lr>"
	// aliceIMPUPhone is alice's public identity as a number.
	aliceIMPUPhone = aliceIMPU + ";user=phone"
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
		"P-Associated-URI: <"+aliceIMPUPhone+">, <"+aliceTel+">")
	r := clientRequest(t, initialText("INVITE", "Route: <sip:10.0.9.9;lr>"), "FLOW-A")
	d := p.Route(context.Background(), r)
	if d.Targets[0].URI.String() != bobIMPU {
		t.Errorf("target %v", d.Targets[0].URI)
	}
	req := prepared(t, d, r)
	first := req.Header.Get("P-Charging-Vector")
	var rr []string
	for _, a := range d.RecordRoute {
		rr = append(rr, a.String())
	}
	// The core-facing value carries the icid for the dialog's later
	// requests (§5.2.6.3.5 7)).
	if want := []string{"<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;icid=" + icidOf(t, first) + ";dlg=" + p.dialogMAC("FLOW-A", "orig-1") + ">", "<sip:" + publicHost + ":5060;transport=tcp;lr>"}; !slices.Equal(rr, want) {
		t.Errorf("Record-Route %q, want %q", rr, want)
	}
	if got := req.Header.Values("Route"); !slices.Equal(got, []string{scscfRoute, "<sip:term@10.0.4.5;lr>"}) {
		t.Errorf("Route %q, want the Service-Route alone", got)
	}
	if got := req.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPUPhone + ">", "<" + aliceTel + ">"}) {
		t.Errorf("P-Asserted-Identity %q", got)
	}
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
	if got := ob.RecordRoute[0].String(); !strings.HasPrefix(got, "<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob;icid=") || ob.RecordRoute[1].URI.Params.Has("ob") {
		t.Errorf("Record-Route %q, %q with an ob Contact", got, ob.RecordRoute[1].String())
	}
	// Each request is charged on its own. A standalone one sets up no
	// dialog, so it is not recorded (§5.2.6.3.7).
	r = clientRequest(t, initialText("MESSAGE"), "FLOW-A")
	if again := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Charging-Vector"); again == first || !icidValue.MatchString(again) {
		t.Errorf("second P-Charging-Vector %q after %q", again, first)
	}
	for method, recorded := range map[string]bool{"MESSAGE": false, "OPTIONS": false, "PUBLISH": false, "INVITE": true, "SUBSCRIBE": true, "REFER": true} {
		if d := p.Route(context.Background(), clientRequest(t, initialText(method), "FLOW-A")); (d.RecordRoute != nil) != recorded {
			t.Errorf("%s: Record-Route %v", method, d.RecordRoute)
		}
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
	// dave has two numbers.
	dave := &registration{uri: mustURI(t, aliceIMPU), seq: 5,
		associated: addrs(t, aliceIMPUPhone, aliceTel, daveIMPUPhone, daveTel)}
	// frank's number has no tel URI of its own.
	frank := &registration{uri: mustURI(t, aliceIMPU), seq: 7, associated: addrs(t, daveIMPUPhone, aliceTel)}
	// grace has two numbers, as SIP URIs without user=phone and as tel URIs.
	grace := &registration{uri: mustURI(t, aliceIMPU), seq: 8, associated: addrs(t, aliceIMPU, aliceTel, bobIMPU, "tel:+15550100002")}
	// erin has a second number as a tel URI only.
	erin := &registration{uri: mustURI(t, aliceIMPU), seq: 6, associated: addrs(t, aliceIMPU, aliceTel, daveTel)}
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
		// Not a number: the registration's first tel URI beside it.
		{"another SIP URI", regs, []string{"<sip:alice@IMS.mnc001.mcc001.3gppnetwork.org>"}, alice, []string{"<sip:alice@ims.mnc001.mcc001.3gppnetwork.org>", "<" + aliceTel + ">"}},
		{"a tel URI", regs, []string{"<" + aliceTel + ">"}, alice, []string{"<" + aliceTel + ">"}},
		{"another registration", regs, []string{"<" + bobIMPU + ">"}, bob, []string{"<" + bobIMPU + ">"}},
		{"another registration's tel URI", regs, []string{"<" + carolTel + ">"}, carol, []string{"<" + carolTel + ">"}},
		// The second registered one is the alternative identity (§5.2.6.3.1).
		// An alternative only from the chosen registration (security
		// review of #208).
		{"the first listed", regs, []string{"<sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>", "<" + bobIMPU + ">", "<" + aliceTel + ">"}, bob, []string{"<" + bobIMPU + ">"}},
		{"an alternative of the chosen registration", []*registration{dave}, []string{"<" + daveIMPUPhone + ">", "<" + aliceTel + ">"}, dave, []string{"<" + daveIMPUPhone + ">", "<" + aliceTel + ">"}},
		{"a number without its tel URI", []*registration{frank}, nil, frank, []string{"<" + daveIMPUPhone + ">"}},
		// A "+" number without user=phone is still a number (QA of #208).
		{"a number without user=phone", []*registration{grace}, []string{"<" + bobIMPU + ">"}, grace, []string{"<" + bobIMPU + ">", "<tel:+15550100002>"}},
		{"an alternative of the same kind", regs, []string{"<" + bobIMPU + ">", "<" + aliceIMPU + ">"}, bob, []string{"<" + bobIMPU + ">"}},
		{"the same one twice", regs, []string{"<" + aliceTel + ">", "<" + aliceTel + ">"}, alice, []string{"<" + aliceTel + ">"}},
		// A number written as a SIP URI matches its tel URI (§5.2.6.3.1).
		{"a number as a SIP URI", []*registration{erin}, []string{"<" + daveIMPUPhone + ">"}, erin, []string{"<" + daveTel + ">"}},
		{"a number and an alternative", []*registration{erin}, []string{"<" + aliceIMPU + ">", "<" + daveTel + ">"}, erin, []string{"<" + aliceIMPU + ">", "<" + daveTel + ">"}},
		// Of two numbers, the tel URI beside a SIP one is the same number
		// (security review of #208).
		{"the second number", []*registration{dave}, []string{"<" + daveIMPUPhone + ">"}, dave, []string{"<" + daveIMPUPhone + ">", "<" + daveTel + ">"}},
		// Spellings of one identity (QA of #208).
		{"an escaped user part", regs, []string{"<sip:%2B15550100002@ims.mnc001.mcc001.3gppnetwork.org>"}, bob, []string{"<" + bobIMPU + ">"}},
		{"a number with separators", regs, []string{"<tel:+1-555-0100-003>"}, carol, []string{"<" + carolTel + ">"}},
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
// One from a flow without a registration is discarded and counted, so a
// client whose registration pcscf lost times out and registers again (TS
// 24.229 §5.2.6.3.2A).
func TestAnInitialRequestNeedsARegistrationOverItsFlow(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	var out strings.Builder
	p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", clock.now, p.log)
	discarded := func(d proxy.Decision) bool {
		return d.Discard && d.Status == 0 && d.Response == nil && d.Targets == nil
	}
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); !discarded(d) {
		t.Errorf("unregistered: %+v", d)
	}
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-B")); !discarded(d) {
		t.Errorf("another flow: %+v", d)
	}
	clock.t = clock.t.Add(time.Hour)
	if d := p.Route(context.Background(), clientRequest(t, initialText("INVITE"), "FLOW-A")); !discarded(d) {
		t.Errorf("expired: %+v", d)
	}
	p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricUnregistered+`":3`) {
		t.Errorf("metrics %s, want %s 3", out.String(), metricUnregistered)
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
	if d := p.Route(context.Background(), other); d.Response != nil {
		t.Errorf("another client was limited: %+v", d)
	}
	clock.t = clock.t.Add(time.Second)
	if d := p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A")); d.Response != nil {
		t.Fatal("the bucket did not refill")
	}
}

// icidOf is the icid of a P-Charging-Vector pcscf wrote.
func icidOf(t *testing.T, pcv string) string {
	t.Helper()
	if !icidValue.MatchString(pcv) {
		t.Fatalf("P-Charging-Vector %q", pcv)
	}
	v, _, _ := strings.Cut(strings.TrimPrefix(pcv, "icid-value="), ";")
	return v
}

// The client-facing Record-Route value says tls unless the client
// transport is plain tcp, so that a client's later requests use the
// connection type it registered over.
func TestTheClientFacingRecordRouteNamesTheClientTransport(t *testing.T) {
	for transport, want := range map[string]string{ClientTLS: "tls", ClientNLBTLS: "tls", ClientTCP: "tcp"} {
		p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
		p.cfg.ClientTransport, p.cfg.PublicPort = transport, 5061
		rr := p.recordRoute("FLOW-A", false, "0123456789abcdef0123456789abcdef", "call-1")
		if got := rr[1].String(); got != "<sip:"+publicHost+":5061;transport="+want+";lr>" {
			t.Errorf("%s: client-facing Record-Route %q", transport, got)
		}
	}
}

const (
	// dialogICID is the icid the tests' dialogs were set up with.
	dialogICID = "0123456789abcdef0123456789abcdef"
	coreEntry  = "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;icid=" + dialogICID
	clientEnt  = "sip:" + publicHost + ":5060;transport=tcp;lr"
)

// inDialogFrom is a BYE over FLOW-A whose consumed Route values were routed,
// with Request-URI uri and extra fields.
func inDialogFrom(t *testing.T, routed []string, uri string, extra ...string) *proxy.Request {
	r := clientRequest(t, inDialogText("BYE", extra...), "FLOW-A")
	r.Message.URI = mustURI(t, uri)
	for _, u := range routed {
		r.Routed = append(r.Routed, sip.Address{URI: mustURI(t, u)})
	}
	return r
}

// A request inside a dialog is forwarded only along a route set this pcscf
// recorded for the flow it came on, and only to scscf's service name on its
// port over TCP, resolving to an address other than this task's; anything
// else is 403 (#16 question 6, narrowed in the review of #208). The request
// carries the dialog's icid from the core-facing value.
func TestAnInDialogRequestMustFollowThisPcscfsRouteForItsFlow(t *testing.T) {
	const remote = "sip:bob@198.51.100.20:5060;transport=tcp"
	toSCSCF := "Route: " + scscfRoute
	for _, tt := range []struct {
		name   string
		routed []string
		uri    string
		extra  []string
		ok     bool
	}{
		{"both, to scscf", []string{clientEnt, coreEntry}, remote, []string{toSCSCF}, true},
		{"scscf on its port, written another way", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:orig@SCSCF.rcs.internal.:5060;transport=TCP;lr;orig>"}, true},
		{"scscf as a strict router", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:scscf.rcs.internal;transport=tcp>"}, true},
		{"the NLB's address", []string{"sip:203.0.113.10:5060;transport=tcp;lr", coreEntry}, remote, []string{toSCSCF}, true},
		{"the public name written another way", []string{"sip:PCSCF.rcs.example.net.:5060;transport=tcp;lr", coreEntry}, remote, []string{toSCSCF}, true},
		{"this task's address written another way", []string{clientEnt, "sip:FLOW-A@[::ffff:10.0.2.9]:5070;transport=tcp;lr;icid=" + dialogICID}, remote, []string{toSCSCF}, true},
		{"to the remote target", []string{clientEnt, coreEntry}, remote, nil, false},
		{"to scscf's address", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:10.0.4.4:5060;transport=tcp;lr>"}, false},
		{"to another task's core listener", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:BOBS-FLOW@10.0.2.8:5070;transport=tcp;lr>"}, false},
		{"to any private host and port", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:10.0.7.7:6379;transport=tcp;lr>"}, false},
		{"to a private Request-URI", []string{clientEnt, coreEntry}, "sip:x@10.0.8.8:8080;transport=tcp", nil, false},
		{"to this task in an IPv4-mapped form", []string{clientEnt, coreEntry}, "sip:OTHER@[::ffff:10.0.2.9]:5070;transport=tcp", nil, false},
		{"to scscf on another port", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:scscf.rcs.internal:5070;transport=tcp;lr>"}, false},
		{"to scscf over UDP", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:scscf.rcs.internal;lr>"}, false},
		{"to scscf over TLS", []string{clientEnt, coreEntry}, remote, []string{"Route: <sips:scscf.rcs.internal;lr>"}, false},
		{"to scscf as sips", []string{clientEnt, coreEntry}, remote, []string{"Route: <sips:scscf.rcs.internal;transport=tcp;lr>"}, false},
		{"to icscf", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:icscf.rcs.internal;transport=tcp;lr>"}, false},
		{"to pcscf's own name", []string{clientEnt, coreEntry}, remote, []string{"Route: <sip:" + publicHost + ":5060;transport=tcp>"}, false},
		{"another flow", []string{clientEnt, "sip:FLOW-B@10.0.2.9:5070;transport=tcp;lr"}, remote, []string{toSCSCF}, false},
		{"another task", []string{clientEnt, "sip:FLOW-A@10.0.2.8:5070;transport=tcp;lr"}, remote, []string{toSCSCF}, false},
		{"another port", []string{clientEnt, "sip:FLOW-A@10.0.2.9:5060;transport=tcp;lr"}, remote, []string{toSCSCF}, false},
		{"the core's only", []string{coreEntry}, remote, []string{toSCSCF}, false},
		{"the client's only", []string{clientEnt}, remote, []string{toSCSCF}, false},
		{"none", nil, remote, []string{toSCSCF}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
			p.cfg.PublicAddrs = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
			r := inDialogFrom(t, tt.routed, tt.uri, tt.extra...)
			d := p.Route(context.Background(), r)
			if !tt.ok {
				if d.Status != 403 {
					t.Errorf("decision %+v, want 403", d)
				}
				return
			}
			if d.Status != 0 || len(d.Targets) != 1 || d.Targets[0].URI.String() != r.Message.URI.String() || d.RecordRoute != nil {
				t.Fatalf("not forwarded as it is: %+v", d)
			}
			if got := prepared(t, d, r).Header.Get("P-Charging-Vector"); icidOf(t, got) != dialogICID {
				t.Errorf("P-Charging-Vector %q, want the dialog's icid", got)
			}
		})
	}
}

// A dialog whose route lost its icid gets a new one rather than none.
func TestAnInDialogRequestWithoutTheDialogsICIDGetsANewOne(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	base := "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr"
	for _, core := range []string{base, base + ";icid", base + ";icid=a%01b", base + ";icid=" + strings.Repeat("a", maxICID+1)} {
		r := inDialogFrom(t, []string{clientEnt, core}, "sip:bob@198.51.100.20", "Route: "+scscfRoute)
		if got := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Charging-Vector"); !icidValue.MatchString(got) {
			t.Errorf("%s: P-Charging-Vector %q, want a new icid", core, got)
		}
	}
}

// An icid from the core can be any value, a quoted string with ";" or a
// quote in it too: the core-facing Record-Route value carries it escaped,
// and the dialog's requests get it back as it was (review of #221).
func TestADialogKeepsTheCoresICIDWhateverItHolds(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	for _, icid := range []string{"plain-token.1", `a b;c=d\"e`, "%41é"} {
		rr := p.recordRoute("FLOW-A", false, icid, "call-1")
		core := rr[0]
		back, err := sip.ParseAddress(core.String())
		if err != nil {
			t.Fatalf("%q: the Record-Route %s does not parse: %v", icid, core, err)
		}
		got, ok := routeICID(back.URI)
		if !ok || got != icid {
			t.Errorf("%q: read back %q, %v from %s", icid, got, ok, core)
		}
		r := inDialogFrom(t, []string{clientEnt, back.URI.String()}, "sip:bob@198.51.100.20", "Route: "+scscfRoute)
		pcv := prepared(t, p.Route(context.Background(), r), r).Header.Get("P-Charging-Vector")
		var h sip.Header
		_ = h.Set("P-Charging-Vector", pcv)
		if cv, err := h.PChargingVector(); err != nil || cv.ICID() != icid {
			t.Errorf("%q: P-Charging-Vector %q (%v)", icid, pcv, err)
		}
	}
}

// A failed lookup of scscf is the network's failure, answered 503 with
// Retry-After; scscf's name resolving to this task is refused like any route
// back into it (review of #208).
func TestAnInDialogRequestWhoseLookupFailsIs503(t *testing.T) {
	for _, tt := range []struct {
		name   string
		lookup func(context.Context, string, string) ([]netip.Addr, error)
		want   int
	}{
		{"no answer", func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, &net.DNSError{Err: "i/o timeout", Name: "scscf.rcs.internal", IsTimeout: true}
		}, 503},
		{"this task", func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("::ffff:10.0.2.9")}, nil
		}, 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
			p.resolve = coreResolver{dns: &proxy.DNSResolver{Namespace: p.cfg.Namespace, Allow: allowCore(p.cfg), Lookup: tt.lookup, Logger: p.log}}
			d := p.Route(context.Background(), inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
			code := d.Status
			if d.Response != nil {
				code = d.Response.StatusCode
				if d.Response.Header.Get("Retry-After") != "1" {
					t.Errorf("Retry-After %q", d.Response.Header.Get("Retry-After"))
				}
			}
			if code != tt.want {
				t.Errorf("decision %+v, want %d", d, tt.want)
			}
		})
	}
}

// Requests inside a dialog count against the client's initial-request
// bucket, so a To tag does not lift the limit (security review of #208).
func TestInDialogRequestsShareTheInitialRequestLimit(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.initials = newLimiter(1, 1, clock.now)
	bye := func() proxy.Decision {
		return p.Route(context.Background(), inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
	}
	if d := bye(); d.Status != 0 || d.Response != nil {
		t.Fatalf("first BYE %+v", d)
	}
	if d := bye(); d.Response == nil || d.Response.StatusCode != 503 || d.Response.Header.Get("Retry-After") != "1" {
		t.Fatalf("BYE past the limit %+v, want 503 with Retry-After", d)
	}
	// An ACK cannot be answered 503: past the limit it is dropped, and
	// counted (security review of #208).
	var out strings.Builder
	p.metrics = runtime.NewMetrics(&out, "RCS", "pcscf", clock.now, p.log)
	ack := clientRequest(t, inDialogText("ACK", "Route: "+scscfRoute), "FLOW-A")
	ack.Routed = []sip.Address{{URI: mustURI(t, clientEnt)}, {URI: mustURI(t, coreEntry)}}
	if d := p.Route(context.Background(), ack); !d.Discard || len(d.Targets) != 0 {
		t.Fatalf("ACK past the limit %+v, want it dropped", d)
	}
	p.metrics.Flush()
	if !strings.Contains(out.String(), `"`+metricACKDiscarded+`":1`) {
		t.Errorf("metrics %s", out.String())
	}
	// Made-up dialogs to any core address go nowhere, and soon not even
	// to the route check.
	for i := range 50 {
		next := []string{"<sip:10.0.3.7:5060;transport=tcp;lr>", "<sip:10.0.4.99:5060;transport=tcp;lr>"}[i%2]
		if d := p.Route(context.Background(), inDialogFrom(t, []string{clientEnt, coreEntry}, bobIMPU, "Route: "+next)); len(d.Targets) != 0 {
			t.Fatalf("made-up dialog %d forwarded", i)
		}
	}
}

// No name a client writes in a request inside a dialog is looked up: only
// scscf's configured name is, so a client cannot spend the VPC resolver's
// budget or fill the logs (QA of #208).
func TestNoNameAClientWritesIsLookedUp(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	lookups := 0
	var logs strings.Builder
	p.resolve = coreResolver{dns: &proxy.DNSResolver{Namespace: p.cfg.Namespace, Allow: allowCore(p.cfg),
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		Lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			lookups++
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}}}
	for i := range 1000 {
		r := inDialogFrom(t, []string{clientEnt, coreEntry}, bobIMPU, fmt.Sprintf("Route: <sip:q%d.rcs.internal;transport=tcp;lr>", i))
		if d := p.Route(context.Background(), r); d.Status != 403 && d.Response == nil {
			t.Fatalf("%+v", d)
		}
	}
	if lookups != 0 || logs.Len() != 0 {
		t.Errorf("%d lookups, logs %q", lookups, logs.String())
	}
}

// Production never sends a core hop to this task's own address, however it
// is written.
func TestProductionNeverResolvesACoreHopToThisTask(t *testing.T) {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	p.cfg.AllowLoopback = false
	r := coreResolver{dns: &proxy.DNSResolver{Namespace: p.cfg.Namespace, Allow: allowCore(p.cfg)}}
	for _, u := range []string{"sip:OTHER@[::ffff:10.0.2.9]:5070;transport=tcp;lr", "sip:OTHER@10.0.2.9:5070;transport=tcp;lr", "sip:[::ffff:a00:209]:5060;transport=tcp"} {
		if dst, err := r.Resolve(context.Background(), mustURI(t, u)); err == nil {
			t.Errorf("%s resolved to %v", u, dst.Addr)
		}
	}
	if _, err := r.Resolve(context.Background(), mustURI(t, "sip:10.0.2.10:5070;transport=tcp")); err != nil {
		t.Errorf("another task: %v", err)
	}
}

// A lookup of a flow's registrations forgets the expired ones, freeing
// their slots.
func TestFlowRegistrationsForgetsTheExpired(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRegistry(2, clock.now)
	for i, ttl := range []time.Duration{time.Minute, time.Hour} {
		if err := r.save(&registration{flow: "F", aor: fmt.Sprintf("sip:%d@h", i), expires: clock.t.Add(ttl)}); err != nil {
			t.Fatal(err)
		}
	}
	clock.t = clock.t.Add(2 * time.Minute)
	if regs := r.flowRegistrations("F"); len(regs) != 1 || r.size() != 1 {
		t.Fatalf("%d registrations, size %d", len(regs), r.size())
	}
}

// Made-up ACKs, which cannot be answered, are held to the client's rate
// like any other request inside a dialog (QA of #208).
func TestMadeUpACKsAreHeldToTheClientsRate(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	p, _ := newTestPcscf(clock)
	p.initials = newLimiter(1, 1, clock.now)
	forwarded := 0
	for range 1000 {
		r := clientRequest(t, inDialogText("ACK", "Route: <sip:scscf.rcs.internal:5060;transport=tcp;lr>"), "FLOW-A")
		r.Message.URI = mustURI(t, "sip:bob@198.51.100.20:5060;transport=tcp")
		for _, u := range []string{clientEnt, coreEntry} {
			r.Routed = append(r.Routed, sip.Address{URI: mustURI(t, u)})
		}
		if d := p.Route(context.Background(), r); d.Status == 0 && d.Response == nil && len(d.Targets) == 1 {
			forwarded++
		}
	}
	if forwarded > 1 {
		t.Errorf("made-up ACKs forwarded with burst 1: %d of 1000", forwarded)
	}
}
