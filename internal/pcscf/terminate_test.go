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
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	// pathEntry is the Path pcscf wrote for FLOW-A's registration.
	pathEntry = "sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob"
	// aliceContact is alice's contact over FLOW-A.
	aliceContact = "sip:alice@192.0.2.10:40000;transport=tcp;ob"
	// coreICID is the icid the core gave the tests' requests.
	coreICID = "fedcba9876543210fedcba9876543210"
)

// fromCore is a request from bob to alice that arrived on the core listener,
// whose consumed Route values were routed.
func fromCore(t *testing.T, method string, inDialog bool, routed []string, extra ...string) *proxy.Request {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, aliceContact)
	b.WriteString("Via: SIP/2.0/TCP 10.0.4.4:5060;branch=z9hG4bK-term-1\r\n")
	b.WriteString("Max-Forwards: 69\r\n")
	b.WriteString("From: <" + bobIMPU + ">;tag=b1\r\n")
	to := "To: <" + aliceIMPU + ">"
	if inDialog {
		to += ";tag=a1"
	}
	b.WriteString(to + "\r\n")
	fmt.Fprintf(&b, "Call-ID: term-1\r\nCSeq: 1 %s\r\n", method)
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	r := &proxy.Request{Message: parseRequest(t, b.String()), Source: transport.Source{
		Flow: "CORE-1", Network: transport.TCP, Addr: netip.MustParseAddrPort("10.0.4.4:41000"), Listener: coreListener}}
	for _, u := range routed {
		r.Routed = append(r.Routed, sip.Address{URI: mustURI(t, u)})
	}
	return r
}

// newTerminatingPcscf is newTestPcscf whose client flows are the ones
// given.
func newTerminatingPcscf(t *testing.T, flows ...transport.FlowID) *pcscf {
	p, _ := newTestPcscf(&testClock{t: time.Unix(1_800_000_000, 0)})
	p.clientFlow = func(id transport.FlowID) bool { return slices.Contains(flows, id) }
	return p
}

// answer is a client's response to req with code and extra fields.
func answer(t *testing.T, req *sip.Request, code int, extra ...string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", "a1")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		name, value, _ := strings.Cut(e, ": ")
		if err := res.Header.Add(name, value); err != nil {
			t.Fatal(err)
		}
	}
	return res
}

// A request from the core outside a dialog goes over the flow its Path
// names and nowhere else, with pcscf's two Record-Route values, the
// client-facing one on top and the core-facing one keeping the Path's ob
// and the request's icid (TS 24.229 §5.2.6.4.4 3), #16 plan D).
func TestATerminatingRequestGoesOverTheFlowItsPathNames(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	r := fromCore(t, "INVITE", false, []string{pathEntry}, "Route: <sip:10.0.9.9;lr>",
		"P-Charging-Vector: icid-value="+coreICID+";orig-ioi=home.example.net")
	d := p.Route(context.Background(), r)
	if len(d.Targets) != 1 || d.Targets[0].Destination == nil || d.Targets[0].Destination.Flow != "FLOW-A" || d.Targets[0].URI.String() != aliceContact {
		t.Fatalf("decision %+v", d)
	}
	var rr []string
	for _, a := range d.RecordRoute {
		rr = append(rr, a.String())
	}
	want := []string{"<sip:" + publicHost + ":5060;transport=tcp;lr>", "<sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;ob;icid=" + coreICID + ">"}
	if !slices.Equal(rr, want) {
		t.Errorf("Record-Route %q, want %q", rr, want)
	}
	// Inside a dialog: the flow of the core-facing value, no Record-Route.
	in := fromCore(t, "BYE", true, []string{"sip:FLOW-A@[::ffff:10.0.2.9]:5070;transport=tcp;lr;icid=" + coreICID, "sip:" + publicHost + ":5060;transport=tcp;lr"})
	d = p.Route(context.Background(), in)
	if len(d.Targets) != 1 || d.Targets[0].Destination.Flow != "FLOW-A" || d.RecordRoute != nil {
		t.Fatalf("in-dialog decision %+v", d)
	}
}

// A request from the core that names no flow of a client of this task is
// answered 430 Flow Failed, kept as it is for scscf (RFC 5626 §5.3, §11.5):
// no token, a token another task or port wrote, or a flow that is closed,
// from an earlier start or not a client's.
func TestATerminatingRequestWithoutALiveClientFlowIs430(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	for name, routed := range map[string][]string{
		"no token":           {"sip:10.0.2.9:5070;transport=tcp;lr"},
		"none":               nil,
		"another task":       {"sip:FLOW-A@10.0.2.8:5070;transport=tcp;lr"},
		"another port":       {"sip:FLOW-A@10.0.2.9:5071;transport=tcp;lr"},
		"not a client flow":  {"sip:CORE-1@10.0.2.9:5070;transport=tcp;lr"},
		"an earlier start's": {"sip:OLD-TOKEN@10.0.2.9:5070;transport=tcp;lr"},
	} {
		if d := p.Route(context.Background(), fromCore(t, "INVITE", false, routed)); d.Status != statusFlowFailed || d.Targets != nil {
			t.Errorf("%s: %+v", name, d)
		}
	}
	// A flow that fails as the request is sent is 430 too, and the proxy's
	// 430 reaches scscf as it is.
	d := p.Route(context.Background(), fromCore(t, "INVITE", false, []string{pathEntry}))
	r := fromCore(t, "INVITE", false, nil)
	res := answer(t, r.Message, statusFlowFailed)
	if d.OnFinal(context.Background(), res); res.StatusCode != statusFlowFailed {
		t.Errorf("430 became %d", res.StatusCode)
	}
}

// The identity is removed toward the client when the request asks for its
// privacy (RFC 3323 §4.2, RFC 3325 §9.3), and kept otherwise.
func TestPrivacyIDHidesTheAssertedIdentityFromTheClient(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	for privacy, kept := range map[string]bool{"": true, "Privacy: id": false, "Privacy: header;ID": false, "Privacy: user": true, "Privacy: none": true} {
		extra := []string{"P-Asserted-Identity: <" + bobIMPU + ">"}
		if privacy != "" {
			extra = append(extra, privacy)
		}
		r := fromCore(t, "MESSAGE", false, []string{pathEntry}, extra...)
		req := prepared(t, p.Route(context.Background(), r), r)
		if req.Header.Has("P-Asserted-Identity") != kept {
			t.Errorf("%q: P-Asserted-Identity %q", privacy, req.Header.Get("P-Asserted-Identity"))
		}
	}
}

// The client's responses carry the request's icid and orig-ioi and this
// network as the type 1 term-ioi; a 1xx or 2xx to a request outside a
// dialog asserts the identity it was for, the P-Called-Party-ID, in place
// of any the client preferred (TS 24.229 §5.2.6.4.4 1), 6)).
func TestTheClientsResponsesCarryChargingAndTheCalledIdentity(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	r := fromCore(t, "INVITE", false, []string{pathEntry}, "P-Called-Party-ID: <"+aliceIMPU+";user=phone;x=1>",
		"P-Charging-Vector: icid-value="+coreICID+";orig-ioi=home.example.net")
	d := p.Route(context.Background(), r)
	wantCV := "icid-value=" + coreICID + ";orig-ioi=home.example.net;term-ioi=ims.mnc001.mcc001.3gppnetwork.org"
	for _, code := range []int{180, 200} {
		res := answer(t, r.Message, code, "P-Preferred-Identity: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>")
		d.OnResponse(context.Background(), res)
		if got := res.Header.Get("P-Charging-Vector"); got != wantCV {
			t.Errorf("%d: P-Charging-Vector %q, want %q", code, got, wantCV)
		}
		if got := res.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ";user=phone>"}) || res.Header.Has("P-Preferred-Identity") {
			t.Errorf("%d: P-Asserted-Identity %q, P-Preferred-Identity %q", code, got, res.Header.Get("P-Preferred-Identity"))
		}
	}
	busy := answer(t, r.Message, 486)
	d.OnResponse(context.Background(), busy)
	if busy.Header.Get("P-Charging-Vector") != wantCV || busy.Header.Has("P-Asserted-Identity") {
		t.Errorf("486: P-Charging-Vector %q, P-Asserted-Identity %q", busy.Header.Get("P-Charging-Vector"), busy.Header.Get("P-Asserted-Identity"))
	}
	trying := answer(t, r.Message, 100)
	if d.OnResponse(context.Background(), trying); trying.Header.Has("P-Charging-Vector") {
		t.Error("a 100 was rewritten")
	}
	// Inside a dialog only the charging vector.
	in := fromCore(t, "BYE", true, []string{"sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr", "sip:" + publicHost + ":5060;transport=tcp;lr"},
		"P-Charging-Vector: icid-value="+coreICID)
	d = p.Route(context.Background(), in)
	ok := answer(t, in.Message, 200)
	if d.OnResponse(context.Background(), ok); ok.Header.Has("P-Asserted-Identity") || !strings.HasPrefix(ok.Header.Get("P-Charging-Vector"), "icid-value="+coreICID+";term-ioi=") {
		t.Errorf("in-dialog 200: %q, %q", ok.Header.Get("P-Asserted-Identity"), ok.Header.Get("P-Charging-Vector"))
	}
}

// Without P-Called-Party-ID the response asserts the flow's default public
// identity, and without a charging vector the request's responses get a
// new icid.
func TestAResponseFallsBackToTheFlowsIdentityAndANewICID(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute, "P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">")
	r := fromCore(t, "MESSAGE", false, []string{pathEntry})
	d := p.Route(context.Background(), r)
	res := answer(t, r.Message, 200)
	d.OnResponse(context.Background(), res)
	if got := res.Header.Get("P-Asserted-Identity"); got != "<"+aliceIMPU+">" {
		t.Errorf("P-Asserted-Identity %q", got)
	}
	if cv := res.Header.Get("P-Charging-Vector"); !strings.HasPrefix(cv, "icid-value=") || len(icidOfVector(cv)) != 32 || !strings.HasSuffix(cv, ";term-ioi=ims.mnc001.mcc001.3gppnetwork.org") {
		t.Errorf("P-Charging-Vector %q", cv)
	}
	// No registration at all: no identity to assert.
	p = newTerminatingPcscf(t, "FLOW-A")
	d = p.Route(context.Background(), r)
	res = answer(t, r.Message, 200)
	if d.OnResponse(context.Background(), res); res.Header.Has("P-Asserted-Identity") {
		t.Errorf("P-Asserted-Identity %q", res.Header.Get("P-Asserted-Identity"))
	}
}

// fakeFlows answers Flow for the flows it has.
type fakeFlows map[transport.FlowID]transport.FlowInfo

func (f fakeFlows) Flow(id transport.FlowID) (transport.FlowInfo, bool) {
	info, ok := f[id]
	return info, ok
}

// Only a live flow of a client listener is a client flow: never a core
// connection, so a request from the core cannot be sent back to it.
func TestOnlyALiveClientListenerFlowIsAClientFlow(t *testing.T) {
	flows := fakeFlows{
		"TCP":  {Listener: clientListener},
		"UDP":  {Listener: clientUDPListener},
		"CORE": {Listener: coreListener},
		"OUT":  {Listener: ""},
	}
	for id, want := range map[transport.FlowID]bool{"TCP": true, "UDP": true, "CORE": false, "OUT": false, "GONE": false} {
		if isClientFlow(flows, id) != want {
			t.Errorf("%s: %v", id, !want)
		}
	}
}

// The network's charging data never reaches the client (TS 24.229 §5.2.1):
// not in a request from the core, nor in a response to the client's own.
func TestChargingDataNeverGoesToTheClient(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	r := fromCore(t, "MESSAGE", false, []string{pathEntry}, "P-Charging-Vector: icid-value="+coreICID,
		"P-Charging-Function-Addresses: ccf=192.0.2.200")
	req := prepared(t, p.Route(context.Background(), r), r)
	if req.Header.Has("P-Charging-Vector") || req.Header.Has("P-Charging-Function-Addresses") {
		t.Errorf("to the client: %q, %q", req.Header.Get("P-Charging-Vector"), req.Header.Get("P-Charging-Function-Addresses"))
	}
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute)
	for name, r := range map[string]*proxy.Request{
		"REGISTER":         clientRequest(t, registerText(outboundContact), "FLOW-A"),
		"outside a dialog": clientRequest(t, initialText("MESSAGE"), "FLOW-A"),
		"inside a dialog":  inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute),
	} {
		d := p.Route(context.Background(), r)
		res := answer(t, r.Message, 200, "P-Charging-Vector: icid-value=1", "P-Charging-Function-Addresses: ccf=192.0.2.200")
		d.OnResponse(context.Background(), res)
		if res.Header.Has("P-Charging-Vector") || res.Header.Has("P-Charging-Function-Addresses") {
			t.Errorf("%s: response to the client %q, %q", name, res.Header.Get("P-Charging-Vector"), res.Header.Get("P-Charging-Function-Addresses"))
		}
	}
}

// Without P-Called-Party-ID the response asserts the Request-URI if the
// flow registered it.
func TestAResponseAssertsARegisteredRequestURI(t *testing.T) {
	p := newTerminatingPcscf(t, "FLOW-A")
	registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute, "P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">")
	r := fromCore(t, "MESSAGE", false, []string{pathEntry})
	r.Message.URI = mustURI(t, aliceTel)
	d := p.Route(context.Background(), r)
	res := answer(t, r.Message, 200)
	if d.OnResponse(context.Background(), res); res.Header.Get("P-Asserted-Identity") != "<"+aliceTel+">" {
		t.Errorf("P-Asserted-Identity %q", res.Header.Get("P-Asserted-Identity"))
	}
}
