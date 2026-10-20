package pcscf

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// respondTo writes the response with code to req, as a UA does: its Vias,
// Record-Route (RFC 3261 §12.1.1), From, To with tag, Call-ID and CSeq,
// then extra fields.
func respondTo(req *sip.Request, code int, tag string, extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", code, sip.DefaultReason(code))
	for _, v := range req.Header.Values("Via") {
		b.WriteString("Via: " + v + "\r\n")
	}
	for _, v := range req.Header.Values("Record-Route") {
		b.WriteString("Record-Route: " + v + "\r\n")
	}
	for _, name := range []string{"From", "Call-ID", "CSeq"} {
		b.WriteString(name + ": " + req.Header.Get(name) + "\r\n")
	}
	to := req.Header.Get("To")
	if !strings.Contains(to, ";tag=") {
		to += ";tag=" + tag
	}
	b.WriteString("To: " + to + "\r\n")
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// write sends text over p.
func (p *peer) write(text string) {
	p.t.Helper()
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(p.nc, text); err != nil {
		p.t.Fatal(err)
	}
}

// nextRequest reads the next request over p.
func (p *peer) nextRequest() *sip.Request {
	p.t.Helper()
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	for {
		m, err := p.r.ReadMessage()
		if err != nil {
			p.t.Fatal(err)
		}
		if req, ok := m.(*sip.Request); ok {
			return req
		}
	}
}

// coreRequest is a request from bob, through scscf, to the client at
// contact, with the given To tag and extra fields.
func coreRequest(method, contact, call, toTag string, cseq int, extra ...string) string {
	n := requests.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, contact)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 10.0.4.4:5060;branch=z9hG4bK-core-%d\r\n", n)
	b.WriteString("Max-Forwards: 69\r\n")
	b.WriteString("From: <" + bobIMPU + ">;tag=b1\r\n")
	to := "To: <" + aliceIMPU + ">"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	b.WriteString(to + "\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d %s\r\n", call, cseq, method)
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// registered registers a client over a new connection to s through icscf,
// and returns it with the Path icscf received.
func registered(t *testing.T, s *service, icscf *fakeCoreNode) (*peer, string) {
	t.Helper()
	c := dial(t, s.client, nil)
	if res := registerOver(t, c); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	paths, err := icscf.receive(t).Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatal("no Path")
	}
	return c, paths[0].URI.String()
}

// A call from the core reaches the client over the flow its Path names,
// with pcscf's Record-Route values; the client's 200 reaches the core with
// pcscf's identity and charging, the client's BYE goes back along the route
// to scscf, and a request of the core inside the dialog reaches the client
// (#16 plan D).
func TestACallFromTheCoreReachesTheClientAndItsDialogFollows(t *testing.T) {
	scscf := startCoreNode(t, answerAsUAS)
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	scscfRR := fmt.Sprintf("<sip:scscf.rcs.internal:%d;transport=tcp;lr>", scscfPort)
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	var pc *pcscf
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }})
	c, path := registered(t, s, icscf)
	token := mustURI(t, path).User
	core := dial(t, s.core, nil)
	contact := "sip:alice@192.0.2.10:40000;transport=tcp"
	call := fmt.Sprintf("term-e2e-%d", requests.Add(1))
	core.write(coreRequest("INVITE", contact, call, "", 1, "Route: <"+path+">", "Record-Route: "+scscfRR,
		fmt.Sprintf("Contact: <sip:bob@scscf.rcs.internal:%d;transport=tcp>", scscfPort),
		"P-Asserted-Identity: <"+bobIMPU+">", "P-Called-Party-ID: <"+aliceIMPU+">",
		"P-Charging-Vector: icid-value="+coreICID+";orig-ioi=home.example.net", "P-Charging-Function-Addresses: ccf=192.0.2.200"))
	invite := c.nextRequest()
	// The network's charging data stays in the network (TS 24.229 §5.2.1).
	if invite.Header.Has("P-Charging-Vector") || invite.Header.Has("P-Charging-Function-Addresses") {
		t.Errorf("charging data reached the client: %q, %q", invite.Header.Get("P-Charging-Vector"), invite.Header.Get("P-Charging-Function-Addresses"))
	}
	if invite.Method != "INVITE" || invite.URI.String() != contact {
		t.Fatalf("the client got %s %s", invite.Method, invite.URI)
	}
	wantRR := []string{
		fmt.Sprintf("<sip:%s:5060;transport=tcp;lr>", publicHost),
		fmt.Sprintf("<sip:%s@127.0.0.2:%d;transport=tcp;lr;ob;icid=%s;dlg=%s>", token, s.core.Port(), coreICID, pc.dialogMAC(transportFlow(token), call)),
		scscfRR,
	}
	if got := invite.Header.Values("Record-Route"); !slices.Equal(got, wantRR) {
		t.Errorf("Record-Route %q, want %q", got, wantRR)
	}
	if got := invite.Header.Get("P-Asserted-Identity"); got != "<"+bobIMPU+">" {
		t.Errorf("P-Asserted-Identity at the client %q", got)
	}
	c.write(respondTo(invite, 200, "a1", "Contact: <"+contact+">", "P-Preferred-Identity: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>",
		"P-Asserted-Identity: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>", "P-Charging-Vector: icid-value=1"))
	ok := core.final()
	if ok.StatusCode != 200 {
		t.Fatalf("INVITE: %d", ok.StatusCode)
	}
	if got := ok.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ">"}) || ok.Header.Has("P-Preferred-Identity") {
		t.Errorf("200 at the core: P-Asserted-Identity %q, P-Preferred-Identity %q", got, ok.Header.Get("P-Preferred-Identity"))
	}
	if got, want := ok.Header.Get("P-Charging-Vector"), "icid-value="+coreICID+";orig-ioi=home.example.net;term-ioi=ims.mnc001.mcc001.3gppnetwork.org"; got != want {
		t.Errorf("200 at the core: P-Charging-Vector %q, want %q", got, want)
	}

	// The client's BYE: its route set is the INVITE's Record-Route (RFC 3261
	// §12.1.1).
	var routeSet []string
	for _, v := range invite.Header.Values("Record-Route") {
		routeSet = append(routeSet, "Route: "+v)
	}
	c.send(call, fmt.Sprintf("BYE sip:bob@scscf.rcs.internal:%d;transport=tcp SIP/2.0", scscfPort), "a1", 2, "BYE", routeSet...)
	bye := scscf.receive(t)
	if bye.Method != "BYE" || bye.Header.Get("P-Charging-Vector") != "icid-value="+coreICID+";orig-ioi=ims.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("%s at scscf, P-Charging-Vector %q", bye.Method, bye.Header.Get("P-Charging-Vector"))
	}
	if res := c.final(); res.StatusCode != 200 {
		t.Errorf("BYE: %d", res.StatusCode)
	}

	// A request of the core inside the dialog: the 200's route set
	// reversed, scscf's own consumed.
	rr := ok.Header.Values("Record-Route")
	core.write(coreRequest("INFO", contact, call, "a1", 2, "Route: "+rr[1], "Route: "+rr[0]))
	info := c.nextRequest()
	if info.Method != "INFO" {
		t.Fatalf("the client got %s", info.Method)
	}
	c.write(respondTo(info, 200, "a1"))
	if res := core.final(); res.StatusCode != 200 {
		t.Errorf("INFO: %d", res.StatusCode)
	}
	// The same route in another dialog reaches no one (security review of
	// #221).
	core.write(coreRequest("INFO", contact, "another-call", "a1", 1, "Route: "+rr[1], "Route: "+rr[0]))
	if res := core.final(); res.StatusCode != statusFlowFailed {
		t.Errorf("another dialog's INFO: %d, want 430", res.StatusCode)
	}

	// Privacy of the identity hides it from the client.
	core.write(coreRequest("MESSAGE", contact, "term-private", "", 1, "Route: <"+path+">", "P-Asserted-Identity: <"+bobIMPU+">", "Privacy: id"))
	msg := c.nextRequest()
	if msg.Header.Has("P-Asserted-Identity") {
		t.Errorf("P-Asserted-Identity reached the client with Privacy: id: %q", msg.Header.Get("P-Asserted-Identity"))
	}
	c.write(respondTo(msg, 200, "a1"))
	if res := core.final(); res.StatusCode != 200 {
		t.Errorf("MESSAGE: %d", res.StatusCode)
	}
}

// A flow token from an earlier start of pcscf, or of a flow that has
// closed, is 430 Flow Failed, even when a new flow comes from the same
// address: tokens are not reused (#16 AC 7, recycled addresses).
func TestAStaleFlowTokenIs430(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	first := start(t, cfg, deps{})
	_, oldPath := registered(t, first, icscf)
	first.stop()

	var pc *pcscf
	s := start(t, cfg, deps{started: func(p *pcscf) { pc = p }})
	c, path := registered(t, s, icscf)
	if mustURI(t, path).User == mustURI(t, oldPath).User {
		t.Fatal("a new start reused a flow token")
	}
	core := dial(t, s.core, nil)
	// The earlier start's token, written for this task's core listener.
	old := mustURI(t, oldPath)
	old.Port = int(s.core.Port())
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", "stale-1", "", 1, "Route: <"+old.String()+">"))
	if res := core.final(); res.StatusCode != statusFlowFailed {
		t.Errorf("an earlier start's token: %d, want 430", res.StatusCode)
	}
	// The client's own flow, once closed; a new flow from the same address
	// gets a new token.
	_ = c.nc.Close()
	c2, path2 := registered(t, s, icscf)
	defer c2.nc.Close()
	if mustURI(t, path2).User == mustURI(t, path).User {
		t.Fatal("a new flow from the same address got the old token")
	}
	// Once pcscf has seen the flow close, which ends its registration.
	closed := transportFlow(mustURI(t, path).User)
	for deadline := time.Now().Add(waitFor); ; time.Sleep(10 * time.Millisecond) {
		if _, ok := pc.registry.lookup(closed, aorKey(mustURI(t, aliceIMPU))); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the closed flow's registration stayed")
		}
	}
	core.write(coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", "stale-2", "", 1, "Route: <"+path+">"))
	if res := core.final(); res.StatusCode != statusFlowFailed {
		t.Fatalf("a closed flow's token: %d, want 430", res.StatusCode)
	}
}

// The core's answer to a client's own request reaches it without the
// network's charging data (TS 24.229 §5.2.1).
func TestAResponseToTheClientCarriesNoChargingData(t *testing.T) {
	scscf := startCoreNode(t, func(req *sip.Request) string {
		return respondTo(req, 200, "b1", "P-Charging-Vector: icid-value=1;term-ioi=home.example.net", "P-Charging-Function-Addresses: ccf=192.0.2.200")
	})
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(echo200(req), "<sip:orig@10.0.4.4;lr>", fmt.Sprintf("<sip:orig@scscf.rcs.internal:%d;transport=tcp;lr>", scscfPort), 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c, _ := registered(t, s, icscf)
	c.send(fmt.Sprintf("charging-%d", requests.Add(1)), "MESSAGE "+bobIMPU+" SIP/2.0", "", 1, "MESSAGE",
		fmt.Sprintf("Route: <sip:%s:5060;transport=tcp;lr>", publicHost))
	_ = scscf.receive(t)
	res := c.final()
	if res.StatusCode != 200 || res.Header.Has("P-Charging-Vector") || res.Header.Has("P-Charging-Function-Addresses") {
		t.Errorf("%d to the client with %q, %q", res.StatusCode, res.Header.Get("P-Charging-Vector"), res.Header.Get("P-Charging-Function-Addresses"))
	}
}
