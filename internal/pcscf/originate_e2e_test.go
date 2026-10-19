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

// answerAsUAS answers a request the way scscf in front of bob would: an ACK
// gets nothing, an INVITE a 200 that records scscf's route on top of the
// request's and names scscf as bob's contact, anything else a plain 200.
func answerAsUAS(req *sip.Request) string {
	if req.Method == "ACK" {
		return ""
	}
	var b strings.Builder
	b.WriteString("SIP/2.0 200 OK\r\n")
	for _, v := range req.Header.Values("Via") {
		b.WriteString("Via: " + v + "\r\n")
	}
	for _, name := range []string{"From", "Call-ID", "CSeq"} {
		b.WriteString(name + ": " + req.Header.Get(name) + "\r\n")
	}
	to := req.Header.Get("To")
	if !strings.Contains(to, ";tag=") {
		to += ";tag=b1"
	}
	b.WriteString("To: " + to + "\r\n")
	if req.Method == "INVITE" {
		routes, _ := req.Header.Route()
		self := routes[0].URI
		b.WriteString("Record-Route: <" + self.String() + ">\r\n")
		for _, v := range req.Header.Values("Record-Route") {
			b.WriteString("Record-Route: " + v + "\r\n")
		}
		fmt.Fprintf(&b, "Contact: <sip:bob@%s:%d;transport=tcp>\r\n", self.Host, self.Port)
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// send writes a request from alice to bob in call callID over p, with the
// given first line, To tag and extra fields.
func (p *peer) send(callID, line, toTag string, cseq int, method string, extra ...string) {
	p.t.Helper()
	n := requests.Add(1)
	var b strings.Builder
	b.WriteString(line + "\r\n")
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-orig-e2e-%d\r\n", n)
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=a1\r\n")
	to := "To: <" + bobIMPU + ">"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	b.WriteString(to + "\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d %s\r\n", callID, cseq, method)
	for _, e := range extra {
		b.WriteString(e + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(p.nc, b.String()); err != nil {
		p.t.Fatal(err)
	}
}

// forged are header fields a client may not set, and so must never reach the
// core from it as the client wrote them (TS 24.229 §5.2, ADR 0007 §7).
var forged = []string{
	"P-Asserted-Identity: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>",
	"P-Charging-Vector: icid-value=1",
	"P-Served-User: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>",
	"P-Visited-Network-ID: forged.example.net",
	"P-Profile-Key: <sip:+15550100005@ims.mnc001.mcc001.3gppnetwork.org>",
	"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; network-provided",
}

// noForged fails if req carries any network-only field the client forged:
// such a field is either absent or pcscf's own.
func noForged(t *testing.T, req *sip.Request) {
	t.Helper()
	for _, name := range networkOnlyHeaders {
		for _, v := range req.Header.Values(name) {
			if v == "icid-value=1" || strings.Contains(v, "+15550100005") || strings.Contains(v, "forged") {
				t.Errorf("%s %s reached the core with %s: %q", req.Method, req.Header.Get("CSeq"), name, v)
			}
		}
	}
	if strings.Contains(strings.Join(req.Header.Values("P-Access-Network-Info"), ","), "network-provided") {
		t.Errorf("%s reached the core with a network-provided P-Access-Network-Info", req.Method)
	}
}

// An INVITE from a registered client crosses pcscf to the scscf its
// registration named, with pcscf's identity, charging and two Record-Route
// values, and the dialog's ACK and BYE follow that route back through pcscf;
// nothing the client forged reaches scscf on any of them (#16 plan, question
// 6). A BYE whose route names another flow, or whose next hop is not scscf's
// name, is refused, and in-dialog requests carry the dialog's icid.
func TestADialogFromAClientCrossesPcscfWithNothingForged(t *testing.T) {
	scscf := startCoreNode(t, answerAsUAS)
	scscfPort := scscf.ln.Addr().(*net.TCPAddr).Port
	scscfURI := fmt.Sprintf("sip:orig@scscf.rcs.internal:%d;transport=tcp;lr", scscfPort)
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(strings.Replace(echo200(req), "<sip:orig@10.0.4.4;lr>", "<"+scscfURI+">", 1),
			"P-Associated-URI: <"+aliceIMPU+">", "P-Associated-URI: <"+aliceIMPU+";user=phone>, <"+aliceTel+">", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.SCSCFPort = scscfPort
	// scscf's service name resolves to the fake.
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1")})
	c := dial(t, s.client, nil)
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, registerText(outboundContact, "Supported: outbound")); err != nil {
		t.Fatal(err)
	}
	if res := c.final(); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	paths, err := icscf.receive(t).Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatal("no Path")
	}
	token := paths[0].URI.User

	call := fmt.Sprintf("orig-e2e-%d", requests.Add(1))
	pcscfRoute := fmt.Sprintf("Route: <sip:%s:5060;transport=tcp;lr>", publicHost)
	c.send(call, "INVITE "+bobIMPU+" SIP/2.0", "", 1, "INVITE",
		append([]string{pcscfRoute, "Route: <sip:10.0.9.9;lr>", "Contact: <sip:alice@192.0.2.10:40000;transport=tcp;ob>",
			"P-Preferred-Identity: <" + aliceIMPU + ";user=phone>"}, forged...)...)
	invite := scscf.receive(t)
	noForged(t, invite)
	if got := invite.Header.Values("Route"); !slices.Equal(got, []string{"<" + scscfURI + ">"}) {
		t.Errorf("Route %q, want the Service-Route alone", got)
	}
	pcv := invite.Header.Get("P-Charging-Vector")
	icid := strings.TrimSuffix(strings.TrimPrefix(pcv, "icid-value="), ";orig-ioi=ims.mnc001.mcc001.3gppnetwork.org")
	wantRR := []string{
		fmt.Sprintf("<sip:%s@127.0.0.2:%d;transport=tcp;lr;ob;icid=%s>", token, s.core.Port(), icid),
		fmt.Sprintf("<sip:%s:5060;transport=tcp;lr>", publicHost),
	}
	if got := invite.Header.Values("Record-Route"); !slices.Equal(got, wantRR) {
		t.Errorf("Record-Route %q, want %q", got, wantRR)
	}
	if got := invite.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ";user=phone>", "<" + aliceTel + ">"}) {
		t.Errorf("P-Asserted-Identity %q", got)
	}
	if invite.Header.Has("P-Preferred-Identity") {
		t.Errorf("P-Preferred-Identity reached scscf: %q", invite.Header.Get("P-Preferred-Identity"))
	}
	if !icidValue.MatchString(pcv) {
		t.Errorf("P-Charging-Vector %q", pcv)
	}
	ok := c.final()
	if ok.StatusCode != 200 {
		t.Fatalf("INVITE: %d", ok.StatusCode)
	}
	// The client's route set is the 200's Record-Route reversed (RFC 3261
	// §12.1.2).
	rr := ok.Header.Values("Record-Route")
	var routeSet []string
	for _, v := range slices.Backward(rr) {
		routeSet = append(routeSet, "Route: "+v)
	}
	contact, err := ok.Header.Contact()
	if err != nil || len(contact) != 1 || len(rr) != 3 {
		t.Fatalf("Contact %q, Record-Route %q", ok.Header.Get("Contact"), rr)
	}
	target := contact[0].URI.String()

	c.send(call, "ACK "+target+" SIP/2.0", "b1", 1, "ACK", append(slices.Clone(routeSet), forged...)...)
	ack := scscf.receive(t)
	if ack.Method != "ACK" {
		t.Fatalf("%s reached scscf, want the ACK", ack.Method)
	}
	noForged(t, ack)
	if got := ack.Header.Get("P-Charging-Vector"); got != pcv {
		t.Errorf("ACK P-Charging-Vector %q, want the INVITE's %q", got, pcv)
	}

	// A route naming a flow other than the one the BYE came on.
	stolen := slices.Clone(routeSet)
	stolen[1] = strings.Replace(stolen[1], token+"@", "OTHERFLOW@", 1)
	c.send(call, "BYE "+target+" SIP/2.0", "b1", 2, "BYE", stolen...)
	if res := c.final(); res.StatusCode != 403 {
		t.Errorf("BYE on another flow's route: %d, want 403", res.StatusCode)
	}
	// A next hop other than scscf's name: scscf's address, or this task's
	// own core listener written another way, as the Route below pcscf's or
	// as the Request-URI (review of #208).
	own := fmt.Sprintf("sip:OTHERFLOW@[::ffff:127.0.0.2]:%d;transport=tcp", s.core.Port())
	for i, tt := range []struct{ uri, hop string }{
		{target, fmt.Sprintf("<sip:127.0.0.1:%d;transport=tcp;lr>", scscfPort)},
		{own, ""},
		{bobIMPU, "<" + own + ";lr>"},
	} {
		aimed := slices.Clone(routeSet[:2])
		if tt.hop != "" {
			aimed = append(aimed, "Route: "+tt.hop)
		}
		c.send(call, "BYE "+tt.uri+" SIP/2.0", "b1", 10+i, "BYE", aimed...)
		if res := c.final(); res.StatusCode != 403 {
			t.Errorf("BYE %s via %q: %d, want 403", tt.uri, tt.hop, res.StatusCode)
		}
	}

	c.send(call, "BYE "+target+" SIP/2.0", "b1", 3, "BYE", append(slices.Clone(routeSet), forged...)...)
	bye := scscf.receive(t)
	if cseq, _ := bye.Header.CSeq(); bye.Method != "BYE" || cseq.Seq != 3 {
		t.Fatalf("%s %s reached scscf, want BYE 3", bye.Method, bye.Header.Get("CSeq"))
	}
	noForged(t, bye)
	if got := bye.Header.Values("Route"); !slices.Equal(got, []string{"<" + scscfURI + ">"}) {
		t.Errorf("BYE Route %q", got)
	}
	if got := bye.Header.Get("P-Charging-Vector"); got != pcv {
		t.Errorf("BYE P-Charging-Vector %q, want the INVITE's %q", got, pcv)
	}
	if res := c.final(); res.StatusCode != 200 {
		t.Errorf("BYE: %d", res.StatusCode)
	}
}

// A route back into this task's own core listener, its address written
// another way, is taken as pcscf's own and so is no next hop: the request
// is refused at the edge rather than delivered to the core side.
func TestARouteBackIntoThisTaskIsRefusedAtTheEdge(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{})
	c := dial(t, s.client, nil)
	if res := registerOver(t, c); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	paths, err := icscf.receive(t).Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatal("no Path")
	}
	own := fmt.Sprintf("Route: <sip:%s@127.0.0.2:%d;transport=tcp;lr>", paths[0].URI.User, s.core.Port())
	pub := fmt.Sprintf("Route: <sip:%s:5060;transport=tcp;lr>", publicHost)
	for _, next := range []string{
		fmt.Sprintf("Route: <sip:OTHERFLOW@[::ffff:127.0.0.2]:%d;transport=tcp;lr>", s.core.Port()),
		fmt.Sprintf("Route: <sip:OTHERFLOW@[::ffff:7f00:2]:%d;transport=tcp;lr>", s.core.Port()),
	} {
		c.send(fmt.Sprintf("back-%d", requests.Add(1)), "MESSAGE "+bobIMPU+" SIP/2.0", "made-up", 1, "MESSAGE", pub, own, next)
		if res := c.final(); res.StatusCode != 403 {
			t.Errorf("%s: %d %s, want 403 at the edge", next, res.StatusCode, res.Reason)
		}
	}
}
