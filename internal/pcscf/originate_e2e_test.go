package pcscf

import (
	"fmt"
	"io"
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

// final reads responses until a final one.
func (p *peer) final() *sip.Response {
	p.t.Helper()
	for {
		m, err := p.r.ReadMessage()
		if err != nil {
			p.t.Fatal(err)
		}
		res, ok := m.(*sip.Response)
		if !ok {
			p.t.Fatalf("got a request: %v", m)
		}
		if res.StatusCode >= 200 {
			return res
		}
	}
}

// receive waits for the next request at n.
func (n *fakeCoreNode) receive(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case req := <-n.got:
		return req
	case <-time.After(waitFor):
		t.Fatal("no request reached the core")
		return nil
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
// 6). A BYE whose route names another flow is refused.
func TestADialogFromAClientCrossesPcscfWithNothingForged(t *testing.T) {
	scscf := startCoreNode(t, answerAsUAS)
	scscfURI := "sip:orig@" + scscf.ln.Addr().String() + ";transport=tcp;lr"
	icscf := startCoreNode(t, func(req *sip.Request) string {
		return strings.Replace(strings.Replace(echo200(req), "<sip:orig@10.0.4.4;lr>", "<"+scscfURI+">", 1),
			"P-Associated-URI: <"+aliceIMPU+">", "P-Associated-URI: <"+aliceIMPU+">, <"+aliceTel+">", 1)
	})
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := start(t, cfg, deps{})
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
			"P-Preferred-Identity: <" + aliceIMPU + ">"}, forged...)...)
	invite := scscf.receive(t)
	noForged(t, invite)
	if got := invite.Header.Values("Route"); !slices.Equal(got, []string{"<" + scscfURI + ">"}) {
		t.Errorf("Route %q, want the Service-Route alone", got)
	}
	wantRR := []string{
		fmt.Sprintf("<sip:%s@127.0.0.1:%d;transport=tcp;lr>", token, s.core.Port()),
		fmt.Sprintf("<sip:%s:5060;transport=tcp;lr>", publicHost),
	}
	if got := invite.Header.Values("Record-Route"); !slices.Equal(got, wantRR) {
		t.Errorf("Record-Route %q, want %q", got, wantRR)
	}
	if got := invite.Header.Values("P-Asserted-Identity"); !slices.Equal(got, []string{"<" + aliceIMPU + ">", "<" + aliceTel + ">"}) {
		t.Errorf("P-Asserted-Identity %q", got)
	}
	if invite.Header.Has("P-Preferred-Identity") {
		t.Errorf("P-Preferred-Identity reached scscf: %q", invite.Header.Get("P-Preferred-Identity"))
	}
	if v := invite.Header.Get("P-Charging-Vector"); !icidValue.MatchString(v) {
		t.Errorf("P-Charging-Vector %q", v)
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

	// A route naming a flow other than the one the BYE came on.
	stolen := slices.Clone(routeSet)
	stolen[1] = strings.Replace(stolen[1], token+"@", "OTHERFLOW@", 1)
	c.send(call, "BYE "+target+" SIP/2.0", "b1", 2, "BYE", stolen...)
	if res := c.final(); res.StatusCode != 403 {
		t.Errorf("BYE on another flow's route: %d, want 403", res.StatusCode)
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
	if res := c.final(); res.StatusCode != 200 {
		t.Errorf("BYE: %d", res.StatusCode)
	}
}
