package pcscf

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The integration of pcscf and msrp-relay (#136 decision 7): pcscf as run
// starts it, msrp-relay as msrprelay.Run starts it with its memory store,
// over real sockets; an MSRP client, and an MSRP endpoint in rcs-as's part,
// passive, which the relay connects to. The compose scenario is #16 PR F.

// freeAddr is a loopback address no one listens on, for a service that
// does not say where it listens.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// msrpAS is rcs-as's MSRP side: a passive endpoint for the sessions a test
// registers.
type msrpAS struct {
	addr string
	reg  *msrp.Registry
}

func startMSRPAS(t *testing.T) *msrpAS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	as := &msrpAS{addr: ln.Addr().String(), reg: &msrp.Registry{}}
	conns := make(chan *msrp.Conn, 16)
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			if c, err := msrp.NewPassiveConn(nc, as.reg, msrp.Config{}); err == nil {
				conns <- c
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case c := <-conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return as
}

func (as *msrpAS) uri(sid string) string { return "msrp://" + as.addr + "/" + sid + ";tcp" }

// session registers a session at sid whose peer is remote, the relay's
// core-side path.
func (as *msrpAS) session(t *testing.T, sid, remote string) (*msrp.Session, *recorded) {
	t.Helper()
	h := &recorded{msgs: make(chan string, 8)}
	s, err := msrp.NewSession(msrp.SessionConfig{Local: mustMSRP(t, as.uri(sid)), Remote: []msrp.URI{mustMSRP(t, remote)}, Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	if err := as.reg.Add(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, h
}

// asSession is a session of rcs-as's MSRP side and what it got.
type asSession struct {
	s *msrp.Session
	h *recorded
}

func mustMSRP(t *testing.T, s string) msrp.URI {
	t.Helper()
	u, err := msrp.ParseURI(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return u
}

// recorded is an msrp.Handler that keeps the bodies it gets.
type recorded struct{ msgs chan string }

func (h *recorded) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	h.msgs <- string(m.Body.Bytes())
	return nil
}
func (h *recorded) HandleReport(*msrp.Session, msrp.Report) {}

func (h *recorded) next(t *testing.T) string {
	t.Helper()
	select {
	case m := <-h.msgs:
		return m
	case <-time.After(waitFor):
		t.Fatal("no message arrived")
		return ""
	}
}

// startRelay runs msrp-relay on loopback with its memory store, rcs-as at
// as, and pcscf's token; it returns its control URL.
func startRelay(t *testing.T, as *msrpAS) *url.URL {
	t.Helper()
	public, control := freeAddr(t), freeAddr(t)
	_, port, _ := net.SplitHostPort(public)
	_, asPort, _ := net.SplitHostPort(as.addr)
	env := map[string]string{
		"RCS_ENV": "dev", "RELAY_LISTEN_ADDR": public, "RELAY_CONTROL_ADDR": control,
		"RELAY_PUBLIC_HOST": "127.0.0.1", "RELAY_PUBLIC_TLS": "false", "RELAY_PUBLIC_PORT": port,
		"RELAY_CORE_HOST": "127.0.0.1", "RELAY_CORE_NETWORKS": "127.0.0.0/8", "RELAY_CORE_PORTS": asPort,
		"RELAY_STORE": "memory", "RELAY_PCSCF_TOKEN": testRelayToken,
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	cfg := msrprelay.Configure(&runtime.Settings{Env: shared.WithPrefix("RELAY_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	if err := shared.Err(); err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "msrp-relay")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- msrprelay.Run(ctx, h.Runtime, cfg) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("msrp-relay did not stop")
		}
	})
	deadline := time.Now().Add(waitFor)
	for {
		if c, err := net.Dial("tcp", control); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("msrp-relay did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, _ := url.Parse("http://" + control)
	return u
}

// integratedStack is pcscf in front of a real msrp-relay, with alice
// registered, scscf answering INVITEs as rcs-as does with as's MSRP side,
// and the Path icscf got.
type integratedStack struct {
	*relayStack
	as   *msrpAS
	path string
	// answered hears each session rcs-as answered an offer with.
	answered chan asSession
}

func startIntegrated(t *testing.T) *integratedStack {
	t.Helper()
	as := startMSRPAS(t)
	relayURL := startRelay(t, as)
	is := &integratedStack{as: as, answered: make(chan asSession, 8)}
	// rcs-as answers a client's offer with a session of its own, passive,
	// whose peer is the relay's core-side path in the offer.
	answer := func(req *sip.Request) string {
		text := answerAsUAS(req)
		if req.Method != "INVITE" || len(req.Body) == 0 {
			return text
		}
		offer, err := sdp.Parse(req.Body)
		if err != nil || len(offer.Media) < 2 {
			return text
		}
		path, _ := offer.Media[1].Path()
		sid := "as" + strconv.Itoa(int(requests.Add(1)))
		ss, h := is.as.session(t, sid, path[0])
		is.answered <- asSession{ss, h}
		body := strings.Replace(rcsAsAnswer, "msrp://10.0.1.20:2855/as9f2c1;tcp", is.as.uri(sid), 1)
		return strings.Replace(text, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body), 1)
	}
	is.relayStack = startRelayStackAt(t, answer, 2*time.Second, deps{}, relayURL)
	paths, err := is.icscf.receive(t).Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatal("no Path")
	}
	is.path = paths[0].URI.String()
	return is
}

// clientSession opens alice's MSRP session to the relay's client path,
// with local, her own path, as she wrote it in the SDP.
func clientSession(t *testing.T, local, relayPath string) (*msrp.Session, *recorded) {
	t.Helper()
	u := mustMSRP(t, relayPath)
	nc, err := net.Dial("tcp", net.JoinHostPort(u.Host, strconv.Itoa(u.Port)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := msrp.NewActiveConn(nc, msrp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	h := &recorded{msgs: make(chan string, 8)}
	s, err := msrp.NewSession(msrp.SessionConfig{Local: mustMSRP(t, local), Remote: []msrp.URI{u}, Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := c.Open(ctx, s); err != nil {
		t.Fatalf("opening the session at the relay: %v", err)
	}
	return s, h
}

func sendMSRP(t *testing.T, s *msrp.Session, body string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if _, err := s.Send(ctx, msrp.Outgoing{ContentType: "text/plain", Body: msrp.BodyOf([]byte(body))}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// pathIn is the a=path of the MSRP line of a description.
func pathIn(t *testing.T, body []byte) string {
	t.Helper()
	d, err := sdp.Parse(body)
	if err != nil {
		t.Fatalf("%v:\n%s", err, body)
	}
	for _, m := range d.Media {
		if m.IsMSRP() && m.Port != 0 {
			p, err := m.Path()
			if err == nil && len(p) == 1 {
				return p[0]
			}
		}
	}
	t.Fatalf("no MSRP line:\n%s", body)
	return ""
}

// A chat alice sets up goes through pcscf and msrp-relay to rcs-as: the
// relay's client path reaches her, she connects to the relay, and what she
// sends reaches rcs-as's MSRP side, which the relay connected to; rcs-as's
// reply reaches her. A re-INVITE that keeps her path keeps the binding,
// and the chat goes on. Her BYE releases the binding.
func TestIntegrationAClientsChatGoesThroughTheRelay(t *testing.T) {
	is := startIntegrated(t)
	plain := strings.NewReplacer("TCP/TLS/MSRP", "TCP/MSRP", "msrps://192.0.2.10:9/s7d2k8f;tcp", "msrp://192.0.2.10:9/s7d2k8f;tcp").Replace(clientChatOffer)
	is.invite(t, "it-chat-1", "INVITE", plain)
	ok := is.c.final()
	if ok.StatusCode != 200 {
		t.Fatalf("INVITE: %d", ok.StatusCode)
	}
	relayPath := pathIn(t, ok.Body)
	inv := is.scscf.receive(t)
	if strings.Contains(string(inv.Body), "192.0.2.10:9/") {
		t.Errorf("the client's path reached rcs-as:\n%s", inv.Body)
	}
	as := <-is.answered
	s, mine := clientSession(t, "msrp://192.0.2.10:9/s7d2k8f;tcp", relayPath)
	sendMSRP(t, s, "hello through the relay")
	if got := as.h.next(t); got != "hello through the relay" {
		t.Fatalf("rcs-as got %q", got)
	}
	sendMSRP(t, as.s, "and back")
	if got := mine.next(t); got != "and back" {
		t.Fatalf("alice got %q", got)
	}

	// A refresh that keeps her path: rcs-as gets the same core-side path.
	is.inDialog(t, "it-chat-1", "INVITE", 2, ok, plain)
	if res := is.c.final(); res.StatusCode != 200 || pathIn(t, res.Body) != relayPath {
		t.Fatalf("re-INVITE: %d\n%s", res.StatusCode, res.Body)
	}
	if re := is.scscf.receive(t); pathIn(t, re.Body) != pathIn(t, inv.Body) {
		t.Errorf("the refresh moved the core-side path:\n%s", re.Body)
	}
	<-is.answered
	sendMSRP(t, s, "after the refresh")
	if got := as.h.next(t); got != "after the refresh" {
		t.Fatalf("rcs-as got %q", got)
	}
	is.inDialog(t, "it-chat-1", "BYE", 3, ok, "")
	if res := is.c.final(); res.StatusCode != 200 {
		t.Fatalf("BYE: %d", res.StatusCode)
	}
	is.waitHeld(t, 0)
}

// inDialog has alice send method in call's dialog, whose 2xx was ok, with
// CSeq seq and body as its description if any, along the route ok set up.
func (is *integratedStack) inDialog(t *testing.T, call, method string, seq int, ok *sip.Response, body string) {
	t.Helper()
	to, _ := ok.Header.To()
	cs, _ := ok.Header.Contact()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", method, cs[0].URI)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-it-%d\r\n", requests.Add(1))
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <" + aliceIMPU + ">;tag=a1\r\n")
	b.WriteString("To: " + to.String() + "\r\n")
	fmt.Fprintf(&b, "Call-ID: %s\r\nCSeq: %d %s\r\n", call, seq, method)
	rr := ok.Header.Values("Record-Route")
	for i := len(rr) - 1; i >= 0; i-- {
		b.WriteString("Route: " + rr[i] + "\r\n")
	}
	b.WriteString("Contact: <" + clientContact + ">\r\n")
	if body != "" {
		b.WriteString("Content-Type: application/sdp\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(body), body)
	is.c.write(b.String())
}

// A chat rcs-as sets up goes the same way round: the client gets the
// relay's client path in rcs-as's offer, actpass, answers active, and
// rcs-as the relay's core-side path, active; she connects to the relay,
// the relay to rcs-as, and messages go both ways.
func TestIntegrationARcsAsChatGoesThroughTheRelay(t *testing.T) {
	is := startIntegrated(t)
	core := dial(t, is.svc.core, nil)
	offer := strings.Replace(rcsAsOffer, "msrp://10.0.1.20:2855/as9f2c1;tcp", is.as.uri("asterm1"), 1)
	scscfPort := is.scscf.ln.Addr().(*net.TCPAddr).Port
	text := coreRequest("INVITE", "sip:alice@192.0.2.10:40000;transport=tcp;ob", "it-term-1", "", 1, "Route: <"+is.path+">",
		fmt.Sprintf("Record-Route: <sip:scscf.rcs.internal:%d;transport=tcp;lr>", scscfPort),
		fmt.Sprintf("Contact: <sip:rcs-as@scscf.rcs.internal:%d;transport=tcp>", scscfPort), "P-Called-Party-ID: <"+aliceIMPU+">")
	core.write(strings.Replace(text, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(offer), offer), 1))
	inv := is.c.nextRequest()
	relayPath := pathIn(t, inv.Body)
	if !strings.Contains(string(inv.Body), "a=setup:actpass") || strings.Contains(string(inv.Body), is.as.addr) {
		t.Fatalf("the offer to the client:\n%s", inv.Body)
	}
	answer := strings.NewReplacer("TCP/TLS/MSRP", "TCP/MSRP", "msrps://192.0.2.10:9/s7d2k8f;tcp", "msrp://192.0.2.10:9/t3rm1n4l;tcp", "a=setup:actpass", "a=setup:active").Replace(clientChatOffer)
	res := respondTo(inv, 200, "a1", "Contact: <"+aliceContact+">")
	is.c.write(strings.Replace(res, "Content-Length: 0\r\n\r\n", fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(answer), answer), 1))
	ok := core.final()
	if ok.StatusCode != 200 || !strings.Contains(string(ok.Body), "a=setup:active") || strings.Contains(string(ok.Body), "192.0.2.10:9/") {
		t.Fatalf("the answer to rcs-as: %d\n%s", ok.StatusCode, ok.Body)
	}
	asSess, asGot := is.as.session(t, "asterm1", pathIn(t, ok.Body))
	s, mine := clientSession(t, "msrp://192.0.2.10:9/t3rm1n4l;tcp", relayPath)
	sendMSRP(t, s, "hello rcs-as")
	if got := asGot.next(t); got != "hello rcs-as" {
		t.Fatalf("rcs-as got %q", got)
	}
	sendMSRP(t, asSess, "hello alice")
	if got := mine.next(t); got != "hello alice" {
		t.Fatalf("alice got %q", got)
	}
	if got := is.pc.msrp.limit.held(); got != 1 {
		t.Errorf("held %d", got)
	}
}
