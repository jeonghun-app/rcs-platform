package pcscf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// fakeCoreNode is icscf or scscf: it accepts pcscf's core connections and
// answers each request with what answer returns, nothing if that is empty,
// after passing it to got.
type fakeCoreNode struct {
	ln     net.Listener
	got    chan *sip.Request
	answer func(req *sip.Request) string
}

func startCoreNode(t *testing.T, answer func(*sip.Request) string) *fakeCoreNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeCoreNode{ln: ln, got: make(chan *sip.Request, 16), answer: answer}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(t, nc)
		}
	}()
	return f
}

func (f *fakeCoreNode) serve(t *testing.T, nc net.Conn) {
	defer nc.Close()
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok {
			continue
		}
		f.got <- req
		if _, err := io.WriteString(nc, f.answer(req)); err != nil {
			return
		}
	}
}

// echo200 answers a REGISTER with 200, echoing its Via, Path and contacts
// with expires=3600, as a registrar does.
func echo200(req *sip.Request) string {
	var b strings.Builder
	b.WriteString("SIP/2.0 200 OK\r\n")
	for _, v := range req.Header.Values("Via") {
		b.WriteString("Via: " + v + "\r\n")
	}
	for _, name := range []string{"From", "Call-ID", "CSeq"} {
		b.WriteString(name + ": " + req.Header.Get(name) + "\r\n")
	}
	b.WriteString("To: " + req.Header.Get("To") + ";tag=s1\r\n")
	if p := req.Header.Get("Path"); p != "" {
		b.WriteString("Path: " + p + "\r\n")
	}
	if cs, err := req.Header.Contact(); err == nil {
		for _, c := range cs {
			if !c.Star {
				if _, ok, _ := c.Expires(); !ok {
					c.Params.Set("expires", "3600")
				}
				b.WriteString("Contact: " + c.String() + "\r\n")
			}
		}
	}
	b.WriteString("Service-Route: <sip:orig@10.0.4.4;lr>\r\n")
	b.WriteString("P-Associated-URI: <" + aliceIMPU + ">\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	return b.String()
}

// The REGISTER crosses pcscf to icscf and back; its Path names a flow the
// transport knows, the client gets the Flow-Timer, and when the client's
// connection closes its registration goes (RFC 5626 §5.3).
func TestARegisterCrossesPcscfAndItsFlowsClosureEndsIt(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	var pc *pcscf
	s := start(t, cfg, deps{started: func(p *pcscf) { pc = p }})
	c := dial(t, s.client, nil)
	// Headers only the network may set do not reach icscf (#16 plan, review
	// of #188).
	text := registerText(outboundContact, "Supported: outbound", "P-Asserted-Identity: <"+aliceIMPU+">",
		"P-Charging-Vector: icid-value=1", "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; network-provided",
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=001010000000001")
	_ = c.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(c.nc, text); err != nil {
		t.Fatal(err)
	}
	m, err := c.r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	res := m.(*sip.Response)
	if res.StatusCode != 200 || res.Header.Get("Flow-Timer") != "120" {
		t.Fatalf("%d, Flow-Timer %q", res.StatusCode, res.Header.Get("Flow-Timer"))
	}
	got := <-icscf.got
	for _, name := range networkOnlyHeaders {
		if got.Header.Has(name) {
			t.Errorf("%s reached icscf: %q", name, got.Header.Get(name))
		}
	}
	if pani := got.Header.Values("P-Access-Network-Info"); len(pani) != 1 || strings.Contains(pani[0], "network-provided") {
		t.Errorf("P-Access-Network-Info at icscf %q, want the client's own only", pani)
	}
	paths, err := got.Header.Path()
	if err != nil || len(paths) != 1 {
		t.Fatalf("Path %q, %v", got.Header.Get("Path"), err)
	}
	if want := fmt.Sprintf("127.0.0.1:%d", s.core.Port()); fmt.Sprintf("%s:%d", paths[0].URI.Host, paths[0].URI.Port) != want {
		t.Errorf("Path %q names %s:%d, want the core listener %s", got.Header.Get("Path"), paths[0].URI.Host, paths[0].URI.Port, want)
	}
	if vias, _ := got.Header.Via(); len(vias) == 0 || vias[0].Port != int(s.core.Port()) {
		t.Errorf("Via %q does not name the core listener", got.Header.Get("Via"))
	}
	if routes, _ := got.Header.Route(); len(routes) != 1 || routes[0].URI.String() != cfg.ICSCF.String() {
		t.Errorf("Route %q", got.Header.Get("Route"))
	}
	token := paths[0].URI.User
	key := aorKey(mustURI(t, aliceIMPU))
	if _, ok := pc.registry.lookup(transportFlow(token), key); !ok {
		t.Fatalf("no registration under the Path's flow token")
	}
	_ = c.nc.Close()
	deadline := time.Now().Add(waitFor)
	for pc.registry.size() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the closed flow's registration stayed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func transportFlow(s string) transport.FlowID { return transport.FlowID(s) }
