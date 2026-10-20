package rcsas

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// waitFor bounds how long a test waits for rcs-as; a safety net, never a
// protocol timer.
const waitFor = 10 * time.Second

// coreStub is scscf: it takes the requests rcs-as sends and answers them
// 200.
type coreStub struct {
	l   net.Listener
	got chan *sip.Request
}

func newCoreStub(t *testing.T) *coreStub {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	c := &coreStub{l: l, got: make(chan *sip.Request, 16)}
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
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
					c.got <- req
					res, err := sip.NewResponse(req, 200, "", "core1")
					if err != nil {
						return
					}
					b, _ := res.Bytes()
					if _, err := nc.Write(b); err != nil {
						return
					}
				}
			}()
		}
	}()
	return c
}

// startRun runs rcs-as with cfg on any free SIP and MSRP ports, which the
// settings refuse and deployments must not use, and the memory store, until the
// test ends; it returns the SIP listener's address.
func startRun(t *testing.T, cfg Config, d deps) netip.AddrPort {
	t.Helper()
	addr, _, _ := startStoppable(t, cfg, d)
	return addr
}

// startStoppable is startRun, and also returns the MSRP listener's
// address and a stop that ends rcs-as as a shutdown does and waits for it;
// the test's end calls it too.
func startStoppable(t *testing.T, cfg Config, d deps) (netip.AddrPort, net.Addr, func()) {
	t.Helper()
	cfg.SIPListenAddr = "127.0.0.1:0"
	// The MSRP port too, which the engine advertises.
	ml, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Messaging.MSRPPort, d.msrp = ml.Addr().(*net.TCPAddr).Port, ml
	h := runtimetest.New(t, "rcs-as")
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan netip.AddrPort, 1)
	done := make(chan error, 1)
	d.store = store.NewMemory()
	d.listening = func(a netip.AddrPort) { listening <- a }
	go func() { done <- run(ctx, h.Runtime, cfg, d) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("run: %v", err)
				}
			case <-time.After(waitFor):
				t.Error("rcs-as did not stop")
			}
		})
	}
	t.Cleanup(stop)
	select {
	case addr := <-listening:
		return addr, ml.Addr(), stop
	case err := <-done:
		t.Fatalf("run ended: %v", err)
	case <-time.After(waitFor):
		t.Fatal("rcs-as did not start")
	}
	return netip.AddrPort{}, nil, nil
}

// rcs-as end to end, with the memory store: a pager-mode MESSAGE from the
// core, with alice's asserted identity, is answered 202 and stored, and
// delivered to bob as a MESSAGE of its own to the core, as a terminating
// request that the default profile does not send back to rcs-as.
func TestAStandaloneMessageIsStoredAndDeliveredThroughTheCore(t *testing.T) {
	core := newCoreStub(t)
	cfg, err := configure(with(devEnv, "RCSAS_SIP_HOST", "127.0.0.1",
		"RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
	if err != nil {
		t.Fatal(err)
	}
	addr := startRun(t, cfg, deps{})
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	body := "From: <sip:anonymous@anonymous.invalid>\r\nTo: <sip:anonymous@anonymous.invalid>\r\n\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nhello"
	var b strings.Builder
	b.WriteString("MESSAGE tel:+15550100002 SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-rcsas-run-1\r\n")
	b.WriteString("Max-Forwards: 70\r\nFrom: <tel:+15550100001>;tag=a1\r\nTo: <tel:+15550100002>\r\n")
	b.WriteString("Call-ID: rcsas-run-1\r\nCSeq: 1 MESSAGE\r\nP-Asserted-Identity: <tel:+15550100001>\r\n")
	fmt.Fprintf(&b, "Content-Type: message/cpim\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	_ = nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		t.Fatal(err)
	}
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			if res.StatusCode != 202 {
				t.Fatalf("answered %d", res.StatusCode)
			}
			break
		}
	}
	select {
	case req := <-core.got:
		if req.Method != "MESSAGE" || req.URI.String() != "tel:+15550100002" ||
			req.Header.Get("P-Asserted-Identity") != "<tel:+15550100001>" ||
			req.Header.Get("P-Served-User") != "<tel:+15550100002>;sescase=term" || string(req.Body) != body {
			t.Fatalf("the core got %s %s, PAI %q, PSU %q", req.Method, req.URI.String(),
				req.Header.Get("P-Asserted-Identity"), req.Header.Get("P-Served-User"))
		}
	case <-time.After(waitFor):
		t.Fatal("the message was not delivered")
	}
}

// scscf hands rcs-as an OPTIONS with the AS URI of the default profile's
// iFC on top of its Route (TS 24.229 §5.4.3.2), then its own entry: rcs-as
// takes the first as its own, without looking it up, and the request goes
// on to scscf rather than back to rcs-as.
func TestAnOptionsFromTheCoreGoesBackToIt(t *testing.T) {
	for top, service := range map[string]string{
		"<sip:rcs-as.rcs.internal;lr>":               "",
		"<sip:rcs-as.rcs.internal;transport=tcp;lr>": "",
		"<sip:127.0.0.1;lr>":                         "",
		// An operator's own AS URI (HSS_RCS_AS_URI), named alike here.
		"<sip:chat-as.rcs.internal;lr>": "chat-as.rcs.internal",
	} {
		t.Run(top, func(t *testing.T) {
			core := newCoreStub(t)
			cfg, err := configure(with(devEnv, "RCSAS_SIP_HOST", "127.0.0.1", "RCS_SERVICE_NAMESPACE", "rcs.internal",
				"RCSAS_SERVICE_NAME", service, "RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
			if err != nil {
				t.Fatal(err)
			}
			addr := startRun(t, cfg, deps{resolver: proxy.NumericResolver{}})
			nc, err := net.Dial("tcp", addr.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = nc.Close() })
			var b strings.Builder
			b.WriteString("OPTIONS tel:+15550100002 SIP/2.0\r\n")
			b.WriteString("Via: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-rcsas-run-options\r\n")
			b.WriteString("Max-Forwards: 70\r\nFrom: <tel:+15550100001>;tag=a1\r\nTo: <tel:+15550100002>\r\n")
			b.WriteString("Call-ID: rcsas-run-options\r\nCSeq: 1 OPTIONS\r\n")
			b.WriteString("Route: " + top + ", <sip:" + core.l.Addr().String() + ";transport=tcp;lr>\r\n")
			b.WriteString("Content-Length: 0\r\n\r\n")
			_ = nc.SetDeadline(time.Now().Add(waitFor))
			if _, err := io.WriteString(nc, b.String()); err != nil {
				t.Fatal(err)
			}
			r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
			for {
				m, err := r.ReadMessage()
				if err != nil {
					t.Fatal(err)
				}
				if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
					if res.StatusCode != 200 {
						t.Fatalf("answered %d", res.StatusCode)
					}
					break
				}
			}
			select {
			case req := <-core.got:
				// rcs-as's own entry is gone; scscf's stays for scscf.
				if req.Method != "OPTIONS" || req.Header.Get("Route") != "<sip:"+core.l.Addr().String()+";transport=tcp;lr>" {
					t.Fatalf("the core got %s with Route %q", req.Method, req.Header.Get("Route"))
				}
			case <-time.After(waitFor):
				t.Fatal("the OPTIONS did not reach the core")
			}
		})
	}
}

// The engine gets the home domain too: a sender asserted by its number
// may name itself in CPIM by the home domain's SIP form of it.
func TestTheEngineComparesAddressesAtTheHomeDomain(t *testing.T) {
	core := newCoreStub(t)
	cfg, err := configure(with(devEnv, "RCSAS_SIP_HOST", "127.0.0.1",
		"RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
	if err != nil {
		t.Fatal(err)
	}
	addr := startRun(t, cfg, deps{})
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	body := "From: <sip:+15550100001@" + devEnv["RCS_IMS_DOMAIN"] + ">\r\nTo: <sip:anonymous@anonymous.invalid>\r\n\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nhello"
	var b strings.Builder
	b.WriteString("MESSAGE tel:+15550100002 SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-rcsas-run-home\r\n")
	b.WriteString("Max-Forwards: 70\r\nFrom: <tel:+15550100001>;tag=a1\r\nTo: <tel:+15550100002>\r\n")
	b.WriteString("Call-ID: rcsas-run-home\r\nCSeq: 1 MESSAGE\r\nP-Asserted-Identity: <tel:+15550100001>\r\n")
	fmt.Fprintf(&b, "Content-Type: message/cpim\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	_ = nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		t.Fatal(err)
	}
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			if res.StatusCode != 202 {
				t.Fatalf("answered %d", res.StatusCode)
			}
			return
		}
	}
}

// rcs-as end to end with a session: a chat INVITE from the core is
// answered passive with a path at the MSRP listener Run serves, the relay's
// connection binds to it there, and a shutdown ends the session with a BYE
// before the transport closes.
func TestRunServesSessionsAndEndsThemOnShutdown(t *testing.T) {
	core := newCoreStub(t)
	cfg, err := configure(with(devEnv, "RCSAS_SIP_HOST", "127.0.0.1", "RCSAS_MSRP_HOST", "127.0.0.1",
		"RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
	if err != nil {
		t.Fatal(err)
	}
	addr, msrpAddr, stop := startStoppable(t, cfg, deps{})
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	relay := msrp.URI{Host: "127.0.0.1", Port: 9, SessionID: "runrelay1", Transport: "tcp"}
	offer := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=message 9 TCP/MSRP *\r\n" +
		"a=accept-types:message/cpim\r\na=path:" + relay.String() + "\r\na=setup:active\r\na=sendrecv\r\n"
	var b strings.Builder
	b.WriteString("INVITE tel:+15550100002 SIP/2.0\r\n")
	b.WriteString("Via: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-rcsas-run-invite\r\n")
	b.WriteString("Max-Forwards: 70\r\nFrom: <tel:+15550100001>;tag=a1\r\nTo: <tel:+15550100002>\r\n")
	b.WriteString("Call-ID: rcsas-run-invite\r\nCSeq: 1 INVITE\r\nP-Asserted-Identity: <tel:+15550100001>\r\n")
	b.WriteString("Contact: <sip:" + core.l.Addr().String() + ";transport=tcp>\r\n")
	b.WriteString(`Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"` + "\r\n")
	fmt.Fprintf(&b, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(offer), offer)
	_ = nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(nc, b.String()); err != nil {
		t.Fatal(err)
	}
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	var res *sip.Response
	for res == nil {
		m, err := r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if x, ok := m.(*sip.Response); ok && x.StatusCode >= 200 {
			res = x
		}
	}
	if res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	answer, err := sdp.Parse(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := answer.Media[0].Path()
	if err != nil || len(paths) != 1 {
		t.Fatalf("path %v, %v", paths, err)
	}
	leg, err := msrp.ParseURI(paths[0])
	if err != nil || leg.Port != msrpAddr.(*net.TCPAddr).Port {
		t.Fatalf("answered path %s, want one at %s", paths[0], msrpAddr)
	}
	to, _ := res.Header.To()
	ack := "ACK sip:" + addr.String() + ";transport=tcp SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-rcsas-run-ack\r\n" +
		"Max-Forwards: 70\r\nFrom: <tel:+15550100001>;tag=a1\r\nTo: <tel:+15550100002>;tag=" + to.Tag() + "\r\n" +
		"Call-ID: rcsas-run-invite\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(nc, ack); err != nil {
		t.Fatal(err)
	}

	// The relay's connection binds to the leg on Run's MSRP listener.
	session, err := msrp.NewSession(msrp.SessionConfig{Local: relay, Remote: []msrp.URI{leg}, Handler: nopHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	mc, err := net.Dial("tcp", msrpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(mc, msrp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := conn.Open(ctx, session); err != nil {
		t.Fatalf("the relay's session did not bind: %v", err)
	}

	stop()
	deadline := time.After(waitFor)
	for {
		select {
		case req := <-core.got:
			if req.Method == "BYE" && req.Header.Get("Call-ID") == "rcsas-run-invite" {
				return
			}
		case <-deadline:
			t.Fatal("no BYE on shutdown")
		}
	}
}

type nopHandler struct{}

func (nopHandler) HandleMessage(*msrp.Session, *msrp.Message) error { return nil }
func (nopHandler) HandleReport(*msrp.Session, msrp.Report)          {}
