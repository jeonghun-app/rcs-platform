package rcsas

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
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

// rcs-as end to end, with the memory store: a pager-mode MESSAGE from the
// core, with alice's asserted identity, is answered 202 and stored, and
// delivered to bob as a MESSAGE of its own to the core, as a terminating
// request that the default profile does not send back to rcs-as.
func TestAStandaloneMessageIsStoredAndDeliveredThroughTheCore(t *testing.T) {
	core := newCoreStub(t)
	cfg, err := configure(with(devEnv, "RCSAS_SIP_LISTEN_ADDR", "127.0.0.1:0", "RCSAS_SIP_HOST", "127.0.0.1",
		"RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
	if err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "rcs-as")
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan netip.AddrPort, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, h.Runtime, cfg, deps{store: store.NewMemory(), listening: func(a netip.AddrPort) { listening <- a }})
	}()
	t.Cleanup(func() {
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
	var addr netip.AddrPort
	select {
	case addr = <-listening:
	case err := <-done:
		t.Fatalf("run ended: %v", err)
	case <-time.After(waitFor):
		t.Fatal("rcs-as did not start")
	}

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
