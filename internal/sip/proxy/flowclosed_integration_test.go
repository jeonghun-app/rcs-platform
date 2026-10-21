package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// #234, over a real transport: a request written onto a client's flow that
// the client then closes reaches the sender as 430 well within Timer F
// (32 s), however soon after the write the close comes.
func TestARequestOnAFlowTheClientClosesGets430Soon(t *testing.T) {
	var (
		mu         sync.Mutex
		clientFlow transport.FlowID
	)
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{
		OnFlowClosed: func(id transport.FlowID, _ transport.FlowInfo) {
			if p := px.Load(); p != nil {
				p.FlowClosed(id)
			}
		},
	}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(_ context.Context, r *Request) Decision {
			// The client's OPTIONS marks its flow; the core's MESSAGE goes
			// to it, as pcscf sends a terminating request.
			if r.Message.Method == "OPTIONS" {
				mu.Lock()
				clientFlow = r.Source.Flow
				mu.Unlock()
				return Decision{Status: 200}
			}
			mu.Lock()
			flow := clientFlow
			mu.Unlock()
			return Decision{
				Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: flow}}},
				OnFinal: keep430,
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)

	client := dialSIP(t, addr.String())
	client.send(t, "OPTIONS", "c1")
	if res := client.final(t); res.StatusCode != 200 {
		t.Fatalf("OPTIONS answered %d", res.StatusCode)
	}
	core := dialSIP(t, addr.String())
	core.send(t, "MESSAGE", "m1")
	// The client reads the MESSAGE and closes without answering.
	if _, err := client.r.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	_ = client.nc.Close()
	start := time.Now()
	res := core.final(t)
	if res.StatusCode != 430 || time.Since(start) > 5*time.Second {
		t.Fatalf("core got %d after %v, want 430 at once", res.StatusCode, time.Since(start))
	}
}

// sipConn is one side of a SIP connection in these tests.
type sipConn struct {
	nc net.Conn
	r  *sip.Reader
}

func dialSIP(t *testing.T, addr string) *sipConn {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	return &sipConn{nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{})}
}

var flowSends atomic.Int64

func (c *sipConn) send(t *testing.T, method, id string) {
	t.Helper()
	n := flowSends.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s sip:bob@example.com SIP/2.0\r\n", method)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP %s;branch=z9hG4bK-fc-%s-%d\r\n", c.nc.LocalAddr(), id, n)
	b.WriteString("Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n")
	fmt.Fprintf(&b, "Call-ID: fc-%s-%d\r\nCSeq: 1 %s\r\nContent-Length: 0\r\n\r\n", id, n, method)
	if _, err := io.WriteString(c.nc, b.String()); err != nil {
		t.Fatal(err)
	}
}

// final reads up to the first final response.
func (c *sipConn) final(t *testing.T) *sip.Response {
	t.Helper()
	for {
		m, err := c.r.ReadMessage()
		if err != nil {
			t.Fatalf("no final response: %v", err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
}
