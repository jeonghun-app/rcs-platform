package transport

import (
	"bufio"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

type panicCounts struct {
	mu sync.Mutex
	n  map[string]int64
}

func (c *panicCounts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int64{}
	}
	c.n[name] += n
}

func (c *panicCounts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

// A panic in Admit refuses that flow, and one in OnFlowClosed ends that
// call; the next flow is admitted and the next closure reported, and both
// panics are counted (#445).
func TestAPanicInAdmitOrOnFlowClosedEndsOnlyThatCall(t *testing.T) {
	var admits, closes atomic.Int32
	closed := make(chan FlowID, 8)
	counts := &panicCounts{}
	server, rec := newTransport(t, Config{
		Metrics: counts,
		Admit: func(FlowID, FlowInfo) bool {
			if admits.Add(1) == 1 {
				panic("admit")
			}
			return true
		},
		OnFlowClosed: func(id FlowID, _ FlowInfo) {
			if closes.Add(1) == 1 {
				panic("closed")
			}
			closed <- id
		},
	})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	refused := dialRaw(t, addr)
	waitClosed(t, refused)
	if n := server.Stats().Refused; n != 1 {
		t.Fatalf("Refused = %d after Admit panicked, want 1", n)
	}
	for _, branch := range []string{"z9hG4bK1", "z9hG4bK2"} {
		c := dialRaw(t, addr)
		c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch="+branch)))
		rec.next(t)
		c.Close()
	}
	// The first closure's call panicked; the second still comes.
	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("no closure reported after OnFlowClosed panicked")
	}
	if n := server.Stats().CallbackPanics; n != 2 {
		t.Errorf("CallbackPanics = %d, want 2", n)
	}
	if n := counts.get(MetricCallbackPanics); n != 2 {
		t.Errorf("%s = %d, want 2", MetricCallbackPanics, n)
	}
}

// A panic in OnPong ends that call; the flow goes on carrying messages.
func TestAPanicInOnPongLeavesTheFlow(t *testing.T) {
	server, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(time.Minute))
	client, rec := newTransport(t, Config{
		Dialer: pipeDialer{server},
		OnPong: func(FlowID) { panic("pong") },
	})
	listen(t, client, ListenerConfig{Network: TCP})
	if _, err := client.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKpong"), pipeDst); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(peer)
	answer := func() {
		req := readMessage(t, br).(*sip.Request)
		b, err := respond(t, req, 200).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := peer.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	answer()
	flow := rec.next(t).Source.Flow
	if err := client.Ping(flow); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("\r\n")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pong's panic to be counted", func() bool { return client.Stats().CallbackPanics == 1 })
	// The flow still carries messages.
	if _, err := client.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKafter"), pipeDst); err != nil {
		t.Fatal(err)
	}
	answer()
	rec.next(t)
}
