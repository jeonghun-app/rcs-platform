package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestClientFacingListenersGetASmallSendQueue(t *testing.T) {
	tr, _ := newTransport(t, Config{SendQueueBytes: 1 << 20})
	listen(t, tr, ListenerConfig{Name: "edge", Network: TCP, ClientFacing: true})
	listen(t, tr, ListenerConfig{Name: "core", Network: TCP})
	listen(t, tr, ListenerConfig{Name: "tuned", Network: TCP, ClientFacing: true, SendQueueBytes: 8 << 10})
	for name, want := range map[string]int{"edge": DefaultClientSendQueueBytes, "core": 1 << 20, "tuned": 8 << 10} {
		if got := tr.listenerNamed(name).sendQueue; got != want {
			t.Errorf("%s: send queue %d, want %d", name, got, want)
		}
	}
}

func TestClientThatStopsReadingIsClosedBeforeItsQueuePassesTheListenerLimit(t *testing.T) {
	server, rec := newTransport(t, Config{WriteTimeout: time.Hour})
	addr := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: true})
	c := dialRaw(t, addr) // never read
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	f := server.flows.lookup(id)
	limit := 2 * DefaultClientSendQueueBytes // the NoWait reserve included

	var err error
	for i := 0; i < 1_000_000 && err == nil; i++ {
		req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKflood")
		req.Body = make([]byte, 1000)
		_, err = server.SendRequest(req, Destination{Flow: id}, NoWait)
		if n := f.q.size(); n > limit {
			t.Fatalf("queue reached %d bytes, past the listener's %d", n, limit)
		}
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("flooding a client that does not read ended with %v, want ErrQueueFull", err)
	}
	if _, ok := server.Flow(id); ok {
		t.Fatal("the connection is still open")
	}
	if s := server.Stats(); s.QueueOverflows != 1 || s.QueuedBytes != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// pipesDialer gives every dial a new net.Pipe whose far end nobody reads.
type pipesDialer struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (d *pipesDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	d.mu.Lock()
	d.peers = append(d.peers, b)
	d.mu.Unlock()
	return a, nil
}

func TestFullBudgetClosesTheConnectionHoldingTheMostOutput(t *testing.T) {
	dialer := &pipesDialer{}
	tr, _ := newTransport(t, Config{Dialer: dialer, WriteTimeout: time.Hour, SendQueueBytes: 1 << 20, MaxQueuedBytes: 3000})
	listen(t, tr, ListenerConfig{Network: TCP})
	t.Cleanup(func() {
		for _, p := range dialer.peers {
			p.Close()
		}
	})
	hog := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.1:5060")}
	other := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.2:5060")}
	send := func(dst Destination, branch string) error {
		req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch="+branch)
		req.Body = make([]byte, 600) // about 850 bytes on the wire
		return within(t, func() error { _, err := tr.SendRequest(req, dst); return err })
	}
	for _, b := range []string{"z9hG4bKh1", "z9hG4bKh2", "z9hG4bKh3"} {
		if err := send(hog, b); err != nil {
			t.Fatal(err)
		}
	}
	hogFlow := tr.flows.peer(reuseKey{network: TCP, remote: hog.Addr})
	if err := send(other, "z9hG4bKo1"); err != nil {
		t.Fatalf("the connection within its share was refused: %v", err)
	}
	if !hogFlow.closed.Load() {
		t.Fatal("the connection holding the most output was not closed")
	}
	if s := tr.Stats(); s.BudgetSheds != 1 || s.QueuedBytes > 3000 || s.OpenOutbound != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestSendQueueBudgetIsReturnedWhenAQueueCloses(t *testing.T) {
	var b queueBudget
	b.max = 1000
	q := newSendQueue(1000, &b)
	if q.push(make([]byte, 400), false, 0) != pushed || b.used.Load() != 400 {
		t.Fatalf("budget used %d", b.used.Load())
	}
	q.close()
	q.written(400) // a write finishing after the close must not release twice
	if b.used.Load() != 0 {
		t.Fatalf("budget used %d after close", b.used.Load())
	}
	if q.push([]byte("x"), false, 0) != queueGone {
		t.Fatal("a closed queue accepted a message")
	}
}

func TestFlowIdleTimeoutCanBeShortenedAndTakesEffectAtOnce(t *testing.T) {
	server, rec := newTransport(t, Config{IdleTimeout: time.Hour})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	if !server.SetFlowIdleTimeout(id, time.Nanosecond) {
		t.Fatal("SetFlowIdleTimeout refused a live flow")
	}
	waitClosed(t, c)
	eventually(t, "an idle timeout", func() bool { return server.Stats().IdleTimeouts == 1 })
}

func TestFlowIdleTimeoutCanBeLengthened(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, IdleTimeout: 300 * time.Millisecond})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	server.SetFlowIdleTimeout(id, time.Hour)
	time.Sleep(600 * time.Millisecond) // past the listener's idle timeout
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK2")))
	if in := rec.next(t); in.Source.Flow != id {
		t.Fatal("the flow was replaced")
	}
	if s := server.Stats(); s.IdleTimeouts != 0 {
		t.Fatalf("the listener's idle timeout still applied: %+v", s)
	}
}

func TestSetFlowIdleTimeoutRefusesWhatItCannotApply(t *testing.T) {
	server, rec := newTransport(t, Config{})
	tcpAddr := listen(t, server, ListenerConfig{Network: TCP})
	udpAddr := listen(t, server, ListenerConfig{Network: UDP})
	c := dialRaw(t, tcpAddr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	tcpFlow := rec.next(t).Source.Flow
	u, err := net.Dial("udp", udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK2")))
	udpFlow := rec.next(t).Source.Flow
	for name, ok := range map[string]bool{
		"unknown flow":  server.SetFlowIdleTimeout("unknown", time.Minute),
		"UDP flow":      server.SetFlowIdleTimeout(udpFlow, time.Minute),
		"zero duration": server.SetFlowIdleTimeout(tcpFlow, 0),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
