package transport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// pingRig is a client transport with one connection it opened to a raw
// server, which the test drives byte by byte.
type pingRig struct {
	client *Transport
	rec    recorder
	pongs  chan FlowID
	flow   FlowID
	server net.Conn
	br     *bufio.Reader
}

func newPingRig(t *testing.T, cfg Config) *pingRig {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r := &pingRig{pongs: make(chan FlowID, 16)}
	cfg.OnPong = func(id FlowID) { r.pongs <- id }
	r.client, r.rec = newTransport(t, cfg)

	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1")
	if _, err := r.client.SendRequest(req, Destination{Network: TCP, Addr: netip.MustParseAddrPort(ln.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	r.server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.server.Close() })
	r.server.SetDeadline(time.Now().Add(waitFor))
	r.br = bufio.NewReader(r.server)
	got := readMessage(t, r.br).(*sip.Request)
	r.write(t, respond(t, got, 200))
	r.flow = r.rec.next(t).Source.Flow
	return r
}

func (r *pingRig) write(t *testing.T, m sip.Message) {
	t.Helper()
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.server.Write(b); err != nil {
		t.Fatal(err)
	}
}

// pingAndPong has the client ping and the server answer, and waits for the
// pong to be reported.
func (r *pingRig) pingAndPong(t *testing.T) {
	t.Helper()
	if err := r.client.Ping(r.flow); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(r.br, got); err != nil || string(got) != "\r\n\r\n" {
		t.Fatalf("ping = %q, %v", got, err)
	}
	r.server.Write([]byte("\r\n"))
	r.nextPong(t)
}

func (r *pingRig) nextPong(t *testing.T) {
	t.Helper()
	select {
	case id := <-r.pongs:
		if id != r.flow {
			t.Fatalf("pong reported for another flow")
		}
	case <-time.After(waitFor):
		t.Fatal("no pong reported")
	}
}

func TestPingSendsADoubleCRLFAndReportsEachPong(t *testing.T) {
	r := newPingRig(t, Config{})
	r.pingAndPong(t)

	// Two pongs back to back, then a request. The request arrives after
	// both CRLFs have been read, so by then an answer to them as a ping
	// would have been counted.
	r.server.Write([]byte("\r\n\r\n"))
	r.write(t, newRequest(t, "OPTIONS", "SIP/2.0/TCP server.example.com;branch=z9hG4bK2"))
	if in := r.rec.next(t); in.Source.Flow != r.flow {
		t.Fatal("request delivered from another flow")
	}
	r.nextPong(t)
	r.nextPong(t)
	if s := r.client.Stats(); s.KeepAlives != 0 {
		t.Fatalf("KeepAlives = %d: the pinging end answered pongs as a ping", s.KeepAlives)
	}
}

// Each pong starts the pinging flow's idle period again. The connection
// records its read deadlines and applies none, so the test reads the idle
// period from them rather than racing a real idle timeout against a loaded
// host (#215).
func TestPongsKeepAPingingFlowFromGoingIdle(t *testing.T) {
	const idle = 3 * time.Second
	server, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	_ = peer.SetDeadline(time.Now().Add(time.Minute))
	conn := &readDeadlines{Conn: server}
	pongs := make(chan FlowID, 16)
	client, rec := newTransport(t, Config{
		Dialer: pipeDialer{conn}, IdleTimeout: idle,
		OnPong: func(id FlowID) { pongs <- id },
	})
	listen(t, client, ListenerConfig{Network: TCP})
	if _, err := client.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKpong"), pipeDst); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(peer)
	req := readMessage(t, br).(*sip.Request)
	b, err := respond(t, req, 200).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write(b); err != nil {
		t.Fatal(err)
	}
	flow := rec.next(t).Source.Flow
	for round := range 3 {
		// Past the idle period the last message started.
		time.Sleep(time.Millisecond)
		before := time.Now()
		if err := client.Ping(flow); err != nil {
			t.Fatalf("Ping: %v", err)
		}
		got := make([]byte, 4)
		if _, err := io.ReadFull(br, got); err != nil || string(got) != "\r\n\r\n" {
			t.Fatalf("ping = %q, %v", got, err)
		}
		if _, err := peer.Write([]byte("\r\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-pongs:
		case <-time.After(waitFor):
			t.Fatal("no pong reported")
		}
		eventually(t, "the pong to start the idle period again", func() bool {
			return !conn.last().Before(before.Add(idle))
		})
		if _, ok := client.Flow(flow); !ok {
			t.Fatalf("round %d: the flow is gone; stats = %+v", round, client.Stats())
		}
	}
}

func TestPingIsOnlyForConnectionsThisTransportOpened(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	accepted := rec.next(t).Source.Flow
	if err := server.Ping(accepted); err == nil || errors.Is(err, ErrNoFlow) {
		t.Fatalf("Ping on an accepted connection = %v, want a refusal", err)
	}

	udpAddr := listen(t, server, ListenerConfig{Network: UDP})
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(udpAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK2")))
	if err := server.Ping(rec.next(t).Source.Flow); err == nil || errors.Is(err, ErrNoFlow) {
		t.Fatalf("Ping on a UDP flow = %v, want a refusal", err)
	}

	if err := server.Ping("unknown"); !errors.Is(err, ErrNoFlow) {
		t.Fatalf("Ping on an unknown flow = %v, want ErrNoFlow", err)
	}
	server.Close()
	if err := server.Ping(accepted); !errors.Is(err, ErrClosed) {
		t.Fatalf("Ping after Close = %v, want ErrClosed", err)
	}
}
