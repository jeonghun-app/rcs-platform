package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// waitFor bounds how long a test waits for an event the network delivers. It is
// a failure deadline, never a delay: tests continue as soon as the event happens.
const waitFor = 5 * time.Second

// recorder is a Handler that queues what it receives.
type recorder chan Inbound

func (r recorder) handle(in Inbound) { r <- in }

func (r recorder) next(t *testing.T) Inbound {
	t.Helper()
	select {
	case in := <-r:
		return in
	case <-time.After(waitFor):
		t.Fatal("no message delivered")
		return Inbound{}
	}
}

func (r recorder) none(t *testing.T) {
	t.Helper()
	select {
	case in := <-r:
		t.Fatalf("unexpected delivery of a %T", in.Message)
	default:
	}
}

func newTransport(t *testing.T, cfg Config) (*Transport, recorder) {
	t.Helper()
	rec := make(recorder, 16)
	tr, err := New(cfg, rec.handle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr, rec
}

func listen(t *testing.T, tr *Transport, lc ListenerConfig) netip.AddrPort {
	t.Helper()
	if lc.Addr == "" {
		lc.Addr = "127.0.0.1:0"
	}
	a, err := tr.Listen(lc)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func dialRaw(t *testing.T, a netip.AddrPort) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", a.String(), waitFor)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(waitFor))
	return c
}

// readResponse reads one message from a raw stream connection.
func readMessage(t *testing.T, br *bufio.Reader) sip.Message {
	t.Helper()
	m, err := sip.NewReader(br, sip.Limits{}).ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// waitClosed waits until the server closes c. A server that closes with our
// bytes unread makes the kernel send a reset, which is a close too.
func waitClosed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(waitFor))
	var ne net.Error
	if _, err := io.Copy(io.Discard, c); errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection was not closed by the server")
	}
}

// eventually polls cond, for counters updated on another goroutine.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func newRequest(t *testing.T, method, via string) *sip.Request {
	t.Helper()
	return parseRequest(t, rawRequest(method, "Via: "+via))
}

func respond(t *testing.T, req *sip.Request, code int) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, code, "", "b1")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func topVia(t *testing.T, m sip.Message) sip.Via {
	t.Helper()
	vias, err := m.Headers().Via()
	if err != nil || len(vias) == 0 {
		t.Fatalf("no top Via: %v", err)
	}
	return vias[0]
}

func TestUDPRequestIsDeliveredWithItsFlowAndSource(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Name: "udp", Network: UDP})

	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr).AddrPort()
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP client.example.com;rport;branch=z9hG4bK1")))

	in := rec.next(t)
	if in.Source.Network != UDP || in.Source.Addr != local || in.Source.Listener != "udp" || in.Source.Flow == "" {
		t.Fatalf("Source = %+v", in.Source)
	}
	if info, ok := server.Flow(in.Source.Flow); !ok || info.Addr != local || info.Network != UDP {
		t.Fatalf("Flow(%q) = %+v, %v", in.Source.Flow, info, ok)
	}
	v := topVia(t, in.Message)
	if rp, _ := v.RPort(); v.Received() != "127.0.0.1" || rp != int(local.Port()) {
		t.Fatalf("top Via = %s, want received and rport of the source", v)
	}

	// A second datagram from the same source is the same flow.
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP client.example.com;rport;branch=z9hG4bK2")))
	if again := rec.next(t); again.Source.Flow != in.Source.Flow {
		t.Fatal("second datagram from one source got a new flow")
	}

	// The response goes back to received:rport from the listening socket.
	if err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(waitFor))
	buf := make([]byte, maxDatagram)
	n, from, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if from.Port() != addr.Port() {
		t.Fatalf("response came from port %d, not the listening socket %d", from.Port(), addr.Port())
	}
	if m, err := sip.ParseMessage(buf[:n]); err != nil || m.(*sip.Response).StatusCode != 200 {
		t.Fatalf("response = %v, %v", m, err)
	}
}

func TestKeepAliveAndMalformedDatagramsAreNotDelivered(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("\r\n\r\n"))
	c.Write([]byte("not SIP at all\r\n\r\n"))
	eventually(t, "the malformed datagram to be counted", func() bool { return server.Stats().MalformedDatagrams == 1 })
	rec.none(t)
}

func TestTCPRequestCarriesReceivedAndRPortAndItsResponseUsesTheConnection(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Name: "tcp", Network: TCP})
	c := dialRaw(t, addr)
	local := addrPortOf(c.LocalAddr())
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com:5060;rport;branch=z9hG4bK1")))

	in := rec.next(t)
	if in.Source.Network != TCP || in.Source.Addr != local || in.Source.Listener != "tcp" {
		t.Fatalf("Source = %+v", in.Source)
	}
	v := topVia(t, in.Message)
	if rp, _ := v.RPort(); v.Received() != "127.0.0.1" || rp != int(local.Port()) {
		t.Fatalf("top Via = %s", v)
	}
	if err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source); err != nil {
		t.Fatal(err)
	}
	res := readMessage(t, bufio.NewReader(c)).(*sip.Response)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if s := server.Stats(); s.Accepted != 1 || s.OpenInbound != 1 || s.OpenOutbound != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestRequestToAFlowUsesTheClientConnection(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, AdvertisedHost: "pcscf.example.com", AdvertisedPort: 5060})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	flow := rec.next(t).Source.Flow

	req := newRequest(t, "MESSAGE", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bKout")
	n, err := server.SendRequest(req, Destination{Flow: flow})
	if err != nil || n != TCP {
		t.Fatalf("SendRequest = %s, %v", n, err)
	}
	got := readMessage(t, bufio.NewReader(c)).(*sip.Request)
	if v := topVia(t, got); v.String() != "SIP/2.0/TCP pcscf.example.com:5060;branch=z9hG4bKout" {
		t.Fatalf("top Via = %s, want the listener's sent-by (RFC 3261 §18.1.1)", v)
	}
}

func TestFlowOfAClosedConnectionIsGone(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	flow := rec.next(t).Source.Flow
	c.Close()

	eventually(t, "the flow to close", func() bool { _, ok := server.Flow(flow); return !ok })
	req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKout")
	if _, err := server.SendRequest(req, Destination{Flow: flow}); !errors.Is(err, ErrNoFlow) {
		t.Fatalf("SendRequest = %v, want ErrNoFlow", err)
	}
}

func TestForgedAndForeignFlowIDsAreUnknown(t *testing.T) {
	// Two transports stand for this process and the one before it, which may
	// have had the same IP address (ADR 0005).
	earlier, recEarlier := newTransport(t, Config{})
	addr := listen(t, earlier, ListenerConfig{Name: "public", Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	old := recEarlier.next(t).Source.Flow

	now, _ := newTransport(t, Config{})
	listen(t, now, ListenerConfig{Name: "public", Network: TCP})
	for name, id := range map[string]FlowID{
		"earlier process": old,
		"forged":          FlowID(strings.Repeat("A", len(old))),
		"empty-looking":   "x",
	} {
		if _, ok := now.Flow(id); ok {
			t.Errorf("%s FlowID resolved", name)
		}
		req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKout")
		if _, err := now.SendRequest(req, Destination{Flow: id}); !errors.Is(err, ErrNoFlow) {
			t.Errorf("%s FlowID: SendRequest = %v, want ErrNoFlow", name, err)
		}
	}
}

func TestRequestToAnAddressDialsOnceAndReusesTheConnection(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	client, crec := newTransport(t, Config{})
	listen(t, client, ListenerConfig{Network: TCP, AdvertisedHost: "client.example.com", AdvertisedPort: 5070})

	for i := range 3 {
		req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK"+string(rune('a'+i)))
		if _, err := client.SendRequest(req, Destination{Network: TCP, Addr: addr}); err != nil {
			t.Fatal(err)
		}
		in := rec.next(t)
		if err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source); err != nil {
			t.Fatal(err)
		}
		if res := crec.next(t); res.Message.(*sip.Response).StatusCode != 200 || res.Source.Listener != "" {
			t.Fatalf("response delivery = %+v", res.Source)
		}
	}
	if s := client.Stats(); s.Dialed != 1 {
		t.Fatalf("Dialed = %d, want one connection reused", s.Dialed)
	}
}

func TestConcurrentRequestsToOneAddressShareOneDial(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	client, _ := newTransport(t, Config{})
	errs := make(chan error, 8)
	for i := range 8 {
		req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKc"+string(rune('a'+i)))
		go func() {
			_, err := client.SendRequest(req, Destination{Network: TCP, Addr: addr})
			errs <- err
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		rec.next(t)
	}
	if s := client.Stats(); s.Dialed != 1 {
		t.Fatalf("Dialed = %d, want 1", s.Dialed)
	}
}

func TestResponseIsRoutedToSentByWhenTheConnectionHasClosed(t *testing.T) {
	// RFC 3261 §18.2.2: over a reliable transport whose connection is gone, the
	// server connects to received (or the sent-by address) at the sent-by port.
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	client, crec := newTransport(t, Config{})
	clientAddr := listen(t, client, ListenerConfig{Network: TCP})

	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1")
	if _, err := client.SendRequest(req, Destination{Network: TCP, Addr: addr}); err != nil {
		t.Fatal(err)
	}
	in := rec.next(t)
	server.closeFlow(server.flows.lookup(in.Source.Flow))

	if err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source); err != nil {
		t.Fatal(err)
	}
	res := crec.next(t)
	if res.Message.(*sip.Response).StatusCode != 200 || res.Source.Listener == "" {
		t.Fatalf("response arrived on %+v, want the client's listener at %v", res.Source, clientAddr)
	}
}

func TestFramingErrorClosesTheConnectionAndIsCounted(t *testing.T) {
	for name, junk := range map[string]string{
		"garbage start line": "HELLO\r\n\r\n",
		"no Content-Length":  strings.Replace(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1"), "Content-Length: 0\r\n", "", 1),
		"bare LF line ends":  "OPTIONS sip:a@example.com SIP/2.0\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			server, rec := newTransport(t, Config{})
			addr := listen(t, server, ListenerConfig{Network: TCP})
			c := dialRaw(t, addr)
			c.Write([]byte(junk))
			waitClosed(t, c)
			eventually(t, "a framing error", func() bool { return server.Stats().FramingErrors == 1 })
			if s := server.Stats(); s.TruncatedMessages != 0 {
				t.Fatalf("stats = %+v", s)
			}
			rec.none(t)
		})
	}
}

func TestMessageCutShortByThePeerIsCountedApartFromFramingErrors(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte("OPTIONS sip:a@example.com SIP/2.0\r\nVia: SIP"))
	c.(*net.TCPConn).CloseWrite()
	waitClosed(t, c)
	eventually(t, "a truncated message", func() bool { return server.Stats().TruncatedMessages == 1 })
	if s := server.Stats(); s.FramingErrors != 0 {
		t.Fatalf("stats = %+v", s)
	}
	rec.none(t)
}

func TestInvalidMessageIsDroppedButTheConnectionStays(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	noCallID := strings.Replace(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1"), "Call-ID: c1@example.com\r\n", "", 1)
	c.Write([]byte(noCallID))
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK2")))
	if v := topVia(t, rec.next(t).Message); v.Branch() != "z9hG4bK2" {
		t.Fatalf("delivered %s, want only the valid request", v)
	}
	if s := server.Stats(); s.InvalidMessages != 1 || s.FramingErrors != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestStrayResponseIsDropped(t *testing.T) {
	// RFC 3261 §18.1.2: a response whose top Via is not ours is discarded.
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, AdvertisedHost: "pcscf.example.com", AdvertisedPort: 5060})
	c := dialRaw(t, addr)
	for _, via := range []string{
		"SIP/2.0/TCP elsewhere.example.com:5060;branch=z9hG4bK1",
		"SIP/2.0/TCP pcscf.example.com:5070;branch=z9hG4bK3", // our host, another port
		"SIP/2.0/TCP pcscf.example.com;branch=z9hG4bK2",
	} {
		res := respond(t, newRequest(t, "OPTIONS", via), 200)
		b, _ := res.Bytes()
		c.Write(b)
	}
	if v := topVia(t, rec.next(t).Message); v.Branch() != "z9hG4bK2" {
		t.Fatalf("delivered %s, want only the response to our sent-by", v)
	}
	eventually(t, "the strays to be counted", func() bool { return server.Stats().StrayResponses == 2 })
}

func TestDoubleCRLFPingIsAnsweredWithASingleCRLF(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte("\r\n\r\n"))
	pong := make([]byte, 2)
	if _, err := io.ReadFull(c, pong); err != nil || string(pong) != "\r\n" {
		t.Fatalf("pong = %q, %v", pong, err)
	}
	// The connection is still good for messages afterwards.
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	if s := server.Stats(); s.KeepAlives != 1 {
		t.Fatalf("KeepAlives = %d", s.KeepAlives)
	}
}

func TestIdleConnectionIsClosedAfterTheIdleTimeout(t *testing.T) {
	server, rec := newTransport(t, Config{IdleTimeout: time.Nanosecond})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	waitClosed(t, c)
	eventually(t, "an idle timeout", func() bool { return server.Stats().IdleTimeouts == 1 })
}

func TestListenerIdleTimeoutOverridesTheTransportDefault(t *testing.T) {
	server, rec := newTransport(t, Config{IdleTimeout: time.Hour})
	addr := listen(t, server, ListenerConfig{Network: TCP, IdleTimeout: time.Nanosecond})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	waitClosed(t, c)
	eventually(t, "an idle timeout", func() bool { return server.Stats().IdleTimeouts == 1 })
}

func TestAcceptedConnectionThatSendsNoMessageIsClosedAfterTheReadTimeout(t *testing.T) {
	// The idle timeout is an hour, and keep-alives do not count as a first
	// message, so only the read timeout can free this slot.
	server, _ := newTransport(t, Config{IdleTimeout: time.Hour, ReadTimeout: 50 * time.Millisecond})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte("\r\n\r\n"))
	waitClosed(t, c)
	eventually(t, "a read timeout", func() bool { return server.Stats().ReadTimeouts == 1 })
	if s := server.Stats(); s.IdleTimeouts != 0 || s.KeepAlives != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestTrickledHeaderIsCutOffByTheReadTimeout(t *testing.T) {
	// The idle timeout is long, so only the read timeout of a started message
	// can close this connection.
	server, rec := newTransport(t, Config{IdleTimeout: time.Hour, ReadTimeout: time.Nanosecond})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte("OPTIONS sip:a@example.com SIP/2.0\r\nVia: SIP/2.0/TCP a"))
	waitClosed(t, c)
	eventually(t, "a read timeout", func() bool { return server.Stats().ReadTimeouts == 1 })
	if s := server.Stats(); s.IdleTimeouts != 0 {
		t.Fatalf("counted as idle: %+v", s)
	}
	rec.none(t)
}

func TestDeadlineReaderStartsTheReadTimeoutAtTheFirstMessageByte(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	d := &deadlineReader{conn: a, idle: time.Hour, read: time.Hour}
	br := bufio.NewReader(d)
	go b.Write([]byte("\r\n\r\n"))
	br.Peek(4)
	if d.inMessage {
		t.Fatal("keep-alive bytes started a message")
	}
	go b.Write([]byte("\r\nINVITE"))
	br.Peek(9)
	if !d.inMessage {
		t.Fatal("message bytes did not start a message")
	}
	br.Discard(4) // the ping
	d.betweenMessages(br)
	if !d.inMessage {
		t.Fatal("a message already buffered was treated as idle time")
	}
	br.Discard(br.Buffered())
	d.betweenMessages(br)
	if d.inMessage {
		t.Fatal("an empty buffer was not idle")
	}
}

func TestConnectionsBeyondTheLimitAreRefused(t *testing.T) {
	server, rec := newTransport(t, Config{MaxConnections: 1})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	first := dialRaw(t, addr)
	first.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)

	waitClosed(t, dialRaw(t, addr))
	if s := server.Stats(); s.Rejected != 1 || s.Accepted != 1 {
		t.Fatalf("stats = %+v", s)
	}
	// Closing the first connection frees its slot.
	first.Close()
	eventually(t, "the slot to free", func() bool { return server.Stats().OpenInbound == 0 })
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK2")))
	rec.next(t)
}

func TestProxyProtocolListenerUsesTheClientAddressFromTheHeader(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true})
	client := netip.MustParseAddrPort("192.0.2.10:40000")
	c := dialRaw(t, addr)
	c.Write(proxyHeaderFor(client, netip.MustParseAddrPort("198.51.100.1:5060"), awsTLV))
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP 10.1.1.1:5060;rport;branch=z9hG4bK1")))

	in := rec.next(t)
	if in.Source.Addr != client {
		t.Fatalf("Source.Addr = %v, want the PROXY source %v", in.Source.Addr, client)
	}
	if v := topVia(t, in.Message); v.String() != "SIP/2.0/TCP 10.1.1.1:5060;rport=40000;branch=z9hG4bK1;received=192.0.2.10" {
		t.Fatalf("top Via = %s", v)
	}
	if info, _ := server.Flow(in.Source.Flow); info.Addr != client {
		t.Fatalf("flow address = %v", info.Addr)
	}
}

func TestProxyProtocolListenerClosesConnectionsWithoutAValidHeader(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP 10.1.1.1:5060;branch=z9hG4bK1")))
	waitClosed(t, c)
	eventually(t, "the refusal to be counted", func() bool { return server.Stats().ProxyHeaderErrors == 1 })
	rec.none(t)
}

func TestProxyLocalHealthCheckIsClosedWithoutAFlow(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true})
	c := dialRaw(t, addr)
	c.Write(proxyHeader(0x20, 0x00, nil, nil))
	waitClosed(t, c)
	eventually(t, "the health check to be counted", func() bool { return server.Stats().HealthChecks == 1 })
	if s := server.Stats(); s.OpenInbound != 0 || s.PendingAccepted != 0 || s.ProxyHeaderErrors != 0 {
		t.Fatalf("stats = %+v", s)
	}
	rec.none(t)
}

// pipeTransport returns a transport whose dials return one end of a net.Pipe,
// which is unbuffered, so a write blocks until the test reads the other end. A
// TCP listener supplies the sent-by, since a pipe has no address.
func pipeTransport(t *testing.T, cfg Config) (*Transport, net.Conn) {
	t.Helper()
	server, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	cfg.Dialer = pipeDialer{server}
	tr, _ := newTransport(t, cfg)
	listen(t, tr, ListenerConfig{Network: TCP})
	return tr, peer
}

var pipeDst = Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.1:5060")}

func TestWriteThatTimesOutClosesTheConnection(t *testing.T) {
	tr, _ := pipeTransport(t, Config{WriteTimeout: 10 * time.Millisecond})
	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1")
	// The send only queues; the writer then misses its deadline.
	if _, err := tr.SendRequest(req, pipeDst); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the write to time out", func() bool {
		s := tr.Stats()
		return s.WriteErrors == 1 && s.OpenOutbound == 0
	})
}

// within runs send and fails the test if it blocks.
func within(t *testing.T, send func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- send() }()
	select {
	case err := <-done:
		return err
	case <-time.After(waitFor):
		t.Fatal("a send blocked")
		return nil
	}
}

// queueTest sends ~850-byte MESSAGEs over a pipe transport.
type queueTest struct {
	t  *testing.T
	tr *Transport
	n  int
}

func (q *queueTest) send(opts ...SendOption) error {
	q.n++
	req := newRequest(q.t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKq"+string(rune('a'+q.n)))
	req.Body = make([]byte, 600)
	return within(q.t, func() error { _, err := q.tr.SendRequest(req, pipeDst, opts...); return err })
}

// writerBusy waits until the writer has taken everything queued and is blocked
// writing it.
func (q *queueTest) writerBusy() {
	eventually(q.t, "the writer to take the queue", func() bool {
		f := q.tr.flows.peer(reuseKey{network: TCP, remote: pipeDst.Addr})
		f.q.mu.Lock()
		defer f.q.mu.Unlock()
		return len(f.q.bufs) == 0
	})
}

func TestNoWaitSendNeverBlocksAndOverflowingTheReserveCloses(t *testing.T) {
	// The limit fits one message; NoWait may use as much again, and the one
	// being written still counts, so the second fits and the third does not.
	tr, _ := pipeTransport(t, Config{WriteTimeout: time.Hour, SendQueueBytes: 1000})
	q := &queueTest{t: t, tr: tr}
	if err := q.send(); err != nil {
		t.Fatal(err)
	}
	q.writerBusy()
	if err := q.send(NoWait); err != nil {
		t.Fatal(err)
	}
	if err := q.send(NoWait); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third send = %v, want ErrQueueFull", err)
	}
	if s := tr.Stats(); s.QueueOverflows != 1 || s.OpenOutbound != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestSendWaitsForRoomWhileThePeerReads(t *testing.T) {
	tr, peer := pipeTransport(t, Config{WriteTimeout: time.Hour, SendQueueBytes: 1000})
	q := &queueTest{t: t, tr: tr}
	if err := q.send(); err != nil {
		t.Fatal(err)
	}
	q.writerBusy()
	// The second send waits; reading the pipe lets the writer finish the first
	// message, which makes room.
	go io.Copy(io.Discard, peer)
	if err := q.send(); err != nil {
		t.Fatalf("a send waiting for a reading peer failed: %v", err)
	}
}

func TestSendThatFindsNoRoomWithinTheWriteTimeoutFails(t *testing.T) {
	tr, _ := pipeTransport(t, Config{WriteTimeout: 50 * time.Millisecond, SendQueueBytes: 1000})
	q := &queueTest{t: t, tr: tr}
	if err := q.send(); err != nil {
		t.Fatal(err)
	}
	q.writerBusy()
	if err := q.send(); err == nil {
		t.Fatal("a send to a peer that never reads succeeded")
	}
	eventually(t, "the connection to close", func() bool { return tr.Stats().OpenOutbound == 0 })
}

func TestDialedConnectionWithoutAnAddressOrListenerIsNotGivenABrokenVia(t *testing.T) {
	server, peer := net.Pipe()
	defer peer.Close()
	tr, _ := newTransport(t, Config{Dialer: pipeDialer{server}})
	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1")
	if _, err := tr.SendRequest(req, pipeDst); !errors.Is(err, ErrNoListener) {
		t.Fatalf("SendRequest = %v, want ErrNoListener", err)
	}
}

type pipeDialer struct{ c net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.c, nil
}

func TestLargeUDPRequestIsSentOverTCP(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	listen(t, server, ListenerConfig{Network: UDP, Addr: addr.String()})
	client, _ := newTransport(t, Config{})
	listen(t, client, ListenerConfig{Network: UDP})

	req := newRequest(t, "MESSAGE", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK1")
	req.Body = bytes.Repeat([]byte("x"), udpMTULimit)
	n, err := client.SendRequest(req, Destination{Network: UDP, Addr: addr})
	if err != nil || n != TCP {
		t.Fatalf("SendRequest = %s, %v; want TCP (RFC 3261 §18.1.1)", n, err)
	}
	in := rec.next(t)
	if in.Source.Network != TCP || !strings.EqualFold(topVia(t, in.Message).Transport, "TCP") {
		t.Fatalf("arrived over %s with Via %s", in.Source.Network, topVia(t, in.Message))
	}

	small := newRequest(t, "MESSAGE", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK2")
	if n, err := client.SendRequest(small, Destination{Network: UDP, Addr: addr}); err != nil || n != UDP {
		t.Fatalf("small request: %s, %v", n, err)
	}
	if in := rec.next(t); in.Source.Network != UDP {
		t.Fatalf("small request arrived over %s", in.Source.Network)
	}
}

func TestLargeUDPRequestFallsBackToUDPWhenTCPIsRefused(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	client, _ := newTransport(t, Config{})
	listen(t, client, ListenerConfig{Network: UDP})
	req := newRequest(t, "MESSAGE", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK1")
	req.Body = bytes.Repeat([]byte("x"), udpMTULimit)
	if n, err := client.SendRequest(req, Destination{Network: UDP, Addr: addr}); err != nil || n != UDP {
		t.Fatalf("SendRequest = %s, %v", n, err)
	}
	rec.next(t)
}

func TestTLSListenerServesARequestAndItsResponse(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	server, rec := newTransport(t, Config{TLS: serverTLS})
	addr := listen(t, server, ListenerConfig{Network: TLS})
	client, crec := newTransport(t, Config{TLSClient: clientTLS})

	req := newRequest(t, "OPTIONS", "SIP/2.0/TLS placeholder.invalid;branch=z9hG4bK1")
	if n, err := client.SendRequest(req, Destination{Network: TLS, Addr: addr, ServerName: "sip.example.com"}); err != nil || n != TLS {
		t.Fatalf("SendRequest = %s, %v", n, err)
	}
	in := rec.next(t)
	if in.Source.Network != TLS {
		t.Fatalf("Network = %s", in.Source.Network)
	}
	if err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source); err != nil {
		t.Fatal(err)
	}
	crec.next(t)

	// A request to the client's address from the server must not reuse the
	// accepted connection: its peer never proved a server identity.
	if f := server.flows.peer(reuseKey{network: TLS, remote: in.Source.Addr}); f != nil {
		t.Fatal("an accepted TLS connection is offered for reuse")
	}
}

func TestFailedTLSHandshakeIsCounted(t *testing.T) {
	serverTLS, _ := testTLS(t)
	server, _ := newTransport(t, Config{TLS: serverTLS})
	addr := listen(t, server, ListenerConfig{Network: TLS})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TLS a.example.com;branch=z9hG4bK1")))
	waitClosed(t, c)
	eventually(t, "a handshake error", func() bool { return server.Stats().TLSHandshakeErrors == 1 })
}

func TestListenRefusesInvalidListeners(t *testing.T) {
	tr, _ := newTransport(t, Config{})
	for name, lc := range map[string]ListenerConfig{
		"TLS without a configuration":  {Network: TLS, Addr: "127.0.0.1:0"},
		"PROXY protocol on UDP":        {Network: UDP, Addr: "127.0.0.1:0", ProxyProtocol: true},
		"unknown network":              {Network: "SCTP", Addr: "127.0.0.1:0"},
		"bad advertised port":          {Network: TCP, Addr: "127.0.0.1:0", AdvertisedPort: 70000},
		"unparseable address":          {Network: TCP, Addr: "nowhere"},
		"unspecified bind, no sent-by": {Network: UDP, Addr: "0.0.0.0:0"},
	} {
		if _, err := tr.Listen(lc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	listen(t, tr, ListenerConfig{Name: "a", Network: TCP})
	listen(t, tr, ListenerConfig{Network: TCP, Addr: "0.0.0.0:0", AdvertisedHost: "pcscf.example.com"})
	if _, err := tr.Listen(ListenerConfig{Name: "a", Network: UDP, Addr: "127.0.0.1:0"}); err == nil {
		t.Error("duplicate listener name accepted")
	}
}

func TestClosedTransportRefusesEverything(t *testing.T) {
	tr, _ := newTransport(t, Config{})
	listen(t, tr, ListenerConfig{Network: UDP})
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal("second Close failed")
	}
	req := newRequest(t, "OPTIONS", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1")
	if _, err := tr.SendRequest(req, Destination{Network: UDP, Addr: netip.MustParseAddrPort("127.0.0.1:5060")}); !errors.Is(err, ErrClosed) {
		t.Errorf("SendRequest = %v", err)
	}
	if err := tr.SendResponse(respond(t, req, 200), Source{Network: UDP}); !errors.Is(err, ErrClosed) {
		t.Errorf("SendResponse = %v", err)
	}
	if _, err := tr.Listen(ListenerConfig{Network: UDP, Addr: "127.0.0.1:0"}); !errors.Is(err, ErrClosed) {
		t.Errorf("Listen = %v", err)
	}
}

func TestNewNeedsAHandlerAndRandomness(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Error("nil handler accepted")
	}
	if _, err := New(Config{Rand: bytes.NewReader(nil)}, func(Inbound) {}); err == nil {
		t.Error("an empty randomness source was accepted")
	}
}

func TestUDPSendNeedsAUDPListener(t *testing.T) {
	tr, _ := newTransport(t, Config{})
	req := newRequest(t, "OPTIONS", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1")
	if _, err := tr.SendRequest(req, Destination{Network: UDP, Addr: netip.MustParseAddrPort("127.0.0.1:5060")}); !errors.Is(err, ErrNoListener) {
		t.Fatalf("SendRequest = %v, want ErrNoListener", err)
	}
}

// testTLS returns a server configuration with a self-signed certificate for
// sip.example.com and a client configuration that trusts it.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sip.example.com"},
		DNSNames:     []string{"sip.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	client = &tls.Config{RootCAs: pool, ServerName: "sip.example.com", MinVersion: tls.VersionTLS12}
	return server, client
}
