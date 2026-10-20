package transport

import (
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"
)

// silentClients opens n connections to a PROXY listener that never send their
// header, as a slow or hostile client behind the NLB would, and waits until
// the transport has accepted them all.
func silentClients(t *testing.T, tr *Transport, addr netip.AddrPort, n int) []net.Conn {
	t.Helper()
	var cs []net.Conn
	for range n {
		cs = append(cs, dialRaw(t, addr))
	}
	eventually(t, "the silent clients to be accepted", func() bool { return tr.Stats().PendingAccepted == n })
	return cs
}

// The client listener at its limit refuses the next client, and a core peer
// still connects (#193): connections in the PROXY header phase, which Admit
// cannot see yet, hold client slots only.
func TestClientListenerAtItsLimitLeavesRoomForTheCore(t *testing.T) {
	server, rec := newTransport(t, Config{MaxConnections: 10})
	edge := listen(t, server, ListenerConfig{Name: "edge", Network: TCP, ProxyProtocol: true,
		MaxConnections: 2, ProxyHeaderTimeout: time.Minute})
	core := listen(t, server, ListenerConfig{Name: "core", Network: TCP})
	silentClients(t, server, edge, 2)

	waitClosed(t, dialRaw(t, edge))
	eventually(t, "the refusal to be counted", func() bool { return server.Stats().ClientListenerRejected == 1 })

	c := dialRaw(t, core)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP scscf.example.com;branch=z9hG4bK1")))
	if in := rec.next(t); in.Source.Listener != "core" {
		t.Fatalf("delivered from %q, want core", in.Source.Listener)
	}
	if s := server.Stats(); s.Rejected != 0 || s.CoreListenerRejected != 0 || s.Accepted != 3 {
		t.Fatalf("stats = %+v", s)
	}
	if got := server.Stats().ListenerConnections; got["edge"] != 2 || got["core"] != 1 || len(got) != 2 {
		t.Fatalf("per-listener connections = %v, want edge 2 and core 1", got)
	}
}

func TestCoreListenerRefusalsAreCountedAsCore(t *testing.T) {
	server, rec := newTransport(t, Config{})
	core := listen(t, server, ListenerConfig{Name: "core", Network: TCP, MaxConnections: 1})
	first := dialRaw(t, core)
	first.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP scscf.example.com;branch=z9hG4bK1")))
	rec.next(t)

	waitClosed(t, dialRaw(t, core))
	if s := server.Stats(); s.CoreListenerRejected != 1 || s.ClientListenerRejected != 0 || s.Rejected != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// A listener's slot is held until the connection closes, and closing it
// gives the slot back.
func TestClosingAConnectionFreesItsListenerSlot(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Name: "one", Network: TCP, MaxConnections: 1})
	first := dialRaw(t, addr)
	first.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	waitClosed(t, dialRaw(t, addr))

	first.Close()
	eventually(t, "the listener slot to free", func() bool { return server.Stats().ListenerConnections["one"] == 0 })
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK2")))
	rec.next(t)
}

// The transport-wide limit still bounds listeners that have room of their
// own, and its refusals keep their counter.
func TestTransportLimitStillAppliesUnderAListenerLimit(t *testing.T) {
	server, _ := newTransport(t, Config{MaxConnections: 2})
	edge := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true, MaxConnections: 5, ProxyHeaderTimeout: time.Minute})
	silentClients(t, server, edge, 2)
	waitClosed(t, dialRaw(t, edge))
	if s := server.Stats(); s.Rejected != 1 || s.ClientListenerRejected != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// A connection that does not send its PROXY header within ProxyHeaderTimeout
// is closed then, not after ReadTimeout (32 s by default), so it frees its
// slot (#193, from the #188 security review).
func TestProxyHeaderNotSentInTimeClosesTheConnection(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true, ProxyHeaderTimeout: 200 * time.Millisecond})
	c := dialRaw(t, addr)
	waitClosed(t, c) // within waitFor, well short of ReadTimeout
	eventually(t, "the slot to free", func() bool {
		s := server.Stats()
		return s.ProxyHeaderTimeouts == 1 && s.ProxyHeaderErrors == 0 && s.PendingAccepted == 0
	})
	rec.none(t)
}

// The PROXY deadline covers the header only: a client that sent it in time
// may take longer than that for its first message.
func TestProxyHeaderDeadlineDoesNotCutTheFirstMessage(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true, ProxyHeaderTimeout: 300 * time.Millisecond})
	c := dialRaw(t, addr)
	c.Write(proxyHeaderFor(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.1:5060"), awsTLV))
	time.Sleep(time.Second)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP 10.1.1.1:5060;rport;branch=z9hG4bK1")))
	rec.next(t)
	if s := server.Stats(); s.ProxyHeaderErrors != 0 || s.ReadTimeouts != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// Behind a PROXY header the TLS handshake gets ReadTimeout of its own, not
// what is left of the PROXY deadline.
func TestProxyHeaderDeadlineDoesNotCutTheTLSHandshake(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	server, rec := newTransport(t, Config{TLS: serverTLS})
	addr := listen(t, server, ListenerConfig{Network: TLS, ProxyProtocol: true, ProxyHeaderTimeout: 300 * time.Millisecond})
	raw := dialRaw(t, addr)
	raw.Write(proxyHeaderFor(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.1:5061"), awsTLV))
	time.Sleep(time.Second)
	c := tls.Client(raw, clientTLS)
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake after the PROXY deadline: %v", err)
	}
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TLS 10.1.1.1:5061;rport;branch=z9hG4bK1")))
	rec.next(t)
}

func TestProxyHeaderTimeoutDefaultsToTwoSeconds(t *testing.T) {
	server, _ := newTransport(t, Config{})
	listen(t, server, ListenerConfig{Name: "edge", Network: TCP, ProxyProtocol: true})
	server.mu.Lock()
	got := server.listeners[0].proxyHeader
	server.mu.Unlock()
	if got != 2*time.Second {
		t.Fatalf("PROXY header timeout = %v, want 2s", got)
	}
}

func TestListenRefusesInvalidListenerLimits(t *testing.T) {
	tr, _ := newTransport(t, Config{})
	for name, lc := range map[string]ListenerConfig{
		"negative MaxConnections":            {Network: TCP, MaxConnections: -1},
		"negative ProxyHeaderTimeout":        {Network: TCP, ProxyProtocol: true, ProxyHeaderTimeout: -time.Second},
		"ProxyHeaderTimeout without PROXY":   {Network: TCP, ProxyHeaderTimeout: time.Second},
		"ProxyHeaderTimeout on a client TCP": {Network: TCP, ClientFacing: true, ProxyHeaderTimeout: time.Second},
		"MaxConnections on UDP":              {Network: UDP, MaxConnections: 10},
	} {
		lc.Addr = "127.0.0.1:0"
		if _, err := tr.Listen(lc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// QA (PR #227): behind a PROXY header the TLS handshake is bounded by
// ReadTimeout, now that the header's deadline is cleared, so a client that
// sends a valid header and no ClientHello frees its slot then.
func TestProxyTLSHandshakeStallFreesItsSlotAtReadTimeout(t *testing.T) {
	serverTLS, _ := testTLS(t)
	server, rec := newTransport(t, Config{TLS: serverTLS, ReadTimeout: 500 * time.Millisecond})
	addr := listen(t, server, ListenerConfig{Network: TLS, ProxyProtocol: true, MaxConnections: 1})
	c := dialRaw(t, addr)
	c.Write(proxyHeaderFor(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.1:5061"), awsTLV))
	start := time.Now()
	waitClosed(t, c)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("closed after %v, want about ReadTimeout", d)
	}
	eventually(t, "the slot to free", func() bool { s := server.Stats(); return s.PendingAccepted == 0 && s.OpenInbound == 0 })
	rec.none(t)
}

// QA (PR #227): the deadline runs from accept and is the configured one, so
// a header trickled a byte at a time is cut at 400 ms, well before the 2 s
// default.
func TestTrickledProxyHeaderIsCutAtTheConfiguredDeadline(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true, ProxyHeaderTimeout: 400 * time.Millisecond})
	c := dialRaw(t, addr)
	h := proxyHeaderFor(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.1:5060"), awsTLV)
	start := time.Now()
	for _, b := range h { // 36 bytes over 1.8 s
		if _, err := c.Write([]byte{b}); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitClosed(t, c)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("closed after %v, want about 400ms", d)
	}
	eventually(t, "the timeout to be counted", func() bool { return server.Stats().ProxyHeaderTimeouts == 1 })
	rec.none(t)
}

// QA (PR #227): the class of a refusal is the listener's client-facing
// mark, not whether it has a PROXY header, as on pcscf in dev without the
// NLB.
func TestClientFacingListenerWithoutProxyCountsClientRefusals(t *testing.T) {
	server, _ := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: true, MaxConnections: 1})
	dialRaw(t, addr)
	eventually(t, "the first to be accepted", func() bool { s := server.Stats(); return s.PendingAccepted+s.OpenInbound == 1 })
	waitClosed(t, dialRaw(t, addr))
	eventually(t, "the refusal", func() bool {
		s := server.Stats()
		return s.ClientListenerRejected == 1 && s.CoreListenerRejected == 0
	})
}

// QA (PR #227): when a client flood fills its listener and the transport at
// once, the refusal is the listener's, which is what an alarm on client
// refusals watches.
func TestListenerLimitIsCheckedBeforeTheTransportLimit(t *testing.T) {
	server, _ := newTransport(t, Config{MaxConnections: 2})
	edge := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true, MaxConnections: 2, ProxyHeaderTimeout: time.Minute})
	silentClients(t, server, edge, 2)
	waitClosed(t, dialRaw(t, edge))
	if s := server.Stats(); s.ClientListenerRejected != 1 || s.Rejected != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// A connection accepted while Close runs is refused as the transport's, even
// on a listener at its own limit: it says nothing about client pressure.
func TestAConnectionAcceptedAfterCloseIsRefusedAsTheTransports(t *testing.T) {
	server, _ := newTransport(t, Config{})
	listen(t, server, ListenerConfig{Name: "edge", Network: TCP, ClientFacing: true, MaxConnections: 1})
	server.mu.Lock()
	l := server.listeners[0]
	server.mu.Unlock()
	first, other := net.Pipe()
	defer other.Close()
	if refused := server.reserveAccepted(l, first); refused != nil {
		t.Fatal("the first connection was refused")
	}
	server.Close()
	late, other2 := net.Pipe()
	defer late.Close()
	defer other2.Close()
	if refused := server.reserveAccepted(l, late); refused != &server.stats.rejected {
		t.Fatal("a connection after Close was not refused as the transport's")
	}
}
