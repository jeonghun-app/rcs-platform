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
	addr := listen(t, server, ListenerConfig{Network: TCP, MaxConnections: 1})
	first := dialRaw(t, addr)
	first.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	waitClosed(t, dialRaw(t, addr))

	first.Close()
	eventually(t, "the slot to free", func() bool { return server.Stats().OpenInbound == 0 })
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
		return s.ProxyHeaderErrors == 1 && s.PendingAccepted == 0
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
	} {
		lc.Addr = "127.0.0.1:0"
		if _, err := tr.Listen(lc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
