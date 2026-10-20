package transport

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestResponseForAClosedClientFacingFlowIsNotDialledBack(t *testing.T) {
	// An attacker sends a request with its own address in Via and closes the
	// connection; the response must not make the server connect out to it.
	for name, lc := range map[string]ListenerConfig{
		"PROXY protocol listener": {Network: TCP, ProxyProtocol: true},
		"client-facing listener":  {Network: TCP, ClientFacing: true},
	} {
		t.Run(name, func(t *testing.T) {
			server, rec := newTransport(t, Config{})
			addr := listen(t, server, lc)
			attacker := listen(t, mustTransport(t), ListenerConfig{Network: TCP})
			c := dialRaw(t, addr)
			if lc.ProxyProtocol {
				c.Write(proxyHeaderFor(netip.MustParseAddrPort("192.0.2.77:40000"), addr, nil))
			}
			c.Write([]byte(rawRequest("MESSAGE", "Via: SIP/2.0/TCP "+attacker.String()+";branch=z9hG4bK1")))
			in := rec.next(t)
			c.Close()
			eventually(t, "the flow to close", func() bool { _, ok := server.Flow(in.Source.Flow); return !ok })

			err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source)
			if !errors.Is(err, ErrNoFlow) {
				t.Fatalf("SendResponse = %v, want ErrNoFlow", err)
			}
			if s := server.Stats(); s.Dialed != 0 || s.OpenOutbound != 0 {
				t.Fatalf("the server connected out: %+v", s)
			}
		})
	}
}

func mustTransport(t *testing.T) *Transport {
	tr, _ := newTransport(t, Config{})
	return tr
}

func TestDialedConnectionsAreCapped(t *testing.T) {
	a, b := mustTransport(t), mustTransport(t)
	addrA := listen(t, a, ListenerConfig{Network: TCP})
	addrB := listen(t, b, ListenerConfig{Network: TCP})
	client, _ := newTransport(t, Config{MaxDialedConnections: 1})

	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1")
	if _, err := client.SendRequest(req, Destination{Network: TCP, Addr: addrA}); err != nil {
		t.Fatal(err)
	}
	req2 := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK2")
	if _, err := client.SendRequest(req2, Destination{Network: TCP, Addr: addrB}); !errors.Is(err, ErrTooManyConnections) {
		t.Fatalf("second dial = %v, want ErrTooManyConnections", err)
	}
	// Reusing the open connection is not a new dial.
	req3 := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK3")
	if _, err := client.SendRequest(req3, Destination{Network: TCP, Addr: addrA}); err != nil {
		t.Fatalf("reuse refused: %v", err)
	}
	if s := client.Stats(); s.Dialed != 1 || s.DialLimited != 1 || s.OpenOutbound != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

type countingDialer struct {
	mu sync.Mutex
	n  int
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.n++
	d.mu.Unlock()
	return nil, errors.New("not dialing in this test")
}

func TestTLSWithoutAServerNameIsUnroutableAndNotDialled(t *testing.T) {
	dialer := &countingDialer{}
	tr, _ := newTransport(t, Config{Dialer: dialer})
	req := newRequest(t, "OPTIONS", "SIP/2.0/TLS placeholder.invalid;branch=z9hG4bK1")
	if _, err := tr.SendRequest(req, Destination{Network: TLS, Addr: netip.MustParseAddrPort("192.0.2.1:5061")}); !errors.Is(err, ErrUnroutable) {
		t.Fatalf("SendRequest = %v, want ErrUnroutable", err)
	}
	// The response fallback of RFC 3261 §18.2.2 has no server name either.
	res := respond(t, newRequest(t, "OPTIONS", "SIP/2.0/TLS 192.0.2.1:5061;branch=z9hG4bK2"), 200)
	if err := tr.SendResponse(res, Source{Network: TLS, Flow: "gone"}); !errors.Is(err, ErrUnroutable) {
		t.Fatalf("SendResponse = %v, want ErrUnroutable", err)
	}
	if dialer.n != 0 {
		t.Fatalf("dialled %d times", dialer.n)
	}
}

// flowEvents records the Admit and OnFlowClosed calls of a transport.
type flowEvents struct {
	mu       sync.Mutex
	admitted []FlowID
	closed   []FlowID
	refuse   bool
}

func (e *flowEvents) config(cfg Config) Config {
	cfg.Admit = func(id FlowID, info FlowInfo) bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.refuse {
			return false
		}
		e.admitted = append(e.admitted, id)
		return true
	}
	cfg.OnFlowClosed = func(id FlowID, info FlowInfo) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.closed = append(e.closed, id)
	}
	return cfg
}

func (e *flowEvents) counts() (admitted, closed int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.admitted), len(e.closed)
}

func TestAdmitSeesEveryNewInboundFlowAndCanRefuseIt(t *testing.T) {
	ev := &flowEvents{}
	server, rec := newTransport(t, ev.config(Config{}))
	tcpAddr := listen(t, server, ListenerConfig{Network: TCP})
	udpAddr := listen(t, server, ListenerConfig{Network: UDP})

	c := dialRaw(t, tcpAddr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	in := rec.next(t)
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(udpAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK2")))
	rec.next(t)
	if a, _ := ev.counts(); a != 2 || ev.admitted[0] != in.Source.Flow {
		t.Fatalf("admitted %v", ev.admitted)
	}

	ev.mu.Lock()
	ev.refuse = true
	ev.mu.Unlock()
	refused := dialRaw(t, tcpAddr)
	waitClosed(t, refused)
	u2, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(udpAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer u2.Close()
	u2.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK3")))
	eventually(t, "two refusals", func() bool { return server.Stats().Refused == 2 })
	rec.none(t)
}

func TestEveryAdmittedFlowIsReportedClosedOnce(t *testing.T) {
	serverTLS, _ := testTLS(t)
	ev := &flowEvents{}
	server, rec := newTransport(t, ev.config(Config{TLS: serverTLS}))
	tcpAddr := listen(t, server, ListenerConfig{Network: TCP})
	tlsAddr := listen(t, server, ListenerConfig{Network: TLS})
	udpAddr := listen(t, server, ListenerConfig{Network: UDP})

	// A TCP flow the client closes.
	c := dialRaw(t, tcpAddr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	rec.next(t)
	c.Close()
	// A TLS connection admitted and then failing its handshake.
	bad := dialRaw(t, tlsAddr)
	bad.Write([]byte("not a ClientHello\r\n\r\n"))
	waitClosed(t, bad)
	// A UDP flow, still open at Close.
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(udpAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK2")))
	rec.next(t)

	eventually(t, "two closures", func() bool { _, closed := ev.counts(); return closed == 2 })
	server.Close()
	admitted, closed := ev.counts()
	if admitted != 3 || closed != 3 {
		t.Fatalf("admitted %d, closed %d", admitted, closed)
	}
	seen := map[FlowID]int{}
	for _, id := range ev.closed {
		seen[id]++
	}
	for _, id := range ev.admitted {
		if seen[id] != 1 {
			t.Fatalf("flow reported closed %d times", seen[id])
		}
	}
}

func TestCloseFlowClosesOneConnection(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	a, b := dialRaw(t, addr), dialRaw(t, addr)
	a.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	first := rec.next(t).Source.Flow
	b.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP b.example.com;branch=z9hG4bK2")))
	second := rec.next(t).Source.Flow

	if !server.CloseFlow(first) {
		t.Fatal("CloseFlow reported a live flow as gone")
	}
	waitClosed(t, a)
	if _, ok := server.Flow(second); !ok {
		t.Fatal("closing one flow closed another")
	}
	if server.CloseFlow(first) || server.CloseFlow("unknown") {
		t.Fatal("CloseFlow reported a gone flow as live")
	}
}

func TestCloseFlowForgetsAUDPFlow(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	if !server.CloseFlow(id) {
		t.Fatal("CloseFlow failed")
	}
	if _, ok := server.Flow(id); ok || server.Stats().OpenUDPFlows != 0 {
		t.Fatal("UDP flow still live")
	}
}

func TestStopListeningKeepsFlowsButRefusesNewConnections(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	flow := rec.next(t).Source.Flow

	server.StopListening()
	if _, err := net.DialTimeout("tcp", addr.String(), time.Second); err == nil {
		t.Fatal("a new connection was accepted after StopListening")
	}
	req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKout")
	if _, err := server.SendRequest(req, Destination{Flow: flow}); err != nil {
		t.Fatalf("existing flow unusable: %v", err)
	}
	readMessage(t, bufio.NewReader(c))
	if err := server.Close(); err != nil {
		t.Fatalf("Close after StopListening: %v", err)
	}
}

// Naming listeners stops only those: pcscf drains its client listeners and
// keeps the core listener open, so scscf can still reach the clients not yet
// closed (review of #188).
func TestStopListeningByNameLeavesTheOtherListenersOpen(t *testing.T) {
	server, _ := newTransport(t, Config{})
	client := listen(t, server, ListenerConfig{Name: "client", Network: TCP})
	core := listen(t, server, ListenerConfig{Name: "core", Network: TCP})
	server.StopListening("client", "no such listener")
	if _, err := net.DialTimeout("tcp", client.String(), time.Second); err == nil {
		t.Fatal("the named listener still accepts")
	}
	c, err := net.DialTimeout("tcp", core.String(), time.Second)
	if err != nil {
		t.Fatalf("the other listener stopped too: %v", err)
	}
	_ = c.Close()
	server.StopListening()
	if _, err := net.DialTimeout("tcp", core.String(), time.Second); err == nil {
		t.Fatal("StopListening without names left a listener open")
	}
}

func TestCloseDoesNotWaitForConnectionsInTheirHandshake(t *testing.T) {
	server, err := New(Config{ReadTimeout: time.Hour}, func(Inbound) {})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := server.Listen(ListenerConfig{Network: TCP, Addr: "127.0.0.1:0", ProxyProtocol: true})
	if err != nil {
		t.Fatal(err)
	}
	c := dialRaw(t, addr)
	c.Write([]byte("\r\n\r\n")) // part of a PROXY header, and then nothing
	eventually(t, "the connection to be pending", func() bool { return server.Stats().PendingAccepted == 1 })

	done := make(chan struct{})
	go func() {
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("Close waited for a connection still reading its PROXY header")
	}
	waitClosed(t, c)
}

func TestFullUDPFlowTableStillDeliversNewSources(t *testing.T) {
	server, rec := newTransport(t, Config{MaxUDPFlows: 1})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	var flows []FlowID
	for i := range 2 {
		u, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addr))
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		u.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK"+string(rune('a'+i)))))
		flows = append(flows, rec.next(t).Source.Flow)
	}
	if _, ok := server.Flow(flows[0]); ok {
		t.Fatal("the older flow was kept")
	}
	if s := server.Stats(); s.UDPFlowsEvicted != 1 || s.OpenUDPFlows != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestDeadlineReaderKeepsTheReadTimeoutUntilTheFirstMessageIsComplete(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var idle atomic.Int64
	idle.Store(int64(time.Hour))
	d := newDeadlineReader(a, &idle, time.Hour, true)
	br := bufio.NewReader(d)
	if !d.strict() {
		t.Fatal("a new accepted connection is not under the read timeout")
	}
	go b.Write([]byte("\r\n\r\n"))
	br.Peek(4)
	br.Discard(4)
	d.keepAlive(br)
	if !d.strict() {
		t.Fatal("a keep-alive before the first message switched to the idle timeout")
	}
	d.messageDone(br)
	if d.strict() {
		t.Fatal("the read timeout still applies after the first message")
	}
}

func TestProxyProtocolListenerIsClientFacing(t *testing.T) {
	tr := mustTransport(t)
	listen(t, tr, ListenerConfig{Name: "edge", Network: TCP, ProxyProtocol: true})
	if l := tr.listenerNamed("edge"); l == nil || !l.clientFacing {
		t.Fatal("a PROXY protocol listener is not client-facing")
	}
}

func TestAddressFromAPROXYHeaderIsNeverReusedForRequestsToThatAddress(t *testing.T) {
	// A connection that claims to come from a core node must not receive the
	// requests meant for that node.
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, ProxyProtocol: true})
	core := netip.MustParseAddrPort("192.0.2.50:5060")
	c := dialRaw(t, addr)
	c.Write(proxyHeaderFor(core, addr, nil))
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP 192.0.2.50:5060;branch=z9hG4bK1")))
	rec.next(t)
	if f := server.flows.peer(reuseKey{network: TCP, remote: core}); f != nil {
		t.Fatal("a PROXY-addressed connection is offered for reuse")
	}
}

func TestTLSConnectionIsReusedOnlyForTheNameItWasVerifiedFor(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	server, rec := newTransport(t, Config{TLS: serverTLS})
	addr := listen(t, server, ListenerConfig{Network: TLS})
	client, _ := newTransport(t, Config{TLSClient: clientTLS})
	req := newRequest(t, "OPTIONS", "SIP/2.0/TLS placeholder.invalid;branch=z9hG4bK1")
	if _, err := client.SendRequest(req, Destination{Network: TLS, Addr: addr, ServerName: "sip.example.com"}); err != nil {
		t.Fatal(err)
	}
	rec.next(t)
	// The certificate does not cover another name, so a fresh connection fails
	// verification; reusing the first one would have skipped it.
	other := newRequest(t, "OPTIONS", "SIP/2.0/TLS placeholder.invalid;branch=z9hG4bK2")
	if _, err := client.SendRequest(other, Destination{Network: TLS, Addr: addr, ServerName: "other.example.com"}); err == nil {
		t.Fatal("a connection verified for one name carried a request for another")
	}
	if s := client.Stats(); s.Dialed != 1 || s.DialErrors != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestUDPSocketIsChosenByAddressFamily(t *testing.T) {
	tr := mustTransport(t)
	listen(t, tr, ListenerConfig{Network: UDP, Addr: "127.0.0.1:0"})
	req := newRequest(t, "OPTIONS", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK1")
	if _, err := tr.SendRequest(req, Destination{Network: UDP, Addr: netip.MustParseAddrPort("[2001:db8::1]:5060")}); !errors.Is(err, ErrNoListener) {
		t.Fatalf("IPv6 destination from an IPv4 socket: %v, want ErrNoListener", err)
	}
	if _, err := tr.SendRequest(req, Destination{Network: UDP, Addr: netip.MustParseAddrPort("127.0.0.1:9")}); err != nil {
		t.Fatalf("IPv4 destination: %v", err)
	}
}

// QA regression (PR #35 review): datagrams that frame but fail Validate must
// not create UDP flows, so they cannot crowd out a real client.
func TestJunkDatagramsDoNotLockOutANewClient(t *testing.T) {
	server, rec := newTransport(t, Config{MaxUDPFlows: 20, MaxUDPFlowsPerIP: 20})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	for range 20 {
		c, err := net.Dial("udp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("OPTIONS sip:x@example.com SIP/2.0\r\n\r\n")) // no Via
	}
	eventually(t, "junk counted", func() bool { return server.Stats().InvalidMessages == 20 })
	if s := server.Stats(); s.OpenUDPFlows != 0 {
		t.Fatalf("invalid datagrams created %d flows", s.OpenUDPFlows)
	}
	legit, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer legit.Close()
	legit.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP 127.0.0.1;rport;branch=z9hG4bKlegit")))
	rec.next(t)
}

// QA regression (PR #35 review): admitting a new UDP source to a full table
// must not scan the table under its lock, which every lookup also takes.
func TestNewUDPSourceIsCheapWhenTheTableIsFull(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	var k [32]byte
	tab := newFlowTable(k, clock.now, tableConfig{udpTimeout: time.Hour, maxUDP: DefaultMaxUDPFlows, maxUDPPerIP: DefaultMaxUDPFlowsPerIP})
	lis := &listener{name: "udp"}
	for i := range DefaultMaxUDPFlows {
		tab.addUDP(tab.newFlow(UDP, lis, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 5060)))
	}
	// The best of five batches, so a loaded host's scheduling does not count.
	// A scan of the table costs milliseconds (3.3 ms when QA measured it, ten
	// times that under the race detector); the limit sits far below either and
	// far above an O(1) insert.
	limit := 100 * time.Microsecond
	if raceEnabled {
		limit = time.Millisecond
	}
	best := time.Hour
	for batch := range 5 {
		start := time.Now()
		for i := range 20 {
			tab.addUDP(tab.newFlow(UDP, lis, netip.AddrPortFrom(netip.AddrFrom4([4]byte{11, 0, byte(batch), byte(i)}), 5060)))
		}
		best = min(best, time.Since(start)/20)
	}
	if best > limit {
		t.Fatalf("each new source held the flow-table lock for %v", best)
	}
	if s := tab.stats(); s.udp != DefaultMaxUDPFlows || s.evicted != 100 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestOnFlowClosedRunsOffTheClosingGoroutineAndInOrder(t *testing.T) {
	// The closing goroutine holds a lock the callback needs, as a transaction
	// holds its own lock while it sends; a synchronous callback would deadlock.
	// UDP flows have no reader goroutine, so CloseFlow's caller is the one that
	// removes them.
	var mu sync.Mutex
	order := make(chan FlowID, 4)
	server, rec := newTransport(t, Config{OnFlowClosed: func(id FlowID, _ FlowInfo) {
		mu.Lock()
		defer mu.Unlock()
		order <- id
	}})
	addr := listen(t, server, ListenerConfig{Network: UDP})
	var ids []FlowID
	for i := range 3 {
		u, err := net.Dial("udp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		u.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bKo"+string(rune('a'+i)))))
		ids = append(ids, rec.next(t).Source.Flow)
	}
	mu.Lock()
	locked := true
	// If a CloseFlow blocks and the test fails, release the lock before the
	// transport's cleanup closes the remaining flows, so the failure is
	// reported instead of hanging.
	defer func() {
		if locked {
			mu.Unlock()
		}
	}()
	for _, id := range ids {
		within(t, func() error { server.CloseFlow(id); return nil })
	}
	mu.Unlock()
	locked = false
	for _, want := range ids {
		select {
		case got := <-order:
			if got != want {
				t.Fatalf("closures out of order")
			}
		case <-time.After(waitFor):
			t.Fatal("OnFlowClosed was not called")
		}
	}
}

func TestSourceSaysWhetherTheListenerIsClientFacing(t *testing.T) {
	server, rec := newTransport(t, Config{})
	edge := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: true})
	core := listen(t, server, ListenerConfig{Network: TCP})
	for addr, want := range map[netip.AddrPort]bool{edge: true, core: false} {
		c := dialRaw(t, addr)
		c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
		if got := rec.next(t).Source.ClientFacing; got != want {
			t.Errorf("listener %v: ClientFacing = %v, want %v", addr, got, want)
		}
	}
}
