package pcscf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// waitFor bounds how long a test waits for the service; it is a safety net,
// never a protocol timer.
const waitFor = 10 * time.Second

// testConfig serves plain TCP on loopback, with the task address 127.0.0.1.
func testConfig() Config {
	return Config{
		PublicHost: publicHost, PublicPort: 5060, ClientTransport: ClientTCP, ClientAddr: "127.0.0.1:0",
		CoreAddr: "127.0.0.1:0", CoreHost: netip.MustParseAddr("127.0.0.1"),
		MaxFlowsPerIP: DefaultMaxFlowsPerIP, ClientIdleTimeout: DefaultClientIdleTimeout, DrainTimeout: time.Second,
		ICSCF:         sip.URI{Scheme: "sip", Host: "icscf.rcs.internal", Params: sip.Params{{Name: "transport", Value: "tcp"}, {Name: "lr"}}},
		AllowLoopback: true, MaxRegistrations: DefaultMaxRegistrations, RegisterRate: DefaultRegisterRate, RegisterBurst: DefaultRegisterBurst,
		MaxConnections: DefaultMaxConnections, MaxClientFlows: DefaultMaxClientFlows, CoreConnections: DefaultCoreConnections,
	}
}

type service struct {
	client, udp, core netip.AddrPort
	stop              func()
	done              chan error
}

// start runs pcscf with cfg and d until the test ends.
func start(t *testing.T, cfg Config, d deps) *service {
	t.Helper()
	h := runtimetest.New(t, "pcscf")
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{done: make(chan error, 1)}
	listening := make(chan struct{})
	d.listening = func(b bound) {
		s.client, s.udp, s.core = b.client, b.udp, b.core
		close(listening)
	}
	go func() { s.done <- run(ctx, h.Runtime, cfg, d) }()
	select {
	case <-listening:
	case err := <-s.done:
		cancel()
		t.Fatalf("run ended: %v", err)
	case <-time.After(waitFor):
		cancel()
		t.Fatal("pcscf did not start")
	}
	var once sync.Once
	s.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-s.done:
				if err != nil {
					t.Errorf("run: %v", err)
				}
			case <-time.After(waitFor):
				t.Error("pcscf did not stop")
			}
		})
	}
	t.Cleanup(s.stop)
	return s
}

// peer is a SIP endpoint on one TCP connection.
type peer struct {
	t  *testing.T
	nc net.Conn
	r  *sip.Reader
}

// requests numbers every request a test sends, so no two share a branch or a
// Call-ID: a server transaction of an earlier connection would take a new
// one for its retransmission (QA of #188).
var requests atomic.Int64

func dial(t *testing.T, addr netip.AddrPort, prefix []byte) *peer {
	t.Helper()
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	if len(prefix) > 0 {
		if _, err := nc.Write(prefix); err != nil {
			t.Fatal(err)
		}
	}
	return &peer{t: t, nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{})}
}

// request sends an OPTIONS with the given Route values and returns the
// response.
func (p *peer) request(routes ...string) *sip.Response {
	p.t.Helper()
	res, err := p.try(routes...)
	if err != nil {
		p.t.Fatalf("no response: %v", err)
	}
	return res
}

// try is request that returns an error when the connection fails.
func (p *peer) try(routes ...string) (*sip.Response, error) {
	var fields []string
	for _, r := range routes {
		fields = append(fields, "Route: <"+r+">")
	}
	return p.tryWith(fields...)
}

// tryWith sends an OPTIONS with extra header fields and returns the
// response.
func (p *peer) tryWith(fields ...string) (*sip.Response, error) {
	n := requests.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "OPTIONS sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n")
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-pcscf-%d\r\n", n)
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>;tag=a1\r\n")
	b.WriteString("To: <sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>\r\n")
	fmt.Fprintf(&b, "Call-ID: pcscf-test-%d\r\n", n)
	fmt.Fprintf(&b, "CSeq: %d OPTIONS\r\n", n)
	for _, f := range fields {
		b.WriteString(f + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\n\r\n")
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(p.nc, b.String()); err != nil {
		return nil, err
	}
	m, err := p.r.ReadMessage()
	if err != nil {
		return nil, err
	}
	res, ok := m.(*sip.Response)
	if !ok {
		return nil, fmt.Errorf("got a request: %v", m)
	}
	return res, nil
}

// closed reports whether pcscf closed the connection: a read that ends in
// anything but its deadline. One left open times out after waitFor.
func (p *peer) closed() bool {
	p.t.Helper()
	_ = p.nc.SetReadDeadline(time.Now().Add(waitFor))
	_, err := p.nc.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestUntilRegistrationClientsGet403AndTheCore430(t *testing.T) {
	s := start(t, testConfig(), deps{})
	if res := dial(t, s.client, nil).request(); res.StatusCode != 403 {
		t.Fatalf("client OPTIONS answered %d, want 403", res.StatusCode)
	}
	if res := dial(t, s.core, nil).request(); res.StatusCode != 430 {
		t.Fatalf("core OPTIONS answered %d, want 430", res.StatusCode)
	}
}

// routes records what the router saw: how many Route values pcscf took as its
// own, and the Route left.
type routes struct {
	mu   sync.Mutex
	seen []string
}

func (r *routes) Route(_ context.Context, req *proxy.Request) proxy.Decision {
	r.mu.Lock()
	r.seen = append(r.seen, fmt.Sprintf("%d %s", len(req.Routed), req.Message.Header.Get("Route")))
	r.mu.Unlock()
	return proxy.Decision{Status: 403}
}

// pcscf recognises itself in Route by its public name, which is what clients
// put there, or by its task address, with the public port, a default port or
// none (#16).
func TestPcscfRecognisesItselfByItsPublicNameOrItsAddress(t *testing.T) {
	rec := &routes{}
	cfg := testConfig()
	cfg.PublicPort = 5061
	cfg.PublicAddrs = []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	s := start(t, cfg, deps{router: rec})
	c := dial(t, s.client, nil)
	for _, r := range []string{
		"sip:" + publicHost + ";lr",
		"sip:PCSCF.rcs.example.net:5060;lr",
		"sip:" + publicHost + ":5061;transport=tls;lr",
		"sips:" + publicHost + ";lr",
		// The NLB's address, as rcsjta writes its first Route (review of #188).
		"sip:203.0.113.10:5061;transport=tls;lr",
		"sip:203.0.113.10;lr",
		"sip:127.0.0.1;lr",
		"sip:127.0.0.1:5061;lr",
		"sip:127.0.0.1:" + fmt.Sprint(s.core.Port()) + ";lr",
	} {
		rec.seen = nil
		c.request(r, "sip:scscf.example.net;lr")
		if len(rec.seen) != 1 || rec.seen[0] != "1 <sip:scscf.example.net;lr>" {
			t.Errorf("Route %s: router saw %q, want it taken as pcscf's own", r, rec.seen)
		}
	}
	for _, r := range []string{"sip:other.rcs.example.net;lr", "sip:127.0.0.2;lr", "sip:" + publicHost + ":5070;lr", "sip:203.0.113.11:5061;lr"} {
		rec.seen = nil
		c.request(r)
		if len(rec.seen) != 1 || !strings.HasPrefix(rec.seen[0], "0 ") {
			t.Errorf("Route %s: router saw %q, want it left", r, rec.seen)
		}
	}
}

// A client address holds at most MaxFlowsPerIP client flows; core flows are
// not counted (#16 AC 6).
func TestAClientAddressHoldsAtMostMaxFlowsPerIP(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFlowsPerIP = 2
	s := start(t, cfg, deps{})
	a, b := dial(t, s.client, nil), dial(t, s.client, nil)
	a.request()
	b.request()
	if !dial(t, s.client, nil).closed() {
		t.Fatal("a third flow from one address was admitted")
	}
	_ = a.nc.Close()
	// The closed flow's place is freed once the transport has noticed.
	deadline := time.Now().Add(waitFor)
	for {
		if _, err := dial(t, s.client, nil).try(); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the place of a closed flow was not freed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for range 3 {
		if res := dial(t, s.core, nil).request(); res.StatusCode != 430 {
			t.Fatalf("core flow answered %d", res.StatusCode)
		}
	}
}

// Behind the NLB a flow's client is the address in its PROXY header, which
// the limit counts; the NLB's LOCAL health checks are not flows (ADR 0003).
func TestTheLimitCountsTheClientInTheProxyHeader(t *testing.T) {
	cfg := testConfig()
	cfg.ProxyProtocol = true
	cfg.MaxFlowsPerIP = 1
	s := start(t, cfg, deps{})
	header := func(cmd proxyproto.Command, src string) []byte {
		h := proxyproto.Header{Command: cmd}
		if cmd == proxyproto.Proxy {
			h.Source, h.Destination = netip.MustParseAddrPort(src), netip.MustParseAddrPort("10.0.2.9:5061")
		}
		return h.Marshal()
	}
	// A health check held open takes no client's place.
	dial(t, s.client, header(proxyproto.Local, ""))
	if res := dial(t, s.client, header(proxyproto.Proxy, "198.51.100.7:40000")).request(); res.StatusCode != 403 {
		t.Fatalf("first flow of 198.51.100.7 answered %d", res.StatusCode)
	}
	if !dial(t, s.client, header(proxyproto.Proxy, "198.51.100.7:40001")).closed() {
		t.Fatal("a second flow of 198.51.100.7 was admitted")
	}
	if res := dial(t, s.client, header(proxyproto.Proxy, "198.51.100.8:40000")).request(); res.StatusCode != 403 {
		t.Fatalf("the flow of another client answered %d", res.StatusCode)
	}
	if res, err := dial(t, s.client, nil).try(); err == nil {
		t.Fatalf("a connection without a PROXY header was answered %d", res.StatusCode)
	}
}

// recordSleep records the gaps a drain waits, and runs during, if set, at
// the first.
// recordSleep is the drain's sleep and clock: a sleep records how long it
// was asked to wait and moves the clock on by that and late.
type recordSleep struct {
	mu     sync.Mutex
	gaps   []time.Duration
	during func()
	t      time.Time
	late   time.Duration
}

func (r *recordSleep) now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.t
}

func (r *recordSleep) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	r.gaps = append(r.gaps, d)
	r.t = r.t.Add(d + r.late)
	f := r.during
	r.during = nil
	r.mu.Unlock()
	if f != nil {
		f()
	}
	return nil
}

// A stop closes every client flow, one at a time over the drain timeout,
// and leaves no new connection in (ADR 0003).
func TestAStopClosesTheClientFlowsOneByOne(t *testing.T) {
	cfg := testConfig()
	cfg.DrainTimeout = 90 * time.Second
	rec := &recordSleep{}
	s := start(t, cfg, deps{sleep: rec.sleep, now: rec.now})
	var peers []*peer
	for range 3 {
		p := dial(t, s.client, nil)
		p.request()
		peers = append(peers, p)
	}
	core := dial(t, s.core, nil)
	core.request()
	accepting, coreOK, served := true, false, 0
	rec.during = func() {
		nc, err := net.DialTimeout("tcp", s.client.String(), time.Second)
		if accepting = err == nil; accepting {
			_ = nc.Close()
		}
		// The core listener stays open, so scscf can still reach the
		// clients not yet closed (review of #188).
		if res, err := dial(t, s.core, nil).try(); err == nil && res.StatusCode == 430 {
			coreOK = true
		}
		for _, p := range peers {
			if res, err := p.try(); err == nil && res.StatusCode == 403 {
				served++
			}
		}
	}
	s.stop()
	if accepting {
		t.Error("the client listener accepted a connection during the drain")
	}
	if !coreOK {
		t.Error("the core listener was not served during the drain")
	}
	if served != 2 {
		t.Errorf("%d client flows served during the drain, want the 2 not yet closed", served)
	}
	for i, p := range peers {
		if !p.closed() {
			t.Errorf("client flow %d is still open", i)
		}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.gaps) != 2 || rec.gaps[0] != 30*time.Second || rec.gaps[1] != 30*time.Second {
		t.Fatalf("gaps %v, want two of 30s", rec.gaps)
	}
}

func TestAFlowThatAlreadyEndedTakesNoTimeOfTheDrain(t *testing.T) {
	rec := &recordSleep{}
	gone := map[transport.FlowID]bool{"b": true, "c": true}
	drain(context.Background(), []transport.FlowID{"a", "b", "c", "d"}, 8*time.Second, func(id transport.FlowID) bool { return !gone[id] }, rec.sleep, rec.now)
	if len(rec.gaps) != 1 {
		t.Fatalf("gaps %v, want one, after a", rec.gaps)
	}
}

func TestDrainSpreadsTheClosesAndStopsWaitingWhenItsTimeRunsOut(t *testing.T) {
	var closed []string
	closeFlow := func(id transport.FlowID) bool { closed = append(closed, string(id)); return true }
	rec := &recordSleep{}
	drain(context.Background(), []transport.FlowID{"a", "b", "c", "d"}, 8*time.Second, closeFlow, rec.sleep, rec.now)
	if len(closed) != 4 || len(rec.gaps) != 3 || rec.gaps[0] != 2*time.Second {
		t.Fatalf("closed %v, gaps %v", closed, rec.gaps)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	closed, rec.gaps = nil, nil
	drain(ctx, []transport.FlowID{"a", "b", "c"}, time.Hour, closeFlow, rec.sleep, rec.now)
	if len(closed) != 3 || len(rec.gaps) != 0 {
		t.Fatalf("after its time: closed %v, gaps %v", closed, rec.gaps)
	}
	drain(context.Background(), nil, time.Hour, closeFlow, rec.sleep, rec.now)
}

// A sleep that wakes late does not push the later closes back: they keep to
// the schedule fixed at the start, so the flows left do not all close at
// the deadline (QA of #188).
func TestALateWakeUpIsMadeUpByTheNextWaits(t *testing.T) {
	rec := &recordSleep{late: 3 * time.Second}
	ids := []transport.FlowID{"a", "b", "c", "d", "e"}
	drain(context.Background(), ids, 10*time.Second, func(transport.FlowID) bool { return true }, rec.sleep, rec.now)
	// Closes are due at 0, 2, 4, 6 and 8 s and every wake-up is 3 s late:
	// a wakes at 5 s, so b closes at once, c waits for 6 s and wakes at
	// 9 s, so d and e close at once.
	want := []time.Duration{2 * time.Second, time.Second}
	if !slices.Equal(rec.gaps, want) {
		t.Fatalf("waits %v, want %v", rec.gaps, want)
	}
}

// The drain ends at DrainTimeout whatever its spacing does: the sleep it is
// given carries that deadline, so a slow clock cannot push Run past the
// runtime's stop deadline (QA of #188).
func TestTheDrainEndsAtTheDrainTimeout(t *testing.T) {
	cfg := testConfig()
	cfg.DrainTimeout = 90 * time.Second
	var left time.Duration
	var ok bool
	sleep := func(ctx context.Context, d time.Duration) error {
		var dl time.Time
		dl, ok = ctx.Deadline()
		left = time.Until(dl)
		return nil
	}
	s := start(t, cfg, deps{sleep: sleep})
	for range 2 {
		dial(t, s.client, nil).request()
	}
	s.stop()
	if !ok || left > cfg.DrainTimeout || left < cfg.DrainTimeout-10*time.Second {
		t.Fatalf("drain ctx deadline in %v (set %v), want about %v", left, ok, cfg.DrainTimeout)
	}
}

// UDP clients, in dev and test, are clients as well.
func TestAUDPClientIsAClient(t *testing.T) {
	cfg := testConfig()
	cfg.ClientUDPAddr = "127.0.0.1:0"
	s := start(t, cfg, deps{})
	nc, err := net.Dial("udp", s.udp.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	req := "OPTIONS sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.10:40000;rport;branch=z9hG4bK-pcscf-udp\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>;tag=a1\r\n" +
		"To: <sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>\r\n" +
		"Call-ID: pcscf-test-udp\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	_ = nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(nc, req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := nc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sip.ParseMessage(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := m.(*sip.Response); !ok || res.StatusCode != 403 {
		t.Fatalf("UDP OPTIONS answered %v", m)
	}
}

// A client connection that says nothing for the idle timeout is closed.
func TestAQuietClientConnectionIsClosed(t *testing.T) {
	cfg := testConfig()
	cfg.ClientIdleTimeout = time.Second
	s := start(t, cfg, deps{})
	c := dial(t, s.client, nil)
	c.request()
	if !c.closed() {
		t.Fatal("a quiet client connection was kept open")
	}
}

// The client listeners are client-facing, so no kernel keep-alive wakes a
// phone and no connection is opened to a client's Via (ADR 0003), and the
// UDP one names its own port in Via.
func TestTheClientListenersAreClientFacing(t *testing.T) {
	for _, tr := range []string{ClientTLS, ClientNLBTLS, ClientTCP} {
		cfg := testConfig()
		cfg.ClientTransport, cfg.ProxyProtocol, cfg.PublicPort = tr, true, 5061
		lc := clientListenerConfig(cfg)
		if !lc.ClientFacing || !lc.ProxyProtocol || lc.IdleTimeout != cfg.ClientIdleTimeout || lc.Name != clientListener ||
			lc.AdvertisedHost != publicHost || lc.AdvertisedPort != 5061 || lc.KeepAlive != nil {
			t.Errorf("%s: %+v", tr, lc)
		}
		if (lc.Network == transport.TLS) != (tr == ClientTLS) {
			t.Errorf("%s: network %s", tr, lc.Network)
		}
	}
	cfg := testConfig()
	cfg.ClientUDPAddr, cfg.PublicPort = "0.0.0.0:5060", 5061
	if u := udpListenerConfig(cfg); !u.ClientFacing || u.AdvertisedPort != 0 || u.Network != transport.UDP || u.Name != clientUDPListener {
		t.Errorf("UDP: %+v", u)
	}
}

// Client flows take at most MaxClientFlows of the transport's connections, so
// the core listener always has room for scscf (review of #188).
func TestClientFlowsLeaveRoomForTheCore(t *testing.T) {
	cfg := testConfig()
	cfg.MaxClientFlows = 2
	s := start(t, cfg, deps{})
	dial(t, s.client, nil).request()
	dial(t, s.client, nil).request()
	if !dial(t, s.client, nil).closed() {
		t.Fatal("a client flow past MaxClientFlows was admitted")
	}
	if res := dial(t, s.core, nil).request(); res.StatusCode != 430 {
		t.Fatalf("the core answered %d", res.StatusCode)
	}
}

// The transport accepts at most MaxConnections connections in all.
func TestTheTransportTakesMaxConnections(t *testing.T) {
	cfg := testConfig()
	cfg.MaxConnections, cfg.MaxClientFlows, cfg.CoreConnections = 2, 1, 1
	s := start(t, cfg, deps{})
	dial(t, s.core, nil).request()
	dial(t, s.core, nil).request()
	if res, err := dial(t, s.core, nil).try(); err == nil {
		t.Fatalf("a connection past MaxConnections was answered %d", res.StatusCode)
	}
}

// A client's message reaches the router without the headers only the
// network may set: they are removed on arrival (review of #188).
func TestTheRouterSeesNoNetworkHeaderFromAClient(t *testing.T) {
	rec := &headerRecorder{}
	s := start(t, testConfig(), deps{router: rec})
	c := dial(t, s.client, nil)
	if _, err := c.tryWith("P-Asserted-Identity: <sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org>", "P-Charging-Vector: icid-value=1"); err != nil {
		t.Fatal(err)
	}
	core := dial(t, s.core, nil)
	if _, err := core.tryWith("P-Asserted-Identity: <sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org>"); err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.pai) != 2 || rec.pai[0] != "" || rec.pai[1] == "" {
		t.Fatalf("P-Asserted-Identity seen %q, want removed from the client's only", rec.pai)
	}
}

type headerRecorder struct {
	mu  sync.Mutex
	pai []string
}

func (h *headerRecorder) Route(_ context.Context, r *proxy.Request) proxy.Decision {
	h.mu.Lock()
	h.pai = append(h.pai, r.Message.Header.Get("P-Asserted-Identity")+r.Message.Header.Get("P-Charging-Vector"))
	h.mu.Unlock()
	return proxy.Decision{Status: 403}
}
