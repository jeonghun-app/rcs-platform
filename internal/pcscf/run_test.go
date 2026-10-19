package pcscf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
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
	n  int
}

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
	p.n++
	var b strings.Builder
	fmt.Fprintf(&b, "OPTIONS sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n")
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.10:40000;branch=z9hG4bK-pcscf-%d\r\n", p.n)
	b.WriteString("Max-Forwards: 70\r\n")
	b.WriteString("From: <sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>;tag=a1\r\n")
	b.WriteString("To: <sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>\r\n")
	fmt.Fprintf(&b, "Call-ID: pcscf-test-%d\r\n", p.n)
	fmt.Fprintf(&b, "CSeq: %d OPTIONS\r\n", p.n)
	for _, r := range routes {
		fmt.Fprintf(&b, "Route: <%s>\r\n", r)
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
	s := start(t, cfg, deps{router: rec})
	c := dial(t, s.client, nil)
	for _, r := range []string{
		"sip:" + publicHost + ";lr",
		"sip:PCSCF.rcs.example.net:5060;lr",
		"sip:" + publicHost + ":5061;transport=tls;lr",
		"sips:" + publicHost + ";lr",
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
	for _, r := range []string{"sip:other.rcs.example.net;lr", "sip:127.0.0.2;lr", "sip:" + publicHost + ":5070;lr"} {
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
type recordSleep struct {
	mu     sync.Mutex
	gaps   []time.Duration
	during func()
}

func (r *recordSleep) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	r.gaps = append(r.gaps, d)
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
	s := start(t, cfg, deps{sleep: rec.sleep})
	var peers []*peer
	for range 3 {
		p := dial(t, s.client, nil)
		p.request()
		peers = append(peers, p)
	}
	core := dial(t, s.core, nil)
	core.request()
	accepting := true
	rec.during = func() {
		nc, err := net.DialTimeout("tcp", s.client.String(), time.Second)
		if accepting = err == nil; accepting {
			_ = nc.Close()
		}
	}
	s.stop()
	if accepting {
		t.Error("the client listener accepted a connection during the drain")
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

func TestDrainSpreadsTheClosesAndStopsWaitingWhenItsTimeRunsOut(t *testing.T) {
	var closed []string
	closeFlow := func(id transport.FlowID) bool { closed = append(closed, string(id)); return true }
	rec := &recordSleep{}
	drain(context.Background(), []transport.FlowID{"a", "b", "c", "d"}, 8*time.Second, closeFlow, rec.sleep)
	if len(closed) != 4 || len(rec.gaps) != 3 || rec.gaps[0] != 2*time.Second {
		t.Fatalf("closed %v, gaps %v", closed, rec.gaps)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	closed, rec.gaps = nil, nil
	drain(ctx, []transport.FlowID{"a", "b", "c"}, time.Hour, closeFlow, rec.sleep)
	if len(closed) != 3 || len(rec.gaps) != 0 {
		t.Fatalf("after its time: closed %v, gaps %v", closed, rec.gaps)
	}
	drain(context.Background(), nil, time.Hour, closeFlow, rec.sleep)
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
