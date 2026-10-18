package diameter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

const (
	appCx      = 16777216
	appSh      = 16777217
	vendor3GPP = 10415
	cmdTest    = 300
	testRealm  = "rcs.test"
	hssHost    = "hss.rcs.test"
	scscfHost  = "scscf-1a2b.rcs.test"

	testWatchdog     = 30 * time.Second
	testRequestWait  = 7 * time.Second
	testCapabilities = 10 * time.Second
	testReconnectMin = 1 * time.Second
	testReconnectMax = 20 * time.Second

	// realWait bounds how long a test waits for another goroutine. It is a
	// safety net against hangs, never a protocol timer.
	realWait = 5 * time.Second
)

// fakeClock fires timers only when the test advances it, synchronously and
// in deadline order.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	changed chan struct{}
}

type fakeTimer struct {
	c    *fakeClock
	when time.Time
	f    func()
	done bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), changed: make(chan struct{})}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, when: c.now.Add(d), f: f}
	live := c.timers[:0]
	for _, x := range c.timers {
		if !x.done {
			live = append(live, x)
		}
	}
	c.timers = append(live, t)
	close(c.changed)
	c.changed = make(chan struct{})
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.done
	t.done = true
	return was
}

// Advance moves time forward by d, firing every timer that falls due,
// including timers that the fired callbacks schedule within the window.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		due := make([]*fakeTimer, 0, len(c.timers))
		for _, t := range c.timers {
			if !t.done && !t.when.After(target) {
				due = append(due, t)
			}
		}
		if len(due) == 0 {
			c.now = target
			c.mu.Unlock()
			return
		}
		sort.Slice(due, func(i, j int) bool { return due[i].when.Before(due[j].when) })
		t := due[0]
		t.done = true
		if t.when.After(c.now) {
			c.now = t.when
		}
		c.mu.Unlock()
		t.f()
	}
}

// waitForTimer blocks until a live timer is due exactly d from now, so the
// test advances the clock only after the code under test has armed it.
func (c *fakeClock) waitForTimer(t testing.TB, d time.Duration) {
	t.Helper()
	c.waitForTimers(t, d, 1)
}

// waitForTimers blocks until n live timers are due exactly d from now.
func (c *fakeClock) waitForTimers(t testing.TB, d time.Duration, n int) {
	t.Helper()
	deadline := time.After(realWait)
	for {
		c.mu.Lock()
		target := c.now.Add(d)
		found := 0
		for _, x := range c.timers {
			if !x.done && x.when.Equal(target) {
				found++
			}
		}
		if found >= n {
			c.mu.Unlock()
			return
		}
		ch := c.changed
		c.mu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			t.Fatalf("%d of %d timers due in %s were armed", found, n, d)
		}
	}
}

// waitFor polls a condition that another goroutine makes true.
func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// addrConn gives one end of a net.Pipe the addresses of a TCP connection, so
// source-network rules and Host-IP-Address defaults can be tested.
type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func tcpAddr(s string) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s))
}

// pipeListener hands net.Pipe connections to Node.Serve.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// connect opens a connection to the listener from remote and returns the
// client end.
func (l *pipeListener) connect(t testing.TB, remote string) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	sc := addrConn{Conn: server, local: tcpAddr("10.0.0.1:3868"), remote: tcpAddr(remote)}
	select {
	case l.conns <- sc:
	case <-time.After(realWait):
		t.Fatal("listener did not accept")
	}
	return client
}

// pipeDialer is a Config.Dial whose connections the test answers by hand.
type pipeDialer struct {
	mu    sync.Mutex
	fail  error
	dials int
	conns chan net.Conn
}

func newPipeDialer() *pipeDialer { return &pipeDialer{conns: make(chan net.Conn, 4)} }

func (d *pipeDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	fail := d.fail
	d.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	client, server := net.Pipe()
	d.conns <- server
	return addrConn{Conn: client, local: tcpAddr("10.0.1.5:40000"), remote: tcpAddr("10.0.0.1:3868")}, nil
}

func (d *pipeDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func (d *pipeDialer) next(t testing.TB) *script {
	t.Helper()
	select {
	case c := <-d.conns:
		return newScript(t, c, hssHost)
	case <-time.After(realWait):
		t.Fatal("node did not dial")
		return nil
	}
}

// script is the test playing a remote Diameter node by hand on one
// connection.
type script struct {
	t    testing.TB
	nc   net.Conn
	br   *bufio.Reader
	dict *Dictionary
	host string
	hbh  uint32
}

func newScript(t testing.TB, nc net.Conn, host string) *script {
	t.Cleanup(func() { _ = nc.Close() })
	return &script{t: t, nc: nc, br: bufio.NewReader(nc), dict: testDictionary(t), host: host, hbh: 0x7000}
}

func (s *script) read() *Message {
	s.t.Helper()
	_ = s.nc.SetReadDeadline(time.Now().Add(realWait))
	m, err := ReadMessage(s.br, s.dict, Limits{})
	if err != nil {
		s.t.Fatalf("script read: %v", err)
	}
	return m
}

func (s *script) write(m *Message) {
	s.t.Helper()
	b, err := m.Encode()
	if err != nil {
		s.t.Fatal(err)
	}
	s.writeRaw(b)
}

func (s *script) writeRaw(b []byte) {
	s.t.Helper()
	_ = s.nc.SetWriteDeadline(time.Now().Add(realWait))
	if _, err := s.nc.Write(b); err != nil {
		s.t.Fatalf("script write: %v", err)
	}
}

// request sends a request with a fresh Hop-by-Hop Identifier.
func (s *script) request(m *Message) *Message {
	s.t.Helper()
	m.Flags |= FlagRequest
	s.hbh++
	m.HopByHop, m.EndToEnd = s.hbh, s.hbh
	s.write(m)
	return m
}

// roundTrip sends a request and reads the next message, which must be its
// answer.
func (s *script) roundTrip(m *Message) *Message {
	s.t.Helper()
	req := s.request(m)
	ans := s.read()
	if ans.IsRequest() || ans.HopByHop != req.HopByHop || ans.EndToEnd != req.EndToEnd || ans.Code != req.Code {
		s.t.Fatalf("answer %+v does not match request %+v", ans, req)
	}
	return ans
}

func (s *script) origin() []*AVP {
	return []*AVP{
		NewAVP(AVPOriginHost, FlagMandatory, 0, []byte(s.host)),
		NewAVP(AVPOriginRealm, FlagMandatory, 0, []byte(testRealm)),
	}
}

// sync exchanges a DWR, proving the node has processed everything sent
// before it: the read loop handles messages in order.
func (s *script) sync() {
	s.t.Helper()
	ans := s.roundTrip(&Message{Code: CodeDeviceWatchdog, AVPs: s.origin()})
	if rc, _ := ans.ResultCode(); rc != ResultSuccess {
		s.t.Fatalf("DWA result %d", rc)
	}
}

func (s *script) answer(req *Message, rc uint32, avps ...*AVP) *Message {
	a := &Message{Code: req.Code, ApplicationID: req.ApplicationID, HopByHop: req.HopByHop, EndToEnd: req.EndToEnd}
	if IsProtocolError(rc) {
		a.Flags |= FlagError
	}
	a.Add(NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(rc)))
	a.Add(s.origin()...)
	a.Add(avps...)
	return a
}

// expectClosed waits for the node to close the connection.
func (s *script) expectClosed() {
	s.t.Helper()
	_ = s.nc.SetReadDeadline(time.Now().Add(realWait))
	m, err := ReadMessage(s.br, s.dict, Limits{})
	if err == nil {
		s.t.Fatalf("expected the connection to close, got command %d", m.Code)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		s.t.Fatalf("expected the connection to close, got %v", err)
	}
}

func cxVSA() *AVP {
	return NewGrouped(AVPVendorSpecificApplicationID, FlagMandatory, 0,
		NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(vendor3GPP)),
		NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(appCx)))
}

// testCER is a CER from host with the required AVPs and Origin-State-Id 7.
func testCER(host, realm string, extra ...*AVP) *Message {
	m := &Message{Flags: FlagRequest, Code: CodeCapabilitiesExchange, ApplicationID: AppCommon, HopByHop: 1, EndToEnd: 1}
	m.Add(
		NewAVP(AVPOriginHost, FlagMandatory, 0, []byte(host)),
		NewAVP(AVPOriginRealm, FlagMandatory, 0, []byte(realm)),
		NewAVP(AVPHostIPAddress, FlagMandatory, 0, Address(netip.MustParseAddr("10.0.1.5"))),
		NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(0)),
		NewAVP(AVPProductName, 0, 0, []byte("test-peer")),
		NewAVP(AVPOriginStateID, FlagMandatory, 0, Unsigned32(7)),
	)
	m.Add(extra...)
	return m
}

// testCEA answers cer as host with the given result and advertised AVPs.
func testCEA(cer *Message, rc uint32, host string, extra ...*AVP) *Message {
	m := &Message{Code: CodeCapabilitiesExchange, ApplicationID: AppCommon, HopByHop: cer.HopByHop, EndToEnd: cer.EndToEnd}
	if IsProtocolError(rc) {
		m.Flags |= FlagError
	}
	m.Add(NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(rc)))
	m.Add(testCER(host, testRealm).AVPs...)
	m.Add(extra...)
	return m
}

func testConfig(clock Clock, host string) Config {
	d, err := NewDictionary(testDefs...)
	if err != nil {
		panic(err)
	}
	return Config{
		OriginHost:          host,
		OriginRealm:         testRealm,
		Applications:        []Application{{ID: appCx, VendorID: vendor3GPP}},
		SupportedVendorIDs:  []uint32{vendor3GPP},
		Dictionary:          d,
		WatchdogInterval:    testWatchdog,
		RequestTimeout:      testRequestWait,
		CapabilitiesTimeout: testCapabilities,
		ReconnectMin:        testReconnectMin,
		ReconnectMax:        testReconnectMax,
		Clock:               clock,
		// 2000 puts the watchdog jitter at exactly zero.
		Random: func() uint64 { return 2000 },
		Logger: slog.New(slog.DiscardHandler),
	}
}

func newTestNode(t testing.TB, cfg Config) *Node {
	t.Helper()
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// A cancelled context closes whatever is left without waiting for
		// DPAs that no script will send.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = n.Shutdown(ctx)
	})
	return n
}

// startResponder runs a node as `hss` behind a pipe listener. It accepts
// `scscf-*` peers from the VPC unless cfg says otherwise.
func startResponder(t testing.TB, edit func(*Config)) (*Node, *pipeListener, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	cfg := testConfig(clock, hssHost)
	cfg.Accept = []PeerRule{{HostPattern: "scscf-*.rcs.test", Realm: testRealm,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}}}
	if edit != nil {
		edit(&cfg)
	}
	n := newTestNode(t, cfg)
	ln := newPipeListener()
	served := make(chan error, 1)
	go func() { served <- n.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		<-served
	})
	return n, ln, clock
}

// openScript connects to a responder as host and completes the capabilities
// exchange successfully.
func openScript(t testing.TB, ln *pipeListener, host string) *script {
	t.Helper()
	s := newScript(t, ln.connect(t, "10.0.1.5:40000"), host)
	s.write(testCER(host, testRealm, cxVSA()))
	cea := s.read()
	if rc, _ := cea.ResultCode(); rc != ResultSuccess {
		t.Fatalf("CEA result %d", rc)
	}
	return s
}

// startInitiator runs a node as `scscf` that dials through a pipe dialer and
// has connected to a scripted `hss`.
func startInitiator(t testing.TB, edit func(*Config)) (*Node, *Peer, *pipeDialer, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	dialer := newPipeDialer()
	cfg := testConfig(clock, scscfHost)
	cfg.Dial = dialer.Dial
	if edit != nil {
		edit(&cfg)
	}
	n := newTestNode(t, cfg)
	p, err := n.Connect(PeerConfig{Address: "hss.rcs.test:3868", Host: hssHost, Realm: testRealm})
	if err != nil {
		t.Fatal(err)
	}
	return n, p, dialer, clock
}

// acceptCER plays the responder side of a capabilities exchange.
func acceptCER(t testing.TB, s *script, extra ...*AVP) {
	t.Helper()
	cer := s.read()
	if !isCER(cer) {
		t.Fatalf("expected CER, got %+v", cer)
	}
	if len(extra) == 0 {
		extra = []*AVP{cxVSA()}
	}
	s.write(testCEA(cer, ResultSuccess, s.host, extra...))
}
