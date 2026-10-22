package msrp

// These tests run over loopback TCP with real time, because what they
// check (kernel buffers filling, a peer reading slowly) has no fake
// equivalent. They started as the tester's reproductions on PR #28 and are
// scaled to run in seconds. Waiting is by polling with a limit, never by
// sleeping for an expected duration.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingHandler counts what it is given; delay stands for work such as a
// database write.
type countingHandler struct {
	msgs, octets, reports, failures atomic.Int64
	delay                           time.Duration
	got                             chan *Message
}

func (h *countingHandler) HandleMessage(_ *Session, m *Message) error {
	if h.delay > 0 {
		time.Sleep(h.delay)
	}
	h.msgs.Add(1)
	h.octets.Add(int64(m.Body.Len()))
	if h.got != nil {
		select {
		case h.got <- m:
		default:
		}
	}
	return nil
}

func (h *countingHandler) HandleReport(_ *Session, r Report) {
	h.reports.Add(1)
	if r.Code != StatusOK {
		h.failures.Add(1)
	}
}

func tcpListen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// rigListen is tcpListen with a real link's segment size (rigListenConfig),
// for the relay rig's connections, which carry traffic both ways (#140).
func rigListen(t *testing.T) net.Listener {
	t.Helper()
	lc := rigListenConfig()
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// tcpEndpoints joins alice (active) and bob (passive) over loopback TCP.
func tcpEndpoints(t *testing.T, cfg Config, aliceH, bobH Handler) (alice, bob *Session, ac, pc *Conn) {
	t.Helper()
	l := tcpListen(t)
	reg := &Registry{}
	bob = newTestSession(t, asURI, clientURI, bobH)
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *Conn, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		c, err := NewPassiveConn(nc, reg, cfg)
		if err != nil {
			t.Error(err)
		}
		accepted <- c
	}()
	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ac, err = NewActiveConn(nc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	pc = <-accepted
	t.Cleanup(func() { _ = ac.Close(); _ = pc.Close() })
	alice = newTestSession(t, clientURI, asURI, aliceH)
	if err := ac.Open(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	return alice, bob, ac, pc
}

func sendMany(ctx context.Context, s *Session, workers, per, size int, sr bool) chan error {
	errs := make(chan error, workers)
	body := bodyOf(size)
	for range workers {
		go func() {
			for range per {
				if _, err := s.Send(ctx, Outgoing{ContentType: "application/octet-stream", Body: BodyOf(body), SuccessReport: sr}); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}
	return errs
}

// waitCount waits for c to reach want while it keeps growing and the
// connections stay up (see waitProgress).
func waitCount(t *testing.T, what string, c *atomic.Int64, want int64, conns ...*Conn) {
	t.Helper()
	waitProgress(t, what, func() bool { return c.Load() >= want }, counter(c), func() error {
		for _, cc := range conns {
			if err := cc.Err(); err != nil {
				return fmt.Errorf("connection ended after %d/%d: %w", c.Load(), want, err)
			}
		}
		return nil
	})
}

// stayUp fails if any connection ends within d.
func stayUp(t *testing.T, d time.Duration, conns ...*Conn) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, c := range conns {
			if err := c.Err(); err != nil {
				t.Fatalf("connection ended: %v", err)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLargeChunksBothWaysOverTCPAllArriveWithTheirReports(t *testing.T) {
	for _, tc := range []struct{ workers, per, size int }{{1, 300, 32 << 10}, {4, 75, 32 << 10}, {8, 6, 512 << 10}} {
		tc.per = scaled(tc.per)
		t.Run(fmt.Sprintf("w%d_n%d_%dKiB", tc.workers, tc.per, tc.size>>10), func(t *testing.T) {
			ah, bh := &countingHandler{}, &countingHandler{}
			alice, bob, ac, pc := tcpEndpoints(t, Config{}, ah, bh)
			ea := sendMany(context.Background(), alice, tc.workers, tc.per, tc.size, true)
			eb := sendMany(context.Background(), bob, tc.workers, tc.per, tc.size, true)
			want := int64(tc.workers * tc.per)
			waitCount(t, "bob received", &bh.msgs, want, ac, pc)
			waitCount(t, "alice received", &ah.msgs, want, ac, pc)
			for range 2 * tc.workers {
				var err error
				select {
				case err = <-ea:
				case err = <-eb:
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			waitCount(t, "alice success reports", &ah.reports, want, ac, pc)
			waitCount(t, "bob success reports", &bh.reports, want, ac, pc)
			if ah.failures.Load()+bh.failures.Load() != 0 {
				t.Fatalf("failures: %d, %d", ah.failures.Load(), bh.failures.Load())
			}
		})
	}
}

func TestASlowHandlerDoesNotDisconnectAHealthyPeer(t *testing.T) {
	// Bob takes 2 ms per message while pushing a bulk transfer; alice sends
	// him many small messages. Bob refuses what his handler cannot keep up
	// with (413), which ends a sender of alice's at most; neither side drops
	// the connection.
	ah, bh := &countingHandler{}, &countingHandler{delay: 2 * time.Millisecond}
	alice, bob, ac, pc := tcpEndpoints(t, Config{}, ah, bh)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ea := sendMany(ctx, alice, 4, scaled(1000), 200, false)
	eb := sendMany(ctx, bob, 4, scaled(60), 256<<10, false)
	finished := 0
	waitProgress(t, "senders", func() bool { return finished == 8 },
		func() int64 { return ah.msgs.Load() + bh.msgs.Load() + int64(finished) },
		func() error {
			for {
				var err error
				select {
				case err = <-ea:
				case err = <-eb:
				default:
					return nil
				}
				finished++
				var se *StatusError
				if err != nil && !(errors.As(err, &se) && se.Code == StatusMessageTooLarge) {
					return fmt.Errorf("a sender ended with %w", err)
				}
			}
		})
	if ac.Err() != nil || pc.Err() != nil {
		t.Fatalf("connections ended: %v, %v", ac.Err(), pc.Err())
	}
	if ah.msgs.Load() == 0 || bh.msgs.Load() == 0 {
		t.Fatalf("delivered %d to alice, %d to bob", ah.msgs.Load(), bh.msgs.Load())
	}
}

// relayRigTCP is msrp-relay between rcs-as and clients, all over TCP.
type relayRigTCP struct {
	// edgeWriteBuffer, when set, is the send buffer of the relay's client
	// sockets; edgeConfig, when set, chooses the Config of the n-th client
	// connection the relay accepts.
	edgeWriteBuffer int
	edgeConfig      func(n int) Config
	relayAddr       string
	asReg           *Registry
	relay           *pairBinder
	relayConns      chan *Conn
	// users are the sessions of each user, by the relay's public
	// session-id, kept for a failed bind's report (#140).
	usersMu sync.Mutex
	users   map[string][3]*Session // rcs-as, relay edge, relay core
	// bindWatchdog is how long a client's bind may wait before the rig
	// takes a report while it still waits (0: 5 s, far above the slowest
	// bind measured and far below the 30 s transaction timeout);
	// clientConfig is the Config of the clients dialClient connects.
	bindWatchdog time.Duration
	clientConfig Config
	// conns are the connections the rig made or accepted, by role, and
	// events what they refused, dropped or ended with, for the report.
	diagMu sync.Mutex
	conns  []roleConn
	events []string
	// kernelBase are the kernel's TCP counters when the rig began, which
	// a report gives the changes since (#140).
	kernelBase map[string]int64
}

type roleConn struct {
	role string
	c    *Conn
}

// maxRigEvents bounds the events a rig keeps for its report: the latest.
const maxRigEvents = 256

// watch returns cfg with an OnEvent that records the connection's events
// under role, as well as passing them to cfg's own.
func (rig *relayRigTCP) watch(role string, cfg Config) Config {
	next := cfg.OnEvent
	cfg.OnEvent = func(e Event) {
		rig.diagMu.Lock()
		if len(rig.events) == maxRigEvents {
			rig.events = rig.events[1:]
		}
		rig.events = append(rig.events, fmt.Sprintf("%s: %s %s %d %v", role, eventKindNames[e.Kind], e.Method, e.Code, e.Err))
		rig.diagMu.Unlock()
		if next != nil {
			next(e)
		}
	}
	return cfg
}

var eventKindNames = map[EventKind]string{EventRefused: "refused", EventDropped: "dropped", EventClosed: "closed"}

func (rig *relayRigTCP) track(role string, c *Conn) {
	rig.diagMu.Lock()
	rig.conns = append(rig.conns, roleConn{role, c})
	rig.diagMu.Unlock()
}

// pairBinder hands out prepared bridges by the relay session-id.
type pairBinder struct {
	pool  *Pool
	mu    sync.Mutex
	pairs map[string][2]*Session
	// opened are pairs whose core side was opened before the client came.
	opened map[string]bool
}

func (r *pairBinder) Bind(_ *Conn, to URI) (*Session, error) {
	r.mu.Lock()
	p, ok := r.pairs[to.SessionID]
	opened := r.opened[to.SessionID]
	delete(r.pairs, to.SessionID)
	r.mu.Unlock()
	if !ok {
		return nil, ErrNoSession
	}
	if opened {
		return p[0], nil
	}
	if err := r.pool.Open(context.Background(), p[1]); err != nil {
		_ = p[0].Close()
		return nil, err
	}
	return p[0], nil
}

func newRelayRigTCP(t *testing.T, relayClientCfg, asCfg Config, opts ...func(*relayRigTCP)) *relayRigTCP {
	t.Helper()
	asL, relayL := rigListen(t), rigListen(t)
	rig := &relayRigTCP{relayAddr: relayL.Addr().String(), asReg: &Registry{}, relayConns: make(chan *Conn, 16), kernelBase: kernelCounters()}
	for _, o := range opts {
		o(rig)
	}
	go func() {
		for {
			nc, err := asL.Accept()
			if err != nil {
				return
			}
			c, err := NewPassiveConn(nc, rig.asReg, rig.watch("rcs-as", asCfg))
			if err != nil {
				return
			}
			rig.track("rcs-as", c)
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	pool := &Pool{Config: rig.watch("relay core", Config{}), Dial: func(ctx context.Context, _ URI) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", asL.Addr().String())
	}}
	t.Cleanup(func() { _ = pool.Close() })
	rig.relay = &pairBinder{pool: pool, pairs: map[string][2]*Session{}}
	go func() {
		for n := 0; ; n++ {
			nc, err := relayL.Accept()
			if err != nil {
				return
			}
			if rig.edgeWriteBuffer > 0 {
				_ = nc.(*net.TCPConn).SetWriteBuffer(rig.edgeWriteBuffer)
			}
			cfg := relayClientCfg
			if rig.edgeConfig != nil {
				cfg = rig.edgeConfig(n)
			}
			c, err := NewPassiveConn(nc, rig.relay, rig.watch("relay edge", cfg))
			if err != nil {
				return
			}
			rig.track("relay edge", c)
			rig.relayConns <- c
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return rig
}

// addUser prepares user n: the rcs-as session and the relay bridge.
func (rig *relayRigTCP) addUser(t *testing.T, n int, asH Handler) (asSess *Session, clientLocal, relayPub URI) {
	t.Helper()
	asU := mustURI(t, fmt.Sprintf("msrp://as.example.org:9000/as%04dx;tcp", n))
	relInt := mustURI(t, fmt.Sprintf("msrp://relay.internal:2855/ri%04dx;tcp", n))
	relPub := mustURI(t, fmt.Sprintf("msrp://relay.example.net:2855/rp%04dx;tcp", n))
	cl := mustURI(t, fmt.Sprintf("msrp://client%d.example.com:2855/cl%04dx;tcp", n, n))
	as, err := NewSession(SessionConfig{Local: asU, Remote: []URI{relInt}, Handler: asH})
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.asReg.Add(as); err != nil {
		t.Fatal(err)
	}
	a, _ := NewSession(SessionConfig{Local: relPub, Remote: []URI{cl}})
	b, _ := NewSession(SessionConfig{Local: relInt, Remote: []URI{asU}})
	if err := Bridge(a, b); err != nil {
		t.Fatal(err)
	}
	rig.relay.mu.Lock()
	rig.relay.pairs[relPub.SessionID] = [2]*Session{a, b}
	rig.relay.mu.Unlock()
	rig.usersMu.Lock()
	if rig.users == nil {
		rig.users = map[string][3]*Session{}
	}
	rig.users[relPub.SessionID] = [3]*Session{as, a, b}
	rig.usersMu.Unlock()
	return as, cl, relPub
}

func (rig *relayRigTCP) dialClient(t *testing.T, local, relayPub URI, h Handler) (*Session, *Conn) {
	t.Helper()
	s, c, report := rig.openClient(t, local, relayPub, h)
	if report != "" {
		t.Fatal(report)
	}
	return s, c
}

// openClient connects a client and binds its session. A bind normally takes
// milliseconds, under a starved CPU well under a second; one that waited
// out the 30 s transaction timeout in CI stood behind a connection loopback
// had stalled (#140, rigListen). A failed bind returns a report instead of
// the session: how far the bind got, the connections' queues and the
// events they reported, and every goroutine, taken while the bind still
// waited (after bindWatchdog) and again once it failed. The relay's own wait ends on a timer as long as
// the client's, so by then it may be gone (QA of #165).
func (rig *relayRigTCP) openClient(t *testing.T, local, relayPub URI, h Handler) (*Session, *Conn, string) {
	t.Helper()
	nc, err := net.Dial("tcp", rig.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewActiveConn(nc, rig.watch("client "+local.SessionID, rig.clientConfig))
	if err != nil {
		t.Fatal(err)
	}
	rig.track("client "+local.SessionID, c)
	t.Cleanup(func() { _ = c.Close() })
	s, _ := NewSession(SessionConfig{Local: local, Remote: []URI{relayPub}, Handler: h})
	wait := rig.bindWatchdog
	if wait <= 0 {
		wait = 5 * time.Second
	}
	waiting := make(chan string, 1)
	watchdog := time.AfterFunc(wait, func() { waiting <- rig.report(relayPub) })
	start := time.Now()
	err = c.Open(context.Background(), s)
	took := time.Since(start)
	if err == nil {
		watchdog.Stop()
		return s, c, ""
	}
	early := "(the bind failed before the watchdog)"
	if !watchdog.Stop() {
		early = <-waiting
	}
	return nil, nil, fmt.Sprintf("bind of %s failed after %v: %v\n--- while it waited, after %v:\n%s\n--- once it failed:\n%s",
		local.SessionID, took, err, wait, early, rig.report(relayPub))
}

// allStacks is every goroutine's stack, whole: the buffer grows until the
// dump fits, so goroutines other tests left behind cannot push out the
// ones a report is read for (#251).
func allStacks() []byte {
	for size := 1 << 20; ; size *= 2 {
		buf := make([]byte, size)
		if n := runtime.Stack(buf, true); n < size {
			return buf[:n]
		}
	}
}

// report is how far relayPub's bind got, the state of every connection the
// rig knows and the latest events, on Linux the kernel's view of each
// socket, then every goroutine's stack. It is only taken for a bind that
// waits past bindWatchdog and only shown if the bind fails.
func (rig *relayRigTCP) report(relayPub URI) string {
	var b strings.Builder
	b.WriteString(rig.bindState(relayPub))
	b.WriteString("\nconnections:\n")
	rig.diagMu.Lock()
	conns := slices.Clone(rig.conns)
	events := slices.Clone(rig.events)
	rig.diagMu.Unlock()
	pool := rig.relay.pool
	pool.mu.Lock()
	for _, c := range pool.conns {
		conns = append(conns, roleConn{"relay core", c})
	}
	pool.mu.Unlock()
	for _, rc := range conns {
		c := rc.c
		c.qmu.Lock()
		queued, posted := len(c.queue), c.posted
		c.qmu.Unlock()
		c.mu.Lock()
		awaiting, closed := len(c.pending), c.closed
		c.mu.Unlock()
		fmt.Fprintf(&b, "  %s %p: %d frames queued (%d bytes posted), %d requests awaiting an answer, closed %t\n",
			rc.role, c, queued, posted, awaiting, closed)
	}
	b.WriteString("events:\n")
	for _, e := range events {
		b.WriteString("  " + e + "\n")
	}
	b.WriteString(kernelReport(rig.kernelBase, conns))
	b.WriteString("goroutines:\n")
	b.Write(allStacks())
	return b.String()
}

// A bind stuck on the relay's core open is caught while it waits: the
// report taken then shows the relay's Bind in Pool.Open and the core
// connection awaiting the answer to its bind, which the report taken once
// the bind failed may no longer show (QA of #165). rcs-as here accepts the
// relay's connection and never answers; the relay waits for it with the
// default 30 s, so the report finds it waiting however late it is taken.
func TestABindStuckOnTheCoreOpenIsReportedWhileItWaits(t *testing.T) {
	rig := newRelayRigTCP(t, Config{}, Config{})
	rig.clientConfig = Config{TransactionTimeout: 2 * time.Second}
	rig.bindWatchdog = time.Second
	hole := tcpListen(t)
	go func() {
		for {
			nc, err := hole.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = nc.Close() })
		}
	}()
	pool := &Pool{Config: rig.watch("relay core", Config{}), Dial: func(ctx context.Context, _ URI) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", hole.Addr().String())
	}}
	t.Cleanup(func() { _ = pool.Close() })
	rig.relay.pool = pool
	_, cl, rp := rig.addUser(t, 0, &countingHandler{})
	_, _, report := rig.openClient(t, cl, rp, &countingHandler{})
	waited, _, ok := strings.Cut(report, "--- once it failed:")
	if !ok {
		t.Fatalf("the bind did not fail:\n%s", report)
	}
	for _, want := range []string{"pairBinder).Bind", "(*Pool).Open", "relay pair still waiting for the bind: false", "requests awaiting an answer"} {
		if !strings.Contains(waited, want) {
			t.Errorf("the report taken while the bind waited lacks %q:\n%s", want, waited)
		}
	}
	if !strings.Contains(waited, "relay core 0x") || !strings.Contains(waited, ": 0 frames queued (0 bytes posted), 1 requests awaiting an answer") {
		t.Errorf("the report does not show the core connection awaiting its bind's answer:\n%s", waited)
	}
	// Where the kernel can say, the report says which end holds the
	// octets of a stalled connection and whether TCP is backing off (#140).
	checkKernelReport(t, waited)
}

// bindState says how far a client's bind got: whether the relay still
// waits for it (its pair not taken, so the bind SEND never reached Bind),
// and which of the user's sessions are attached to a connection. A pair
// taken with every session attached is a bind whose 200 to the client was
// lost; one with the core or rcs-as session unattached is a core bind that
// failed or was never answered.
func (rig *relayRigTCP) bindState(relayPub URI) string {
	rig.relay.mu.Lock()
	_, waiting := rig.relay.pairs[relayPub.SessionID]
	rig.relay.mu.Unlock()
	rig.usersMu.Lock()
	u := rig.users[relayPub.SessionID]
	rig.usersMu.Unlock()
	attached := func(s *Session) bool {
		if s == nil {
			return false
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.conn != nil && !s.closed
	}
	return fmt.Sprintf("relay pair still waiting for the bind: %t; attached: relay edge %t, relay core %t, rcs-as %t",
		waiting, attached(u[1]), attached(u[2]), attached(u[0]))
}

// rawClient binds a session with a bare TCP connection and returns it, so
// the test decides how it reads.
func (rig *relayRigTCP) rawClient(t *testing.T, local, relayPub URI) net.Conn {
	t.Helper()
	return rig.rawClientWith(t, &net.Dialer{}, local, relayPub)
}

func (rig *relayRigTCP) rawClientWith(t *testing.T, d *net.Dialer, local, relayPub URI) net.Conn {
	t.Helper()
	nc, err := d.Dial("tcp", rig.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	bind := "MSRP b1nd SEND\r\nTo-Path: " + relayPub.String() + "\r\nFrom-Path: " + local.String() + "\r\nMessage-ID: b1nd\r\n-------b1nd$\r\n"
	if _, err := nc.Write([]byte(bind)); err != nil {
		t.Fatal(err)
	}
	return nc
}

func (rig *relayRigTCP) relayEdgeSession(t *testing.T, c *Conn) *Session {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.sessions {
		return s
	}
	t.Fatal("no session on the client connection")
	return nil
}

// openCoreFirst opens the rcs-as side of a user's bridge before its client
// connects, against the order ADR 0004 gives.
func (rig *relayRigTCP) openCoreFirst(t *testing.T, relayPub URI) {
	t.Helper()
	rig.relay.mu.Lock()
	p := rig.relay.pairs[relayPub.SessionID]
	if rig.relay.opened == nil {
		rig.relay.opened = map[string]bool{}
	}
	rig.relay.opened[relayPub.SessionID] = true
	rig.relay.mu.Unlock()
	if err := rig.relay.pool.Open(context.Background(), p[1]); err != nil {
		t.Fatal(err)
	}
}

func (rig *relayRigTCP) coreConn(t *testing.T) *Conn {
	t.Helper()
	rig.relay.pool.mu.Lock()
	defer rig.relay.pool.mu.Unlock()
	for _, c := range rig.relay.pool.conns {
		return c
	}
	t.Fatal("no connection toward rcs-as")
	return nil
}

func TestTrafficThroughARelayOverTCPArrivesBothWays(t *testing.T) {
	rig := newRelayRigTCP(t, Config{}, Config{})
	const users, size = 4, 256 << 10
	per := scaled(12)
	var clientHs, asHs []*countingHandler
	var clients, ases []*Session
	var conns []*Conn
	for n := range users {
		ah := &countingHandler{}
		as, cl, rp := rig.addUser(t, n, ah)
		ch := &countingHandler{}
		cs, cc := rig.dialClient(t, cl, rp, ch)
		clientHs, asHs = append(clientHs, ch), append(asHs, ah)
		clients, ases, conns = append(clients, cs), append(ases, as), append(conns, cc)
	}
	for n := range users {
		sendMany(context.Background(), clients[n], 2, per, size, true)
		sendMany(context.Background(), ases[n], 2, per, size, true)
	}
	for n := range users {
		waitCount(t, fmt.Sprintf("as%d received", n), &asHs[n].msgs, int64(2*per), conns...)
		waitCount(t, fmt.Sprintf("client%d received", n), &clientHs[n].msgs, int64(2*per), conns...)
		waitCount(t, fmt.Sprintf("client%d reports", n), &clientHs[n].reports, int64(2*per), conns...)
		waitCount(t, fmt.Sprintf("as%d reports", n), &asHs[n].reports, int64(2*per), conns...)
		if asHs[n].octets.Load() != int64(2*per*size) || clientHs[n].octets.Load() != int64(2*per*size) {
			t.Fatalf("user %d octets as=%d client=%d", n, asHs[n].octets.Load(), clientHs[n].octets.Load())
		}
	}
}

func TestARelayStreamsAHugeChunkInBoundedMemory(t *testing.T) {
	rig := newRelayRigTCP(t, Config{MaxMessageSize: 1 << 30}, Config{})
	// rcs-as is a raw peer here: it answers every piece and keeps nothing.
	asL := tcpListen(t)
	rig.relay.pool.Dial = func(ctx context.Context, _ URI) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", asL.Addr().String())
	}
	var octets atomic.Int64
	var badRange atomic.Value
	go func() {
		nc, err := asL.Accept()
		if err != nil {
			return
		}
		r := NewReader(nc, 0)
		next := int64(1)
		for {
			m, err := r.ReadHeader()
			if err != nil {
				return
			}
			n, _ := io.Copy(io.Discard, r.Body())
			if m.HasBody() {
				octets.Add(n)
				if m.ByteRange.Start != next {
					badRange.Store(fmt.Sprintf("piece at %d, want %d", m.ByteRange.Start, next))
				}
				next += n
			}
			resp, _ := NewResponse(m, StatusOK, "OK")
			b, _ := resp.Marshal()
			_, _ = nc.Write(b)
		}
	}()
	_, cl, rp := rig.addUser(t, 1, &countingHandler{})
	nc := rig.rawClient(t, cl, rp)
	go func() { _, _ = io.Copy(io.Discard, nc) }()
	head := "MSRP b1gx SEND\r\nTo-Path: " + rp.String() + "\r\nFrom-Path: " + cl.String() +
		"\r\nMessage-ID: m1d1\r\nByte-Range: 1-*/*\r\nContent-Type: application/octet-stream\r\n\r\n"
	if _, err := nc.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	// Under the race detector, less data with closer pauses: a relay that
	// held the chunk would still exceed the bound below by the second pause.
	total, pause := 64<<20, 16<<20
	if raceEnabled {
		total, pause = 24<<20, 8<<20
	}
	block := bodyOf(64 << 10)
	// What the relay retains is measured at pauses in the middle of the
	// chunk, once everything sent so far has come out the other side: with
	// pieces still churning through, a collection counts what is allocated
	// while it runs, and on a busy machine that is tens of MiB of garbage.
	liveHeap := func() uint64 {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc
	}
	base := liveHeap()
	peak := base
	for sent := 0; sent < total; {
		for end := sent + pause; sent < end; sent += len(block) {
			if _, err := nc.Write(block); err != nil {
				t.Fatal(err)
			}
		}
		// The relay keeps back at most one piece and its look-ahead.
		want := int64(sent) - 2*DefaultChunkSize
		waitProgress(t, "octets through the relay", func() bool { return octets.Load() >= want }, counter(&octets), nil)
		peak = max(peak, liveHeap())
	}
	if _, err := nc.Write([]byte("\r\n-------b1gx$\r\n")); err != nil {
		t.Fatal(err)
	}
	waitProgress(t, "octets through the relay", func() bool { return octets.Load() >= int64(total) }, counter(&octets), nil)
	if v := badRange.Load(); v != nil {
		t.Fatal(v)
	}
	if octets.Load() != int64(total) {
		t.Fatalf("only %d octets arrived", octets.Load())
	}
	if peak > base+8<<20 {
		t.Fatalf("heap grew by %.1f MiB in the middle of a %d MiB chunk", float64(peak-base)/(1<<20), total>>20)
	}
}

func TestSlowAndSilentClientsDoNotHoldUpOthersOnTheSharedRelayConnection(t *testing.T) {
	// The relay writes to the silent client, which connects first, with a
	// short deadline so that it is cut off within the test; the others keep
	// the default 30 s, comfortably above the 8–9 s a single write was
	// measured to wait for a client reading 4 KiB a second, since the
	// kernel lets a writer go on in bursts.
	const deadline = time.Second
	// Linux wakes a blocked writer only once much of its send buffer has
	// drained; with a large one that takes minutes at 4 KiB/s and a slow
	// reader looks like a silent one. A small buffer keeps them apart.
	rig := newRelayRigTCP(t, Config{}, Config{}, func(r *relayRigTCP) {
		r.edgeWriteBuffer = 16 << 10
		r.edgeConfig = func(n int) Config {
			if n == 0 {
				return Config{WriteTimeout: deadline}
			}
			return Config{}
		}
	})
	asSilent, clSilent, rpSilent := rig.addUser(t, 1, &countingHandler{})
	asSlow, clSlow, rpSlow := rig.addUser(t, 2, &countingHandler{})
	asFast, clFast, rpFast := rig.addUser(t, 3, &countingHandler{})

	// The silent client binds and never reads again.
	rig.rawClient(t, clSilent, rpSilent)
	silentEdge := <-rig.relayConns
	// The slow one reads 4 KiB a second. Loopback's 64 KiB segments would
	// let TCP report its progress only every 16 s, so it uses the segment
	// size and receive buffer of a real link.
	slow := rig.rawClientWith(t, mobileDialer(), clSlow, rpSlow)
	slowEdge := <-rig.relayConns
	var slowRead atomic.Int64
	go func() {
		buf := make([]byte, 4<<10)
		for {
			n, err := io.ReadFull(slow, buf)
			slowRead.Add(int64(n))
			if err != nil {
				return
			}
			time.Sleep(time.Second)
		}
	}()
	fastH := &countingHandler{got: make(chan *Message, 16)}
	_, fastConn := rig.dialClient(t, clFast, rpFast, fastH)
	for _, s := range []*Session{asSilent, asSlow, asFast} {
		if _, err := s.waitBound(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	core := rig.coreConn(t)

	// rcs-as pushes 16 MiB at each of the two over the shared connection.
	for _, s := range []*Session{asSilent, asSlow} {
		sendMany(context.Background(), s, 1, 16, 1<<20, false)
	}
	// Each message to the fast client gets 5 s, counted from the start of
	// its Send, which waits for the relay's answer. A relay that held the
	// shared connection behind the slow client would stall for a write's
	// 8–9 s or its 30 s timeout, past it. The bound is 5 s under the race
	// detector too, not stallBound's 10 s, which an 8–9 s stall would fit
	// in. A loaded host's delivery can take longer than prompt (1 s), as
	// #157 showed; QA measured it well under 5 s, race or not (#173).
	const fastBound = 5 * time.Second
	for i := range 10 {
		time.Sleep(200 * time.Millisecond)
		bound := time.After(fastBound)
		sent := make(chan error, 1)
		go func() {
			_, err := asFast.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte(fmt.Sprintf("hi %d", i)))})
			sent <- err
		}()
		for got, answered := false, false; !got || !answered; {
			select {
			case <-fastH.got:
				got = true
			case err := <-sent:
				if err != nil {
					t.Fatalf("rcs-as could not send to the fast client: %v", err)
				}
				answered = true
			case <-bound:
				t.Fatalf("message %d to the fast client: delivered %v, answered %v after %v", i, got, answered, fastBound)
			}
		}
	}
	// The silent client has been cut off by the write deadline. The slow
	// one still reads and stays, at its own pace; so do the shared
	// connection and the fast client.
	select {
	case <-silentEdge.Done():
		// Cut off by the write deadline, or earlier for having too much
		// unanswered.
		if err := silentEdge.Err(); !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, ErrPeerNotReading) {
			t.Errorf("silent client cut off with %v", err)
		}
	case <-time.After(deadline + stallBound):
		t.Errorf("silent client still connected well after its %v write deadline", deadline)
	}
	if slowEdge.Err() != nil || slowRead.Load() == 0 {
		t.Errorf("slow client: %v after reading %d octets", slowEdge.Err(), slowRead.Load())
	}
	if core.Err() != nil || fastConn.Err() != nil {
		t.Fatalf("shared connection %v, fast client %v", core.Err(), fastConn.Err())
	}
	// What the relay holds for the slow client stays within one window of
	// rcs-as's chunks.
	slowSession := rig.relayEdgeSession(t, slowEdge)
	if b := slowSession.backlog.Load(); b > int64(DefaultSendWindow)*3<<10 {
		t.Fatalf("%d octets queued for the slow client", b)
	}
}

func TestARelayKeepsItsRcsAsConnectionWhileRcsAsHandlesSlowly(t *testing.T) {
	for _, delay := range []time.Duration{200 * time.Microsecond, time.Millisecond, 5 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			rig := newRelayRigTCP(t, Config{}, Config{})
			const users = 4
			var conns []*Conn
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for n := range users {
				as, cl, rp := rig.addUser(t, n, &countingHandler{delay: delay})
				cs, cc := rig.dialClient(t, cl, rp, &countingHandler{})
				conns = append(conns, cc)
				sendMany(ctx, cs, 1, 1<<20, 200, false) // chat as fast as it goes
				sendMany(ctx, as, 1, 100, 1<<20, false) // file push
			}
			stayUp(t, time.Second, append(conns, rig.coreConn(t))...)
		})
	}
}

func TestARelayKeepsItsRcsAsConnectionUnderPacedChatAndFilePush(t *testing.T) {
	for _, tc := range []struct {
		delay, gap time.Duration
		flooders   int
	}{{0, 0, 4}, {time.Millisecond, 10 * time.Millisecond, 0}, {200 * time.Microsecond, 0, 1}} {
		t.Run(fmt.Sprintf("delay%v_gap%v_flooders%d", tc.delay, tc.gap, tc.flooders), func(t *testing.T) {
			rig := newRelayRigTCP(t, Config{}, Config{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for n := range 4 {
				as, cl, rp := rig.addUser(t, n, &countingHandler{delay: tc.delay})
				cs, _ := rig.dialClient(t, cl, rp, &countingHandler{})
				switch {
				case n < tc.flooders:
					sendMany(ctx, cs, 1, 1<<20, 200, false)
				case tc.gap > 0:
					go func() {
						for ctx.Err() == nil {
							if _, err := cs.Send(ctx, Outgoing{ContentType: "text/plain", Body: BodyOf(bodyOf(200))}); err != nil {
								return
							}
							time.Sleep(tc.gap)
						}
					}()
				}
				if n >= tc.flooders {
					sendMany(ctx, as, 1, 100, 1<<20, false)
				}
			}
			stayUp(t, time.Second, rig.coreConn(t))
		})
	}
}

func TestSendHonoursItsContextWhenThePeerStopsReading(t *testing.T) {
	ours, theirs := net.Pipe()
	// Write and transaction timeouts of an hour: a Send that waited for
	// either instead of honouring its context would block far past the 20 s
	// this test waits, which is below every default the package has (30 s),
	// so no other bound can end it in time either (#130, review of #131).
	c, err := NewActiveConn(ours, Config{WriteTimeout: time.Hour, TransactionTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p := newSyncPeer(t, theirs)
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusOK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan error, 1)
	go func() {
		_, err := s.Send(ctx, Outgoing{ContentType: "text/plain", Body: BodyOf(bodyOf(10000))})
		sent <- err
	}()
	// The peer takes one byte, so the write has begun, and then stops
	// reading; only then is the context cancelled.
	_ = theirs.SetReadDeadline(time.Now().Add(hangGuard))
	if _, err := theirs.Read(make([]byte, 1)); err != nil {
		t.Fatalf("the send never began: %v", err)
	}
	cancel()
	select {
	case err := <-sent:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Send = %v, want its context's cancellation", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Send ignored its context while the peer was not reading")
	}
}

func TestRcsAsSendingBeforeTheClientConnectsHoldsUpNoOtherSession(t *testing.T) {
	rig := newRelayRigTCP(t, Config{}, Config{})
	asLate, clLate, rpLate := rig.addUser(t, 1, &countingHandler{})
	overH := &countingHandler{}
	asOver, clOver, rpOver := rig.addUser(t, 2, overH)
	asFast, clFast, rpFast := rig.addUser(t, 3, &countingHandler{})
	fastH := &countingHandler{got: make(chan *Message, 16)}
	_, fastConn := rig.dialClient(t, clFast, rpFast, fastH)
	rig.openCoreFirst(t, rpLate)
	rig.openCoreFirst(t, rpOver)
	for _, s := range []*Session{asLate, asOver, asFast} {
		if _, err := s.waitBound(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	// The unconnected client's edge, looked up once: Bind removes it from
	// pairs, and a later change of order should fail on a message here,
	// not on a nil edge.
	rig.relay.mu.Lock()
	lateEdges := rig.relay.pairs[rpLate.SessionID]
	rig.relay.mu.Unlock()
	if len(lateEdges) == 0 {
		t.Fatal("the relay has no edge for the unconnected client's session")
	}
	lateEdge := lateEdges[0]
	held := func() int {
		lateEdge.mu.Lock()
		defer lateEdge.mu.Unlock()
		return len(lateEdge.held)
	}

	// A stored message for a client that has not connected yet is held.
	sendsStart := time.Now()
	stored := make(chan error, 1)
	go func() {
		_, err := asLate.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("kept for you"))})
		stored <- err
	}()
	// More than the relay holds for an unbound session, from a sender that
	// does not wait for answers, is refused for that session alone.
	over := make(chan error, 1)
	go func() {
		_, err := asOver.Send(context.Background(), Outgoing{ContentType: "application/octet-stream", Body: BodyOf(bodyOf(1 << 20)), FailureReport: ReportPartial})
		over <- err
	}()
	// The connected client gets its messages while the unconnected one's
	// is still held: proved by order, not by a prompt bound, which a loaded
	// host broke (#157). Each wait still ends at stallBound, far above any
	// delivery a loaded host has shown, so a relay that stalls the shared
	// rcs-as connection for seconds behind the unconnected client fails
	// here, not only one that stalls it until the 30 s transaction timeout.
	for held() == 0 {
		if time.Since(sendsStart) > stallBound {
			t.Fatalf("the message for the unconnected client was not held within %v", stallBound)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// The relay refuses the push over the bound on the same shared
	// connection. Messages go on until one has been sent after the refusal
	// was seen, so a stall in the refusal path falls inside this loop too.
	start := time.Now()
	for i, afterRefusal := 0, false; i < 5 || !afterRefusal; i++ {
		refused := overH.failures.Load() > 0
		// The bound runs from the start of the send, which itself waits
		// for the relay's answer.
		bound := time.After(stallBound)
		sent := make(chan error, 1)
		go func() {
			_, err := asFast.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte(fmt.Sprintf("hi %d", i)))})
			sent <- err
		}()
		for got, answered := false, false; !got || !answered; {
			select {
			case <-fastH.got:
				got = true
			case err := <-sent:
				if err != nil {
					t.Fatalf("message %d: %v", i, err)
				}
				answered = true
			case <-bound:
				t.Fatalf("message %d to the connected client: delivered %v, answered %v after %v", i, got, answered, stallBound)
			}
		}
		if held() == 0 {
			t.Fatalf("message %d arrived only after the unconnected client's message was released", i)
		}
		afterRefusal = refused
		if !afterRefusal && time.Since(start) > hangGuard {
			t.Fatalf("the push over the bound was not refused within %v", hangGuard)
		}
	}
	if err := <-stored; err != nil {
		t.Fatalf("stored message: %v", err)
	}
	// Send may have written every chunk before the refusal came back; the
	// refusal reaches the session's reports either way.
	var se *StatusError
	if err := <-over; err != nil && !(errors.As(err, &se) && se.Code == StatusMessageTooLarge) {
		t.Fatalf("unbound session over its bound: %v", err)
	}
	waitCount(t, "refusals for the session over its bound", &overH.failures, 1)
	// What was held of the refused message is dropped, so its client, when
	// it comes, gets no truncated message.
	rig.relay.mu.Lock()
	overEdge := rig.relay.pairs[rpOver.SessionID][0]
	rig.relay.mu.Unlock()
	overEdge.mu.Lock()
	heldLeft, octetsLeft := len(overEdge.held), overEdge.heldOctets
	overEdge.mu.Unlock()
	if heldLeft != 0 || octetsLeft != 0 {
		t.Fatalf("%d pieces (%d octets) of the refused message still held", heldLeft, octetsLeft)
	}
	overClient := &countingHandler{got: make(chan *Message, 4)}
	rig.dialClient(t, clOver, rpOver, overClient)
	if _, err := asOver.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("after"))}); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-overClient.got:
		if string(m.Body.Bytes()) != "after" {
			t.Fatalf("the client got %d octets of %q first", m.Body.Len(), m.MessageID)
		}
	case <-time.After(hangGuard):
		t.Fatal("the later message never arrived")
	}
	// The client comes and gets what was held.
	lateH := &countingHandler{got: make(chan *Message, 4)}
	rig.dialClient(t, clLate, rpLate, lateH)
	select {
	case m := <-lateH.got:
		if string(m.Body.Bytes()) != "kept for you" {
			t.Fatalf("got %q", m.Body.Bytes())
		}
	case <-time.After(hangGuard):
		t.Fatal("the held message was not delivered")
	}
	if rig.coreConn(t).Err() != nil || fastConn.Err() != nil {
		t.Fatalf("shared connection %v, connected client %v", rig.coreConn(t).Err(), fastConn.Err())
	}
}
