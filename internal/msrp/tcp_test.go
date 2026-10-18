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
	h.octets.Add(int64(len(m.Body)))
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
				if _, err := s.Send(ctx, Outgoing{ContentType: "application/octet-stream", Body: body, SuccessReport: sr}); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}
	return errs
}

func waitCount(t *testing.T, what string, c *atomic.Int64, want int64, limit time.Duration, conns ...*Conn) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for c.Load() < want {
		for _, cc := range conns {
			if err := cc.Err(); err != nil {
				t.Fatalf("%s: connection ended after %d/%d: %v", what, c.Load(), want, err)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: only %d/%d after %v", what, c.Load(), want, limit)
		}
		time.Sleep(5 * time.Millisecond)
	}
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
		t.Run(fmt.Sprintf("w%d_n%d_%dKiB", tc.workers, tc.per, tc.size>>10), func(t *testing.T) {
			ah, bh := &countingHandler{}, &countingHandler{}
			alice, bob, ac, pc := tcpEndpoints(t, Config{}, ah, bh)
			ea := sendMany(context.Background(), alice, tc.workers, tc.per, tc.size, true)
			eb := sendMany(context.Background(), bob, tc.workers, tc.per, tc.size, true)
			want := int64(tc.workers * tc.per)
			waitCount(t, "bob received", &bh.msgs, want, 60*time.Second, ac, pc)
			waitCount(t, "alice received", &ah.msgs, want, 60*time.Second, ac, pc)
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
			waitCount(t, "alice success reports", &ah.reports, want, 30*time.Second, ac, pc)
			waitCount(t, "bob success reports", &bh.reports, want, 30*time.Second, ac, pc)
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
	ea := sendMany(ctx, alice, 4, 1000, 200, false)
	eb := sendMany(ctx, bob, 4, 60, 256<<10, false)
	for range 8 {
		var err error
		select {
		case err = <-ea:
		case err = <-eb:
		case <-time.After(60 * time.Second):
			t.Fatal("senders did not finish")
		}
		var se *StatusError
		if err != nil && !(errors.As(err, &se) && se.Code == StatusMessageTooLarge) {
			t.Fatalf("a sender ended with %v", err)
		}
	}
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
	// sockets.
	edgeWriteBuffer int
	relayAddr       string
	asReg           *Registry
	relay           *pairBinder
	relayConns      chan *Conn
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
	asL, relayL := tcpListen(t), tcpListen(t)
	rig := &relayRigTCP{relayAddr: relayL.Addr().String(), asReg: &Registry{}, relayConns: make(chan *Conn, 16)}
	for _, o := range opts {
		o(rig)
	}
	go func() {
		for {
			nc, err := asL.Accept()
			if err != nil {
				return
			}
			c, err := NewPassiveConn(nc, rig.asReg, asCfg)
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	pool := &Pool{Dial: func(ctx context.Context, _ URI) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", asL.Addr().String())
	}}
	t.Cleanup(func() { _ = pool.Close() })
	rig.relay = &pairBinder{pool: pool, pairs: map[string][2]*Session{}}
	go func() {
		for {
			nc, err := relayL.Accept()
			if err != nil {
				return
			}
			if rig.edgeWriteBuffer > 0 {
				_ = nc.(*net.TCPConn).SetWriteBuffer(rig.edgeWriteBuffer)
			}
			c, err := NewPassiveConn(nc, rig.relay, relayClientCfg)
			if err != nil {
				return
			}
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
	return as, cl, relPub
}

func (rig *relayRigTCP) dialClient(t *testing.T, local, relayPub URI, h Handler) (*Session, *Conn) {
	t.Helper()
	nc, err := net.Dial("tcp", rig.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewActiveConn(nc, Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, _ := NewSession(SessionConfig{Local: local, Remote: []URI{relayPub}, Handler: h})
	if err := c.Open(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	return s, c
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
	const users, per, size = 4, 25, 256 << 10
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
		waitCount(t, fmt.Sprintf("as%d received", n), &asHs[n].msgs, 2*per, 60*time.Second, conns...)
		waitCount(t, fmt.Sprintf("client%d received", n), &clientHs[n].msgs, 2*per, 60*time.Second, conns...)
		waitCount(t, fmt.Sprintf("client%d reports", n), &clientHs[n].reports, 2*per, 30*time.Second, conns...)
		waitCount(t, fmt.Sprintf("as%d reports", n), &asHs[n].reports, 2*per, 30*time.Second, conns...)
		if asHs[n].octets.Load() != 2*per*size || clientHs[n].octets.Load() != 2*per*size {
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
	const total = 64 << 20
	block := bodyOf(64 << 10)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base, peak := ms.HeapAlloc, ms.HeapAlloc
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sent := 0; sent < total; sent += len(block) {
			if _, err := nc.Write(block); err != nil {
				return
			}
		}
		_, _ = nc.Write([]byte("\r\n-------b1gx$\r\n"))
	}()
	deadline := time.Now().Add(60 * time.Second)
	for octets.Load() < total && time.Now().Before(deadline) {
		runtime.ReadMemStats(&ms)
		peak = max(peak, ms.HeapAlloc)
		time.Sleep(10 * time.Millisecond)
	}
	<-done
	if v := badRange.Load(); v != nil {
		t.Fatal(v)
	}
	if octets.Load() != total {
		t.Fatalf("only %d octets arrived", octets.Load())
	}
	if peak > base+32<<20 {
		t.Fatalf("heap grew by %.1f MiB while streaming %d MiB", float64(peak-base)/(1<<20), total>>20)
	}
}

func TestSlowAndSilentClientsDoNotHoldUpOthersOnTheSharedRelayConnection(t *testing.T) {
	// The relay writes to clients with a deadline short enough to cut the
	// silent client off within the test, yet longer than the 8–9 s a single
	// write was measured to wait for a client reading 4 KiB a second: the
	// kernel lets a writer go on in bursts. The production default is 30 s.
	const deadline = 15 * time.Second
	// Linux wakes a blocked writer only once much of its send buffer has
	// drained; with a large one that takes minutes at 4 KiB/s and a slow
	// reader looks like a silent one. A small buffer keeps them apart.
	rig := newRelayRigTCP(t, Config{WriteTimeout: deadline}, Config{}, func(r *relayRigTCP) { r.edgeWriteBuffer = 16 << 10 })
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
	for i := range 10 {
		time.Sleep(200 * time.Millisecond)
		start := time.Now()
		if _, err := asFast.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte(fmt.Sprintf("hi %d", i))}); err != nil {
			t.Fatalf("rcs-as could not send to the fast client: %v", err)
		}
		select {
		case <-fastH.got:
			if d := time.Since(start); d > time.Second {
				t.Errorf("message %d to the fast client took %v", i, d)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("message %d to the fast client never arrived", i)
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
	case <-time.After(3 * deadline):
		t.Error("silent client still connected")
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
			stayUp(t, 2*time.Second, append(conns, rig.coreConn(t))...)
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
							if _, err := cs.Send(ctx, Outgoing{ContentType: "text/plain", Body: bodyOf(200)}); err != nil {
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
			stayUp(t, 2*time.Second, rig.coreConn(t))
		})
	}
}

func TestSendHonoursItsContextWhenThePeerStopsReading(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{WriteTimeout: 3 * time.Second})
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
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.Send(ctx, Outgoing{ContentType: "text/plain", Body: bodyOf(10000)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Send ignored its context for %v", d)
	}
}

func TestRcsAsSendingBeforeTheClientConnectsHoldsUpNoOtherSession(t *testing.T) {
	rig := newRelayRigTCP(t, Config{}, Config{})
	asLate, clLate, rpLate := rig.addUser(t, 1, &countingHandler{})
	asOver, _, rpOver := rig.addUser(t, 2, &countingHandler{})
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

	// A stored message for a client that has not connected yet is held.
	stored := make(chan error, 1)
	go func() {
		_, err := asLate.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("kept for you")})
		stored <- err
	}()
	// More than the relay holds for an unbound session, from a sender that
	// does not wait for answers, is refused for that session alone.
	over := make(chan error, 1)
	go func() {
		_, err := asOver.Send(context.Background(), Outgoing{ContentType: "application/octet-stream", Body: bodyOf(1 << 20), FailureReport: ReportPartial})
		over <- err
	}()
	for i := range 5 {
		start := time.Now()
		if _, err := asFast.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte(fmt.Sprintf("hi %d", i))}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-fastH.got:
			if d := time.Since(start); d > time.Second {
				t.Errorf("message %d to the connected client took %v", i, d)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("message %d to the connected client never arrived", i)
		}
	}
	if err := <-stored; err != nil {
		t.Fatalf("stored message: %v", err)
	}
	var se *StatusError
	if err := <-over; !errors.As(err, &se) || se.Code != StatusMessageTooLarge {
		t.Fatalf("unbound session over its bound: %v", err)
	}
	// The client comes and gets what was held.
	lateH := &countingHandler{got: make(chan *Message, 4)}
	rig.dialClient(t, clLate, rpLate, lateH)
	select {
	case m := <-lateH.got:
		if string(m.Body) != "kept for you" {
			t.Fatalf("got %q", m.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held message was not delivered")
	}
	if rig.coreConn(t).Err() != nil || fastConn.Err() != nil {
		t.Fatalf("shared connection %v, connected client %v", rig.coreConn(t).Err(), fastConn.Err())
	}
}
