package sipua

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// The tests in this file are QA's, from the review of #169.

// gateRand blocks the first 2-byte read, the keep-alive jitter, after it is
// armed, so a test can hold the UA's lock at a known point.
type gateRand struct {
	mu      sync.Mutex
	armed   bool
	reached chan struct{}
	release chan struct{}
}

func (g *gateRand) Read(p []byte) (int, error) {
	g.mu.Lock()
	block := g.armed && len(p) == 2
	if block {
		g.armed = false
	}
	g.mu.Unlock()
	if block {
		close(g.reached)
		<-g.release
	}
	return rand.Read(p)
}

func goroutineIn(fn string) bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), fn)
}

func TestRefreshRacingAPingLeavesOneKeepAliveChain(t *testing.T) {
	// The keep-alive timer fires while a refresh holds the UA's lock. The
	// timer that fired must not survive beside the one the refresh armed.
	s := newStandIn(t, transport.TCP)
	s.flowTimer = 100
	clock := newFakeClock()
	g := &gateRand{reached: make(chan struct{}), release: make(chan struct{})}
	cfg := s.config()
	cfg.Clock, cfg.Rand = clock, g
	ua := dial(t, cfg)
	register(t, ua)
	d1 := clock.waitArmed(t, "keep-alive", func(d time.Duration) bool { return d >= 80*time.Second && d <= 100*time.Second })

	// A failure below must not leave Register blocked in the gate, holding
	// the lock Close needs.
	release := sync.OnceFunc(func() { close(g.release) })
	t.Cleanup(release)
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
	refreshed := make(chan error, 1)
	go func() { _, err := ua.Register(context.Background()); refreshed <- err }()
	<-g.reached // Register holds ua.mu, in jitter

	fired := make(chan struct{})
	go func() { clock.advance(d1); close(fired) }()
	waitUntil(t, "ping blocked on the UA's lock", func() bool { return goroutineIn("sipua.(*UA).ping") })
	release()
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	<-fired
	settle := func() {
		// Every pong read, and its timer stopped (pong counts before it locks).
		waitUntil(t, "pongs for every ping", func() bool {
			p, q := ua.KeepAlives()
			ua.mu.Lock()
			defer ua.mu.Unlock()
			return p == q && ua.pongDue == nil
		})
	}
	settle()
	// 1000 s more at 80 s or more per interval: one chain sends at most 13
	// more pings. One second at a time, so each pong beats its deadline.
	for range 1000 {
		clock.advance(time.Second)
		settle()
	}
	if err := ua.Err(); err != nil {
		t.Fatalf("Err = %v", err)
	}
	if pings, _ := ua.KeepAlives(); pings > 1+13 {
		t.Fatalf("pings = %d in 1000 s: more than one keep-alive chain is running", pings)
	}
}

// rawFlow answers every REGISTER on a bare socket, with Require: outbound,
// and never answers pings.
type rawFlow struct{ ln net.Listener }

func newRawFlow(t *testing.T) *rawFlow {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := sip.NewReader(bufio.NewReader(c), sip.Limits{})
		for {
			m, err := rd.ReadMessage()
			if err != nil {
				return
			}
			req := m.(*sip.Request)
			res, _ := sip.NewResponse(req, 200, "", "r1")
			if exp, _ := req.Header.Expires(); exp > 0 {
				contacts, _ := req.Header.Contact()
				contacts[0].Params.Set("expires", "3600")
				res.Header.Add("Contact", contacts[0].String())
			}
			res.Header.Add("Require", "outbound")
			b, _ := res.Bytes()
			c.Write(b)
		}
	}()
	return &rawFlow{ln: ln}
}

func (r *rawFlow) config(t *testing.T, clock *fakeClock, keepAlive time.Duration) Config {
	return Config{
		Network: transport.TCP, Proxy: netip.MustParseAddrPort(r.ln.Addr().String()), Domain: testDomain,
		IMPU: mustURI(t, testIMPU), InstanceID: testInstance, Clock: clock, KeepAlive: keepAlive,
	}
}

func TestRefreshKeepsTheDeadlineOfAPongDue(t *testing.T) {
	clock := newFakeClock()
	ua := dial(t, newRawFlow(t).config(t, clock, 30*time.Second))
	register(t, ua)
	clock.armedFor(t, 30*time.Second)
	clock.advance(30 * time.Second) // a ping that is never answered
	waitUntil(t, "the ping", func() bool { p, _ := ua.KeepAlives(); return p == 1 })
	clock.advance(5 * time.Second)
	register(t, ua) // a refresh while the pong is due
	clock.advance(5 * time.Second)
	select {
	case <-ua.Done():
	case <-time.After(waitFor):
		t.Fatal("the refresh dropped the deadline of the pong that was due")
	}
}

func TestPingsFasterThanThePongTimeoutDoNotExtendIt(t *testing.T) {
	clock := newFakeClock()
	ua := dial(t, newRawFlow(t).config(t, clock, 3*time.Second))
	register(t, ua)
	clock.armedFor(t, 3*time.Second)
	for range 13 { // the first ping at 3 s is due at 13 s
		clock.advance(time.Second)
	}
	select {
	case <-ua.Done():
	case <-time.After(waitFor):
		p, _ := ua.KeepAlives()
		t.Fatalf("no failure 10 s after the first unanswered ping (%d pings sent)", p)
	}
}

func TestFailedTLSHandshakeEndsTheUA(t *testing.T) {
	// The handshake closes the one connection before any flow opens, so no
	// OnFlowClosed comes; the UA must still finish.
	s := newStandIn(t, transport.TLS)
	cfg := s.config()
	cfg.ServerName = "wrong.example.org"
	ua := dial(t, cfg)
	if _, err := ua.Register(context.Background()); !errors.Is(err, safeerr.ErrCertificate) {
		t.Fatalf("Register = %v, want the certificate refused", err)
	}
	waitDone(t, ua)
	if err := ua.Err(); !errors.Is(err, ErrFlowFailed) {
		t.Fatalf("Err = %v, want ErrFlowFailed", err)
	}
}
