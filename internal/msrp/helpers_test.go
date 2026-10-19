package msrp

import (
	"bytes"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock fires timers only when a test advances it, in due order and on
// the advancing goroutine.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	// armed, when set, hears the duration of every timer armed, so a test
	// can wait until the code under test is waiting.
	armed chan time.Duration
}

type fakeTimer struct {
	c       *fakeClock
	when    time.Time
	f       func()
	stopped bool
	fired   bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
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
	c.timers = append(c.timers, t)
	if c.armed != nil {
		select {
		case c.armed <- d:
		default:
		}
	}
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	active := !t.stopped && !t.fired
	t.stopped = true
	return active
}

// watchTimers starts recording armed timers afresh.
func (c *fakeClock) watchTimers() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = make(chan time.Duration, 256)
}

// waitTimer waits until a timer of duration d is armed after watchTimers,
// so that advancing the clock cannot overtake the code under test.
func (c *fakeClock) waitTimer(t *testing.T, d time.Duration) {
	t.Helper()
	c.mu.Lock()
	armed := c.armed
	c.mu.Unlock()
	for {
		select {
		case got := <-armed:
			if got == d {
				return
			}
		case <-time.After(hangGuard):
			t.Fatalf("no %v timer was armed", d)
		}
	}
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	target := c.now
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].when.Before(c.timers[j].when) })
		var due *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.fired && !t.when.After(target) {
				due = t
				break
			}
		}
		if due == nil {
			c.mu.Unlock()
			return
		}
		due.fired = true
		c.mu.Unlock()
		due.f()
	}
}

// wirePeer is the far end of a connection, speaking raw MSRP so that tests
// see exactly what goes on the wire.
type wirePeer struct {
	nc   net.Conn
	msgs chan *Message
	errs chan error
}

func newWirePeer(t *testing.T, nc net.Conn) *wirePeer {
	t.Helper()
	p := &wirePeer{nc: nc, msgs: make(chan *Message, 64), errs: make(chan error, 1)}
	go func() {
		r := NewReader(nc, 0)
		for {
			m, err := r.ReadMessage(DefaultMaxMessageSize)
			var me *MessageError
			if err != nil && !errors.As(err, &me) {
				p.errs <- err
				close(p.msgs)
				return
			}
			// A refused message is still handed over: tests look at
			// answers we send to malformed requests, such as one echoing
			// an oddly sized transaction id.
			p.msgs <- m
		}
	}()
	t.Cleanup(func() { _ = nc.Close() })
	return p
}

// next returns the next message the peer received. The real-time limit only
// stops a broken test from hanging; no test relies on it.
func (p *wirePeer) next(t *testing.T) *Message {
	t.Helper()
	select {
	case m, ok := <-p.msgs:
		if !ok {
			t.Fatalf("connection ended: %v", <-p.errs)
		}
		return m
	case <-time.After(hangGuard):
		t.Fatal("no message arrived")
	}
	return nil
}

// closed waits for the connection to end from the other side.
func (p *wirePeer) closed(t *testing.T) {
	t.Helper()
	for {
		select {
		case _, ok := <-p.msgs:
			if !ok {
				return
			}
		case <-time.After(hangGuard):
			t.Fatal("connection stayed open")
		}
	}
}

func (p *wirePeer) send(t *testing.T, lines ...string) {
	t.Helper()
	if _, err := p.nc.Write([]byte(wire(lines...))); err != nil {
		t.Fatalf("peer write: %v", err)
	}
}

func (p *wirePeer) sendMessage(t *testing.T, m *Message) {
	t.Helper()
	b, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := p.nc.Write(b); err != nil {
		t.Fatalf("peer write: %v", err)
	}
}

// respond answers req with code the way an endpoint would.
func (p *wirePeer) respond(t *testing.T, req *Message, code int) {
	t.Helper()
	resp, err := NewResponse(req, code, StatusText(code))
	if err != nil {
		t.Fatal(err)
	}
	p.sendMessage(t, resp)
}

// syncPeer reads only when the test asks, so the writer on the other side
// stays blocked until then; tests use it to order events exactly.
type syncPeer struct {
	nc net.Conn
	r  *Reader
}

func newSyncPeer(t *testing.T, nc net.Conn) *syncPeer {
	t.Helper()
	t.Cleanup(func() { _ = nc.Close() })
	return &syncPeer{nc: nc, r: NewReader(nc, 0)}
}

func (p *syncPeer) next(t *testing.T) *Message {
	t.Helper()
	// The deadline only stops a broken test from hanging.
	_ = p.nc.SetReadDeadline(time.Now().Add(hangGuard))
	m, err := p.r.ReadMessage(DefaultMaxMessageSize)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	return m
}

func (p *syncPeer) respond(t *testing.T, req *Message, code int) {
	t.Helper()
	resp, err := NewResponse(req, code, StatusText(code))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := resp.Marshal()
	if _, err := p.nc.Write(b); err != nil {
		t.Fatalf("peer write: %v", err)
	}
}

// wire joins lines with CRLF and ends the last one too.
func wire(lines ...string) string {
	return strings.Join(lines, "\r\n") + "\r\n"
}

func mustURI(t testing.TB, s string) URI {
	t.Helper()
	u, err := ParseURI(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// recorder is a Handler that keeps what it is given.
type recorder struct {
	mu       sync.Mutex
	messages chan *Message
	reports  chan Report
	err      error
	code     int // returned by HandleRequest
	requests chan *Message
}

func newRecorder() *recorder {
	return &recorder{
		messages: make(chan *Message, 16),
		reports:  make(chan Report, 16),
		requests: make(chan *Message, 16),
	}
}

func (h *recorder) HandleMessage(_ *Session, m *Message) error {
	h.messages <- m
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *recorder) HandleReport(_ *Session, r Report) { h.reports <- r }

func (h *recorder) failWith(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.err = err
}

func (h *recorder) message(t *testing.T) *Message {
	t.Helper()
	select {
	case m := <-h.messages:
		return m
	case <-time.After(hangGuard):
		t.Fatal("no message delivered")
	}
	return nil
}

func (h *recorder) report(t *testing.T) Report {
	t.Helper()
	select {
	case r := <-h.reports:
		return r
	case <-time.After(hangGuard):
		t.Fatal("no report delivered")
	}
	return Report{}
}

// nicknameRecorder also serves extension methods.
type nicknameRecorder struct{ *recorder }

func (h nicknameRecorder) HandleRequest(_ *Session, m *Message) int {
	h.requests <- m
	return h.code
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(hangGuard):
		t.Fatalf("%s did not end", what)
	}
}

func bodyOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[i%36]
	}
	return b
}

func equalBodies(a, b []byte) bool { return bytes.Equal(a, b) }
