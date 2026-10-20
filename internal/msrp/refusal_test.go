package msrp

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// unknownSends are n pipelined SENDs, each for a session nobody bound.
func unknownSends(n int) []byte {
	var b strings.Builder
	for i := range n {
		tid := "unkn" + string(rune('a'+i))
		b.WriteString(wire("MSRP "+tid+" SEND", "To-Path: msrp://as.example.org:9000/guess"+tid+";tcp",
			"From-Path: "+clientURI, "Message-ID: "+tid, "-------"+tid+"$"))
	}
	return []byte(b.String())
}

// refusedOverTCP has a client over TCP name unknown sessions more often
// than MaxFailedBinds (2) allows, pipelining six requests, and read until
// the end of the stream. It returns the connection, which waits without
// bound for the client's end, and the client.
func refusedOverTCP(t *testing.T) (*Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	conns := make(chan *Conn, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		c, err := NewPassiveConn(nc, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2, refusalFlush: time.Hour})
		if err != nil {
			_ = nc.Close()
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		conns <- c
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	// All at once, before reading: the third ends the connection, and the
	// rest are still unread when it does.
	if _, err := client.Write(unknownSends(6)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hangGuard))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("after %q: %v, want the end of the stream", got, err)
	}
	for _, tid := range []string{"unkna", "unknb"} {
		if !strings.Contains(string(got), "MSRP "+tid+" 481") {
			t.Errorf("no 481 for %s in %q", tid, got)
		}
	}
	if strings.Contains(string(got), "unknc") {
		t.Errorf("the request over the limit was answered: %q", got)
	}
	return <-conns, client
}

// A client that names unknown sessions more often than MaxFailedBinds
// allows still reads the 481s it was owed before the connection ends,
// with an end of stream rather than a reset, though it sent more than
// was read (#219). The end of the stream is a half-close: the connection
// waits, still reading, for the client to close its side in turn.
func TestTheAnswersOwedAreDeliveredBeforeTooManyUnknownSessionsCloses(t *testing.T) {
	c, client := refusedOverTCP(t)
	select {
	case <-c.Done():
		t.Fatalf("closed before the client's end of the stream: %v", c.Err())
	case <-time.After(100 * time.Millisecond):
	}
	_ = client.(*net.TCPConn).CloseWrite()
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
}

// Whatever ends the connection while it delivers what it owed, it ends
// for the refusal, which is what its metrics count.
func TestAConnectionClosedWhileItDeliversItsAnswersEndsForTheRefusal(t *testing.T) {
	c, _ := refusedOverTCP(t)
	_ = c.Close()
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
}

// An answer the connection is still writing when the limit is reached is
// delivered too: the peer reads it only after the refusal.
func TestAnAnswerBeingWrittenAtTheLimitIsDelivered(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	// The first 481's write waits for a reader that comes only once the
	// second request, over the limit, has been read. The pauses let the
	// write start first, and the refusal start while it waits; a stall
	// can only make the test pass without proving it, not fail.
	sends := unknownSends(2)
	half := len(sends) / 2
	if _, err := theirs.Write(sends[:half]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := theirs.Write(sends[half:]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = theirs.SetReadDeadline(time.Now().Add(hangGuard))
	got, _ := io.ReadAll(theirs)
	if !strings.Contains(string(got), "MSRP unkna 481") {
		t.Fatalf("the answer being written was lost: %q", got)
	}
	waitDone(t, c.Done(), "connection")
}

// flushBound is the refusal flush's bound for a test: it ends when the
// test fires it, and counts how often it was started.
type flushBound struct {
	fire  chan time.Time
	calls atomic.Int32
}

func newFlushBound() *flushBound { return &flushBound{fire: make(chan time.Time)} }

func (b *flushBound) after(time.Duration) <-chan time.Time {
	b.calls.Add(1)
	return b.fire
}

// end fires the bound, which only a flush waiting on it takes.
func (b *flushBound) end(t *testing.T) {
	t.Helper()
	select {
	case b.fire <- time.Time{}:
	case <-time.After(hangGuard):
		t.Fatal("the flush is not waiting on its bound")
	}
}

// The default bound is the documented 2 s.
func TestTheRefusalFlushBoundDefaultsToTwoSeconds(t *testing.T) {
	cfg, err := Config{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.refusalFlush != 2*time.Second {
		t.Fatalf("refusalFlush = %v, documented 2 s", cfg.refusalFlush)
	}
}

// A peer that takes none of the answers does not hold the connection
// open: the flush's bound ends it, for the same reason. The write timeout
// is far longer, so only the bound can.
func TestAPeerThatDoesNotReadItsAnswersIsClosedAtTheFlushBound(t *testing.T) {
	bound := newFlushBound()
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2, WriteTimeout: time.Hour, refusalAfter: bound.after})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	go func() { _, _ = theirs.Write(unknownSends(3)) }()
	bound.end(t)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
}

// One bound, started once, ends the wait for the client's end too: a
// client over TCP that reads its answers to the end of the stream but
// never closes its side is cut when the bound fires (QA on #237).
func TestOneFlushBoundEndsTheWaitForTheClient(t *testing.T) {
	bound := newFlushBound()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	conns := make(chan *Conn, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		c, err := NewPassiveConn(nc, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2, refusalFlush: time.Hour, refusalAfter: bound.after})
		if err != nil {
			_ = nc.Close()
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		conns <- c
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Write(unknownSends(3)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hangGuard))
	// The end of the stream is the half-close: the wait for the client's
	// end has begun.
	got, err := io.ReadAll(client)
	if err != nil || !strings.Contains(string(got), "MSRP unknb 481") {
		t.Fatalf("read %q, %v", got, err)
	}
	c := <-conns
	bound.end(t)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
	if n := bound.calls.Load(); n != 1 {
		t.Fatalf("bound started %d times, want once for both waits", n)
	}
}

// slowWriteConn delays every Write; CloseWrite passes through to TCP.
type slowWriteConn struct {
	*net.TCPConn
	delay time.Duration
}

func (c slowWriteConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.TCPConn.Write(p)
}

// slowRefusal is refusedOverTCP's setup with a slow writer and a given
// bound (QA on #237).
func slowRefusal(t *testing.T, delay, flush time.Duration) (<-chan *Conn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	conns := make(chan *Conn, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			return
		}
		c, err := NewPassiveConn(slowWriteConn{nc.(*net.TCPConn), delay}, &Registry{},
			Config{Clock: newFakeClock(), MaxFailedBinds: 2, refusalFlush: flush})
		if err != nil {
			_ = nc.Close()
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		conns <- c
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return conns, client.(*net.TCPConn)
}

// Both 481s still queued at the limit reach the client before the
// half-close, not only the first.
func TestEveryAnswerQueuedAtTheLimitIsWrittenBeforeTheHalfClose(t *testing.T) {
	conns, client := slowRefusal(t, 300*time.Millisecond, time.Hour)
	if _, err := client.Write(unknownSends(6)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hangGuard))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("after %q: %v", got, err)
	}
	for _, tid := range []string{"unkna", "unknb"} {
		if !strings.Contains(string(got), "MSRP "+tid+" 481") {
			t.Errorf("no 481 for %s in %q", tid, got)
		}
	}
	_ = client.CloseWrite()
	waitDone(t, (<-conns).Done(), "connection")
}
