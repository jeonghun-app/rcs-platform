package msrp

import (
	"context"
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

// A peer that takes none of the answers does not hold the connection
// open: it ends within refusalFlushTimeout of the limit, the documented
// 2 s, for the same reason. The write timeout is far longer, so only the
// flush's bound can end it.
func TestAPeerThatDoesNotReadItsAnswersIsClosedAfterTheFlushBound(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2, WriteTimeout: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	go func() { _, _ = theirs.Write(unknownSends(3)) }()
	start := time.Now()
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
	took := time.Since(start)
	if refusalFlushTimeout != 2*time.Second {
		t.Fatalf("refusalFlushTimeout is %v, documented as 2 s", refusalFlushTimeout)
	}
	if took < refusalFlushTimeout/2 || took > refusalFlushTimeout+time.Second {
		t.Fatalf("closed after %v, want the %v bound", took, refusalFlushTimeout)
	}
}

// Over TCP, a client that reads its answers to the end of the stream but
// never closes its side is cut at the default bound, with the refusal.
func TestAClientThatNeverClosesIsCutAtTheDefaultBound(t *testing.T) {
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
		c, err := NewPassiveConn(nc, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2})
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
	start := time.Now()
	if _, err := client.Write(unknownSends(3)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, client) }()
	c := <-conns
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
	if took := time.Since(start); took > refusalFlushTimeout+time.Second {
		t.Fatalf("closed after %v, want the %v bound", took, refusalFlushTimeout)
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

// One bound covers the wait for the writes and the wait for the client's
// end together: a client that reads everything but never closes is cut
// at it, not at twice it.
func TestOneFlushBoundCoversBothWaitsOverTCP(t *testing.T) {
	conns, client := slowRefusal(t, 400*time.Millisecond, time.Second)
	start := time.Now()
	if _, err := client.Write(unknownSends(3)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.Copy(io.Discard, client) }()
	waitDone(t, (<-conns).Done(), "connection")
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("took %v, bound 1 s for both waits", took)
	}
}

// QA on #237 (#240): a client under the unknown-session limit sends two
// SENDs and half-closes. The two 481s already queued still reach it, and
// the connection's end is the peer's close, EOF, as before.
func TestAnswersQueuedWhenThePeerHalfClosesAreDelivered(t *testing.T) {
	conns, client := slowRefusal(t, 0, time.Hour)
	if _, err := client.Write(unknownSends(2)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(hangGuard))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("after %q: %v", got, err)
	}
	for _, want := range []string{"MSRP unkna 481", "MSRP unknb 481"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("got %q, want %q in it", got, want)
		}
	}
	c := <-conns
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), io.EOF) {
		t.Fatalf("connection ended with %v, want the peer's EOF", c.Err())
	}
}

// The wait for what is owed after a half-close has the refusal flush's
// bound: a peer that half-closes and then reads nothing, behind a write
// that takes 2 s, holds the connection for the bound, not for the write.
func TestTheHalfCloseFlushIsBounded(t *testing.T) {
	conns, client := slowRefusal(t, 2*time.Second, 300*time.Millisecond)
	if _, err := client.Write(unknownSends(1)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c := <-conns
	start := time.Now()
	waitDone(t, c.Done(), "connection")
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("closed after %v, bound 300 ms", took)
	}
	if !errors.Is(c.Err(), io.EOF) {
		t.Fatalf("connection ended with %v, want the peer's EOF", c.Err())
	}
}

// QA on #243: with no bound set, the half-close's wait is
// refusalFlushTimeout, 2 s, behind a write that takes 5 s.
func TestTheHalfCloseFlushHasTheDefaultBound(t *testing.T) {
	conns, client := slowRefusal(t, 5*time.Second, 0)
	if _, err := client.Write(unknownSends(1)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c := <-conns
	start := time.Now()
	waitDone(t, c.Done(), "connection")
	took := time.Since(start)
	if refusalFlushTimeout != 2*time.Second {
		t.Fatalf("refusalFlushTimeout is %v, documented as 2 s", refusalFlushTimeout)
	}
	if took < refusalFlushTimeout/2 || took > refusalFlushTimeout+time.Second {
		t.Fatalf("closed after %v, want the %v bound", took, refusalFlushTimeout)
	}
	if !errors.Is(c.Err(), io.EOF) {
		t.Fatalf("connection ended with %v, want the peer's EOF", c.Err())
	}
}

// QA on #243 (team lead's decision): a peer that half-closes inside a
// request still gets the answers to the requests it completed before it,
// and the connection ends with the framing error, as before.
func TestAnswersQueuedBeforeAHalfCloseInsideARequestAreDelivered(t *testing.T) {
	for name, tail := range map[string]string{
		"inside a line":   "MSRP q99999 SEND\r\nTo-Pa",
		"inside the body": "MSRP q99999 SEND\r\nTo-Path: msrp://as.example.org:9000/guessq;tcp\r\nFrom-Path: " + clientURI + "\r\nMessage-ID: q\r\nByte-Range: 1-*/*\r\nContent-Type: text/plain\r\n\r\nhal",
	} {
		t.Run(name, func(t *testing.T) {
			conns, client := slowRefusal(t, 150*time.Millisecond, time.Hour)
			if _, err := client.Write(append(unknownSends(2), tail...)); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_ = client.SetReadDeadline(time.Now().Add(hangGuard))
			got, _ := io.ReadAll(client)
			for _, want := range []string{"MSRP unkna 481", "MSRP unknb 481"} {
				if !strings.Contains(string(got), want) {
					t.Fatalf("got %q, want %q in it", got, want)
				}
			}
			c := <-conns
			waitDone(t, c.Done(), "connection")
			if !errors.Is(c.Err(), ErrFraming) {
				t.Fatalf("connection ended with %v, want the framing error", c.Err())
			}
		})
	}
}

// Code review on #243: a client that sends two unknown SENDs and closes
// altogether, reading nothing, resets the 481s' writes; the connection
// still ends with the client's close, EOF, not with the write's error.
func TestAPeerThatClosesAltogetherEndsTheConnectionWithEOF(t *testing.T) {
	// The writes wait, so the end of the stream is read before any of
	// them meets the reset.
	conns, client := slowRefusal(t, 100*time.Millisecond, time.Hour)
	if _, err := client.Write(unknownSends(2)); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	c := <-conns
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), io.EOF) {
		t.Fatalf("connection ended with %v, want the peer's EOF", c.Err())
	}
}

// firstFastConn writes its first write at once and the others after
// delay, so a binding goes out and what follows is slow.
type firstFastConn struct {
	net.Conn
	delay  time.Duration
	writes atomic.Int64
}

func (c *firstFastConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) > 1 {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(p)
}

// Code review on #243: an active connection whose peer half-closes ends at
// once, with what it still has to write: waiting would leave it open to a
// Pool, which would put a new session on it. Here the peer, rcs-as in the
// relay's place, half-closes with a 481 owed to it that takes 1 s to
// write; the next Pool.Open must dial anew and succeed.
func TestAPooledConnectionWhosePeerHalfClosesIsNotReused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan *wirePeer, 2)
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- newWirePeer(t, nc)
		}
	}()
	pool := &Pool{Config: Config{Clock: newFakeClock(), KeepAliveInterval: -1}, Dial: func(ctx context.Context, _ URI) (net.Conn, error) {
		var d net.Dialer
		nc, err := d.DialContext(ctx, "tcp", l.Addr().String())
		if err != nil {
			return nil, err
		}
		return &firstFastConn{Conn: nc, delay: time.Second}, nil
	}}
	open := func(local string) (*Session, chan error) {
		s := newTestSession(t, local, asURI, newRecorder())
		done := make(chan error, 1)
		go func() { done <- pool.Open(context.Background(), s) }()
		return s, done
	}
	first, opened := open(clientURI)
	p := <-accepted
	p.respond(t, p.next(t), StatusOK)
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
	// A request the client must refuse, then the peer half-closes.
	p.sendMessage(t, &Message{TransactionID: "n0sess10n", Method: MethodSend,
		ToPath: []URI{mustURI(t, "msrp://client.example.com:2855/n0such;tcp")}, FromPath: []URI{mustURI(t, asURI)}, MessageID: "n0sess10n"})
	if err := p.nc.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the half-closed active connection is still up")
	}
	_, opened = open("msrp://client.example.com:2855/an0th3r;tcp")
	select {
	case p2 := <-accepted:
		p2.respond(t, p2.next(t), StatusOK)
	case <-time.After(hangGuard):
		t.Fatal("the Pool did not dial a new connection")
	}
	if err := <-opened; err != nil {
		t.Fatalf("Open on a new connection = %v", err)
	}
}
