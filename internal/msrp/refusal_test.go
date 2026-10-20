package msrp

import (
	"errors"
	"io"
	"net"
	"strings"
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
// open: it ends refusalFlushTimeout after the limit, for the same reason.
func TestAPeerThatDoesNotReadItsAnswersIsClosedAfterTheFlushBound(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2})
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
	// It waited for the answers, at most the bound: a write it gave up on
	// would show as the write timeout (30 s), not as the refusal.
	if took := time.Since(start); took < refusalFlushTimeout/2 {
		t.Fatalf("closed after %v, before the answers had their chance", took)
	}
}
