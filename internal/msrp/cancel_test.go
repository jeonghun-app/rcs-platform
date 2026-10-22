package msrp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A Send whose frame is still queued, behind a write the peer is not
// reading, ends with its context's error when the context ends, and its
// frame is taken out of the queue rather than written later (#141). The
// test waits on progress, the first frame's bytes, not on a timer.
func TestASendCancelledWhileQueuedEndsWithItsContextsError(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{WriteTimeout: DefaultWriteTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p := newSyncPeer(t, theirs)
	s := newTestSession(t, clientURI, asURI, newRecorder())
	opened := make(chan error, 1)
	go func() { opened <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusOK)
	if err := <-opened; err != nil {
		t.Fatal(err)
	}

	// The first message, one chunk, is being written: the peer has read
	// one octet of it, and net.Pipe holds the writer until it reads the
	// rest.
	first := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf(bytes.Repeat([]byte("a"), 1000))})
		first <- err
	}()
	_ = theirs.SetReadDeadline(time.Now().Add(hangGuard))
	octet := make([]byte, 1)
	if _, err := io.ReadFull(theirs, octet); err != nil {
		t.Fatal(err)
	}

	// The second waits in the queue behind it until its context ends.
	ctx, cancel := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() {
		_, err := s.Send(ctx, Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("cancelled"))})
		second <- err
	}()
	waitQueued(t, c, 1, "the second message")
	cancel()
	err = <-second
	if !errors.Is(err, context.Canceled) || errors.As(err, &startedError{}) {
		t.Fatalf("queued Send = %v (%T), want context.Canceled from the queue", err, err)
	}

	// The first message completes; the next thing on the wire is a third
	// message, not the cancelled one.
	p.r = NewReader(io.MultiReader(bytes.NewReader(octet), theirs), 0)
	p.respond(t, p.next(t), StatusOK)
	if err := <-first; err != nil {
		t.Fatalf("first Send = %v", err)
	}
	third := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("third"))})
		third <- err
	}()
	m := p.next(t)
	if string(m.Body.Bytes()) != "third" {
		t.Fatalf("after the first message the peer read %q, want the third", m.Body)
	}
	p.respond(t, m, StatusOK)
	if err := <-third; err != nil {
		t.Fatalf("third Send = %v", err)
	}
}

// waitQueued waits until n frames wait in c's write queue.
func waitQueued(t *testing.T, c *Conn, n int, what string) {
	t.Helper()
	deadline := time.Now().Add(hangGuard)
	for {
		c.qmu.Lock()
		queued := len(c.queue)
		c.qmu.Unlock()
		if queued == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d frames queued, want %d", what, queued, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// A message whose later chunk is cancelled while still queued is ended with
// an abort chunk, "#", at that chunk's start (RFC 4975 §7.1), so the
// receiver does not hold the first chunk until its own timeout (#162, from
// QA on #152).
func TestALaterChunkCancelledWhileQueuedIsAborted(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{WriteTimeout: DefaultWriteTimeout, ChunkSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p := newSyncPeer(t, theirs)
	s := newTestSession(t, clientURI, asURI, newRecorder())
	opened := make(chan error, 1)
	go func() { opened <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusOK)
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
	_ = theirs.SetReadDeadline(time.Now().Add(hangGuard))
	octet := make([]byte, 1)

	// B is two chunks of 8. Its first chunk is held mid-write: the peer has
	// read one octet, and net.Pipe holds the writer until it reads on.
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	b := make(chan error, 1)
	go func() {
		_, err := s.Send(ctxB, Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("bbbbbbbbBBBBBBBB"))})
		b <- err
	}()
	if _, err := io.ReadFull(theirs, octet); err != nil {
		t.Fatal(err)
	}
	// A, one chunk, queues behind B's first chunk.
	a := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("aaaa"))})
		a <- err
	}()
	waitQueued(t, c, 1, "A")
	// B's first chunk finishes, the writer takes A, and B's second chunk
	// queues behind A. Then B is cancelled.
	p.r = NewReader(io.MultiReader(bytes.NewReader(octet), theirs), 0)
	b1 := p.next(t)
	if string(b1.Body.Bytes()) != "bbbbbbbb" {
		t.Fatalf("first chunk %q", b1.Body)
	}
	if _, err := io.ReadFull(theirs, octet); err != nil { // A is being written
		t.Fatal(err)
	}
	waitQueued(t, c, 1, "B's second chunk")
	cancelB()
	if err := <-b; !errors.Is(err, context.Canceled) || errors.As(err, &startedError{}) {
		t.Fatalf("B = %v, want context.Canceled from the queue", err)
	}
	p.r = NewReader(io.MultiReader(bytes.NewReader(octet), theirs), 0)
	am := p.next(t)
	if string(am.Body.Bytes()) != "aaaa" {
		t.Fatalf("after B's first chunk the peer read %q, want A", am.Body)
	}
	p.respond(t, am, StatusOK)
	p.respond(t, b1, StatusOK)
	if err := <-a; err != nil {
		t.Fatal(err)
	}
	// A third message, so a missing abort shows at once as the wrong next
	// message.
	go func() {
		_, _ = s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("cccc"))})
	}()
	m := p.next(t)
	if m.Continuation != FlagAbort || m.MessageID != b1.MessageID || m.Range() != (ByteRange{Start: 9, End: 8, Total: 16}) || m.Body.Len() != 0 {
		t.Fatalf("after A the peer read %q flag %q range %+v (id %s, B's %s); want B's abort chunk 9-8/16",
			m.Body, m.Continuation, m.ByteRange, m.MessageID, b1.MessageID)
	}
}
