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
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: bytes.Repeat([]byte("a"), 1000)})
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
		_, err := s.Send(ctx, Outgoing{ContentType: "text/plain", Body: []byte("cancelled")})
		second <- err
	}()
	deadline := time.Now().Add(hangGuard)
	for queued := 0; queued == 0; {
		c.qmu.Lock()
		queued = len(c.queue)
		c.qmu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the second message was never queued")
		}
		time.Sleep(time.Millisecond)
	}
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
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("third")})
		third <- err
	}()
	m := p.next(t)
	if string(m.Body) != "third" {
		t.Fatalf("after the first message the peer read %q, want the third", m.Body)
	}
	p.respond(t, m, StatusOK)
	if err := <-third; err != nil {
		t.Fatalf("third Send = %v", err)
	}
}
