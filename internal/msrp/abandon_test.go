package msrp

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
)

// The tests here pin the three places where Send ends a message it gives
// up on between chunks with an empty "#" chunk (RFC 4975 §7.1), so that
// the receiver drops what it holds of it at once rather than at its own
// timeout (#168): the context is found ended before the next chunk, or it
// ends while that chunk waits for room for reports or for a window place.
// Each runs in a synctest bubble, so "Send is waiting there" is a state the
// test waits for (synctest.Wait), not a sleep. Message B is two chunks of
// 8 octets; its abort chunk must be the next thing on the wire, with the
// Byte-Range 9-8/16. A third message C follows, so that a missing abort
// shows at once as the wrong next message.

// abandonRig is a client connection over net.Pipe with a session opened
// on it.
type abandonRig struct {
	c *Conn
	p *syncPeer
	s *Session
}

func newAbandonRig(t *testing.T, cfg Config, h Handler) *abandonRig {
	t.Helper()
	ours, theirs := net.Pipe()
	cfg.ChunkSize = 8
	c, err := NewActiveConn(ours, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	r := &abandonRig{c: c, p: newSyncPeer(t, theirs), s: newTestSession(t, clientURI, asURI, h)}
	opened := make(chan error, 1)
	go func() { opened <- c.Open(context.Background(), r.s) }()
	r.p.respond(t, r.p.next(t), StatusOK)
	if err := <-opened; err != nil {
		t.Fatal(err)
	}
	return r
}

// sendB starts Send of B on ctx and returns its result.
func (r *abandonRig) sendB(ctx context.Context) <-chan error {
	b := make(chan error, 1)
	go func() {
		_, err := r.s.Send(ctx, Outgoing{ContentType: "text/plain", Body: []byte("bbbbbbbbBBBBBBBB")})
		b <- err
	}()
	return b
}

// cancelled checks that Send of B ended with its context's error.
func cancelled(t *testing.T, b <-chan error) {
	t.Helper()
	if err := <-b; !errors.Is(err, context.Canceled) {
		t.Fatalf("B = %v, want context.Canceled", err)
	}
}

// abortBeforeC sends C and requires the peer to read B's abort chunk
// first.
func (r *abandonRig) abortBeforeC(t *testing.T, b1 *Message) {
	t.Helper()
	go func() {
		_, _ = r.s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("cccc")})
	}()
	m := r.p.next(t)
	if m.Continuation != FlagAbort || m.MessageID != b1.MessageID || m.Range() != (ByteRange{Start: 9, End: 8, Total: 16}) || len(m.Body) != 0 {
		t.Fatalf("after B the peer read %q flag %q range %+v (id %s, B's %s); want B's abort chunk 9-8/16",
			m.Body, m.Continuation, m.ByteRange, m.MessageID, b1.MessageID)
	}
}

func (r *abandonRig) firstChunk(t *testing.T) *Message {
	t.Helper()
	b1 := r.p.next(t)
	if string(b1.Body) != "bbbbbbbb" {
		t.Fatalf("first chunk %q", b1.Body)
	}
	return b1
}

// The context is found ended before the second chunk (session.go, the
// check at the top of Send's loop). The test holds the session's lock
// while the first chunk is written: Send takes it (touch) after that write
// and before it looks at the context again, so the cancel made meanwhile
// is the one it finds there.
func TestASendCancelledBetweenChunksIsAborted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newAbandonRig(t, Config{WriteTimeout: DefaultWriteTimeout}, newRecorder())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := r.sendB(ctx)
		synctest.Wait() // B's first chunk is being written, its locks taken and left
		r.s.mu.Lock()
		b1 := r.firstChunk(t)
		cancel()
		r.s.mu.Unlock()
		cancelled(t, b)
		r.p.respond(t, b1, StatusOK)
		r.abortBeforeC(t, b1)
	})
}

// The context ends while the second chunk waits for a window place
// (SendWindow 1, the first chunk not yet answered).
func TestASendCancelledWhileWaitingForAWindowPlaceIsAborted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newAbandonRig(t, Config{WriteTimeout: DefaultWriteTimeout, SendWindow: 1}, newRecorder())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := r.sendB(ctx)
		b1 := r.firstChunk(t)
		synctest.Wait() // B's second chunk waits for the window place b1 holds
		cancel()
		cancelled(t, b)
		r.p.respond(t, b1, StatusOK) // frees the window place for C
		r.abortBeforeC(t, b1)
	})
}

// heldReports blocks HandleReport until gate is closed.
type heldReports struct {
	*recorder
	gate chan struct{}
}

func (h heldReports) HandleReport(*Session, Report) { <-h.gate }

// The context ends while the second chunk waits for room for reports:
// with SendWindow 1, one refusal of an earlier message is still to be
// handed to a handler busy with another.
func TestASendCancelledWhileWaitingForRoomForReportsIsAborted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := heldReports{newRecorder(), make(chan struct{})}
		r := newAbandonRig(t, Config{WriteTimeout: DefaultWriteTimeout, SendWindow: 1}, h)
		// Two one-chunk messages with Failure-Report partial, which take
		// no window place, are on the wire and not yet answered.
		var as []*Message
		for _, body := range []string{"a1", "a2"} {
			sent := make(chan error, 1)
			go func() {
				_, err := r.s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte(body), FailureReport: ReportPartial})
				sent <- err
			}()
			as = append(as, r.p.next(t))
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		b := r.sendB(ctx)
		synctest.Wait() // B's first chunk is being written, past the room check
		// Both are refused: the handler takes the first and holds it, the
		// second waits for it.
		for _, a := range as {
			r.p.respond(t, a, StatusMessageTooLarge)
		}
		synctest.Wait()
		if n := r.s.undeliveredReports(); n != 1 {
			t.Fatalf("%d reports waiting for the handler, want 1", n)
		}
		b1 := r.firstChunk(t)
		synctest.Wait() // B's second chunk waits for room for reports
		cancel()
		cancelled(t, b)
		close(h.gate) // the handler takes the reports, which makes room for C
		r.p.respond(t, b1, StatusOK)
		r.abortBeforeC(t, b1)
	})
}
