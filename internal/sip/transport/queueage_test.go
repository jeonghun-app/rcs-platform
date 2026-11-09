package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The rule of #623 on a fake clock: a chunk write ends WriteTimeout from now,
// or, on a core connection, when its message has waited MaxQueueAge, whichever
// is first. The writer always writes the oldest message it holds, so this
// bounds the age of the oldest output in the queue.
func TestAChunkWriteEndsAtWriteTimeoutOrWhenItsMessageHasWaitedMaxQueueAge(t *testing.T) {
	const write, age = 10 * time.Second, 32 * time.Second
	queued := time.Unix(1000, 0)
	for _, c := range []struct {
		name   string
		waited time.Duration
		client bool
		want   time.Duration // after queued
		byAge  bool
	}{
		{"a fresh message gets WriteTimeout", 0, false, write, false},
		{"one that waited less than MaxQueueAge-WriteTimeout still gets WriteTimeout", 21 * time.Second, false, 31 * time.Second, false},
		{"one that waited longer gets what is left of MaxQueueAge", 25 * time.Second, false, age, true},
		{"one past MaxQueueAge ends at once", 40 * time.Second, false, age, true},
		{"a client-facing connection gets WriteTimeout however long the message waited", 40 * time.Second, true, 50 * time.Second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			deadline, byAge := chunkDeadline(queued.Add(c.waited), queued, write, age, c.client)
			if !deadline.Equal(queued.Add(c.want)) || byAge != c.byAge {
				t.Errorf("deadline %v after queueing (by age %t), want %v (by age %t)", deadline.Sub(queued), byAge, c.want, c.byAge)
			}
		})
	}
}

// stallPeer is a TCP listener standing in for a core peer. Each connection it
// accepts is handed to the test, which decides how it reads.
type stallPeer struct {
	ln    net.Listener
	conns chan net.Conn
}

func newStallPeer(t *testing.T) *stallPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &stallPeer{ln: ln, conns: make(chan net.Conn, 4)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			p.conns <- c
		}
	}()
	return p
}

func (p *stallPeer) dst() Destination {
	return Destination{Network: TCP, Addr: netip.MustParseAddrPort(p.ln.Addr().String())}
}

func (p *stallPeer) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-p.conns:
		return c
	case <-time.After(waitFor):
		t.Fatal("the transport did not connect")
		return nil
	}
}

// lockedBuffer collects log output written from the transport's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// stallBound is how long a test waits for the queue-age rule to act. It is a
// failure deadline only: the rule acts after MaxQueueAge, and the test goes
// on as soon as it has.
const stallBound = 30 * time.Second

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(stallBound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A core peer that takes nothing more: once the oldest message in the queue
// has waited MaxQueueAge the connection is reset, not closed, since a FIN
// would wait behind the output the kernel still holds. It counts as a stall,
// in Stats and in the metric at once, with one log line that names no peer,
// and the next send dials anew (#623). WriteTimeout is an hour, so only the
// queue-age rule can end the connection.
func TestACoreConnectionWhoseOldestOutputWaitsLongerThanMaxQueueAgeIsReset(t *testing.T) {
	peer := newStallPeer(t)
	counts := &panicCounts{}
	var logs lockedBuffer
	tr, _ := newTransport(t, Config{
		WriteTimeout: time.Hour, MaxQueueAge: time.Second, Metrics: counts,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	body := []byte(strings.Repeat("x", 32<<10))
	// 3 MiB: more than the kernel's buffers on both ends hold, less than
	// the queue's limit, so no send waits for room.
	for i := range 96 {
		req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKage%d", i))
		req.Body = body
		if _, err := tr.SendRequest(req, peer.dst()); err != nil {
			t.Fatal(err)
		}
	}
	stalled := peer.next(t) // never read until the reset
	waitUntil(t, "the stall reset", func() bool { return tr.Stats().WriteStalls == 1 })

	stalled.SetReadDeadline(time.Now().Add(stallBound))
	if _, err := io.Copy(io.Discard, stalled); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the peer read to %v, want a reset", err)
	}
	s := tr.Stats()
	if s.WriteErrors != 0 || s.OpenOutbound != 0 || s.QueuedBytes != 0 {
		t.Errorf("WriteErrors %d, OpenOutbound %d, QueuedBytes %d after the reset, want 0, 0, 0", s.WriteErrors, s.OpenOutbound, s.QueuedBytes)
	}
	if n := counts.get(MetricWriteStalls); n != 1 {
		t.Errorf("%s counted %d, want 1", MetricWriteStalls, n)
	}
	out := logs.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "MaxQueueAge") {
		t.Errorf("log %q, want one line about the reset", out)
	}
	if host := peer.dst().Addr.Addr().String(); strings.Contains(out, host) {
		t.Errorf("log %q names the peer", out)
	}

	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP p.invalid;branch=z9hG4bKagenext")
	if _, err := tr.SendRequest(req, peer.dst()); err != nil {
		t.Fatalf("the next send failed: %v", err)
	}
	fresh := peer.next(t)
	fresh.SetReadDeadline(time.Now().Add(waitFor))
	if m, ok := readMessage(t, bufio.NewReader(fresh)).(*sip.Request); !ok || m.Method != "OPTIONS" {
		t.Fatal("the next send did not arrive on the new connection")
	}
	if s := tr.Stats(); s.Dialed != 2 {
		t.Errorf("Dialed %d, want 2", s.Dialed)
	}
}

// Client-facing connections keep the rules they had: a client that stops
// reading is cut by WriteTimeout, as a write error, never by the queue-age
// rule, which is for core links only (#623).
func TestAClientFacingConnectionIsNotResetForTheAgeOfItsQueue(t *testing.T) {
	tr, rec := newTransport(t, Config{WriteTimeout: 2 * time.Second, MaxQueueAge: 100 * time.Millisecond})
	addr := listen(t, tr, ListenerConfig{Network: TCP, ClientFacing: true})
	c := dialRaw(t, addr) // never read
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	body := []byte(strings.Repeat("x", 32<<10))
	var err error
	for i := 0; i < 1000 && !errors.Is(err, ErrNoFlow); i++ {
		req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKcl%d", i))
		req.Body = body
		_, err = tr.SendRequest(req, Destination{Flow: id})
	}
	if !errors.Is(err, ErrNoFlow) {
		t.Fatalf("the client's connection stayed open: %v", err)
	}
	waitUntil(t, "the write error", func() bool { return tr.Stats().WriteErrors == 1 })
	if n := tr.Stats().WriteStalls; n != 0 {
		t.Errorf("WriteStalls %d, want 0: a client-facing connection was reset for its queue's age", n)
	}
}

// QA's slow core peer, reading 320 KiB/s while a burst larger than the queue
// arrives (#623 AC 2), keeps its connection at the default MaxQueueAge: each
// message waits about 4 MiB / 320 KiB/s, 13 s, well inside 32 s. The reader
// keeps to its rate on average, catching up after a pause, so a loaded host
// that delays it does not make the messages wait longer.
func TestACorePeerReading320KiBPerSecondKeepsItsConnectionAtTheDefaultMaxQueueAge(t *testing.T) {
	peer := newStallPeer(t)
	tr, _ := newTransport(t, Config{})
	const rate = 320 << 10 // bytes a second
	var read atomic.Int64
	go func() {
		c := <-peer.conns
		buf := make([]byte, 16<<10)
		start := time.Now()
		for {
			allowed := int64(time.Since(start).Seconds()*rate) - read.Load()
			if allowed <= 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			n, err := c.Read(buf[:min(int64(len(buf)), allowed)])
			read.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	body := []byte(strings.Repeat("x", 32<<10))
	var sent, failed atomic.Int64
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 17 { // 8*17*32 KiB, 4.25 MiB: a little more than the queue holds
				req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKr%d-%d", g, i))
				req.Body = body
				if _, err := tr.SendRequest(req, peer.dst()); err != nil {
					failed.Add(1)
				} else {
					sent.Add(1)
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	peak := 0
	waitUntil(t, "the burst to drain", func() bool {
		peak = max(peak, tr.Stats().QueuedBytes)
		select {
		case <-done:
			return tr.Stats().QueuedBytes == 0
		default:
			return false
		}
	})
	// Without a full queue no message waited long, and the test would pass
	// without the rule being near.
	if peak < 3<<20 {
		t.Fatalf("the queue held at most %d bytes, want 3 MiB or more for messages to wait over 9 s", peak)
	}
	s := tr.Stats()
	if s.WriteStalls != 0 || s.WriteErrors != 0 || s.Dialed != 1 || s.OpenOutbound != 1 {
		t.Errorf("sent %d, failed %d; WriteStalls %d, WriteErrors %d, Dialed %d, OpenOutbound %d: the connection to a peer reading 320 KiB/s was ended",
			sent.Load(), failed.Load(), s.WriteStalls, s.WriteErrors, s.Dialed, s.OpenOutbound)
	}
}
