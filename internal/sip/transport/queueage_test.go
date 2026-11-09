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

// The floor the documentation gives for the queue-age rule (Config.MaxQueueAge,
// docs/architecture.md §7) is computed from these defaults: a full 4 MiB queue
// drained within 32 s is about 128 KiB/s. A change to either changes the
// floor; update both places. An unset MaxQueueAge takes the default.
func TestTheQueueAgeFloorIsSetByTheDefaultQueueAndAge(t *testing.T) {
	if DefaultMaxQueueAge != 32*time.Second || DefaultSendQueueBytes != 4<<20 {
		t.Fatalf("DefaultMaxQueueAge %v and DefaultSendQueueBytes %d, but the documented floor of about 128 KiB/s assumes 32 s and 4 MiB: update the documentation", DefaultMaxQueueAge, DefaultSendQueueBytes)
	}
	if got := (Config{}).withDefaults().MaxQueueAge; got != DefaultMaxQueueAge {
		t.Fatalf("an unset MaxQueueAge is %v, want %v", got, DefaultMaxQueueAge)
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

// stallBound is how long a test waits for the queue-age rule to act, or for
// a paced burst to drain, the longest in about 45 s. It is a failure deadline
// only: the test goes on as soon as what it waits for has happened.
const stallBound = 2 * time.Minute

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
// in Stats and in the metric at once, with one log line that says it was
// dialed and for which service but gives no address, and the next send dials
// anew (#623). WriteTimeout is an hour, so only the
// queue-age rule can end the connection.
func TestACoreConnectionWhoseOldestOutputWaitsLongerThanMaxQueueAgeIsReset(t *testing.T) {
	peer := newStallPeer(t)
	counts := &panicCounts{}
	var logs lockedBuffer
	tr, _ := newTransport(t, Config{
		WriteTimeout: time.Hour, MaxQueueAge: time.Second, Metrics: counts,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	dst := peer.dst()
	dst.PeerName = "scscf.rcs.internal"
	queueThreeMiB(t, tr, dst)
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
	checkResetLog(t, logs.String(), stalled, `"dialed":true`, `"peer":"scscf.rcs.internal"`, `"max_queue_age":"1s"`)

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

// queueThreeMiB queues 3 MiB for dst: more than the kernel's buffers on both
// ends hold, less than the queue's limit, so no send waits for room.
func queueThreeMiB(t *testing.T, tr *Transport, dst Destination) {
	t.Helper()
	body := []byte(strings.Repeat("x", 32<<10))
	for i := range 96 {
		req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKage%d", i))
		req.Body = body
		if _, err := tr.SendRequest(req, dst); err != nil {
			t.Fatal(err)
		}
	}
}

// checkResetLog checks that out is the reset's one warning, in JSON as the
// services log, with want in it and no address or port of conn, the peer's
// end of the connection.
func checkResetLog(t *testing.T, out string, conn net.Conn, want ...string) {
	t.Helper()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "MaxQueueAge") {
		t.Errorf("log %q, want one line about the reset", out)
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("log %q lacks %s", out, w)
		}
	}
	for _, a := range []net.Addr{conn.LocalAddr(), conn.RemoteAddr()} {
		ap := netip.MustParseAddrPort(a.String())
		if strings.Contains(out, ap.Addr().String()) || strings.Contains(out, fmt.Sprint(ap.Port())) {
			t.Errorf("log %q shows %s", out, ap)
		}
	}
}

// A connection accepted on a core listener is reset by the same rule, and its
// warning names the listener (#623).
func TestAnAcceptedCoreConnectionWhoseOldestOutputWaitsTooLongIsReset(t *testing.T) {
	var logs lockedBuffer
	tr, rec := newTransport(t, Config{WriteTimeout: time.Hour, MaxQueueAge: time.Second, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	c := dialRaw(t, listen(t, tr, ListenerConfig{Name: "core", Network: TCP})) // never read until the reset
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP scscf.example.com;branch=z9hG4bK1")))
	queueThreeMiB(t, tr, Destination{Flow: rec.next(t).Source.Flow})
	waitUntil(t, "the stall reset", func() bool { return tr.Stats().WriteStalls == 1 })
	c.SetReadDeadline(time.Now().Add(stallBound))
	if _, err := io.Copy(io.Discard, c); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the peer read to %v, want a reset", err)
	}
	if s := tr.Stats(); s.WriteErrors != 0 || s.OpenInbound != 0 {
		t.Errorf("WriteErrors %d, OpenInbound %d after the reset, want 0, 0", s.WriteErrors, s.OpenInbound)
	}
	checkResetLog(t, logs.String(), c, `"listener":"core"`)
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

// pacedBurst sends 8*perSender 32 KiB MESSAGEs from 8 goroutines to a peer
// that reads every connection at rate bytes a second. The reader keeps to its
// rate on average, catching up after a pause, so a loaded host that delays it
// does not make the messages wait longer. pacedBurst watches until stop
// holds, then closes the transport, and returns the most the queue held. The
// tests run in parallel, since each takes as long as its burst.
func pacedBurst(t *testing.T, cfg Config, rate float64, perSender int, stop func(*Transport, bool) bool) (tr *Transport, peak int) {
	t.Helper()
	t.Parallel()
	peer := newStallPeer(t)
	tr, _ = newTransport(t, cfg)
	quit := make(chan struct{})
	t.Cleanup(func() { close(quit) })
	go func() {
		for {
			var c net.Conn
			select {
			case c = <-peer.conns:
			case <-quit:
				return
			}
			go func() {
				var read int64
				buf := make([]byte, 16<<10)
				start := time.Now()
				for {
					allowed := int64(time.Since(start).Seconds()*rate) - read
					if allowed <= 0 {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					n, err := c.Read(buf[:min(int64(len(buf)), allowed)])
					read += int64(n)
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	body := []byte(strings.Repeat("x", 32<<10))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perSender {
				req := newRequest(t, "MESSAGE", fmt.Sprintf("SIP/2.0/TCP p.invalid;branch=z9hG4bKr%d-%d", g, i))
				req.Body = body
				_, _ = tr.SendRequest(req, peer.dst())
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	waitUntil(t, "the burst", func() bool {
		peak = max(peak, tr.Stats().QueuedBytes)
		select {
		case <-done:
			return stop(tr, true)
		default:
			return stop(tr, false)
		}
	})
	tr.Close()
	<-done
	return tr, peak
}

// A peer that drains each message within the default MaxQueueAge keeps its
// connection (#623 AC 2). QA's slow core peer reads 320 KiB/s while 4.25 MiB,
// a little more than a queue holds, arrives: its messages wait about 13 s.
// One reading 200 KiB/s, above the documented floor of about 128 KiB/s, gets
// 8.5 MiB, twice a queue: each message waits about 21 s, but the writer takes
// a queue's worth at a time and spends about 40 s on two of them, so a rule
// that dated a batch by its first message would cut it (code review of #725).
func TestACorePeerThatDrainsEachMessageWithinTheDefaultMaxQueueAgeKeepsItsConnection(t *testing.T) {
	for _, c := range []struct {
		name      string
		rate      float64
		perSender int
	}{{"320 KiB/s, 4.25 MiB", 320 << 10, 17}, {"200 KiB/s, 8.5 MiB", 200 << 10, 34}} {
		t.Run(c.name, func(t *testing.T) {
			var s Stats
			_, peak := pacedBurst(t, Config{}, c.rate, c.perSender, func(tr *Transport, sent bool) bool {
				s = tr.Stats()
				return s.WriteStalls+s.WriteErrors > 0 || sent && s.QueuedBytes == 0
			})
			// Without a full queue no message waited long, and the test would
			// pass without the rule being near.
			if peak < 3<<20 {
				t.Fatalf("the queue held at most %d bytes, want 3 MiB or more for messages to wait over 9 s", peak)
			}
			if s.WriteStalls != 0 || s.WriteErrors != 0 || s.Dialed != 1 || s.OpenOutbound != 1 {
				t.Errorf("WriteStalls %d, WriteErrors %d, Dialed %d, OpenOutbound %d: the connection was ended",
					s.WriteStalls, s.WriteErrors, s.Dialed, s.OpenOutbound)
			}
		})
	}
}

// QA's peer loses its connection when MaxQueueAge is 4 s, shorter than its
// messages wait: the rule is the age of the queue, not how long one
// message takes to write, which is a tenth of a second here. This is the
// trade-off #623 accepts, a peer slower than SendQueueBytes / MaxQueueAge
// with its queue full.
func TestACorePeerWhoseMessagesWaitLongerThanMaxQueueAgeIsResetThoughItReads(t *testing.T) {
	var s Stats
	pacedBurst(t, Config{MaxQueueAge: 4 * time.Second}, 320<<10, 17, func(tr *Transport, sent bool) bool {
		s = tr.Stats()
		return s.WriteStalls > 0 || sent && s.QueuedBytes == 0
	})
	if s.WriteStalls == 0 || s.WriteErrors != 0 {
		t.Errorf("WriteStalls %d, WriteErrors %d: a queue whose messages waited over 4 s was not reset", s.WriteStalls, s.WriteErrors)
	}
}
