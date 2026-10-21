package msrp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// allocated returns the bytes f allocates, measured as the growth of the
// runtime's running total, which garbage collection does not lower.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestReassemblyMemoryFollowsReceivedOctetsNotDeclaredRanges(t *testing.T) {
	const size = 1 << 20
	var msgs []*Message
	// One octet near the end of a declared megabyte, then single octets
	// spread across another: everything a peer can claim without sending
	// data. Each message stays within the fragment limit.
	msgs = append(msgs, chunkMsg("sparse1", ByteRange{size, size, size}, "x", FlagMore))
	for i := range DefaultMaxFragments {
		pos := int64(i)*16000 + 2
		msgs = append(msgs, chunkMsg("sparse2", ByteRange{pos, pos, size}, "y", FlagMore))
	}
	r := Reassembler{MaxSize: size}
	var held int64
	n := allocated(func() {
		for _, m := range msgs {
			if _, err := r.Add(m, t0); err != nil {
				t.Fatal(err)
			}
		}
		held = r.Buffered()
	})
	if held > 1024 {
		t.Fatalf("%d octets held for %d received", held, len(msgs))
	}
	if n > 64<<10 {
		t.Fatalf("%d bytes allocated for %d received octets", n, len(msgs))
	}
}

// timed returns how long f takes.
func timed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func TestAMaximumSizeSpreadOfOneOctetChunksStaysCheap(t *testing.T) {
	// 64k one-octet chunks spread over one megabyte message, the input
	// that is quadratic for a reassembler that keeps every gap.
	const size = 1 << 20
	const chunks = 1 << 16
	spread := make([]*Message, chunks)
	for i := range spread {
		pos := int64(i)*(size/chunks) + 1
		spread[i] = chunkMsg("spread", ByteRange{pos, pos, Unknown}, "s", FlagMore)
	}
	// The same number of one-octet chunks in order, which costs the same
	// for every chunk: the yardstick for the spread.
	inOrder := make([]*Message, chunks)
	for i := range inOrder {
		pos := int64(i) + 1
		inOrder[i] = chunkMsg("inorder", ByteRange{pos, pos, Unknown}, "s", FlagMore)
	}
	refused, maxHeld := 0, int64(0)
	var n uint64
	spreadRun := func() {
		r := Reassembler{MaxSize: size}
		refused, maxHeld = 0, 0
		n = allocated(func() {
			for _, m := range spread {
				if _, err := r.Add(m, t0); err != nil {
					refused++
				}
				maxHeld = max(maxHeld, r.Buffered())
			}
		})
	}
	inOrderRun := func() {
		r := Reassembler{MaxSize: size}
		for _, m := range inOrder {
			if _, err := r.Add(m, t0); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A spread run costs about two in-order ones (7.7 ms against 3.5 ms
	// unloaded, QA of #352), and each timing of the yardstick runs four:
	// the yardstick then lasts about twice the spread, long enough that
	// load seldom leaves it unthrottled while it stretches the spread
	// (#232: the best of three 200 ms spread runs against 7 ms in-order
	// ones made 28.7x). Two runs, which would match the spread, failed
	// unchanged code 2 times in 100 under the load model, against none for
	// four in the same slots (QA of #352). The two are timed in turn, so a
	// burst of load meets both, and the shortest of each is taken, since
	// other work only adds time.
	const baseRuns = 4
	spreadTime, baseTime := time.Duration(1<<63-1), time.Duration(1<<63-1)
	for range 5 {
		spreadTime = min(spreadTime, timed(spreadRun))
		baseTime = min(baseTime, timed(func() {
			for range baseRuns {
				inOrderRun()
			}
		}))
	}
	baseTime /= baseRuns
	// The 65th gap is refused and the message dropped, so it starts over;
	// at most one fragment limit's worth is ever held.
	if refused < chunks/(DefaultMaxFragments+1)-1 || maxHeld > DefaultMaxFragments {
		t.Fatalf("%d refused, at most %d octets held", refused, maxHeld)
	}
	if n > 32<<20 {
		t.Fatalf("%d bytes allocated for %d one-octet chunks", n, chunks)
	}
	// Time relative to a yardstick measured in the same run, so that a
	// loaded host or the race detector, which slow both alike, do not
	// matter. Per chunk the spread costs a few times an in-order chunk
	// (it holds up to a fragment limit of gaps); a reassembler whose cost
	// grows with the gaps or the declared size is hundreds of times
	// slower.
	t.Logf("spread %v, in order %v (%.1fx)", spreadTime, baseTime, float64(spreadTime)/float64(baseTime))
	if spreadTime > 25*baseTime {
		t.Fatalf("%d spread chunks took %v, %d in order %v", chunks, spreadTime, chunks, baseTime)
	}
}

func TestReassemblingAMessageInOrderCostsTheSameForEveryChunk(t *testing.T) {
	const size = 1 << 20
	chunks, _ := Split(bodyOf(size), DefaultChunkSize)
	msgs := make([]*Message, len(chunks))
	for i, c := range chunks {
		msgs[i] = chunkMsg("big", c.Range, string(c.Data), c.Flag)
	}
	r := Reassembler{MaxSize: size}
	var got *Message
	n := allocated(func() {
		for _, m := range msgs {
			var err error
			if got, err = r.Add(m, t0); err != nil {
				t.Fatal(err)
			}
		}
	})
	if got == nil || !bytes.Equal(got.Body, bodyOf(size)) {
		t.Fatal("message not reassembled")
	}
	// The one run doubles up to the declared total and is handed over
	// without a final copy: about twice the message, never per chunk.
	if n > 3*size {
		t.Fatalf("%d bytes allocated to reassemble %d", n, size)
	}

	// Averaged over many chunks, adding one allocates next to nothing,
	// however much of the message is already held.
	r = Reassembler{MaxSize: size}
	i := 0
	avg := testing.AllocsPerRun(len(msgs)-2, func() {
		if _, err := r.Add(msgs[i], t0); err != nil {
			t.Fatal(err)
		}
		i++
	})
	if avg > 1 {
		t.Fatalf("%.2f allocations per in-order chunk", avg)
	}
}

func TestOutOfOrderChunksCostAtMostAFragmentEach(t *testing.T) {
	r := Reassembler{MaxSize: 1 << 20}
	// Every other chunk, from the end backwards: each one is a new gap.
	var msgs []*Message
	for i := 2 * DefaultMaxFragments; i > 0; i -= 2 {
		start := int64(i-1)*100 + 1
		msgs = append(msgs, chunkMsg("holes", ByteRange{start, start + 99, 20000}, strings.Repeat("h", 100), FlagMore))
	}
	k := 0
	avg := testing.AllocsPerRun(len(msgs)-1, func() {
		if _, err := r.Add(msgs[k], t0); err != nil {
			t.Fatal(err)
		}
		k++
	})
	if avg > 3 {
		t.Fatalf("%.2f allocations per out-of-order chunk", avg)
	}
	if held := r.Buffered(); held > int64(len(msgs))*100 {
		t.Fatalf("%d octets held for %d received", held, len(msgs)*100)
	}
}

func TestAMessageInTooManyFragmentsIsRefused(t *testing.T) {
	r := Reassembler{MaxFragments: 4}
	for i := range 4 {
		start := int64(i)*10 + 1
		mustAdd(t, &r, chunkMsg("frag", ByteRange{start, start, 100}, "f", FlagMore))
	}
	// Filling a gap next to a fragment costs nothing more...
	mustAdd(t, &r, chunkMsg("frag", ByteRange{2, 3, 100}, "ff", FlagMore))
	// ...a fifth separate one does.
	if _, err := r.Add(chunkMsg("frag", ByteRange{50, 50, 100}, "f", FlagMore), t0); statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("err = %v, want 413", err)
	}
	if r.Pending() != 0 || r.Buffered() != 0 {
		t.Fatalf("refused message still held: %d messages, %d octets", r.Pending(), r.Buffered())
	}
}

func TestBufferedOctetsAreBoundedPerReassemblerAndAcrossThem(t *testing.T) {
	part := strings.Repeat("p", 4000)
	r := Reassembler{MaxBuffered: 10000}
	mustAdd(t, &r, chunkMsg("one", ByteRange{1, 4000, 8000}, part, FlagMore))
	mustAdd(t, &r, chunkMsg("two", ByteRange{1, 4000, 8000}, part, FlagMore))
	if _, err := r.Add(chunkMsg("three", ByteRange{1, 4000, 8000}, part, FlagMore), t0); statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("err = %v, want 413", err)
	}
	if r.Buffered() > 10000 {
		t.Fatalf("%d octets held", r.Buffered())
	}

	shared := &Budget{Limit: 6000}
	a, b := Reassembler{Budget: shared}, Reassembler{Budget: shared}
	mustAdd(t, &a, chunkMsg("one", ByteRange{1, 4000, 8000}, part, FlagMore))
	if _, err := b.Add(chunkMsg("two", ByteRange{1, 4000, 8000}, part, FlagMore), t0); statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("err = %v, want 413", err)
	}
	a.Close()
	if shared.Used() != 0 {
		t.Fatalf("closing kept %d octets of the budget", shared.Used())
	}
	if _, err := a.Add(chunkMsg("one", ByteRange{4001, 8000, 8000}, part, FlagEnd), t0); statusCode(err) != StatusNoSession {
		t.Fatalf("Add after Close = %v, want 481", err)
	}
	mustAdd(t, &b, chunkMsg("two", ByteRange{1, 4000, 8000}, part, FlagMore))
}

func TestIncompleteMessagesExpireWhenTheirChunksStop(t *testing.T) {
	var r Reassembler
	mustAdd(t, &r, chunkMsg("old", ByteRange{1, 1, 2}, "a", FlagMore))
	later := t0.Add(10 * time.Second)
	if _, err := r.Add(chunkMsg("new", ByteRange{1, 1, 2}, "a", FlagMore), later); err != nil {
		t.Fatal(err)
	}
	if due, ok := r.NextExpiry(time.Minute, time.Hour); !ok || !due.Equal(t0.Add(time.Minute)) {
		t.Fatalf("NextExpiry = %v, %v", due, ok)
	}
	never := t0.Add(-time.Hour)
	if n := r.Expire(t0, never); n != 1 || r.Pending() != 1 {
		t.Fatalf("expired %d, %d left", n, r.Pending())
	}
	if n := r.Expire(later, never); n != 1 || r.Buffered() != 0 {
		t.Fatalf("expired %d, %d octets left", n, r.Buffered())
	}
	if _, ok := r.NextExpiry(time.Minute, time.Hour); ok {
		t.Fatal("NextExpiry with nothing held")
	}
}

func TestAnIncompleteMessageExpiresAFixedTimeAfterItsFirstChunk(t *testing.T) {
	// Chunks keep coming every 10 s, so the idle rule never fires; the
	// lifetime, counted from the first chunk, does.
	clock := newFakeClock()
	const lifetime = 30 * time.Second
	s, p := boundPassive(t, newRecorder(), Config{Clock: clock, MaxReassemblyLifetime: lifetime, ReassemblyTimeout: time.Hour})
	for i := range 3 {
		clock.watchTimers()
		start := i*10 + 1
		tid := fmt.Sprintf("tr1ckle%d", i)
		p.send(t, sendLines(tid, "Message-ID: tr1ckle", fmt.Sprintf("Byte-Range: %d-%d/1000", start, start+9),
			"Content-Type: text/plain", "", "0123456789", "-------"+tid+"+")...)
		expectResponse(t, p, tid, StatusOK)
		sentinel(t, p) // the chunk's read buffer has been given back
		if i == 0 {
			clock.waitTimer(t, lifetime)
		}
		if s.reasm.Pending() != 1 {
			t.Fatalf("chunk %d: message not held", i)
		}
		clock.Advance(10 * time.Second)
	}
	// 30 s after the first chunk, with the last one 10 s old.
	if s.reasm.Pending() != 0 || s.budget.Used() != 0 {
		t.Fatalf("after the lifetime: %d pending, %d octets", s.reasm.Pending(), s.budget.Used())
	}
}

func TestASessionDropsAnIncompleteMessageAfterTheReassemblyTimeout(t *testing.T) {
	clock := newFakeClock()
	const timeout = 20 * time.Second
	s, p := boundPassive(t, newRecorder(), Config{Clock: clock, ReassemblyTimeout: timeout})
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()

	clock.watchTimers()
	p.send(t, sendLines("h4lf1", "Message-ID: half", "Byte-Range: 1-3/6", "Content-Type: text/plain", "", "abc", "-------h4lf1+")...)
	expectResponse(t, p, "h4lf1", StatusOK)
	// The chunk's read buffer is given back only after its answer is
	// queued; the answer to a later request shows that has happened.
	sentinel(t, p)
	clock.waitTimer(t, timeout)
	if s.reasm.Pending() != 1 || s.budget.Used() == 0 {
		t.Fatalf("%d pending, %d octets charged", s.reasm.Pending(), s.budget.Used())
	}
	clock.Advance(timeout)
	if s.reasm.Pending() != 0 || s.budget.Used() != 0 || c.budget.Used() != 0 {
		t.Fatalf("after the timeout: %d pending, %d and %d octets charged", s.reasm.Pending(), s.budget.Used(), c.budget.Used())
	}
	// The rest of the message now starts a new, incomplete one.
	p.send(t, sendLines("h4lf2", "Message-ID: half", "Byte-Range: 4-6/6", "Content-Type: text/plain", "", "def", "-------h4lf2$")...)
	expectResponse(t, p, "h4lf2", StatusOK)
	sentinel(t, p)
	if s.reasm.Pending() != 1 {
		t.Fatal("the expired start of the message was kept")
	}
	// Closing the session gives its octets back.
	_ = s.Close()
	if s.budget.Used() != 0 || c.budget.Used() != 0 {
		t.Fatalf("%d and %d octets still charged after Close", s.budget.Used(), c.budget.Used())
	}
}

// fillSession has session n of a passive connection hold incomplete
// messages until it is refused, and returns how many octets it got in.
func fillSession(t *testing.T, p *wirePeer, n int, part string) int {
	t.Helper()
	held := 0
	for i := 0; ; i++ {
		tid := fmt.Sprintf("f%02d%04d", n, i)
		p.send(t, "MSRP "+tid+" SEND", fmt.Sprintf("To-Path: msrp://as.example.org:9000/fill%02d;tcp", n),
			fmt.Sprintf("From-Path: msrp://client.example.com:2855/fill%02d;tcp", n), fmt.Sprintf("Message-ID: m%02d%04d", n, i),
			fmt.Sprintf("Byte-Range: 1-%d/%d", len(part), 2*len(part)), "Content-Type: text/plain", "", part, "-------"+tid+"+")
		if r := p.next(t); r.StatusCode != StatusOK {
			return held
		}
		held += len(part)
	}
}

func fillRegistry(t *testing.T, sessions int) *Registry {
	t.Helper()
	reg := &Registry{}
	for n := range sessions {
		s := newTestSession(t, fmt.Sprintf("msrp://as.example.org:9000/fill%02d;tcp", n),
			fmt.Sprintf("msrp://client.example.com:2855/fill%02d;tcp", n), newRecorder())
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func TestSessionsFillingTheSharedBufferLeaveAnotherSessionItsReserve(t *testing.T) {
	// A reserve just big enough for one message of the largest size (its
	// read buffer may run one octet over, then the message waits for the
	// handler), so that filling the pool matters.
	cfg := Config{Clock: newFakeClock(), MaxMessageSize: 4096, MaxPendingMessages: 64,
		MaxSessionBuffer: 64 << 10, MaxConnBuffer: 32 << 10, SessionReserve: 2*4096 + 1}
	_, p := passiveWithPeer(t, fillRegistry(t, 4), cfg)
	part := strings.Repeat("q", 2000)
	for n := range 3 {
		fillSession(t, p, n, part)
	}
	// The shared part is full, yet a whole message of the largest size on
	// the fourth session still fits within its own reserve.
	whole := strings.Repeat("w", 4096)
	p.send(t, "MSRP sh4re0k SEND", "To-Path: msrp://as.example.org:9000/fill03;tcp", "From-Path: msrp://client.example.com:2855/fill03;tcp",
		"Message-ID: whole1", "Byte-Range: 1-4096/4096", "Content-Type: text/plain", "", whole, "-------sh4re0k$")
	expectResponse(t, p, "sh4re0k", StatusOK)
}

func TestWhatSessionsHoldBeyondTheirReserveIsBoundedTogether(t *testing.T) {
	const reserve = 8192
	cfg := Config{Clock: newFakeClock(), MaxMessageSize: 4096, MaxPendingMessages: 64,
		MaxSessionBuffer: 64 << 10, MaxConnBuffer: 32 << 10, SessionReserve: reserve}
	c, p := passiveWithPeer(t, fillRegistry(t, 3), cfg)
	part := strings.Repeat("q", 2000)
	total := 0
	for n := range 3 {
		total += fillSession(t, p, n, part)
	}
	if limit := 3*reserve + 32<<10; total > limit {
		t.Fatalf("sessions held %d octets, bound %d", total, limit)
	}
	if used := c.budget.Used(); used > 32<<10 {
		t.Fatalf("shared part %d octets", used)
	}
}

func TestAStalledPeerIsDisconnectedWithinTheWriteDeadline(t *testing.T) {
	// Write deadlines are enforced by the operating system in real time,
	// so this test runs on a short real one. That the write deadline ended
	// the connection is its error; that the deadline is WriteTimeout is
	// the one the connection set, read where it sets it. A bound on the
	// time to the end in wall clock is no part of either, and a loaded host
	// under -race passed 2 s (#401).
	const deadline = 100 * time.Millisecond
	ours, theirs := net.Pipe()
	defer theirs.Close()
	nc := &deadlineRecorder{Conn: ours}
	c, err := NewActiveConn(nc, Config{Clock: newFakeClock(), WriteTimeout: deadline})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestSession(t, clientURI, asURI, nil)
	start := time.Now()
	go func() { _ = c.Open(context.Background(), s) }() // the peer never reads it
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), os.ErrDeadlineExceeded) {
		t.Fatalf("Err = %v", c.Err())
	}
	// A deadline never comes early.
	if elapsed := time.Since(start); elapsed < deadline {
		t.Fatalf("disconnected after %v, before the %v write deadline", elapsed, deadline)
	}
	// The deadline is WriteTimeout from when the write began: it was
	// computed after start and before the call that set it, so it lies
	// between start+deadline and call+deadline however late either came.
	set, at := nc.first()
	if set.IsZero() || set.Before(start.Add(deadline)) || set.After(at.Add(deadline)) {
		t.Fatalf("write deadline %v, set at %v; want WriteTimeout %v after the write began (start %v)", set, at, deadline, start)
	}
	waitDone(t, s.Done(), "session")
}

// deadlineRecorder records the first write deadline set on its Conn and
// when it was set.
type deadlineRecorder struct {
	net.Conn
	mu      sync.Mutex
	set, at time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	if d.at.IsZero() {
		d.set, d.at = t, time.Now()
	}
	d.mu.Unlock()
	return d.Conn.SetWriteDeadline(t)
}

func (d *deadlineRecorder) first() (set, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.set, d.at
}

// discard is a Handler that keeps nothing, for floods.
type discard struct{}

func (discard) HandleMessage(*Session, *Message) error { return nil }
func (discard) HandleReport(*Session, Report)          {}

func TestAFloodAskingForReportsCannotQueueThemWithoutBound(t *testing.T) {
	// REPORTs join the bounded answer queue, so a peer that asks for them
	// and reads nothing never makes the queue pass its bound: the
	// connection is closed at the bound or by the write deadline.
	const deadline = 200 * time.Millisecond
	const bound = 64 << 10
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, discard{})); err != nil {
		t.Fatal(err)
	}
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, reg, Config{Clock: newFakeClock(), MaxQueuedBytes: bound, WriteTimeout: deadline})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	req := []byte(wire(sendLines("r3pflood", "Message-ID: msg1", "Success-Report: yes",
		"Content-Type: text/plain", "", "report this", "-------r3pflood$")...))
	go func() {
		for {
			if _, err := theirs.Write(req); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	for {
		c.qmu.Lock()
		posted := c.posted
		c.qmu.Unlock()
		if posted > bound {
			t.Fatalf("%d octets of answers queued, bound %d", posted, bound)
		}
		select {
		case <-c.Done():
			if elapsed := time.Since(start); elapsed > 20*deadline {
				t.Fatalf("closed after %v", elapsed)
			}
			if !errors.Is(c.Err(), os.ErrDeadlineExceeded) && !errors.Is(c.Err(), ErrPeerNotReading) {
				t.Fatalf("Err = %v", c.Err())
			}
			return
		case <-time.After(time.Millisecond):
		}
	}
}

// unwindowed sends a request that holds a connection slot, as a relay's
// forwarding does.
func unwindowed(t *testing.T, c *Conn, mode sendMode, id string) error {
	return c.sendRequest(context.Background(), &Message{Method: MethodSend, ToPath: []URI{mustURI(t, asURI)},
		FromPath: []URI{mustURI(t, clientURI)}, MessageID: id}, mode, func(int, string) {})
}

func TestRequestsAwaitingAnswersAreBounded(t *testing.T) {
	c, p := activeWithPeer(t, Config{Clock: newFakeClock(), MaxInFlight: 2})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	for _, id := range []string{"msg1", "msg2"} {
		if err := unwindowed(t, c, sendWait, id); err != nil {
			t.Fatal(err)
		}
		p.next(t)
	}
	// A request that must not wait is refused, and its connection with it.
	if err := unwindowed(t, c, sendQueue, "msg3"); !errors.Is(err, ErrPeerNotReading) {
		t.Fatalf("queued request = %v", err)
	}
	waitDone(t, c.Done(), "connection")
}

func TestARequestWaitsForAFreeSlot(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, MaxInFlight: 2})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	for _, id := range []string{"msg1", "msg2"} {
		if err := unwindowed(t, c, sendWait, id); err != nil {
			t.Fatal(err)
		}
		p.next(t)
	}
	sent := make(chan error, 1)
	go func() { sent <- unwindowed(t, c, sendWait, "msg3") }()
	// The unanswered two expire, which frees their slots.
	clock.Advance(DefaultTransactionTimeout)
	if m := p.next(t); m.MessageID != "msg3" {
		t.Fatalf("got %+v", m)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestASenderWaitsForRoomInItsSessionsWindow(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, SendWindow: 2})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	for range 2 {
		if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		p.next(t)
	}
	sent := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("third")})
		sent <- err
	}()
	clock.Advance(DefaultTransactionTimeout)
	if m := p.next(t); string(m.Body) != "third" {
		t.Fatalf("got %+v", m)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

// bridgeByHand sets up client -> relay -> rcs-as with the two outer ends
// left to the test as raw connections, already bound.
func bridgeByHand(t *testing.T, edgeCfg, coreCfg Config) (client net.Conn, as *syncPeer, edgeConn *Conn, edge, core *Session) {
	t.Helper()
	asEnds := make(chan net.Conn, 1)
	pool := &Pool{Config: coreCfg, Dial: func(context.Context, URI) (net.Conn, error) {
		ours, theirs := net.Pipe()
		asEnds <- theirs
		return ours, nil
	}}
	t.Cleanup(func() { _ = pool.Close() })
	relay := &testRelay{t: t, pool: pool, sessions: make(chan [2]*Session, 1)}
	ours, theirs := net.Pipe()
	edgeConn, err := NewPassiveConn(ours, relay, edgeCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = edgeConn.Close(); _ = theirs.Close() })

	go func() {
		_, _ = theirs.Write([]byte(wire(clientSend("cl1b1nd", "Message-ID: cl1b1nd", "-------cl1b1nd$")...)))
	}()
	as = newSyncPeer(t, <-asEnds)
	as.respond(t, as.next(t), StatusOK)
	clientReader := newSyncPeer(t, theirs)
	expectSync := clientReader.next(t)
	if expectSync.StatusCode != StatusOK {
		t.Fatalf("binding answered %d", expectSync.StatusCode)
	}
	pair := <-relay.sessions
	return theirs, as, edgeConn, pair[0], pair[1]
}

func TestARelayStopsReadingAClientWhileRcsAsIsNotReading(t *testing.T) {
	const deadline = 200 * time.Millisecond
	client, _, _, _, core := bridgeByHand(t,
		Config{Clock: newFakeClock()},
		Config{Clock: newFakeClock(), WriteTimeout: deadline})

	body := bodyOf(1 << 20)
	wrote := make(chan bool, 1)
	go func() {
		head := wire(clientSend("pr3ssure", "Message-ID: msg1", "Byte-Range: 1-*/*", "Content-Type: text/plain", "")...)
		_, _ = client.Write(append(append([]byte(head), body...), "\r\n-------pr3ssure$\r\n"...))
		select {
		case <-core.Done():
			wrote <- true
		default:
			wrote <- false
		}
	}()
	// rcs-as reads nothing more, so the relay can take only a few pieces
	// of the megabyte before it stops reading the client; the client's
	// write cannot finish until the connection to rcs-as has given up,
	// after the configured deadline rather than the 30 s default.
	select {
	case <-core.Done():
	case <-time.After(deadline + stallBound):
		t.Fatalf("the rcs-as side outlived its %v write deadline", deadline)
	}
	select {
	case afterCore := <-wrote:
		if !afterCore {
			t.Fatal("the relay buffered the client's chunk while rcs-as was not reading")
		}
	case <-time.After(hangGuard):
		t.Fatal("client write never finished")
	}
}

func TestARelayDisconnectsAClientThatFallsBehindWithoutStallingRcsAs(t *testing.T) {
	_, as, edgeConn, edge, core := bridgeByHand(t,
		Config{Clock: newFakeClock()},
		Config{Clock: newFakeClock()})
	// The client reads nothing more; rcs-as keeps sending to it through the
	// shared connection, which must keep being read.
	var told atomic.Int64 // answers for what the relay could not deliver
	go func() {
		for {
			_ = as.nc.SetReadDeadline(time.Now().Add(hangGuard))
			m, err := as.r.ReadMessage(DefaultMaxMessageSize)
			if err != nil {
				return
			}
			if (m.Method == MethodReport && m.Status.Code == StatusRequestTimeout) ||
				(!m.IsRequest() && m.StatusCode == StatusNoSession) {
				told.Add(1)
			}
		}
	}()
	piece := strings.Repeat("z", 2000)
	sent := 0
	for i := 0; ; i++ {
		select {
		case <-edgeConn.Done():
		default:
			msg := wire("MSRP fl"+fmt.Sprintf("%06d", i)+" SEND", "To-Path: "+relayInternalURI, "From-Path: "+asURI,
				"Message-ID: m"+fmt.Sprintf("%06d", i), "Content-Type: text/plain", "", piece, "-------fl"+fmt.Sprintf("%06d", i)+"$")
			// The only check that rcs-as is never held up: its writes must
			// keep going, well inside the relay's 30 s write deadline.
			_ = as.nc.SetWriteDeadline(time.Now().Add(stallBound))
			if _, err := as.nc.Write([]byte(msg)); err != nil {
				t.Fatalf("rcs-as could not write after %d messages: %v", sent, err)
			}
			sent++
			continue
		}
		break
	}
	if !errors.Is(edgeConn.Err(), ErrPeerNotReading) {
		t.Fatalf("client connection ended with %v", edgeConn.Err())
	}
	waitDone(t, edge.Done(), "client side")
	waitDone(t, core.Done(), "rcs-as side")
	if sent > 4000 {
		t.Fatalf("%d messages queued for a client that reads nothing", sent)
	}
	// What was queued for the client is answered back to rcs-as as not
	// delivered rather than forgotten.
	deadline := time.Now().Add(hangGuard)
	for told.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if told.Load() == 0 {
		t.Fatal("rcs-as was not told that queued messages were lost")
	}
}

func TestURIsPrintWithoutTheirSessionID(t *testing.T) {
	u := mustURI(t, "msrp://alice@client.example.com:2855/s3cr3tsess10n;tcp")
	if !strings.Contains(u.String(), "s3cr3tsess10n") {
		t.Fatal("String must stay the wire form")
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "uri", u, "path", []URI{u}, "in", struct{ To URI }{u})
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "uri", u, "path", []URI{u})
	for _, out := range []string{
		fmt.Sprint(u), fmt.Sprintf("%v %s %q %+v %#v", u, u, u, u, u), fmt.Sprint([]URI{u}), logged.String(), u.Redacted(),
	} {
		if strings.Contains(out, "s3cr3tsess10n") || strings.Contains(out, "alice") {
			t.Errorf("revealed: %s", out)
		}
		if !strings.Contains(out, "client.example.com") {
			t.Errorf("host lost: %s", out)
		}
	}
	if got := u.Redacted(); got != "msrp://[redacted]@client.example.com:2855/[redacted];tcp" {
		t.Fatalf("Redacted() = %q", got)
	}
}

func TestClientAddressesInURIsAreLoggedAsTheirNetwork(t *testing.T) {
	// A client's a=path names the UE's address (#80); like sip's hosts,
	// every IP address is logged as its /24 or /48 without the port, and a
	// name is kept.
	for _, tt := range []struct{ uri, want string }{
		{"msrp://198.51.100.23:49152/s3cr3tsess10n;tcp", "msrp://198.51.100.0/24/[redacted];tcp"},
		{"msrps://10.20.30.40:2856/s3cr3tsess10n;tcp", "msrps://10.20.30.0/24/[redacted];tcp"},
		{"msrp://[2001:db8:5:6::17]:2855/s3cr3tsess10n;tcp", "msrp://[2001:db8:5::/48]/[redacted];tcp"},
		{"msrp://[::ffff:198.51.100.23]:2855/s3cr3tsess10n;tcp", "msrp://198.51.100.0/24/[redacted];tcp"},
		{"msrp://192.000.002.001:2855/s3cr3tsess10n;tcp", "msrp://192.0.2.0/24/[redacted];tcp"},
		{"msrp://relay.example.com:2855/s3cr3tsess10n;tcp", "msrp://relay.example.com:2855/[redacted];tcp"},
		// Parameters are the client's text and could name the address
		// again (security review of #98): only the transport is kept.
		{"msrp://198.51.100.23:1/s;tcp;x=198.51.100.23;y", "msrp://198.51.100.0/24/[redacted];tcp"},
	} {
		u := mustURI(t, tt.uri)
		if got := u.Redacted(); got != tt.want {
			t.Errorf("Redacted(%s) = %q, want %q", tt.uri, got, tt.want)
		}
	}
	// The same in a message's paths, as every log line shows them.
	m := &Message{TransactionID: "t1", Method: MethodSend,
		ToPath:   []URI{mustURI(t, "msrp://relay.example.com:2855/r3l4ysess;tcp")},
		FromPath: []URI{mustURI(t, "msrp://198.51.100.23:49152/s3cr3tsess10n;tcp")}}
	var logged bytes.Buffer
	untimedJSONLogger(&logged).Info("x", "msg", m)
	if strings.Contains(logged.String(), `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", logged.String())
	}
	for _, out := range []string{logged.String(), fmt.Sprint(m)} {
		if strings.Contains(out, "198.51.100.23") || strings.Contains(out, "49152") {
			t.Errorf("the client's address is logged: %s", out)
		}
		if !strings.Contains(out, "198.51.100.0/24") {
			t.Errorf("the client's network is lost: %s", out)
		}
	}
}

func TestMessagesPrintWithoutBodiesOrSessionIDs(t *testing.T) {
	m := &Message{TransactionID: "l0gged", Method: MethodSend, ToPath: []URI{mustURI(t, asURI)}, FromPath: []URI{mustURI(t, clientURI)},
		MessageID: "msg1", ByteRange: &ByteRange{1, 15, 15}, ContentType: "text/plain",
		Header: []Field{{"Content-Disposition", "s3cr3tvalue"}}, Body: []byte("private content")}
	resp := &Message{TransactionID: "l0gged", StatusCode: 200, ToPath: m.FromPath, FromPath: m.ToPath}
	rep := NewReport(m, m.ToPath[0], *m.ByteRange, 200)
	rep.TransactionID = "l0gged"
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "msg", m, "value", *m, "resp", resp, "rep", rep,
		"nested", []*Message{m}, "struct", struct{ M *Message }{m})
	for _, out := range []string{fmt.Sprint(m), fmt.Sprintf("%v %+v %s", *m, m, resp), fmt.Sprint(rep), logged.String()} {
		for _, secret := range []string{"private content", "as9ses", "cl1ses", "s3cr3tvalue"} {
			if strings.Contains(out, secret) {
				t.Errorf("%q revealed in %s", secret, out)
			}
		}
		if !strings.Contains(out, "l0gged") {
			t.Errorf("transaction id lost: %s", out)
		}
	}
	if !strings.Contains(fmt.Sprint(m), "body_octets=15") || !strings.Contains(logged.String(), `"status":200`) {
		t.Fatalf("summary missing: %s / %s", fmt.Sprint(m), logged.String())
	}
}

// bindOnlyPeer answers the SENDs that bind sessions and swallows the rest
// unanswered, like a relay whose clients have all stopped reading.
func bindOnlyPeer(t *testing.T, nc net.Conn) *atomic.Int64 {
	t.Helper()
	var chunks atomic.Int64
	go func() {
		r := NewReader(nc, 0)
		for {
			m, err := r.ReadMessage(DefaultMaxMessageSize)
			if err != nil {
				return
			}
			if m.Method == MethodSend && !m.HasBody() {
				resp, _ := NewResponse(m, StatusOK, "OK")
				b, _ := resp.Marshal()
				if _, err := nc.Write(b); err != nil {
					return
				}
				continue
			}
			chunks.Add(1)
		}
	}()
	t.Cleanup(func() { _ = nc.Close() })
	return &chunks
}

func TestSessionsStalledAtAFullWindowDoNotStallAnotherSession(t *testing.T) {
	// One more stalled session than the connection has slots for at the
	// default window, so the windows alone would use up every slot.
	stalled := DefaultMaxInFlight/DefaultSendWindow + 1
	before := runtime.NumGoroutine()
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	chunks := bindOnlyPeer(t, theirs)
	open := func(i int) *Session {
		// No handler: when the connection closes, each chunk still in
		// flight is reported, thousands of them. A recorder, which nobody
		// reads after the test, would hold a goroutine per session for the
		// rest of the process (#251, #258).
		s := newTestSession(t, fmt.Sprintf("msrp://relay.internal:2855/st%05d;tcp", i), fmt.Sprintf("msrp://as.example.org:9000/st%05d;tcp", i), nil)
		if err := c.Open(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	body := bodyOf((DefaultSendWindow + 1) * DefaultChunkSize)
	for i := range stalled {
		s := open(i)
		go func() { _, _ = s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: body}) }()
	}
	want := int64(stalled * DefaultSendWindow)
	deadline := time.Now().Add(hangGuard)
	for chunks.Load() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if chunks.Load() < want {
		t.Fatalf("only %d of %d chunks went out", chunks.Load(), want)
	}
	other := open(stalled)
	done := make(chan error, 1)
	go func() {
		_, err := other.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("not stuck")})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(hangGuard):
		t.Fatal("a session with an empty window waited for the stalled ones")
	}
	// QA on #257: the connection closed, the test leaves no goroutine
	// behind, so a leak cannot hide behind a larger stack dump.
	_ = c.Close()
	deadline = time.Now().Add(hangGuard)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if left := runtime.NumGoroutine() - before; left > 2 {
		t.Fatalf("%d goroutines left behind after the connection closed", left)
	}
}

// untimedJSONLogger writes JSON lines without the time attribute, so that a
// test searching a line for leaked digits cannot find them in the
// timestamp's nanoseconds (#99).
func untimedJSONLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}
