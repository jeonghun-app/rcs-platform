package msrp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
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

func TestAMaximumSizeSpreadOfOneOctetChunksStaysCheap(t *testing.T) {
	// 64k one-octet chunks spread over one megabyte message, the input
	// that is quadratic for a reassembler that keeps every gap.
	const size = 1 << 20
	const chunks = 1 << 16
	msgs := make([]*Message, chunks)
	for i := range msgs {
		pos := int64(i)*(size/chunks) + 1
		msgs[i] = chunkMsg("spread", ByteRange{pos, pos, Unknown}, "s", FlagMore)
	}
	r := Reassembler{MaxSize: size}
	refused, maxHeld := 0, int64(0)
	start := time.Now()
	n := allocated(func() {
		for _, m := range msgs {
			if _, err := r.Add(m, t0); err != nil {
				refused++
			}
			maxHeld = max(maxHeld, r.Buffered())
		}
	})
	elapsed := time.Since(start)
	// The 65th gap is refused and the message dropped, so it starts over;
	// at most one fragment limit's worth is ever held.
	if refused < chunks/(DefaultMaxFragments+1)-1 || maxHeld > DefaultMaxFragments {
		t.Fatalf("%d refused, at most %d octets held", refused, maxHeld)
	}
	if n > 32<<20 {
		t.Fatalf("%d bytes allocated for %d one-octet chunks", n, chunks)
	}
	// Generous enough for a loaded CI runner; the quadratic version takes
	// tens of seconds here.
	if elapsed > 2*time.Second {
		t.Fatalf("%d chunks took %v", chunks, elapsed)
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
	if oldest, ok := r.Oldest(); !ok || !oldest.Equal(t0) {
		t.Fatalf("Oldest = %v, %v", oldest, ok)
	}
	if n := r.Expire(t0); n != 1 || r.Pending() != 1 {
		t.Fatalf("expired %d, %d left", n, r.Pending())
	}
	if n := r.Expire(later); n != 1 || r.Buffered() != 0 {
		t.Fatalf("expired %d, %d octets left", n, r.Buffered())
	}
	if _, ok := r.Oldest(); ok {
		t.Fatal("Oldest with nothing held")
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
	clock.waitTimer(t, timeout)
	if s.reasm.Pending() != 1 || c.budget.Used() == 0 {
		t.Fatalf("%d pending, %d octets charged", s.reasm.Pending(), c.budget.Used())
	}
	clock.Advance(timeout)
	if s.reasm.Pending() != 0 || c.budget.Used() != 0 {
		t.Fatalf("after the timeout: %d pending, %d octets charged", s.reasm.Pending(), c.budget.Used())
	}
	// The rest of the message now starts a new, incomplete one.
	p.send(t, sendLines("h4lf2", "Message-ID: half", "Byte-Range: 4-6/6", "Content-Type: text/plain", "", "def", "-------h4lf2$")...)
	expectResponse(t, p, "h4lf2", StatusOK)
	if s.reasm.Pending() != 1 {
		t.Fatal("the expired start of the message was kept")
	}
	// Closing the session gives its octets back to the connection.
	_ = s.Close()
	if c.budget.Used() != 0 {
		t.Fatalf("%d octets still charged after Close", c.budget.Used())
	}
}

func TestSessionsOnAConnectionShareItsBuffer(t *testing.T) {
	reg := &Registry{}
	one := newTestSession(t, asURI, clientURI, newRecorder())
	two := newTestSession(t, "msrp://as.example.org:9000/as9two;tcp", "msrp://client.example.com:2855/cl1two;tcp", newRecorder())
	for _, s := range []*Session{one, two} {
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	// A chunk being read is charged too, so the first 4000 octets briefly
	// need about twice that; the second session's then do not fit.
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock(), MaxMessageSize: 8192, MaxSessionBuffer: 8192, MaxConnBuffer: 10000})
	part := strings.Repeat("q", 4000)
	p.send(t, sendLines("sh4re1", "Message-ID: msg1", "Byte-Range: 1-4000/8000", "Content-Type: text/plain", "", part, "-------sh4re1+")...)
	expectResponse(t, p, "sh4re1", StatusOK)
	p.send(t, "MSRP sh4re2 SEND", "To-Path: msrp://as.example.org:9000/as9two;tcp", "From-Path: msrp://client.example.com:2855/cl1two;tcp",
		"Message-ID: msg2", "Byte-Range: 1-4000/8000", "Content-Type: text/plain", "", part, "-------sh4re2+")
	expectResponse(t, p, "sh4re2", StatusMessageTooLarge)
}

func TestAStalledPeerIsDisconnectedWithinTheWriteDeadline(t *testing.T) {
	// Write deadlines are enforced by the operating system in real time,
	// so this test runs on a short real one.
	const deadline = 100 * time.Millisecond
	ours, theirs := net.Pipe()
	defer theirs.Close()
	c, err := NewActiveConn(ours, Config{Clock: newFakeClock(), WriteTimeout: deadline})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestSession(t, clientURI, asURI, nil)
	start := time.Now()
	go func() { _ = c.Open(context.Background(), s) }() // the peer never reads it
	waitDone(t, c.Done(), "connection")
	if elapsed := time.Since(start); elapsed > 20*deadline {
		t.Fatalf("disconnected after %v", elapsed)
	}
	if !errors.Is(c.Err(), os.ErrDeadlineExceeded) {
		t.Fatalf("Err = %v", c.Err())
	}
	waitDone(t, s.Done(), "session")
}

// discard is a Handler that keeps nothing, for floods.
type discard struct{}

func (discard) HandleMessage(*Session, *Message) error { return nil }
func (discard) HandleReport(*Session, Report)          {}

func TestAFloodAskingForReportsCannotQueueThemWithoutBound(t *testing.T) {
	// REPORTs are written by the session's handler goroutine, which waits
	// for the peer, so a peer that asks for them and reads nothing gets its
	// messages refused once the handler queue is full, the answer queue
	// stays within its bound, and the write deadline ends the connection.
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

func TestRequestsAwaitingAnswersAreBounded(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, MaxInFlight: 2})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	for range 2 {
		if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("x")}); err != nil {
			t.Fatal(err)
		}
		p.next(t)
	}
	// A request that must not wait is refused, and its connection with it.
	if err := c.sendRequest(context.Background(), &Message{Method: MethodSend, ToPath: []URI{mustURI(t, asURI)}, FromPath: []URI{mustURI(t, clientURI)},
		MessageID: "msg9"}, sendQueue, func(int, string) {}); !errors.Is(err, ErrPeerNotReading) {
		t.Fatalf("queued request = %v", err)
	}
	waitDone(t, c.Done(), "connection")
}

func TestASenderWaitsForAFreeSlot(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, MaxInFlight: 2})
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
	// The unanswered two expire, which frees their slots.
	clock.Advance(DefaultTransactionTimeout)
	if m := p.next(t); string(m.Body) != "third" {
		t.Fatalf("got %+v", m)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	n := len(c.pending)
	c.mu.Unlock()
	if n > 2 {
		t.Fatalf("%d requests awaited", n)
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
	// write cannot finish until the connection to rcs-as has given up.
	waitDone(t, core.Done(), "rcs-as side")
	select {
	case afterCore := <-wrote:
		if !afterCore {
			t.Fatal("the relay buffered the client's chunk while rcs-as was not reading")
		}
	case <-time.After(5 * time.Second):
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
			_ = as.nc.SetReadDeadline(time.Now().Add(5 * time.Second))
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
			_ = as.nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
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
	deadline := time.Now().Add(5 * time.Second)
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
