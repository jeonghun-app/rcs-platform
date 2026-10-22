package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// #234, over a real transport: a request written onto a client's flow that
// the client then closes reaches the sender as 430 well within Timer F
// (32 s), however soon after the write the close comes.
func TestARequestOnAFlowTheClientClosesGets430Soon(t *testing.T) {
	var (
		mu         sync.Mutex
		clientFlow transport.FlowID
	)
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{
		OnFlowClosed: func(id transport.FlowID, _ transport.FlowInfo) {
			if p := px.Load(); p != nil {
				p.FlowClosed(id)
			}
		},
	}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(_ context.Context, r *Request) Decision {
			// The client's OPTIONS marks its flow; the core's MESSAGE goes
			// to it, as pcscf sends a terminating request.
			if r.Message.Method == "OPTIONS" {
				mu.Lock()
				clientFlow = r.Source.Flow
				mu.Unlock()
				return Decision{Status: 200}
			}
			mu.Lock()
			flow := clientFlow
			mu.Unlock()
			return Decision{
				Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: flow}}},
				OnFinal: keep430,
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)

	client := dialSIP(t, addr.String())
	client.send(t, "OPTIONS", "c1")
	if res := client.final(t); res.StatusCode != 200 {
		t.Fatalf("OPTIONS answered %d", res.StatusCode)
	}
	core := dialSIP(t, addr.String())
	core.send(t, "MESSAGE", "m1")
	// The client reads the MESSAGE and closes without answering.
	if _, err := client.r.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	_ = client.nc.Close()
	start := time.Now()
	res := core.final(t)
	if res.StatusCode != 430 || time.Since(start) > 5*time.Second {
		t.Fatalf("core got %d after %v, want 430 at once", res.StatusCode, time.Since(start))
	}
}

// sipConn is one side of a SIP connection in these tests.
type sipConn struct {
	nc net.Conn
	r  *sip.Reader
}

func dialSIP(t *testing.T, addr string) *sipConn {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	return &sipConn{nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{})}
}

var flowSends atomic.Int64

func (c *sipConn) send(t *testing.T, method, id string) {
	t.Helper()
	n := flowSends.Add(1)
	var b strings.Builder
	fmt.Fprintf(&b, "%s sip:bob@example.com SIP/2.0\r\n", method)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP %s;branch=z9hG4bK-fc-%s-%d\r\n", c.nc.LocalAddr(), id, n)
	b.WriteString("Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n")
	fmt.Fprintf(&b, "Call-ID: fc-%s-%d\r\nCSeq: 1 %s\r\nContent-Length: 0\r\n\r\n", id, n, method)
	if _, err := io.WriteString(c.nc, b.String()); err != nil {
		t.Fatal(err)
	}
}

// final reads up to the first final response.
func (c *sipConn) final(t *testing.T) *sip.Response {
	t.Helper()
	for {
		m, err := c.r.ReadMessage()
		if err != nil {
			t.Fatalf("no final response: %v", err)
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
}

// A peer that has stopped reading leaves its answers in the transport's
// queue, where Close drops them whatever Drain waits: Drain stops waiting
// once no connection with output queued makes progress, rather than spend
// all of DrainSendWait, most of a service's stop margin, on them (QA of
// #366). Another peer that keeps sending and reading meanwhile does not hide
// the stalled one: progress is per connection. DrainSendWait is an hour
// here, so only that rule ends the wait.
func TestDrainDoesNotWaitOnAPeerThatStoppedReading(t *testing.T) {
	for _, chatty := range []bool{false, true} {
		t.Run(map[bool]string{false: "alone", true: "with a busy peer that reads"}[chatty], func(t *testing.T) {
			drainSendWait = time.Hour
			t.Cleanup(func() { drainSendWait = DrainSendWait })
			p, tr, addr := stalledPeerProxy(t)
			if chatty {
				busy := dialSIP(t, addr.String())
				_ = busy.nc.SetDeadline(time.Now().Add(time.Hour))
				go func() { _, _ = io.Copy(io.Discard, busy.nc) }()
				stop := make(chan struct{})
				t.Cleanup(func() { close(stop) })
				go func() {
					for {
						select {
						case <-stop:
							return
						case <-time.After(20 * time.Millisecond):
						}
						n := flowSends.Add(1)
						if _, err := io.WriteString(busy.nc, fmt.Sprintf("OPTIONS sip:bob@example.com SIP/2.0\r\n"+
							"Via: SIP/2.0/TCP %s;branch=z9hG4bK-busy-%d\r\nMax-Forwards: 70\r\n"+
							"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
							"Call-ID: busy-%d\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
							busy.nc.LocalAddr(), n, n)); err != nil {
							return
						}
					}
				}()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan struct{})
			go func() { p.Drain(ctx); close(done) }()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("Drain is still waiting for a peer that does not read")
			}
			if tr.Stats().QueuedBytes == 0 {
				t.Fatal("the stalled peer's queue emptied, so nothing showed that Drain stopped waiting on it")
			}
		})
	}
}

// stalledPeerProxy is a proxy over a real transport that answers every
// request 200, with a peer that stopped reading and has over 1 MiB of
// answers queued (stallPeer).
func stalledPeerProxy(t *testing.T) (*Proxy, *transport.Transport, netip.AddrPort) {
	t.Helper()
	var px atomic.Pointer[Proxy]
	var stalledAnswers atomic.Int64
	tr, err := transport.New(transport.Config{WriteTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(_ context.Context, r *Request) Decision {
			if r.Message.Method == "INFO" {
				return answerStalled(t, &stalledAnswers)
			}
			return Decision{Status: 200}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)
	stallPeer(t, addr, tr, &stalledAnswers)
	return p, tr, addr
}

// stalledAnswerBody is the body of each answer to a peer that stops
// reading: large, so that a few dozen fill the sockets' buffers.
const stalledAnswerBody = 64 << 10

// answerStalled is the Decision for a stalled peer's INFO: a 200 with a
// stalledAnswerBody body, counted in answered once it is in the queue.
// Nothing waits for room (stallPeer), so a failed answer is a broken
// setup.
func answerStalled(t *testing.T, answered *atomic.Int64) Decision {
	return Decision{Serve: func(_ context.Context, u *UAS) {
		res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1")
		if err != nil {
			t.Error(err)
			return
		}
		res.Header.Set("Content-Type", "text/plain")
		res.Body = bytes.Repeat([]byte("z"), stalledAnswerBody)
		if err := u.Respond(res); err != nil {
			t.Errorf("answering the stalled peer's INFO: %v", err)
			return
		}
		answered.Add(1)
	}}
}

// stallPeer connects a peer to addr that stops reading, with over 1 MiB of
// answers queued for it by tr. The peer sends its requests, INFO, one at a
// time, each once the one before has its answer in the queue (answered,
// answerStalled), so that none is in flight when 1 MiB is queued.
// Requests still in the sockets' buffers would be answered later, and on a
// host with large loopback buffers their answers outgrew the queue's room
// and waited for it. Drain then waited all of drainSendWait, an hour in
// these tests, for the one whose handler it had seen still answering: the
// tests here rule that out (#565).
func stallPeer(t *testing.T, addr netip.AddrPort, tr *transport.Transport, answered *atomic.Int64) *sipConn {
	t.Helper()
	peer := dialSIP(t, addr.String())
	if tc, ok := peer.nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	_ = peer.nc.SetDeadline(time.Now().Add(time.Hour))
	// Well past what the two sockets' buffers take, so the writer is
	// stuck, and well short of the queue's limit.
	for i := int64(0); tr.Stats().QueuedBytes < 1<<20; i++ {
		peer.send(t, "INFO", "stuck")
		waitUntil(t, "the stalled peer's request to be answered", func() bool { return answered.Load() > i }, answered.Load, tr)
	}
	return peer
}

// A peer that reads, slowly, still gets a long answer that takes it well
// past drainFlushStall to read: what counts as progress is bytes written,
// chunk by chunk, not a whole message leaving the queue (code review of
// #366). The peer reads 32 KiB every 45 ms, about 700 KB/s, so the 900 KiB
// answer takes over a second, while the kernel takes more of it every
// quarter second or so. The transport closes right
// after Drain, as in pcscf, and drops whatever is left. DrainSendWait is an
// hour, so only the stall rule could cut the answer short.
func TestDrainWaitsForAPeerThatReadsALongAnswerSlowly(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "alone", true: "beside a peer that stopped reading"}[stalled], func(t *testing.T) {
			longAnswerToASlowReader(t, stalled)
		})
	}
}

// longAnswerToASlowReader is TestDrainWaitsForAPeerThatReadsALongAnswerSlowly,
// with another peer that has stopped reading and holds a full queue
// meanwhile if stalled, which must not end the wait for the one still
// reading (QA of #366). drainFlushStall is long, so that a loaded host
// cannot make the reader look stalled; Transport.Flush's tests cover the
// window itself.
func longAnswerToASlowReader(t *testing.T, stalled bool) {
	const long = 900 << 10
	drainSendWait, drainFlushStall = time.Hour, 10*time.Second
	t.Cleanup(func() { drainSendWait, drainFlushStall = DrainSendWait, time.Second })
	responded := make(chan struct{}, 2)
	var px atomic.Pointer[Proxy]
	var stalledAnswers atomic.Int64
	// No write deadline cuts the stalled peer first, which would end its
	// connection rather than let Drain judge it.
	tr, err := transport.New(transport.Config{WriteTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(_ context.Context, r *Request) Decision {
			if r.Message.Method == "INFO" {
				return answerStalled(t, &stalledAnswers)
			}
			size := 10
			if r.Message.Method == "MESSAGE" {
				size = long
			}
			return Decision{Serve: func(_ context.Context, u *UAS) {
				res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1")
				if err != nil {
					t.Error(err)
					return
				}
				res.Header.Set("Content-Type", "text/plain")
				res.Body = []byte(strings.Repeat("b", size))
				if err := u.Respond(res); err != nil {
					t.Errorf("answering %s: %v", r.Message.Method, err)
				}
				responded <- struct{}{}
			}}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)

	if stalled {
		stallPeer(t, addr, tr, &stalledAnswers)
	}

	peer := dialSIP(t, addr.String())
	// The two sockets' buffers then hold well under the long answer, so it
	// is still in the queue when Drain starts.
	if tc, ok := peer.nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(64 << 10)
	}
	_ = peer.nc.SetDeadline(time.Now().Add(time.Minute))
	peer.send(t, "MESSAGE", "long")
	peer.send(t, "OPTIONS", "short")
	for range 2 {
		select {
		case <-responded:
		case <-time.After(30 * time.Second):
			t.Fatal("the handlers did not answer")
		}
	}
	if tr.Stats().QueuedBytes == 0 {
		t.Fatal("the answers are already out, so Drain has nothing to wait for")
	}
	read := make(chan []byte, 1)
	var progress atomic.Int64
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 32<<10)
		for {
			n, err := peer.nc.Read(buf)
			got.Write(buf[:n])
			progress.Add(int64(n))
			if err != nil {
				read <- got.Bytes()
				return
			}
			time.Sleep(45 * time.Millisecond)
		}
	}()
	if stalled {
		// Still there, with its output queued: otherwise this would be the
		// case alone (code review of #366).
		if st := tr.Stats(); st.OpenInbound != 2 || st.QueuedBytes < 1<<20 {
			t.Fatalf("before Drain, %d connections and %d bytes queued, want both peers and the stalled one's 1 MiB", st.OpenInbound, st.QueuedBytes)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	drainWatched(t, p, ctx, progress.Load, tr)
	_ = tr.Close()
	r := sip.NewReader(bufio.NewReader(bytes.NewReader(peerRead(t, read, &progress, peer, tr))), sip.Limits{MaxBodyBytes: 1 << 20})
	var sizes []int
	for {
		m, err := r.ReadMessage()
		if err != nil {
			break
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode == 200 {
			sizes = append(sizes, len(res.Body))
		}
	}
	// The two handlers answer concurrently, so either may come first.
	slices.Sort(sizes)
	if !slices.Equal(sizes, []int{10, long}) {
		t.Fatalf("the peer got answers of %v bytes, want the long one and the short one", sizes)
	}
}

// Answers already decided but still waiting for room in a queue when Drain
// starts are delivered too, to a peer that reads: Flush waits for them as for
// what is queued (QA of #366, whose probe this is). The peer sends 3000
// requests, each answered 200 with its long Via, and reads none until every
// one has been routed, so most answers wait for room in the full queue; it
// then reads at about 16 MB/s while Drain runs, and the transport closes
// right after it, as in pcscf.
func TestDrainDeliversAnswersStillWaitingForRoom(t *testing.T) {
	// Past its deadline Drain goes straight to the flush; far from it,
	// Drain no longer waits for the finals already on their way (#375), and
	// the flush still delivers them.
	for _, far := range []bool{false, true} {
		t.Run(map[bool]string{false: "the drain's deadline passed", true: "the drain's deadline far off"}[far], func(t *testing.T) {
			answersWaitingForRoom(t, far)
		})
	}
}

func answersWaitingForRoom(t *testing.T, far bool) {
	const requests = 3000
	drainSendWait, drainFlushStall = time.Hour, 10*time.Second
	t.Cleanup(func() { drainSendWait, drainFlushStall = DrainSendWait, time.Second })
	var routed atomic.Int64
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{WriteTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			routed.Add(1)
			return Decision{Status: 200}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)

	peer := dialSIP(t, addr.String())
	_ = peer.nc.SetDeadline(time.Now().Add(time.Hour))
	pad := strings.Repeat("z", 3000)
	go func() {
		for i := range requests {
			text := fmt.Sprintf("MESSAGE sip:bob@example.com SIP/2.0\r\n"+
				"Via: SIP/2.0/TCP %s;branch=z9hG4bK-room-%d;p=%s\r\n"+
				"Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
				"Call-ID: room-%d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n", peer.nc.LocalAddr(), i, pad, i)
			if _, err := io.WriteString(peer.nc, text); err != nil {
				return
			}
		}
	}()
	waitUntil(t, "every request to be routed", func() bool { return routed.Load() == requests }, routed.Load, tr)
	read := make(chan []byte, 1)
	var progress atomic.Int64
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 64<<10)
		for {
			n, err := peer.nc.Read(buf)
			got.Write(buf[:n])
			progress.Add(int64(n))
			if err != nil {
				read <- got.Bytes()
				return
			}
			time.Sleep(4 * time.Millisecond)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	if far {
		ctx, cancel = context.WithTimeout(context.Background(), time.Hour)
	}
	defer cancel()
	if !far {
		cancel()
	}
	drainWatched(t, p, ctx, progress.Load, tr)
	_ = tr.Close()
	r := sip.NewReader(bufio.NewReader(bytes.NewReader(peerRead(t, read, &progress, peer, tr))), sip.Limits{})
	answered := 0
	for {
		m, err := r.ReadMessage()
		if err != nil {
			break
		}
		if res, ok := m.(*sip.Response); ok && res.StatusCode >= 200 {
			answered++
		}
	}
	if answered != requests {
		t.Fatalf("the peer got %d final responses of %d", answered, requests)
	}
}

// drainWatched runs p.Drain(ctx) while progress, what the reading peer
// has read, keeps changing, and fails once it has not for 30 s, with the
// transport's stats. drainSendWait is an hour in these tests, so a wait
// Drain should not have would otherwise run to the package's timeout with
// no message (#565). It closes the transport first, which ends the sends
// Drain waits for.
func drainWatched(t *testing.T, p *Proxy, ctx context.Context, progress func() int64, tr *transport.Transport) {
	t.Helper()
	done := make(chan struct{})
	go func() { p.Drain(ctx); close(done) }()
	last, lastAt := progress(), time.Now()
	for {
		select {
		case <-done:
			return
		case <-time.After(100 * time.Millisecond):
		}
		if n := progress(); n != last {
			last, lastAt = n, time.Now()
		} else if time.Since(lastAt) > 30*time.Second {
			st := tr.Stats()
			_ = tr.Close()
			t.Fatalf("Drain still waiting, the peer read nothing for 30 s after %d bytes: %+v", n, st)
		}
	}
}

// waitUntil waits for cond while progress keeps changing, and fails, with
// the transport's stats, once it has not for 30 s.
func waitUntil(t *testing.T, what string, cond func() bool, progress func() int64, tr *transport.Transport) {
	t.Helper()
	last, lastAt := progress(), time.Now()
	for !cond() {
		if n := progress(); n != last {
			last, lastAt = n, time.Now()
		} else if time.Since(lastAt) > 30*time.Second {
			t.Fatalf("waiting for %s, nothing moved for 30 s: %+v", what, tr.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A stalled peer's finals waiting for room in its full queue do not hold
// Drain to its deadline (#375): they are on their way, Flush waits for them
// as senders waiting for room, and gives up once the connection stalls. The
// deadline is an hour here; before #375 Drain waited all of it.
func TestDrainDoesNotWaitOutItsDeadlineForFinalsBehindAStalledPeer(t *testing.T) {
	for _, kind := range []string{"the proxy's own answers", "a Serve handler's answers", "answers for branches that all failed"} {
		t.Run(kind, func(t *testing.T) { finalsBehindAStalledPeer(t, kind) })
	}
}

func finalsBehindAStalledPeer(t *testing.T, kind string) {
	var routed atomic.Int64
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{WriteTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			routed.Add(1)
			switch kind {
			case "a Serve handler's answers":
				return Decision{Serve: func(_ context.Context, u *UAS) {
					if res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1"); err == nil {
						_ = u.Respond(res)
					}
				}}
			case "answers for branches that all failed":
				// A flow that is gone: the branch fails at once, and the
				// proxy answers the best failure, 430 (code review of #438).
				return Decision{Targets: []Target{{URI: mustURI("sip:bob@192.0.2.10"), Destination: &transport.Destination{Flow: "gone"}}}}
			}
			return Decision{Status: 200}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)

	peer := dialSIP(t, addr.String())
	if tc, ok := peer.nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	_ = peer.nc.SetDeadline(time.Now().Add(time.Hour))
	// Far more 200s than the queue holds, each with the request's long Via;
	// the peer reads none of them.
	const requests = 2000
	pad := strings.Repeat("z", 3000)
	go func() {
		for i := range requests {
			text := fmt.Sprintf("MESSAGE sip:bob@example.com SIP/2.0\r\n"+
				"Via: SIP/2.0/TCP %s;branch=z9hG4bK-behind-%d;p=%s\r\n"+
				"Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
				"Call-ID: behind-%d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n", peer.nc.LocalAddr(), i, pad, i)
			if _, err := io.WriteString(peer.nc, text); err != nil {
				return
			}
		}
	}()
	waitUntil(t, "every request to be routed", func() bool { return routed.Load() == requests }, routed.Load, tr)
	inProgress := func() int64 { return int64(p.inProgress()) }
	waitUntil(t, "no request in progress, the finals decided", func() bool { return inProgress() == 0 }, inProgress, tr)
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	done := make(chan struct{})
	go func() { p.Drain(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain is still waiting for the finals behind a peer that does not read")
	}
}

// A final whose connection closed and is being dialled again, to the Via's
// sent-by (RFC 3261 §18.2.2), is in no queue yet, but on its way: Drain's
// flush waits for it, and the peer still gets it (code review of #438,
// whose repro this is). The dial is held for 1.5 s, past drainFlushStall,
// as a lost SYN holds it: the stall bounds a writer that does not move, not
// a dial, which has DialTimeout (QA of #438). drainSendWait is long, so that
// only the stall could end the wait.
func TestDrainWaitsForAFinalWhoseConnectionIsBeingDialled(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	d := startDialledFinal(t)
	done := d.drain()
	select {
	case <-done:
		t.Fatal("Drain returned while the 200 was still being dialled")
	case <-time.After(drainFlushStall + 500*time.Millisecond):
	}
	d.release()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain did not return once the dial was done")
	}
	if tl, ok := d.back.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(30 * time.Second))
	}
	got, err := d.back.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	_ = got.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(got), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 200 {
		t.Fatalf("the peer got %v, %v, want the 200", m, err)
	}
}

// But only until the stop's deadline (code review of #470): a dial that
// never ends, with an hour of DialTimeout, does not keep Drain past
// drainSendWait.
func TestDrainGivesUpOnADialAtItsDeadline(t *testing.T) {
	drainSendWait = time.Second
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	d := startDialledFinal(t)
	start := time.Now()
	done := d.drain()
	select {
	case <-done:
	case <-time.After(30 * time.Second): // a hang guard, past the deadline
		t.Fatal("Drain waits for the dial past its deadline")
	}
	if took := time.Since(start); took < drainSendWait {
		t.Errorf("Drain returned after %v, before its %v deadline, with the 200 still being dialled", took, drainSendWait)
	}
}

// dialledFinal is a proxy whose 200 to a MESSAGE goes to the Via's address
// once the sender's connection has closed, over a dial that heldDialer
// holds until release, with an hour of DialTimeout so that only release
// ends it.
type dialledFinal struct {
	p       *Proxy
	tr      *transport.Transport
	back    net.Listener
	release func()
}

// startDialledFinal returns once the 200's dial has begun.
func startDialledFinal(t *testing.T) *dialledFinal {
	t.Helper()
	// The peer's own address, where the 200 goes once its connection closed.
	back, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { back.Close() })
	dialing, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{Dialer: heldDialer{dialing: dialing, release: release}, DialTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			<-closed // the peer's connection is gone before the answer
			return Decision{Status: 200}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	// Before p.Close, which waits for the transaction the dial holds.
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	px.Store(p)

	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(nc, fmt.Sprintf("MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP %s;branch=z9hG4bK-redial\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: redial\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n", back.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the connection to be accepted", func() bool { return tr.Stats().OpenInbound == 1 }, func() int64 { return int64(tr.Stats().Accepted) }, tr)
	_ = nc.Close()
	waitUntil(t, "the connection to close", func() bool { return tr.Stats().OpenInbound == 0 }, func() int64 { return int64(tr.Stats().OpenInbound) }, tr)
	close(closed)
	select {
	case <-dialing:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never went to the Via's address")
	}
	return &dialledFinal{p: p, tr: tr, back: back, release: func() { once.Do(func() { close(release) }) }}
}

// drain starts Drain, and then the transport's Close, as pcscf and icscf
// stop, and returns a channel closed once both are done.
func (d *dialledFinal) drain() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		d.p.Drain(ctx)
		_ = d.tr.Close()
		close(done)
	}()
	return done
}

// heldDialer dials once release is closed, and says on dialing that it was
// asked.
type heldDialer struct {
	dialing, release chan struct{}
}

func (d heldDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case d.dialing <- struct{}{}:
	default:
	}
	select {
	case <-d.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

// peerRead waits for the peer's reader to end, the transport closed, and
// returns what it read. A reader still going while it keeps getting bytes
// is waited for; one that gets none for 30 s fails the test with how far it
// got and the transport's stats, rather than hang until the package's
// timeout (#441), and its connection is closed so it ends too.
func peerRead(t *testing.T, read <-chan []byte, progress *atomic.Int64, peer *sipConn, tr *transport.Transport) []byte {
	t.Helper()
	last, lastAt := progress.Load(), time.Now()
	for {
		select {
		case b := <-read:
			return b
		case <-time.After(100 * time.Millisecond):
		}
		if n := progress.Load(); n != last {
			last, lastAt = n, time.Now()
		} else if time.Since(lastAt) > 30*time.Second {
			_ = peer.nc.Close()
			t.Fatalf("the peer read nothing for 30 s after %d bytes, the transport closed: %+v", n, tr.Stats())
		}
	}
}

// A final on its way but not yet at the transport, as when the transaction
// layer has it and has not called SendResponse, is not in progress for
// Drain, and Drain's flush still waits for it: the proxy holds it for
// Transport.Flush until SendResponse counts it, so the Close after Drain
// does not drop it (#469). The test holds the final in that gap until it
// has seen Drain wait past drainFlushStall's reach for the queues, a lower
// bound only.
func TestDrainWaitsForAFinalTheTransactionLayerHas(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	in, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	letGo := func() { once.Do(func() { close(release) }) }
	hold := func() {
		select {
		case in <- struct{}{}:
		default:
		}
		<-release
	}
	handingFinal.Store(&hold)
	t.Cleanup(func() { handingFinal.Store(nil); letGo() })
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{}, func(m transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(m)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tr, Config{
		Self:   []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision { return Decision{Status: 200} }),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t.Cleanup(letGo) // before p.Close, which waits for the held final
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-held-final\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: held-final\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never reached the gap")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		p.Drain(ctx)
		_ = tr.Close() // as pcscf and icscf do
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Drain returned while the 200 was still on its way to the transport")
	case <-time.After(drainFlushStall + 500*time.Millisecond):
	}
	letGo()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain did not return once the 200 was sent")
	}
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(nc), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 200 {
		t.Fatalf("the sender got %v, %v, want the 200", m, err)
	}
}

// A final held when Drain's flush looks, whose send then dials the Via's
// address again, is still waited for: the send counts itself under the
// hold's number, which the flush saw, not under a new one it did not
// (code review of #493, whose repro this is). The dial is held past
// drainFlushStall, a lower bound only.
func TestDrainWaitsForAHeldFinalWhoseSendDialsAgain(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	in, gapRelease := make(chan struct{}, 1), make(chan struct{})
	var gapOnce sync.Once
	letGo := func() { gapOnce.Do(func() { close(gapRelease) }) }
	hold := func() {
		select {
		case in <- struct{}{}:
		default:
		}
		<-gapRelease
	}
	handingFinal.Store(&hold)
	t.Cleanup(func() { handingFinal.Store(nil); letGo() })
	back, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { back.Close() })
	dialing, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{Dialer: heldDialer{dialing: dialing, release: release}, DialTimeout: time.Hour}, func(in transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			<-closed // the sender's connection is gone before the answer
			return Decision{Status: 200}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	// Before p.Close, which waits for the transaction the dial holds.
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	t.Cleanup(letGo)
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(nc, fmt.Sprintf("MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP %s;branch=z9hG4bK-held-redial\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: held-redial\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n", back.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the connection to be accepted", func() bool { return tr.Stats().OpenInbound == 1 }, func() int64 { return int64(tr.Stats().Accepted) }, tr)
	_ = nc.Close()
	waitUntil(t, "the connection to close", func() bool { return tr.Stats().OpenInbound == 0 }, func() int64 { return int64(tr.Stats().OpenInbound) }, tr)
	close(closed)
	select {
	case <-in:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never reached the gap")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		p.Drain(ctx)
		_ = tr.Close() // as pcscf and icscf do
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Drain returned while the 200 was held")
	case <-time.After(300 * time.Millisecond):
	}
	letGo()
	select {
	case <-dialing:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never went to the Via's address")
	}
	select {
	case <-done:
		t.Fatal("Drain returned while the held 200's send was dialling")
	case <-time.After(drainFlushStall + 500*time.Millisecond):
	}
	once.Do(func() { close(release) })
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain did not return once the dial was done")
	}
	if tl, ok := back.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(30 * time.Second))
	}
	got, err := back.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	_ = got.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(got), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 200 {
		t.Fatalf("the peer got %v, %v, want the 200", m, err)
	}
}

// So is a Serve handler's final, held from before UAS.Respond marks the
// request answered, which ends it for Drain, until its send counts it
// (code review of #493).
func TestDrainWaitsForAServedFinalTheTransactionLayerHas(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	in, release := make(chan struct{}, 1), make(chan struct{})
	var once sync.Once
	letGo := func() { once.Do(func() { close(release) }) }
	hold := func() {
		select {
		case in <- struct{}{}:
		default:
		}
		<-release
	}
	handingFinal.Store(&hold)
	t.Cleanup(func() { handingFinal.Store(nil); letGo() })
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{}, func(m transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(m)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	respErr := make(chan error, 1)
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			return Decision{Serve: func(_ context.Context, u *UAS) {
				res, err := sip.NewResponse(u.Request().Message, 200, "", "uas1")
				if err != nil {
					respErr <- err
					return
				}
				respErr <- u.Respond(res)
			}}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	t.Cleanup(letGo) // before p.Close, which waits for the held final
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-uas-gap\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: uas-gap\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(30 * time.Second):
		t.Fatal("the 200 never reached the gap")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		p.Drain(ctx)
		_ = tr.Close() // as pcscf, icscf and rcs-as do
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Drain returned while the served 200 was on its way to the transport")
	case <-time.After(drainFlushStall + 500*time.Millisecond):
	}
	letGo()
	if err := <-respErr; err != nil {
		t.Fatalf("UAS.Respond = %v", err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain did not return once the 200 was sent")
	}
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(nc), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 200 {
		t.Fatalf("the sender got %v, %v, want the 200", m, err)
	}
}

// A Serve handler that answers once Drain's time is up and its context is
// cancelled, as scscf's and pcscf's do, still has its final reach the
// client: Drain waits for it, within its own deadline, before the flush and
// the Close (#499, whose repro this is: the 503 was lost 5 times in 5). The
// handler takes 200 ms over its answer, a lower bound only, so that a Drain
// that did not wait would be done by then; drainSendWait is long, so that
// only the answer ends the wait.
func TestDrainWaitsForAServeHandlerToAnswerItsCancellation(t *testing.T) {
	drainSendWait = time.Hour
	t.Cleanup(func() { drainSendWait = DrainSendWait })
	var px atomic.Pointer[Proxy]
	tr, err := transport.New(transport.Config{}, func(m transport.Inbound) {
		if p := px.Load(); p != nil {
			p.Receive(m)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	serving := make(chan struct{})
	respErr := make(chan error, 1)
	p, err := New(tr, Config{
		Self: []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision {
			return Decision{Serve: func(ctx context.Context, u *UAS) {
				close(serving)
				<-ctx.Done() // the stop
				time.Sleep(200 * time.Millisecond)
				res, err := sip.NewResponse(u.Request().Message, 503, "", "uas1")
				if err != nil {
					respErr <- err
					return
				}
				respErr <- u.Respond(res)
			}}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	px.Store(p)
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if _, err := io.WriteString(nc, "MESSAGE sip:bob@example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-serve-stop\r\nMax-Forwards: 70\r\n"+
		"To: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
		"Call-ID: serve-stop\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serving:
	case <-time.After(30 * time.Second):
		t.Fatal("the request never reached the handler")
	}
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		p.Drain(ctx)
		_ = tr.Close() // as pcscf, icscf and rcs-as do
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Drain and Close did not return")
	}
	if err := <-respErr; err != nil {
		t.Fatalf("UAS.Respond = %v", err)
	}
	_ = nc.SetReadDeadline(time.Now().Add(30 * time.Second))
	m, err := sip.NewReader(bufio.NewReader(nc), sip.Limits{}).ReadMessage()
	if res, ok := m.(*sip.Response); err != nil || !ok || res.StatusCode != 503 {
		t.Fatalf("the sender got %v, %v, want the handler's 503", m, err)
	}
}
