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
// answers queued.
func stalledPeerProxy(t *testing.T) (*Proxy, *transport.Transport, netip.AddrPort) {
	t.Helper()
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
		Self:   []sip.URI{mustURI("sip:" + addr.String() + ";lr")},
		Router: RouterFunc(func(context.Context, *Request) Decision { return Decision{Status: 200} }),
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
	// Each 200 carries the request's long Via; the peer reads none of them.
	pad := strings.Repeat("z", 3000)
	go func() {
		for i := 0; ; i++ {
			text := fmt.Sprintf("MESSAGE sip:bob@example.com SIP/2.0\r\n"+
				"Via: SIP/2.0/TCP %s;branch=z9hG4bK-stall-%d;p=%s\r\n"+
				"Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
				"Call-ID: stall-%d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n", peer.nc.LocalAddr(), i, pad, i)
			// Stop past 1 MiB, well short of the queue's limit, so that no
			// answer waits for room in it: Drain would wait for that for
			// DrainSendWait, which these tests make an hour.
			if _, err := io.WriteString(peer.nc, text); err != nil || tr.Stats().QueuedBytes >= 1<<20 {
				return
			}
		}
	}()
	// Well past what the two sockets' buffers take: the writer is stuck.
	queued := func() int64 { return int64(tr.Stats().QueuedBytes) }
	waitUntil(t, "1 MiB queued for the peer that does not read", func() bool { return queued() >= 1<<20 }, queued, tr)
	return p, tr, addr
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
	var draining atomic.Bool
	var px atomic.Pointer[Proxy]
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
				err = u.Respond(res)
				if r.Message.Method == "INFO" {
					// The stalled peer's: the requests it had in flight
					// when it stopped fill its queue, and the answers still
					// waiting for room fail once Drain has begun and the
					// transport closes. Before that, a failure is a broken
					// setup.
					if err != nil && !draining.Load() {
						t.Errorf("answering INFO before Drain: %v", err)
					}
					return
				}
				if err != nil {
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
		stuck := dialSIP(t, addr.String())
		if tc, ok := stuck.nc.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096)
		}
		_ = stuck.nc.SetDeadline(time.Now().Add(time.Hour))
		pad := strings.Repeat("z", 3000)
		go func() {
			for i := 0; ; i++ {
				text := fmt.Sprintf("INFO sip:bob@example.com SIP/2.0\r\n"+
					"Via: SIP/2.0/TCP %s;branch=z9hG4bK-stuck-%d;p=%s\r\n"+
					"Max-Forwards: 70\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=a1\r\n"+
					"Call-ID: stuck-%d\r\nCSeq: 1 INFO\r\nContent-Length: 0\r\n\r\n", stuck.nc.LocalAddr(), i, pad, i)
				// Stop past 1 MiB, well short of the queue's limit, so that
				// no answer waits for room in it: Drain would wait for that
				// for DrainSendWait, an hour here.
				if _, err := io.WriteString(stuck.nc, text); err != nil || tr.Stats().QueuedBytes >= 1<<20 {
					return
				}
			}
		}()
		queued := func() int64 { return int64(tr.Stats().QueuedBytes) }
		waitUntil(t, "1 MiB queued for the peer that does not read", func() bool { return queued() >= 1<<20 }, queued, tr)
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
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 32<<10)
		for {
			n, err := peer.nc.Read(buf)
			got.Write(buf[:n])
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
	draining.Store(true)
	p.Drain(ctx)
	_ = tr.Close()
	r := sip.NewReader(bufio.NewReader(bytes.NewReader(<-read)), sip.Limits{MaxBodyBytes: 1 << 20})
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
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 64<<10)
		for {
			n, err := peer.nc.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				read <- got.Bytes()
				return
			}
			time.Sleep(4 * time.Millisecond)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Drain(ctx)
	_ = tr.Close()
	r := sip.NewReader(bufio.NewReader(bytes.NewReader(<-read)), sip.Limits{})
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
