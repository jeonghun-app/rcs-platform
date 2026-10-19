package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestClientFacingListenersGetASmallSendQueue(t *testing.T) {
	tr, _ := newTransport(t, Config{SendQueueBytes: 1 << 20})
	listen(t, tr, ListenerConfig{Name: "edge", Network: TCP, ClientFacing: true})
	listen(t, tr, ListenerConfig{Name: "core", Network: TCP})
	listen(t, tr, ListenerConfig{Name: "tuned", Network: TCP, ClientFacing: true, SendQueueBytes: 8 << 10})
	for name, want := range map[string]int{"edge": DefaultClientSendQueueBytes, "core": 1 << 20, "tuned": 8 << 10} {
		if got := tr.listenerNamed(name).sendQueue; got != want {
			t.Errorf("%s: send queue %d, want %d", name, got, want)
		}
	}
}

func TestClientThatStopsReadingIsClosedBeforeItsQueuePassesTheListenerLimit(t *testing.T) {
	server, rec := newTransport(t, Config{WriteTimeout: time.Hour})
	addr := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: true})
	c := dialRaw(t, addr) // never read
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	f := server.flows.lookup(id)
	limit := 2 * DefaultClientSendQueueBytes // the NoWait reserve included

	var err error
	for i := 0; i < 1_000_000 && err == nil; i++ {
		req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKflood")
		req.Body = make([]byte, 1000)
		_, err = server.SendRequest(req, Destination{Flow: id}, NoWait)
		if n := f.q.size(); n > limit {
			t.Fatalf("queue reached %d bytes, past the listener's %d", n, limit)
		}
	}
	// The transport closed the connection, so the error says no flow, which a
	// P-CSCF answers with 430.
	if !errors.Is(err, ErrNoFlow) || errors.Is(err, ErrQueueFull) {
		t.Fatalf("flooding a client that does not read ended with %v, want ErrNoFlow", err)
	}
	if _, ok := server.Flow(id); ok {
		t.Fatal("the connection is still open")
	}
	if s := server.Stats(); s.QueueOverflows != 1 || s.QueuedBytes != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// pipesDialer gives every dial a new net.Pipe whose far end nobody reads.
type pipesDialer struct {
	mu    sync.Mutex
	peers []net.Conn
}

func (d *pipesDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	d.mu.Lock()
	d.peers = append(d.peers, b)
	d.mu.Unlock()
	return a, nil
}

// stalled marks a flow's writer as having made no progress for a long time, as
// a peer that stopped reading leaves it; the pipes in these tests stall at
// once, and waiting out the shedding grace for real would only slow the tests.
func stalled(f *flow) { f.q.progress.Store(time.Now().Add(-time.Hour).UnixNano()) }

// budgetRig is a transport with a 3000-byte budget whose dials are pipes no
// one reads, and a sender of ~850-byte MESSAGEs (or larger, with extra body).
type budgetRig struct {
	t      *testing.T
	tr     *Transport
	dialer *pipesDialer
}

func newBudgetRig(t *testing.T) *budgetRig {
	dialer := &pipesDialer{}
	tr, err := New(Config{Dialer: dialer, WriteTimeout: time.Hour, SendQueueBytes: 1 << 20, MaxQueuedBytes: 3000,
		Limits: sip.Limits{MaxHeaderBytes: 1000, MaxBodyBytes: 2000}}, func(Inbound) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tr.Close()
		for _, p := range dialer.peers {
			p.Close()
		}
	})
	listen(t, tr, ListenerConfig{Network: TCP})
	return &budgetRig{t: t, tr: tr, dialer: dialer}
}

func (r *budgetRig) send(host string, body int) error {
	r.t.Helper()
	req := newRequest(r.t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK"+host+strconv.Itoa(body))
	req.Body = make([]byte, body)
	dst := Destination{Network: TCP, Addr: netip.MustParseAddrPort(host + ":5060")}
	return within(r.t, func() error { _, err := r.tr.SendRequest(req, dst); return err })
}

func (r *budgetRig) flow(host string) *flow {
	return r.tr.flows.peer(reuseKey{network: TCP, remote: netip.MustParseAddrPort(host + ":5060")})
}

func TestFullBudgetShedsAStalledConnectionToMakeRoom(t *testing.T) {
	r := newBudgetRig(t)
	for range 3 {
		if err := r.send("192.0.2.1", 600); err != nil {
			t.Fatal(err)
		}
	}
	hog := r.flow("192.0.2.1")
	stalled(hog)
	if err := r.send("192.0.2.2", 600); err != nil {
		t.Fatalf("a send that shedding made room for failed: %v", err)
	}
	if !hog.closed.Load() {
		t.Fatal("the stalled connection was not closed")
	}
	if s := r.tr.Stats(); s.BudgetSheds != 1 || s.BudgetRefusals != 0 || s.QueuedBytes > 3000 || s.OpenOutbound != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// Code review (PR #35, round 3), finding 1: when the budget is full, the send
// fails alone and the sender's healthy connection stays open, whether nothing
// could be shed or what was shed did not free enough.
func TestFullBudgetFailsOnlyTheSendNeverTheSendersConnection(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		stallOthers, stallOwn bool
		sheds                 uint64
	}{
		{"nothing to shed", false, false, 0},
		{"shedding frees too little", true, false, 1},
		{"only the sender has stalled", false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newBudgetRig(t)
			for _, h := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
				if err := r.send(h, 600); err != nil {
					t.Fatal(err)
				}
				if tc.stallOthers {
					stalled(r.flow(h))
				}
			}
			// The sender's connection exists before the budget runs out. It is
			// the one sending, so it is never shed.
			if err := r.send("192.0.2.9", 10); err != nil {
				t.Fatal(err)
			}
			if tc.stallOwn {
				stalled(r.flow("192.0.2.9"))
			}
			err := r.send("192.0.2.9", 1700)
			if !errors.Is(err, ErrQueueFull) || errors.Is(err, ErrNoFlow) {
				t.Fatalf("send = %v, want ErrQueueFull alone", err)
			}
			if f := r.flow("192.0.2.9"); f == nil || f.closed.Load() {
				t.Fatal("the sender's own connection was closed")
			}
			if s := r.tr.Stats(); s.QueueOverflows != 0 || s.BudgetRefusals != 1 || s.BudgetSheds != tc.sheds {
				t.Fatalf("stats = %+v", s)
			}
		})
	}
}

func TestSendQueueBudgetIsReturnedWhenAQueueCloses(t *testing.T) {
	var b queueBudget
	b.max = 1000
	q := newSendQueue(1000, &b)
	if q.push(make([]byte, 400), false, time.Time{}) != pushed || b.used.Load() != 400 {
		t.Fatalf("budget used %d", b.used.Load())
	}
	q.close()
	q.written(400) // a write finishing after the close must not release twice
	if b.used.Load() != 0 {
		t.Fatalf("budget used %d after close", b.used.Load())
	}
	if q.push([]byte("x"), false, time.Time{}) != queueGone {
		t.Fatal("a closed queue accepted a message")
	}
}

func TestFlowIdleTimeoutCanBeShortenedAndTakesEffectAtOnce(t *testing.T) {
	server, rec := newTransport(t, Config{IdleTimeout: time.Hour})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	if !server.SetFlowIdleTimeout(id, time.Nanosecond) {
		t.Fatal("SetFlowIdleTimeout refused a live flow")
	}
	waitClosed(t, c)
	eventually(t, "an idle timeout", func() bool { return server.Stats().IdleTimeouts == 1 })
}

func TestFlowIdleTimeoutCanBeLengthened(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP, IdleTimeout: 300 * time.Millisecond})
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	id := rec.next(t).Source.Flow
	server.SetFlowIdleTimeout(id, time.Hour)
	time.Sleep(600 * time.Millisecond) // past the listener's idle timeout
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK2")))
	if in := rec.next(t); in.Source.Flow != id {
		t.Fatal("the flow was replaced")
	}
	if s := server.Stats(); s.IdleTimeouts != 0 {
		t.Fatalf("the listener's idle timeout still applied: %+v", s)
	}
}

func TestSetFlowIdleTimeoutRefusesWhatItCannotApply(t *testing.T) {
	server, rec := newTransport(t, Config{})
	tcpAddr := listen(t, server, ListenerConfig{Network: TCP})
	udpAddr := listen(t, server, ListenerConfig{Network: UDP})
	c := dialRaw(t, tcpAddr)
	c.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
	tcpFlow := rec.next(t).Source.Flow
	u, err := net.Dial("udp", udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.Write([]byte(rawRequest("REGISTER", "Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK2")))
	udpFlow := rec.next(t).Source.Flow
	for name, ok := range map[string]bool{
		"unknown flow":  server.SetFlowIdleTimeout("unknown", time.Minute),
		"UDP flow":      server.SetFlowIdleTimeout(udpFlow, time.Minute),
		"zero duration": server.SetFlowIdleTimeout(tcpFlow, 0),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Code review (PR #35, round 3), finding 2: core connections have queue limits
// 64 times a client's, so shedding by raw bytes would always close a core link.
// Clients that stopped reading go first; a connection that is making progress
// is never shed.
func TestFullBudgetShedsAStalledClientNotABusyCoreConnection(t *testing.T) {
	for name, coreProgressing := range map[string]bool{"core progressing": true, "core stalled too": false} {
		t.Run(name, func(t *testing.T) {
			dialer := &pipesDialer{}
			server, _ := newTransport(t, Config{Dialer: dialer, WriteTimeout: time.Hour, MaxQueuedBytes: 420 << 10,
				Limits: sip.Limits{MaxHeaderBytes: 16 << 10, MaxBodyBytes: 64 << 10}})
			t.Cleanup(func() {
				for _, p := range dialer.peers {
					p.Close()
				}
			})
			listen(t, server, ListenerConfig{Network: TCP, Name: "edge", ClientFacing: true})
			listen(t, server, ListenerConfig{Network: TCP, Name: "core"})

			// Three client flows on the client-facing listener. Their connections are
			// pipes, which take nothing until read, so a writer that stops is stopped
			// for good; the first two are never read.
			var clients []*flow
			for i := range 3 {
				clients = append(clients, pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), uint16(40000+i))))
			}
			msg := func(body int) *sip.Request {
				req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKm")
				req.Body = make([]byte, body)
				return req
			}
			// The core connection holds about 200 KiB, a twentieth of its limit, and keeps
			// making progress.
			core := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.50:5060")}
			for range 25 {
				if _, err := server.SendRequest(msg(8<<10), core); err != nil {
					t.Fatal(err)
				}
			}
			coreFlow := server.flows.peer(reuseKey{network: TCP, remote: core.Addr})
			// Each stalled client holds about 80% of its 128 KiB reserve, once its
			// writer has filled the kernel's buffers and stopped.
			for _, f := range clients[:2] {
				for f.q.size() < 100<<10 {
					if _, err := server.SendRequest(msg(1<<10), Destination{Flow: f.id}, NoWait); err != nil {
						t.Fatal(err)
					}
				}
				stalled(f)
			}
			if coreProgressing {
				coreFlow.q.progress.Store(time.Now().UnixNano())
			} else {
				// Stalled as well: it holds the most bytes, but a far smaller share of
				// its own limit than the clients do.
				stalled(coreFlow)
			}

			// A message to the third client takes the total past the budget.
			over := 420<<10 - int(server.budget.used.Load()) + 1<<10
			if _, err := server.SendRequest(msg(over), Destination{Flow: clients[2].id}, NoWait); err != nil {
				t.Fatalf("send to the third client: %v", err)
			}
			if coreFlow.closed.Load() {
				t.Fatal("the busy core connection was shed")
			}
			if clients[0].closed.Load() == clients[1].closed.Load() {
				t.Fatalf("want exactly one stalled client shed: %v %v", clients[0].closed.Load(), clients[1].closed.Load())
			}
			if s := server.Stats(); s.BudgetSheds != 1 || s.QueuedBytes > 420<<10 {
				t.Fatalf("stats = %+v", s)
			}
		})
	}
}

// pipeFlow enters an accepted flow on the named listener whose connection is a
// pipe nobody reads, as if a client had connected from remote.
func pipeFlow(t *testing.T, tr *Transport, listener string, remote netip.AddrPort) *flow {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { b.Close() })
	l := tr.listenerNamed(listener)
	f := tr.flows.newFlow(TCP, l, remote)
	f.conn = a
	f.idle.Store(int64(l.idle))
	tr.startWriter(f)
	if !tr.flows.addStream(f) {
		t.Fatal("flow not entered")
	}
	return f
}

func TestNewRefusesABudgetSmallerThanTheLargestMessage(t *testing.T) {
	if _, err := New(Config{MaxQueuedBytes: 4096}, func(Inbound) {}); err == nil {
		t.Fatal("accepted a budget below the default largest message")
	}
	if _, err := New(Config{MaxQueuedBytes: 4096, Limits: sip.Limits{MaxHeaderBytes: 1024, MaxBodyBytes: 3072}}, func(Inbound) {}); err != nil {
		t.Fatalf("refused a budget equal to the largest message: %v", err)
	}
}

// fillQueue makes a flow's queue look full without a writer to drain it.
func fillQueue(f *flow) {
	f.q.mu.Lock()
	defer f.q.mu.Unlock()
	f.q.budget.reserve(f.q.limit)
	f.q.queued += f.q.limit
}

func TestResponseThatCannotBeQueuedClosesAClientFlowButNotACoreOne(t *testing.T) {
	for name, clientFacing := range map[string]bool{"client-facing": true, "core": false} {
		t.Run(name, func(t *testing.T) {
			server, rec := newTransport(t, Config{WriteTimeout: 20 * time.Millisecond})
			addr := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: clientFacing})
			c := dialRaw(t, addr)
			c.Write([]byte(rawRequest("MESSAGE", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1")))
			in := rec.next(t)
			f := server.flows.lookup(in.Source.Flow)
			fillQueue(f)
			err := server.SendResponse(respond(t, in.Message.(*sip.Request), 200), in.Source)
			_, open := server.Flow(in.Source.Flow)
			if clientFacing {
				if !errors.Is(err, ErrNoFlow) || open || server.Stats().ResponseFlowCloses != 1 {
					t.Fatalf("err %v, open %v: a client flow must be closed so the client sees the failure", err, open)
				}
				return
			}
			if !errors.Is(err, ErrQueueFull) || !open {
				t.Fatalf("err %v, open %v: a core flow must stay open", err, open)
			}
		})
	}
}

func TestSheddingPrefersClientsThenTheFullestShareThenTheLongestStall(t *testing.T) {
	tests := []struct {
		name string
		a, b shedRank
	}{
		{"a client before a fuller core connection", shedRank{client: true, share: 0.1}, shedRank{share: 0.9, stalled: time.Hour}},
		{"the fuller share among clients", shedRank{client: true, share: 0.9}, shedRank{client: true, share: 0.5, stalled: time.Hour}},
		{"the fuller share among core connections", shedRank{share: 0.6}, shedRank{share: 0.2}},
		{"the longer stall at equal shares", shedRank{client: true, share: 0.5, stalled: time.Minute}, shedRank{client: true, share: 0.5, stalled: time.Second}},
	}
	for _, tt := range tests {
		if !tt.a.before(tt.b) || tt.b.before(tt.a) {
			t.Errorf("%s: order is wrong", tt.name)
		}
	}
}

func TestQueueThatWasIdleDoesNotLookStalledWhenOutputArrives(t *testing.T) {
	var b queueBudget
	b.max = 1 << 20
	q := newSendQueue(1<<20, &b)
	q.progress.Store(time.Now().Add(-time.Hour).UnixNano()) // idle for an hour
	q.push(make([]byte, 100), false, time.Time{})
	if _, idle := q.stall(time.Now()); idle > time.Second {
		t.Fatalf("a queue that just received output looks stalled for %v", idle)
	}
}

// Code review (PR #35, round 4): a response the transport-wide budget refuses
// says nothing about the client it is for, so that client's flow stays open;
// only a client whose own queue has no room loses its flow.
func TestBudgetRefusalOfAResponseLeavesTheClientFlowOpen(t *testing.T) {
	dialer := &pipesDialer{}
	server, rec := newTransport(t, Config{Dialer: dialer, WriteTimeout: time.Hour, MaxQueuedBytes: 3072,
		Limits: sip.Limits{MaxHeaderBytes: 1024, MaxBodyBytes: 2048}})
	t.Cleanup(func() {
		for _, p := range dialer.peers {
			p.Close()
		}
	})
	edge := listen(t, server, ListenerConfig{Network: TCP, ClientFacing: true})
	listen(t, server, ListenerConfig{Network: TCP, Name: "core"})

	// A client that reads everything it is sent.
	c := dialRaw(t, edge)
	go io.Copy(io.Discard, c)
	c.Write([]byte(rawRequest("MESSAGE", "Via: SIP/2.0/TCP client.example.com;branch=z9hG4bKr")))
	in := rec.next(t)

	// Three core connections fill the budget just now, inside the shedding
	// grace, so none of them can be shed yet.
	for _, h := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK"+h)
		req.Body = make([]byte, 600) // about 850 bytes
		if _, err := server.SendRequest(req, Destination{Network: TCP, Addr: netip.MustParseAddrPort(h + ":5060")}); err != nil {
			t.Fatal(err)
		}
	}

	res := respond(t, in.Message.(*sip.Request), 200)
	res.Body = make([]byte, 1450) // about 1.7 KiB
	err := server.SendResponse(res, in.Source)
	if !errors.Is(err, ErrQueueFull) || errors.Is(err, ErrNoFlow) {
		t.Fatalf("SendResponse = %v, want ErrQueueFull alone", err)
	}
	if _, open := server.Flow(in.Source.Flow); !open {
		t.Fatal("a budget refusal closed a healthy client's flow")
	}
	if s := server.Stats(); s.ResponseFlowCloses != 0 || s.BudgetRefusals != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// push takes an absolute deadline, which write computes once per send, so the
// retry after shedding gives up when the first attempt would have and a send
// blocks for at most WriteTimeout in all.
func TestWaitingPushGivesUpAtItsDeadline(t *testing.T) {
	var b queueBudget
	b.max = 1 << 20
	q := newSendQueue(100, &b)
	q.push(make([]byte, 100), false, time.Time{}) // the queue is now at its limit
	start := time.Now()
	if r := q.push(make([]byte, 100), true, start.Add(-time.Second)); r != waitTimedOut {
		t.Fatalf("push past its deadline = %v, want waitTimedOut", r)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("a push whose deadline had passed waited %v", d)
	}
}

// QA (PR #35, final check): a flow that is already closing frees nothing, so
// it is never chosen, and only a shed that closes something is counted.
func TestSheddingSkipsAFlowThatIsAlreadyClosing(t *testing.T) {
	r := newBudgetRig(t)
	for _, h := range []string{"192.0.2.1", "192.0.2.2"} {
		if err := r.send(h, 600); err != nil {
			t.Fatal(err)
		}
		stalled(r.flow(h))
	}
	closing, other := r.flow("192.0.2.1"), r.flow("192.0.2.2")
	// The fuller of the two candidates, but already on its way out: closeFlow
	// has marked it and not yet closed its connection and queue. The cleanup
	// finishes that close, so the transport's own Close does not wait for this
	// writer forever.
	closing.q.mu.Lock()
	closing.q.budget.reserve(100)
	closing.q.queued += 100
	closing.q.mu.Unlock()
	closing.closed.Store(true)
	t.Cleanup(func() {
		closing.conn.Close()
		closing.q.close()
	})
	if !r.tr.shedStalledQueue(nil) {
		t.Fatal("no connection was shed")
	}
	if !other.closed.Load() {
		t.Fatal("the shed went to the flow that was already closing")
	}
}

func TestSheddingScansAtMostOncePerInterval(t *testing.T) {
	r := newBudgetRig(t)
	if err := r.send("192.0.2.1", 600); err != nil {
		t.Fatal(err)
	}
	f := r.flow("192.0.2.1")
	stalled(f)
	r.tr.lastShedScan.Store(time.Now().UnixNano())
	if r.tr.shedStalledQueue(nil) || f.closed.Load() {
		t.Fatal("a second scan within the interval ran")
	}
	r.tr.lastShedScan.Store(time.Now().Add(-shedScanInterval).UnixNano())
	if !r.tr.shedStalledQueue(nil) || !f.closed.Load() {
		t.Fatal("a scan after the interval did not run")
	}
}
