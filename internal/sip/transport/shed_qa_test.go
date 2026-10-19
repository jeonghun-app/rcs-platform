package transport

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func shedMsg(t *testing.T, body int) *sip.Request {
	req := newRequest(t, "MESSAGE", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKm")
	req.Body = make([]byte, body)
	return req
}

func shedRig(t *testing.T, budget int, lim sip.Limits) *Transport {
	dialer := &pipesDialer{}
	server, _ := newTransport(t, Config{Dialer: dialer, WriteTimeout: time.Hour, MaxQueuedBytes: budget, Limits: lim})
	t.Cleanup(func() {
		dialer.mu.Lock()
		defer dialer.mu.Unlock()
		for _, p := range dialer.peers {
			p.Close()
		}
	})
	listen(t, server, ListenerConfig{Network: TCP, Name: "edge", ClientFacing: true})
	listen(t, server, ListenerConfig{Network: TCP, Name: "core"})
	return server
}

// QA (PR #153, finding 1): senders that find the budget full while another
// sender's scan runs wait for it and use the room it made. Before scans were
// serialized this failed in 107 of 200 runs.
func TestConcurrentBurstAfterAMassStallIsNotRefused(t *testing.T) {
	const budget = 1000 << 10
	server := shedRig(t, budget, sip.Limits{MaxHeaderBytes: 4 << 10, MaxBodyBytes: 16 << 10})
	for i := range 200 {
		f := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), uint16(40000+i)))
		if _, err := server.SendRequest(shedMsg(t, 4864-300), Destination{Flow: f.id}, NoWait); err != nil {
			t.Fatal(err)
		}
		stalled(f)
	}
	var dsts []Destination
	for i := range 8 {
		d := Destination{Network: TCP, Addr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.50"), uint16(5060+i))}
		if _, err := server.SendRequest(shedMsg(t, 10), d); err != nil {
			t.Fatal(err)
		}
		dsts = append(dsts, d)
	}
	var wg sync.WaitGroup
	var refused atomic.Int64
	start := make(chan struct{})
	for g := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := server.SendRequest(shedMsg(t, 3<<10-300), dsts[g%len(dsts)]); err != nil {
				refused.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if s := server.Stats(); refused.Load() > 0 {
		t.Fatalf("%d of 32 concurrent sends refused; one scan shed %d of 200 stalled clients", refused.Load(), s.BudgetSheds)
	}
}

// QA (PR #153, finding 2), with the tech lead's final rule: healthy queues hold
// so much of the budget that no headroom level is reachable, and a scan frees
// a fixed amount rather than everything it can: the shortfall plus 10% of the
// budget, overshooting by at most one client. Here that is all eight stalled
// clients, about 11 KiB, which QA's version of this test called too many;
// the bound is what the tech lead chose to keep a burst moving.
func TestOneScanFreesAtMostTheShortfallPlusTheHeadroom(t *testing.T) {
	const budget = 100 << 10
	server := shedRig(t, budget, sip.Limits{MaxHeaderBytes: 4 << 10, MaxBodyBytes: 64 << 10})
	busy := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.50:5060")}
	for range 2 {
		if _, err := server.SendRequest(shedMsg(t, 44<<10), busy); err != nil {
			t.Fatal(err)
		}
	}
	var clients []*flow
	for i := range 8 {
		f := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), uint16(40000+i)))
		if _, err := server.SendRequest(shedMsg(t, 1100), Destination{Flow: f.id}, NoWait); err != nil {
			t.Fatal(err)
		}
		stalled(f)
		clients = append(clients, f)
	}
	// The busy core peer is reading: not a candidate, but it holds over 88% of the budget.
	server.flows.peer(reuseKey{network: TCP, remote: busy.Addr}).q.progress.Store(time.Now().UnixNano())
	other := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.51:5060")}
	if _, err := server.SendRequest(shedMsg(t, 1700), other); err != nil {
		t.Fatal(err)
	}
	freed := 0
	for _, f := range clients {
		if f.closed.Load() {
			freed += 1100 + 300 // body plus about the header of each
		}
	}
	shortfall := 1940 - (budget - 101300) // QA's figures: the shortfall was 814 B
	if limit := shortfall + budget/10 + 1400; freed > limit {
		t.Fatalf("one scan freed about %d B, past the shortfall plus the headroom (%d B)", freed, limit)
	}
	if freed == 0 {
		t.Fatal("nothing was shed")
	}
}

// QA (PR #153, finding 3): several sheds follow shedRank, clients by fullness
// before stalled core connections.
func TestSheddingSeveralFollowsTheRankOrder(t *testing.T) {
	const budget = 100 << 10
	server := shedRig(t, budget, sip.Limits{MaxHeaderBytes: 4 << 10, MaxBodyBytes: 64 << 10})
	var cores []*flow
	for i, h := range []string{"192.0.2.60:5060", "192.0.2.61:5060"} {
		d := Destination{Network: TCP, Addr: netip.MustParseAddrPort(h)}
		if _, err := server.SendRequest(shedMsg(t, 38<<10+i), d); err != nil {
			t.Fatal(err)
		}
		f := server.flows.peer(reuseKey{network: TCP, remote: d.Addr})
		stalled(f)
		cores = append(cores, f)
	}
	var clients []*flow // body 1..6 KiB: share rises with i
	for i := range 6 {
		f := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), uint16(41000+i)))
		if _, err := server.SendRequest(shedMsg(t, (i+1)<<10), Destination{Flow: f.id}, NoWait); err != nil {
			t.Fatal(err)
		}
		stalled(f)
		clients = append(clients, f)
	}
	fill := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.81"), 42000)) // fresh: not a candidate
	if _, err := server.SendRequest(shedMsg(t, budget-int(server.budget.used.Load())-700), Destination{Flow: fill.id}, NoWait); err != nil {
		t.Fatal(err)
	}
	if _, err := server.SendRequest(shedMsg(t, 1000), Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.62:5060")}); err != nil {
		t.Fatal(err)
	}
	for _, c := range cores {
		if c.closed.Load() {
			t.Error("a stalled core connection was shed while stalled clients remained")
		}
	}
	// Want the two fullest clients shed (5 and 6 KiB), the rest kept.
	for i, f := range clients {
		if want := i >= 4; f.closed.Load() != want {
			t.Errorf("client %d KiB: closed=%v, want %v", i+1, f.closed.Load(), want)
		}
	}
}

// With more stalled clients than the shortfall plus the headroom needs, a scan
// closes only as many as that takes, not all of them.
func TestOneScanLeavesTheStalledClientsItDoesNotNeed(t *testing.T) {
	const budget = 100 << 10
	server := shedRig(t, budget, sip.Limits{MaxHeaderBytes: 4 << 10, MaxBodyBytes: 64 << 10})
	busy := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.50:5060")}
	if _, err := server.SendRequest(shedMsg(t, 40<<10), busy); err != nil {
		t.Fatal(err)
	}
	var clients []*flow
	for i := range 20 {
		f := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), uint16(40000+i)))
		if _, err := server.SendRequest(shedMsg(t, 1100), Destination{Flow: f.id}, NoWait); err != nil {
			t.Fatal(err)
		}
		stalled(f)
		clients = append(clients, f)
	}
	server.flows.peer(reuseKey{network: TCP, remote: busy.Addr}).q.progress.Store(time.Now().UnixNano())
	// A fresh, healthy client fills the budget to within 1 KiB.
	fill := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.81"), 42000))
	if _, err := server.SendRequest(shedMsg(t, budget-int(server.budget.used.Load())-1300), Destination{Flow: fill.id}, NoWait); err != nil {
		t.Fatal(err)
	}
	other := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.51:5060")}
	if _, err := server.SendRequest(shedMsg(t, 1700), other); err != nil {
		t.Fatal(err)
	}
	closed := 0
	for _, f := range clients {
		if f.closed.Load() {
			closed++
		}
	}
	// About 1 KiB short plus 10 KiB of headroom is eight 1.4 KiB clients; nine
	// allows for the estimate. Twenty would be every stalled client.
	if closed == 0 || closed > 9 {
		t.Fatalf("%d of 20 stalled clients shed (%+v)", closed, server.Stats())
	}
}

// QA (PR #153, round 2): once the clients have covered the shortfall, a stalled core connection
// behind them stays open, even when the headroom is out of reach.
func TestStalledCoreStaysOnceClientsCoverTheShortfall(t *testing.T) {
	const budget = 100 << 10
	server := shedRig(t, budget, sip.Limits{MaxHeaderBytes: 4 << 10, MaxBodyBytes: 64 << 10})
	busy := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.50:5060")}
	for range 2 {
		if _, err := server.SendRequest(shedMsg(t, 44<<10), busy); err != nil {
			t.Fatal(err)
		}
	}
	stalledCore := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.60:5060")}
	if _, err := server.SendRequest(shedMsg(t, 5<<10), stalledCore); err != nil {
		t.Fatal(err)
	}
	core := server.flows.peer(reuseKey{network: TCP, remote: stalledCore.Addr})
	stalled(core)
	client := pipeFlow(t, server, "edge", netip.AddrPortFrom(netip.MustParseAddr("192.0.2.80"), 40000))
	if _, err := server.SendRequest(shedMsg(t, 2500), Destination{Flow: client.id}, NoWait); err != nil {
		t.Fatal(err)
	}
	stalled(client)
	server.flows.peer(reuseKey{network: TCP, remote: busy.Addr}).q.progress.Store(time.Now().UnixNano())
	free := budget - int(server.budget.used.Load())
	other := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.51:5060")}
	if _, err := server.SendRequest(shedMsg(t, free+500-300), other); err != nil {
		t.Fatalf("send: %v (%+v)", err, server.Stats())
	}
	if !client.closed.Load() || core.closed.Load() {
		t.Fatalf("client closed=%v (want true), stalled core closed=%v (want false); %+v", client.closed.Load(), core.closed.Load(), server.Stats())
	}
}

// QA (PR #153, round 2): a scan records its time itself, so a second scan within the interval
// closes nothing even though candidates remain.
func TestAScanStartsTheIntervalItself(t *testing.T) {
	r := newBudgetRig(t)
	for _, h := range []string{"192.0.2.1", "192.0.2.2"} {
		if err := r.send(h, 600); err != nil {
			t.Fatal(err)
		}
		stalled(r.flow(h))
	}
	a, b := r.flow("192.0.2.1"), r.flow("192.0.2.2")
	need := 3000 - int(r.tr.budget.used.Load()) + 1
	if n := r.tr.shedStalledQueues(nil, need); n != 1 {
		t.Fatalf("first scan closed %d, want 1", n)
	}
	need = 3000 - int(r.tr.budget.used.Load()) + 3000
	if n := r.tr.shedStalledQueues(nil, need); n != 0 || (a.closed.Load() && b.closed.Load()) {
		t.Fatalf("a second scan within the interval closed %d", n)
	}
}
