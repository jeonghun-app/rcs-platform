package msrp

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatedHandler blocks HandleReport while gate is open (nil = never blocks) and
// records the order of the ranges it got.
type gatedHandler struct {
	mu    sync.Mutex
	order []int64
	gate  chan struct{}
	delay time.Duration
	got   atomic.Int64
}

func (h *gatedHandler) HandleMessage(*Session, *Message) error { return nil }
func (h *gatedHandler) HandleReport(_ *Session, r Report) {
	h.got.Add(1)
	h.mu.Lock()
	h.order = append(h.order, r.Range.Start)
	g := h.gate
	h.mu.Unlock()
	if g != nil {
		<-g
	}
	if h.delay > 0 {
		time.Sleep(h.delay)
	}
}

func ownReport(i, n int) Report {
	return Report{MessageID: "m", Range: ByteRange{Start: int64(i), End: int64(i), Total: int64(n)}, Code: StatusRequestTimeout}
}

func goroutinesIn(sub string) int {
	n := 0
	for _, g := range bytes.Split(allStacks(), []byte("\n\n")) {
		if bytes.Contains(g, []byte(sub)) {
			n++
		}
	}
	return n
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// QA on #259: a slow handler that eventually drains. 10000 reports after the close;
// the drainer exits once done, the goroutine count returns, and a later
// report is still delivered (a new drainer).
func TestAReportAfterTheDrainStillReachesTheHandler(t *testing.T) {
	var dropped atomic.Int64
	c, p := activeWithPeer(t, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		if e.Kind == EventDropped && e.Err == ErrHandlerBusy {
			dropped.Add(1)
		}
	}})
	h := &gatedHandler{delay: 100 * time.Microsecond}
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s.Done(), "session")
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	const n = 10000
	var afters atomic.Int64
	maxG := 0
	for i := 1; i <= n; i++ {
		s.reportOwn(ownReport(i, n), func() { afters.Add(1) })
		if i%500 == 0 {
			if g := runtime.NumGoroutine() - before; g > maxG {
				maxG = g
			}
		}
	}
	waitUntil(t, "every report delivered or dropped", func() bool { return afters.Load() == n })
	waitUntil(t, "the drainer to exit", func() bool { return goroutinesIn("(*Session).drain") == 0 })
	time.Sleep(20 * time.Millisecond)
	after := runtime.NumGoroutine()
	got := h.got.Load()
	t.Logf("delivered=%d dropped=%d afters=%d maxGrowth=%d goroutines before=%d after=%d", got, dropped.Load(), afters.Load(), maxG, before, after)
	if got+dropped.Load() != n || maxG > 2 || after > before {
		t.Errorf("delivered %d + dropped %d != %d, or growth %d, or %d goroutines left over %d", got, dropped.Load(), n, maxG, after, before)
	}
	s.reportOwn(ownReport(n+1, n+1), nil)
	waitUntil(t, "a report after the drain", func() bool { return h.got.Load() == got+1 })
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := 1; i < len(h.order); i++ {
		if h.order[i] < h.order[i-1] {
			t.Fatalf("out of order at %d: %v then %v", i, h.order[i-1], h.order[i])
		}
	}
}

// QA on #259: the bound is the connection's MaxHandlerQueue, exactly: one in the
// handler and MaxHandlerQueue waiting.
func TestTheBoundAfterACloseIsTheConfiguredQueueExactly(t *testing.T) {
	for _, limit := range []int{4, 256} {
		var dropped atomic.Int64
		cfg := Config{Clock: newFakeClock(), MaxHandlerQueue: limit, OnEvent: func(e Event) {
			if e.Kind == EventDropped && e.Err == ErrHandlerBusy {
				dropped.Add(1)
			}
		}}
		c, p := activeWithPeer(t, cfg)
		h := &gatedHandler{gate: make(chan struct{})}
		t.Cleanup(func() { close(h.gate) })
		s := newTestSession(t, clientURI, asURI, h)
		openWithPeer(t, c, p, s)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		waitDone(t, s.Done(), "session")
		const n = 1000
		s.reportOwn(ownReport(1, n), nil)
		waitUntil(t, "the first in the handler", func() bool { return h.got.Load() == 1 })
		for i := 2; i <= n; i++ {
			s.reportOwn(ownReport(i, n), nil)
		}
		if want := int64(n - 1 - limit); dropped.Load() != want {
			t.Errorf("limit %d: dropped %d, want %d", limit, dropped.Load(), want)
		}
	}
}
