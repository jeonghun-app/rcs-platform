package msrp

import (
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

// isDelivering reports whether a goroutine is delivering s's reports. The
// drainer clears it in the same lock in which it finds nothing left, just
// before it returns, so it tells about this session's drainer alone,
// whatever other sessions are still draining (#265).
func isDelivering(s *Session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.delivering
}

// QA on #259: a slow handler that eventually drains. 10000 reports after the close;
// the drainer exits once done, the goroutine count returns, and a later
// report is still delivered (a new drainer).
//
// #265: every wait is for an event of this session's (its reports all
// handled, its drainer done), and fails only once nothing has moved for
// hangGuard, so a loaded host slows the test without failing it. Another
// session draining meanwhile, as one an earlier test can leave behind,
// changes none of it.
func TestAReportAfterTheDrainStillReachesTheHandler(t *testing.T) {
	var dropped atomic.Int64
	c, p := activeWithPeer(t, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		if e.Kind == EventDropped && e.Err == ErrHandlerBusy {
			dropped.Add(1)
		}
	}})
	// Another session's drainer, stuck in its handler for the whole test.
	stuck := &gatedHandler{gate: make(chan struct{})}
	t.Cleanup(func() { close(stuck.gate) })
	other := newTestSession(t, asURI, clientURI, stuck)
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	other.reportOwn(ownReport(1, 1), nil)

	h := &gatedHandler{delay: 100 * time.Microsecond}
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s.Done(), "session")
	still := func() int64 { return 0 }
	idle := func() bool { return !isDelivering(s) }
	// The report goroutine drains what the close left, possibly nothing,
	// once it is scheduled; until then it is the one that delivers.
	waitProgress(t, "the report goroutine to drain on close", idle, still, nil)
	before := runtime.NumGoroutine()
	const n = 10000
	var afters atomic.Int64
	all := make(chan struct{})
	maxG := 0
	for i := 1; i <= n; i++ {
		s.reportOwn(ownReport(i, n), func() {
			if afters.Add(1) == n {
				close(all)
			}
		})
		if i%500 == 0 {
			if g := runtime.NumGoroutine() - before; g > maxG {
				maxG = g
			}
		}
	}
	closed := func(ch chan struct{}) func() bool {
		return func() bool {
			select {
			case <-ch:
				return true
			default:
				return false
			}
		}
	}
	waitProgress(t, "every report delivered or dropped", closed(all), afters.Load, nil)
	waitProgress(t, "the drainer to exit", idle, still, nil)
	after := runtime.NumGoroutine()
	// The count is the whole binary's, which goroutines of earlier tests
	// ending late move by one or two (#265); one per report would move it
	// by thousands. This session's drainer is known to be done above.
	if g := after - before; g > maxG {
		maxG = g
	}
	got := h.got.Load()
	t.Logf("delivered=%d dropped=%d afters=%d maxGrowth=%d goroutines before=%d after=%d", got, dropped.Load(), afters.Load(), maxG, before, after)
	if got+dropped.Load() != n || maxG > 2 {
		t.Errorf("delivered %d + dropped %d != %d, or the goroutines grew by %d (%d before, %d after)", got, dropped.Load(), n, maxG, before, after)
	}
	last := make(chan struct{})
	s.reportOwn(ownReport(n+1, n+1), func() { close(last) })
	waitProgress(t, "a report after the drain", closed(last), still, nil)
	if h.got.Load() != got+1 {
		t.Fatalf("the handler got %d reports, want %d", h.got.Load(), got+1)
	}
	// Its drainer is done before the test ends, so that none of this
	// test's is left running into the next one.
	waitProgress(t, "the second drainer to exit", idle, still, nil)
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
