package msrp

import (
	"bytes"
	"context"
	"fmt"
	"runtime/pprof"
	"strconv"
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

// labelled runs f with the pprof label session=<s>. Goroutines inherit the
// labels of the goroutine that starts them, so a drainer that reportOwn
// starts within f carries the label from its creation on, before it has
// run at all, and no other session's does (#265).
func labelled(s *Session, f func()) {
	pprof.Do(context.Background(), pprof.Labels("session", fmt.Sprintf("%p", s)), func(context.Context) { f() })
}

// labelledGoroutines counts the goroutines carrying s's label, from the
// goroutine profile: each record starts "N @ ..." and has a "# labels:"
// line. Called outside labelled, it does not count the caller.
func labelledGoroutines(t *testing.T, s *Session) int {
	t.Helper()
	var b bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&b, 1); err != nil {
		t.Fatal(err)
	}
	want := []byte(fmt.Sprintf(`# labels: {"session":"%p"}`, s))
	n, count := 0, 0
	for _, line := range bytes.Split(b.Bytes(), []byte("\n")) {
		if c, _, ok := bytes.Cut(line, []byte(" @ ")); ok {
			var err error
			if count, err = strconv.Atoi(string(c)); err != nil {
				t.Fatalf("goroutine profile line %q", line)
			}
		} else if bytes.Equal(line, want) {
			n += count
		}
	}
	return n
}

// QA on #259: a slow handler that eventually drains. 10000 reports after the close;
// the drainer exits once done, the goroutine count returns, and a later
// report is still delivered (a new drainer).
//
// #265: every wait is for this session's own events: its reports all
// handled, which fails only once the count has not moved for hangGuard,
// and single steps (a drainer gone, one report handled), each bounded by
// hangGuard. The goroutines counted are those carrying the session's
// label, so another session draining meanwhile, as one an earlier test can
// leave behind, changes none of it.
func TestAReportAfterTheDrainStillReachesTheHandler(t *testing.T) {
	var dropped atomic.Int64
	c, p := activeWithPeer(t, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		if e.Kind == EventDropped && e.Err == ErrHandlerBusy {
			dropped.Add(1)
		}
	}})
	// Another session's drainer, stuck in its handler for the whole test.
	// It runs under a label of its own, so that the cleanup can wait for it
	// to return as well, and the test leaves no goroutine behind.
	stuck := &gatedHandler{gate: make(chan struct{})}
	other := newTestSession(t, asURI, clientURI, stuck)
	t.Cleanup(func() {
		close(stuck.gate)
		waitProgress(t, "the other session's drainer to exit", func() bool {
			return !isDelivering(other) && labelledGoroutines(t, other) == 0
		}, func() int64 { return 0 }, nil)
	})
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	labelled(other, func() { other.reportOwn(ownReport(1, 1), nil) })

	h := &gatedHandler{delay: 100 * time.Microsecond}
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s.Done(), "session")
	still := func() int64 { return 0 }
	// The report goroutine drains what the close left, possibly nothing,
	// once it is scheduled; until then it is the one that delivers. It was
	// started at the bind, without the label.
	waitProgress(t, "the report goroutine to drain on close", func() bool { return !isDelivering(s) }, still, nil)
	// Gone: the drainer cleared delivering and has returned.
	gone := func() bool { return !isDelivering(s) && labelledGoroutines(t, s) == 0 }
	const n = 10000
	var afters atomic.Int64
	all := make(chan struct{})
	maxG := 0
	labelled(s, func() {
		for i := 1; i <= n; i++ {
			s.reportOwn(ownReport(i, n), func() {
				if afters.Add(1) == n {
					close(all)
				}
			})
			if i%500 == 0 {
				// A report was just queued, or dropped for a full queue,
				// so a drainer is running. The count includes this
				// goroutine, which runs with the label; a drainer that has
				// let go of delivering may not have returned yet when the
				// next one starts, so two at a time can be seen.
				maxG = max(maxG, labelledGoroutines(t, s)-1)
			}
		}
	})
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
	waitProgress(t, "the drainer to exit", gone, still, nil)
	got := h.got.Load()
	t.Logf("delivered=%d dropped=%d afters=%d drainers at most %d", got, dropped.Load(), afters.Load(), maxG)
	if got+dropped.Load() != n || maxG < 1 || maxG > 2 {
		t.Errorf("delivered %d + dropped %d != %d, or %d drainers at most, want one or two", got, dropped.Load(), n, maxG)
	}
	last := make(chan struct{})
	labelled(s, func() { s.reportOwn(ownReport(n+1, n+1), func() { close(last) }) })
	waitProgress(t, "a report after the drain", closed(last), still, nil)
	if h.got.Load() != got+1 {
		t.Fatalf("the handler got %d reports, want %d", h.got.Load(), got+1)
	}
	// Its drainer is done before the test ends, so that none of this
	// test's is left running into the next one.
	waitProgress(t, "the second drainer to exit", gone, still, nil)
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
