package regevent

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// qaGate holds every NOTIFY until the test lets one go (one token on
// release per send), then fails it; it counts sends in flight per Call-ID.
type qaGate struct {
	mu      sync.Mutex
	release chan struct{}
	rel     map[string]chan struct{}
	sent    chan string
	busy    map[string]int
	most    map[string]int
	total   map[string]int
	log     []string
	now     func() time.Time
	start   time.Time
}

func newQAGate(now func() time.Time) *qaGate {
	return &qaGate{release: make(chan struct{}), rel: map[string]chan struct{}{}, sent: make(chan string, 1000), busy: map[string]int{}, most: map[string]int{}, total: map[string]int{}, now: now, start: now()}
}

func (s *qaGate) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	cid := req.Header.Get("Call-ID")
	cs, _ := req.Header.CSeq()
	s.mu.Lock()
	s.busy[cid]++
	s.total[cid]++
	s.most[cid] = max(s.most[cid], s.busy[cid])
	s.log = append(s.log, fmt.Sprintf("+%v %s cseq=%d busy=%d", s.now().Sub(s.start), cid, cs.Seq, s.busy[cid]))
	mine := make(chan struct{})
	s.rel[cid] = mine
	s.mu.Unlock()
	s.sent <- cid
	defer func() { s.mu.Lock(); s.busy[cid]--; s.mu.Unlock() }()
	select {
	case <-mine:
	case <-s.release:
	case <-ctx.Done():
	}
	return nil, transport.ErrQueueFull
}

// let fails the sends in flight to cids, and only those.
func (s *qaGate) let(cids []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range cids {
		close(s.rel[c])
	}
}

func (s *qaGate) waitSent(t *testing.T, k int) []string {
	t.Helper()
	var got []string
	for range k {
		select {
		case c := <-s.sent:
			got = append(got, c)
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d sends started: %v", len(got), k, got)
		}
	}
	return got
}

// TestAFinalWaitingBehindItsSetsOthersIsNotSentTwiceAtOnce (QA on #346): a set with k
// subscriptions behind a silent P-CSCF ends on instance A. SetConcurrency
// (2) lets two finals go; the others wait in A's queue for a full
// NotifyTimeout while their pendingEnd runs. B's sweep after pendingEnd
// sends the same finals A is about to send / sending.
func TestAFinalWaitingBehindItsSetsOthersIsNotSentTwiceAtOnce(t *testing.T) {
	for _, k := range []int{4, 8} {
		t.Run(fmt.Sprint(k), func(t *testing.T) { finalsBehindTheirSet(t, k) })
	}
}

func finalsBehindTheirSet(t *testing.T, k int) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour), binding(2, time.Hour))
	n0 := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.MaxPerSubscriber = k })
	for i := range k {
		req := subscribe(t, impu1, pcscfPath, 3600)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("sub-%d", i))
		res, after := n0.Subscribe(bg, req)
		wantStatus(t, res, 200)
		after(bg)
	}
	if got := len(e.subscriptions(impu1)); got != k {
		t.Fatalf("%d subscriptions", got)
	}
	s := newQAGate(e.clock.Now)
	a := newNotifierWith(t, e, e.store, s)
	b := newNotifierWith(t, e, e.store, s)
	if err := a.Ended(bg, before, Rejected); err != nil {
		t.Fatal(err)
	}
	first := s.waitSent(t, DefaultSetConcurrency)
	// The first two wait NotifyTimeout for an answer that never comes.
	e.clock.advance(DefaultNotifyTimeout)
	s.let(first)
	second := s.waitSent(t, DefaultSetConcurrency)
	retried(t, e, len(first))
	// B sweeps a little after pendingEnd from the end (15 s + 1 s).
	e.clock.advance(a.pendingEnd() - DefaultNotifyTimeout + time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = b.Sweep(bg, 10)
	}()
	var third []string
	select {
	case c := <-s.sent:
		third = append(third, c)
	case <-time.After(2 * time.Second):
	}
	time.Sleep(200 * time.Millisecond)
	for len(s.sent) > 0 {
		third = append(third, <-s.sent)
	}
	s.mu.Lock()
	t.Logf("A's first sends %v, then %v; B's sweep sent %v", first, second, third)
	for _, l := range s.log {
		t.Log(l)
	}
	twice := 0
	for cid, m := range s.most {
		if m > 1 {
			twice++
			t.Errorf("%s: %d sends of its final at once", cid, m)
		}
	}
	s.mu.Unlock()
	// Let everything go.
	close(s.release)
	<-done
	a.Wait()
	b.Wait()
	t.Logf("%d of %d subscriptions had their final sent twice at once", twice, k)
}

// TestAFinalWaitingBehindItsHopIsNotSentTwiceAtOnce (QA on #346): 34 sets behind
// one P-CSCF task that died end on A (an RTR each, or a sweep's
// expiries); HopConcurrency (32) lets 32 finals go, two wait a full
// NotifyTimeout. B's sweep after pendingEnd sends those two again.
func TestAFinalWaitingBehindItsHopIsNotSentTwiceAtOnce(t *testing.T) {
	const k = DefaultHopConcurrency + 2
	e := newEnv(t)
	sets := e.otherSets(k, "hop")
	s := newQAGate(e.clock.Now)
	a := newNotifierWith(t, e, e.store, s)
	b := newNotifierWith(t, e, e.store, s)
	for _, r := range sets {
		if err := a.Ended(bg, r, Rejected); err != nil {
			t.Fatal(err)
		}
	}
	first := s.waitSent(t, DefaultHopConcurrency)
	e.clock.advance(DefaultNotifyTimeout)
	s.let(first)
	t.Logf("then %v", s.waitSent(t, 2))
	retried(t, e, len(first))
	e.clock.advance(a.pendingEnd() - DefaultNotifyTimeout + time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = b.Sweep(bg, 100)
	}()
	select {
	case <-s.sent:
	case <-time.After(2 * time.Second):
	}
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	twice := 0
	for cid, m := range s.most {
		if m > 1 {
			twice++
			t.Errorf("%s: %d sends of its final at once", cid, m)
		}
	}
	s.mu.Unlock()
	close(s.release)
	<-done
	a.Wait()
	b.Wait()
	t.Logf("%d of %d sets had their final sent twice at once", twice, k)
}

// retried waits until n finals that failed are kept for their retry
// (retryFinal), so that their sends have ended before the test's clock
// moves on: until then a sweep's takeover would overlap a send whose answer
// is already known, which only a test's goroutines can make happen.
func retried(t *testing.T, e *env, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		subs, err := e.store.ExpiringSubscriptions(bg, e.clock.Now().Add(time.Hour), 1000)
		if err != nil {
			t.Fatal(err)
		}
		k := 0
		for _, sub := range subs {
			if sub.FinalAttempts >= 1 {
				k++
			}
		}
		if k >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d failed finals kept for their retry", k, n)
		}
		time.Sleep(time.Millisecond)
	}
}
