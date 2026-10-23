package digest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreAcceptsEachCountOnceInsideTheWindow(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	m := NewMemoryNonceCounts(clock.now)
	ctx := context.Background()
	exp := clock.t.Add(time.Hour)
	steps := []struct {
		nonce string
		nc    uint32
		want  bool
	}{
		{"a", 1, true},
		{"a", 1, false},
		{"a", 5, true},
		{"a", 4, true}, // late, but inside the window
		{"a", 4, false},
		{"b", 1, true},
		{"a", 6, true},
		{"a", 7 + NonceCountWindow, true},
		{"a", 6, false}, // used, and now below the window
		{"a", 7, false}, // never used, but below the window
		{"a", 2, false}, // never used, far below
		{"a", 8, true},  // the lowest count inside the window
		{"a", 8, false}, // used
	}
	for i, s := range steps {
		got, err := m.Advance(ctx, "u", s.nonce, s.nc, exp)
		if err != nil || got != s.want {
			t.Fatalf("step %d Advance(%s, %d) = %v, %v; want %v", i, s.nonce, s.nc, got, err, s.want)
		}
	}
}

func TestMemoryStoreForgetsExpiredNonces(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	m := NewMemoryNonceCounts(clock.now)
	ctx := context.Background()
	_, _ = m.Advance(ctx, "u", "old", 3, clock.t.Add(10*time.Second))
	_, _ = m.Advance(ctx, "u", "live", 1, clock.t.Add(time.Hour))

	clock.advance(sweepInterval)
	_, _ = m.Advance(ctx, "u", "trigger", 1, clock.t.Add(time.Hour))
	if m.Len() != 2 {
		t.Fatalf("Len = %d after the sweep, want the two live nonces", m.Len())
	}
	// An expired entry no longer blocks, even before a sweep removes it.
	_, _ = m.Advance(ctx, "u", "short", 9, clock.t.Add(time.Second))
	clock.advance(2 * time.Second)
	if ok, _ := m.Advance(ctx, "u", "short", 9, clock.t.Add(time.Second)); !ok {
		t.Fatal("expired entry still rejected its count")
	}
}

func TestMemoryStoreKeepsSeparateCountsPerUser(t *testing.T) {
	m := NewMemoryNonceCounts(nil)
	exp := time.Now().Add(time.Hour)
	ctx := context.Background()
	if ok, _ := m.Advance(ctx, "bob", "n", 0xffffffff, exp); !ok {
		t.Fatal("first count for bob refused")
	}
	if ok, _ := m.Advance(ctx, "alice", "n", 1, exp); !ok {
		t.Fatal("bob's count blocked alice")
	}
	if ok, _ := m.Advance(ctx, "alice", "n", 1, exp); ok {
		t.Fatal("alice's replay accepted")
	}
}

func TestMemoryStoreDefaultsToTheSystemClock(t *testing.T) {
	m := NewMemoryNonceCounts(nil)
	if ok, err := m.Advance(context.Background(), "u", "n", 1, time.Now().Add(time.Minute)); !ok || err != nil {
		t.Fatalf("Advance = %v, %v", ok, err)
	}
}

func TestMemoryStoreAcceptsEachCountOnceUnderConcurrency(t *testing.T) {
	// Every count of a window arrives twice, from goroutines racing in no
	// particular order: each must be accepted exactly once.
	m := NewMemoryNonceCounts(nil)
	exp := time.Now().Add(time.Hour)
	var accepted [NonceCountWindow + 1]atomic.Int32
	var wg sync.WaitGroup
	for nc := uint32(1); nc <= NonceCountWindow; nc++ {
		for range 2 {
			wg.Go(func() {
				if ok, _ := m.Advance(context.Background(), "u", "n", nc, exp); ok {
					accepted[nc].Add(1)
				}
			})
		}
	}
	wg.Wait()
	for nc := 1; nc <= NonceCountWindow; nc++ {
		if got := accepted[nc].Load(); got != 1 {
			t.Errorf("nc %d accepted %d times", nc, got)
		}
	}
}

func TestUsedCountsAcceptEachCountOnceInsideTheWindow(t *testing.T) {
	var u UsedCounts
	use := func(nc uint32, want bool) {
		t.Helper()
		next, ok := u.Use(nc)
		if ok != want {
			t.Fatalf("Use(%d) after %+v = %v, want %v", nc, u, ok, want)
		}
		if !ok && next != u {
			t.Fatalf("a refused Use(%d) changed %+v to %+v", nc, u, next)
		}
		u = next
	}
	use(3, true)
	use(1, true) // first use need not be nc 1
	use(2, true)
	use(2, false)
	if u != (UsedCounts{Highest: 3, Window: 0b111}) {
		t.Fatalf("record = %+v", u)
	}
	use(3+NonceCountWindow-1, true) // 3 is the lowest count left in the window
	use(3, false)
	use(4, true)
	use(1, false)
	use(3+NonceCountWindow, true) // shifts 3 out
	use(3, false)
	use(0xffffffff, true) // a jump wider than the window keeps only itself
	if u != (UsedCounts{Highest: 0xffffffff, Window: 1}) {
		t.Fatalf("record after a jump = %+v", u)
	}
	use(0xffffffff-NonceCountWindow+1, true)
	use(0xffffffff-NonceCountWindow, false)
}
