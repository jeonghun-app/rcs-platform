package digest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreAcceptsOnlyIncreasingCounts(t *testing.T) {
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
		{"a", 4, false},
		{"b", 1, true},
		{"a", 6, true},
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
	if ok, _ := m.Advance(ctx, "u", "short", 1, clock.t.Add(time.Second)); !ok {
		t.Fatal("expired entry still rejected a count")
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
	m := NewMemoryNonceCounts(nil)
	exp := time.Now().Add(time.Hour)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if ok, _ := m.Advance(context.Background(), "u", "n", 1, exp); ok {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("nc 1 accepted %d times", accepted.Load())
	}
}
