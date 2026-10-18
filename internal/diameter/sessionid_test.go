package diameter

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionIDHasTheIdentityAndTheTwoCounterHalves(t *testing.T) {
	start := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	g := NewSessionIDGenerator("scscf-1a.rcs.test", start)
	high := uint32(start.Unix() + ntpUnixOffset)

	first := g.Next("")
	parts := strings.Split(first, ";")
	if len(parts) != 3 || parts[0] != "scscf-1a.rcs.test" || parts[1] != strconv.FormatUint(uint64(high), 10) || parts[2] != "0" {
		t.Fatalf("first Session-Id = %q, want host;%d;0", first, high)
	}
	if second := g.Next(""); second != "scscf-1a.rcs.test;"+strconv.FormatUint(uint64(high), 10)+";1" {
		t.Fatalf("second Session-Id = %q", second)
	}
}

func TestSessionIDCarriesTheOptionalValueLast(t *testing.T) {
	g := NewSessionIDGenerator("hss.rcs.test", time.Unix(0, 0))
	if got := g.Next("reg"); !strings.HasSuffix(got, ";0;reg") {
		t.Fatalf("Next(reg) = %q", got)
	}
}

func TestSessionIDLowHalfCarriesIntoTheHighHalf(t *testing.T) {
	g := NewSessionIDGenerator("h.test", time.Unix(0, 0))
	g.next.Store(5<<32 | 0xffffffff)
	if got := g.Next(""); got != "h.test;5;4294967295" {
		t.Fatalf("Next = %q", got)
	}
	if got := g.Next(""); got != "h.test;6;0" {
		t.Fatalf("Next after the low half wrapped = %q", got)
	}
}

func TestConcurrentSessionIDsAreUnique(t *testing.T) {
	g := NewSessionIDGenerator("h.test", time.Unix(0, 0))
	const workers, each = 8, 500
	var mu sync.Mutex
	seen := make(map[string]bool, workers*each)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				id := g.Next("")
				mu.Lock()
				if seen[id] {
					t.Errorf("duplicate Session-Id %q", id)
				}
				seen[id] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}
