package store_test

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
)

func TestMemoryCountersMeetTheContract(t *testing.T) {
	storetest.RunCounters(t, func(*testing.T) (store.Counters, store.Counters) {
		m := store.NewMemoryCounters()
		return m, m
	})
}

// TakeBucket gives what a token bucket counted in exact integers gives:
// capacity burst, refilled continuously at the rate, one per take. Rates
// that divide a minute in nanoseconds keep the interval exact.
func FuzzTakeBucketIsATokenBucket(f *testing.F) {
	f.Add(uint16(60), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 200, 3})
	f.Add(uint16(1), []byte{0, 255, 255})
	f.Add(uint16(6000), []byte{1, 1, 1, 1, 0, 0, 0})
	rates := []int64{1, 2, 3, 5, 6, 7, 8, 12, 20, 30, 60, 100, 600, 1200, 6000}
	f.Fuzz(func(t *testing.T, r uint16, gaps []byte) {
		perMinute := rates[int(r)%len(rates)]
		if int64(time.Minute)%perMinute != 0 {
			perMinute = 60
		}
		burst := (perMinute + 5) / 6
		// The bucket in units of a token / (one minute in nanoseconds):
		// a nanosecond refills perMinute of them.
		unit := int64(time.Minute)
		tokens := burst * unit
		now, full := time.Unix(1_700_000_000, 0), time.Time{}
		for i, g := range gaps {
			step := time.Duration(g) * time.Duration(unit/perMinute) / 16
			now = now.Add(step)
			tokens = min(burst*unit, tokens+int64(step)*perMinute)
			var take store.Take
			full, take = store.TakeBucket(full, perMinute, now)
			want := tokens >= unit
			if want {
				tokens -= unit
			}
			if take.Taken != want {
				t.Fatalf("take %d at rate %d: taken %v, the bucket held %d/%d", i, perMinute, take.Taken, tokens, unit)
			}
			if !want && time.Duration((unit-tokens+perMinute-1)/perMinute) != take.Wait {
				t.Fatalf("take %d: wait %v, the bucket needs %v", i, take.Wait, time.Duration((unit-tokens+perMinute-1)/perMinute))
			}
		}
	})
}

// exactBucket is a token bucket in exact integers, the oracle of the fuzz
// tests: tokens in units of a token / (a minute in nanoseconds), so that a
// nanosecond refills perMinute of them, at rates that divide a minute.
type exactBucket struct {
	perMinute, tokens int64
	at                time.Time
}

func newExact(perMinute int64, at time.Time) *exactBucket {
	return &exactBucket{perMinute, (perMinute + 5) / 6 * int64(time.Minute), at}
}

func (b *exactBucket) refill(now time.Time) {
	b.tokens = min((b.perMinute+5)/6*int64(time.Minute), b.tokens+int64(now.Sub(b.at))*b.perMinute)
	b.at = now
}

// take takes one at now if the bucket holds one.
func (b *exactBucket) take(now time.Time) bool {
	b.refill(now)
	if b.tokens < int64(time.Minute) {
		return false
	}
	b.tokens -= int64(time.Minute)
	return true
}

// A bucket given back to holds no more than an exact token bucket would
// if the takes given back had never happened (lead decision on #713):
// every take a fuzzed run of takes, give-backs of earlier takes and time
// steps lets through, together with the takes not given back, is a run an
// exact bucket lets through, and what the bucket holds at each step is no
// more than that bucket holds.
func FuzzGiveBackNeverPassesAnExactBucket(f *testing.F) {
	f.Add(uint8(4), []byte{0, 0, 0, 2, 40, 1, 0, 3, 200, 5, 9, 0, 1})
	f.Add(uint8(14), []byte{1, 1, 1, 1, 1, 1, 7, 7, 7, 2, 0, 0, 0, 9})
	f.Add(uint8(0), []byte{0, 255, 2, 0, 3, 3})
	rates := []int64{1, 2, 5, 6, 12, 60, 100, 600, 1200, 6000}
	f.Fuzz(func(t *testing.T, r uint8, ops []byte) {
		perMinute := rates[int(r)%len(rates)]
		interval, _ := store.Bucket(perMinute)
		start := time.Unix(1_700_000_000, 0)
		now, full, returned := start, time.Time{}, time.Duration(0)
		type took struct {
			take  store.Take
			given bool
		}
		var takes []took
		for i, op := range ops {
			switch op % 3 {
			case 0: // time goes on, up to about four intervals
				now = now.Add(time.Duration(op/3) * interval / 21)
			case 1:
				var tk store.Take
				full, tk = store.TakeBucket(full, perMinute, now)
				tk.Returned = returned
				if tk.Taken {
					takes = append(takes, took{take: tk})
				}
			case 2: // give back the k-th take still counted
				for k, n := int(op/3), 0; k < len(takes) && n <= len(takes); k = (k + 1) % len(takes) {
					if n++; !takes[k].given {
						full, returned = store.GiveBackBucket(full, returned, perMinute, takes[k].take, now)
						takes[k].given = true
						break
					}
				}
			}
			exact := newExact(perMinute, start)
			for _, x := range takes {
				if !x.given && !exact.take(x.take.At) {
					t.Fatalf("op %d: a take at %v that an exact bucket refuses", i, x.take.At.Sub(start))
				}
			}
			exact.refill(now)
			if held := (perMinute+5)/6*int64(time.Minute) - max(0, int64(full.Sub(now)))*perMinute; held > exact.tokens {
				t.Fatalf("op %d: the bucket holds %d, an exact one %d", i, held, exact.tokens)
			}
		}
	})
}
