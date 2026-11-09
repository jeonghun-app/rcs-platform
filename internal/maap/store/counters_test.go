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

// A give-back undoes the take it follows, and a bucket given back to
// never holds more than its burst, checked against the exact integer
// bucket of FuzzTakeBucketIsATokenBucket.
func FuzzGiveBackBucketNeverPassesTheBurst(f *testing.F) {
	f.Add([]byte{0, 0, 1, 1, 1, 0, 0, 200, 1, 1, 1, 1})
	f.Fuzz(func(t *testing.T, ops []byte) {
		const perMinute = 60 // a second a token, a burst of 10
		unit, burst := int64(time.Minute), int64(10)
		tokens := burst * unit
		now, full := time.Unix(1_700_000_000, 0), time.Time{}
		for i, op := range ops {
			step := time.Duration(op>>1) * 125 * time.Millisecond
			now = now.Add(step)
			tokens = min(burst*unit, tokens+int64(step)*perMinute)
			if op&1 == 1 {
				full = store.GiveBackBucket(full, perMinute, now)
				tokens = min(burst*unit, tokens+unit)
				continue
			}
			var take store.Take
			full, take = store.TakeBucket(full, perMinute, now)
			if want := tokens >= unit; take.Taken != want {
				t.Fatalf("op %d: taken %v, the bucket held %d/%d", i, take.Taken, tokens, unit)
			}
			if take.Taken {
				tokens -= unit
			}
		}
	})
}
