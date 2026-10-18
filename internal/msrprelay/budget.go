package msrprelay

import (
	"net/netip"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// maxBudgetSources bounds how many sources the lookup budget remembers. A
// source is remembered only while its bucket is short of full: a whole
// minute after it was emptied, but one token's worth (half a second at the
// default 120 a minute) after a single failed lookup. So to keep the table
// full, each of 65,536 sources has to fail a lookup about every half
// second, which is a distributed attack in its own right, and one a
// per-source budget does not hold back anyway; that is why a full table
// lets lookups through uncounted rather than refusing them. At about 100
// bytes a source the table is a few MiB at most.
const maxBudgetSources = 1 << 16

// lookupBudget is a token bucket per source (sourceKey) for lookups that
// find no binding. internal/msrp limits unknown sessions per connection,
// which a client resets by reconnecting; this budget outlives connections,
// so a source cannot turn reconnects into an unbounded stream of DynamoDB
// reads, nor fill the bind slots other sources need.
//
// A lookup takes a token before it goes to the store and gives it back
// unless it found nothing. A client that only names sessions pcscf handed
// out almost never spends one, so many such clients behind one
// carrier-grade NAT address do not run the bucket dry.
type lookupBudget struct {
	clock   msrp.Clock
	burst   float64
	perTick float64 // tokens per nanosecond

	mu      sync.Mutex
	buckets map[netip.Prefix]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// newLookupBudget allows perMinute failed lookups per source per minute,
// with a burst of the same size.
func newLookupBudget(clock msrp.Clock, perMinute int) *lookupBudget {
	return &lookupBudget{
		clock:   clock,
		burst:   float64(perMinute),
		perTick: float64(perMinute) / float64(time.Minute),
		buckets: map[netip.Prefix]*bucket{},
	}
}

// take spends a token of key's bucket, reporting false when there is none.
// tracked is false when the table is full of sources that are all short of
// tokens; the lookup is then let through uncounted, since a source spread
// that wide is not held back by a per-source budget anyway.
func (l *lookupBudget) take(key netip.Prefix) (ok, tracked bool) {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= maxBudgetSources {
			l.sweep(now)
			if len(l.buckets) >= maxBudgetSources {
				return true, false
			}
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	l.refill(b, now)
	if b.tokens < 1 {
		return false, true
	}
	b.tokens--
	return true, true
}

// refund gives back the token of a lookup that found its binding, or
// failed for a reason the client did not choose.
func (l *lookupBudget) refund(key netip.Prefix) {
	now := l.clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		return
	}
	l.refill(b, now)
	b.tokens = min(b.tokens+1, l.burst)
	if b.tokens >= l.burst {
		delete(l.buckets, key)
	}
}

func (l *lookupBudget) refill(b *bucket, now time.Time) {
	if d := now.Sub(b.at); d > 0 {
		b.tokens = min(b.tokens+float64(d)*l.perTick, l.burst)
	}
	b.at = now
}

// sweep forgets the sources whose buckets have refilled; a forgotten
// source starts again with a full bucket, which is the same thing. l.mu is
// held.
func (l *lookupBudget) sweep(now time.Time) {
	for key, b := range l.buckets {
		if l.refill(b, now); b.tokens >= l.burst {
			delete(l.buckets, key)
		}
	}
}

// size returns how many sources are remembered, for tests.
func (l *lookupBudget) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
