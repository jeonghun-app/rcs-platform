package pcscf

import (
	"net/netip"
	"sync"
	"time"
)

// maxLimitedAddrs bounds the client addresses a limiter tracks. Past it the
// buckets that are full again, which carry no state, are dropped; if none is,
// a new address is refused, which a flood of addresses can only cause for
// as long as it lasts.
const maxLimitedAddrs = 100_000

// limiter is a token bucket per client address: rate tokens a second, at
// most burst (#16 question 1). It counts requests, not flows, so a client
// that reconnects does not get a fresh bucket.
type limiter struct {
	rate  float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(rate, burst int, now func() time.Time) *limiter {
	return &limiter{rate: float64(rate), burst: float64(burst), now: now, buckets: map[netip.Addr]*bucket{}}
}

// allow takes a token of addr's bucket, and reports whether there was one.
func (l *limiter) allow(addr netip.Addr) bool {
	t := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[addr]
	if !ok {
		if len(l.buckets) >= maxLimitedAddrs && !l.dropFull(t) {
			return false
		}
		b = &bucket{tokens: l.burst, at: t}
		l.buckets[addr] = b
	}
	b.tokens = min(l.burst, b.tokens+t.Sub(b.at).Seconds()*l.rate)
	b.at = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// dropFull forgets the buckets that have refilled by t, and reports whether
// there is room now.
func (l *limiter) dropFull(t time.Time) bool {
	for a, b := range l.buckets {
		if b.tokens+t.Sub(b.at).Seconds()*l.rate >= l.burst {
			delete(l.buckets, a)
		}
	}
	return len(l.buckets) < maxLimitedAddrs
}

// taskLimit bounds the REGISTERs of all clients of a task together, at rate
// a second with burst. New registrations may take refreshShare less of it;
// what is left is kept for refreshes of registrations the task holds.
type taskLimit struct {
	shared, reserved *limiter
}

// refreshShare is the part of a task's REGISTER rate kept for refreshes, in
// hundredths.
const refreshShare = 25

func newTaskLimit(rate, burst int, now func() time.Time) taskLimit {
	sharedRate, sharedBurst := max(1, rate*(100-refreshShare)/100), max(1, burst*(100-refreshShare)/100)
	return taskLimit{
		shared:   newLimiter(sharedRate, sharedBurst, now),
		reserved: newLimiter(max(1, rate-sharedRate), max(1, burst-sharedBurst), now),
	}
}

// allow takes a token for a REGISTER, a refresh or not, and reports whether
// there was one: a new registration from the shared part only, a refresh
// from either.
func (l taskLimit) allow(refresh bool) bool {
	if l.shared.allow(netip.Addr{}) {
		return true
	}
	return refresh && l.reserved.allow(netip.Addr{})
}
