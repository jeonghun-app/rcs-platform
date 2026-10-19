package messaging

import (
	"sync"
	"time"
)

// Rate is a token bucket: Burst messages at once, refilled at PerMinute.
// A negative PerMinute disables the limit; in Config, a zero Rate takes the
// default.
type Rate struct {
	PerMinute int
	Burst     int
}

// limiter keeps one bucket per sender. It is per task, not shared: a
// sender spread over n tasks gets up to n times the rate, which is still a
// bound, and a shared counter would put a store write in front of every
// message. maxKeys bounds the memory; at the bound a bucket is forgotten,
// which hands one sender a fresh burst at worst.
//
// Each bucket is kept as the time at which it will be full again (the
// generic cell rate algorithm), so it is exact integer arithmetic on
// durations rather than fractional tokens.
type limiter struct {
	interval  time.Duration // between tokens
	tolerance time.Duration // how far ahead of now a full burst puts the bucket
	maxKeys   int
	mu        sync.Mutex
	full      map[string]time.Time
}

func newLimiter(r Rate, maxKeys int) *limiter {
	l := &limiter{maxKeys: maxKeys, full: map[string]time.Time{}}
	if r.PerMinute > 0 { // otherwise interval stays 0: no limit
		l.interval = time.Minute / time.Duration(r.PerMinute)
		l.tolerance = time.Duration(max(r.Burst, 1)-1) * l.interval
	}
	return l
}

// allow takes a token from key's bucket at now.
func (l *limiter) allow(key string, now time.Time) bool { return l.allowN(key, now, 1) }

// allowN takes n tokens from key's bucket at now, all or none. More than
// a burst's worth is never allowed.
func (l *limiter) allowN(key string, now time.Time, n int) bool {
	if l.interval == 0 || n <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	full, ok := l.full[key]
	if !ok && len(l.full) >= l.maxKeys {
		l.evict(now)
	}
	if full.Before(now) {
		full = now
	}
	if full.Sub(now)+time.Duration(n-1)*l.interval > l.tolerance {
		return false
	}
	l.full[key] = full.Add(time.Duration(n) * l.interval)
	return true
}

// evictScan bounds the buckets evict looks at, so that a full map costs a
// new sender a constant amount of work rather than a pass over every key.
const evictScan = 64

// evict makes room for one bucket. Among up to evictScan buckets, in the
// map's random order, it forgets the full ones, which are the same as no
// bucket; if none is full it forgets the first one it saw.
func (l *limiter) evict(now time.Time) {
	var first string
	n, freed := 0, false
	for k, full := range l.full {
		if n == 0 {
			first = k
		}
		if !full.After(now) {
			delete(l.full, k)
			freed = true
		}
		if n++; n == evictScan {
			break
		}
	}
	if !freed {
		delete(l.full, first)
	}
}

// Limiter is the engine's token bucket per key, for the limits other
// rcs-as packages apply (the group package: per sender and group, per
// group's fan-out). It is safe for concurrent use.
type Limiter struct{ l *limiter }

// NewLimiter returns a Limiter of rate r, keeping at most maxKeys buckets.
func NewLimiter(r Rate, maxKeys int) *Limiter { return &Limiter{newLimiter(r, maxKeys)} }

// Allow takes n tokens from key's bucket at now, all or none.
func (l *Limiter) Allow(key string, now time.Time, n int) bool { return l.l.allowN(key, now, n) }
