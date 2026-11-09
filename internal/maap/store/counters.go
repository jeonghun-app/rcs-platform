package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Counter names one of the limit counters every task shares (ADR 0009 §9):
// a chatbot's, or, with no chatbot, one of all chatbots (a subscriber's
// from all chatbots). The name is the caller's (#683): the bound and, for
// a bound per subscriber, the subscriber, so it is never logged.
type Counter struct {
	Chatbot string
	Name    string
}

// MaxCounterName bounds a counter's name, which a DynamoDB key holds.
const MaxCounterName = 512

// MaxLimit bounds a limit, far above any of §9, so that a bucket's
// arithmetic cannot overflow.
const MaxLimit = 1_000_000_000

// CheckCounter checks a counter and its limit before any write, so that no
// other value reaches a key: a name is printable ASCII without spaces.
func CheckCounter(c Counter, limit int64) error {
	switch {
	case c.Chatbot != "" && !ValidID(c.Chatbot):
		return fmt.Errorf("%w: a malformed chatbot ID", ErrInvalid)
	case c.Name == "" || len(c.Name) > MaxCounterName ||
		strings.ContainsFunc(c.Name, func(r rune) bool { return r <= ' ' || r > '~' }):
		return fmt.Errorf("%w: a counter name not of 1–%d printable ASCII characters", ErrInvalid, MaxCounterName)
	case limit < 1 || limit > MaxLimit:
		return fmt.Errorf("%w: a limit not from 1 to %d", ErrInvalid, MaxLimit)
	}
	return nil
}

// Take is the answer to a take of one from a counter, and what a
// give-back of it needs.
type Take struct {
	Taken bool
	// Wait is, for a refused take, the time until one can be taken, for
	// Retry-After.
	Wait time.Duration
	// At is the time the take was given. For a bucket's, Full is when the
	// bucket was full again right after it, and Returned what had been
	// given back to the bucket in all until then (GiveBackBucket).
	At, Full time.Time
	Returned time.Duration
}

// Bucket returns the interval at which a bucket of perMinute refills and
// its burst, a sixth of the rate rounded up (ADR 0009 §9). The interval
// is rounded up to the nanosecond, so a bucket never gives more.
func Bucket(perMinute int64) (interval time.Duration, burst int64) {
	return time.Duration((int64(time.Minute) + perMinute - 1) / perMinute), (perMinute + 5) / 6
}

// TakeBucket takes one at now from a bucket that is full again at full
// (the zero time for one never used), and returns when it is full again
// after. A bucket full at full holds burst - (full - now) / interval
// tokens, so this is a token bucket refilled continuously (the generic
// cell rate algorithm): one number, which a conditional update can keep.
// The caller sets the take's Returned.
func TakeBucket(full time.Time, perMinute int64, now time.Time) (time.Time, Take) {
	interval, burst := Bucket(perMinute)
	if full.Before(now) {
		full = now
	}
	if edge := now.Add(time.Duration(burst-1) * interval); full.After(edge) {
		return full, Take{Wait: full.Sub(edge), At: now}
	}
	full = full.Add(interval)
	return full, Take{Taken: true, At: now, Full: full}
}

// GiveBackBucket gives back at now what taken took from a bucket that is
// full again at full and was given back returned in all, and returns the
// bucket's new full and returned.
//
// A give-back returns only what of the take has not refilled since, so
// that the bucket never holds more than an exact token bucket would had
// the take never happened (lead decision on #713, after the #751 review):
// a token refilled while it was out would come back twice. In time, the
// bucket missed taken.Full - taken.At right after the take; since then it
// refilled now - taken.At, and give-backs of older takes, at most what
// those still missed, taken.Full - taken.At - interval, may have refilled
// the rest in its stead. Give-backs of newer takes cannot: each followed
// a take that added the interval it returns at most. So at least
// taken.Full - now less those older give-backs is still missing, of which
// it returns at most an interval; returned - taken.Returned bounds them.
// full never moves before now, a full bucket.
//
// A second give-back of the same take is not told from another's: the
// caller gives back a take once.
func GiveBackBucket(full time.Time, returned time.Duration, perMinute int64, taken Take, now time.Time) (time.Time, time.Duration) {
	interval, _ := Bucket(perMinute)
	older := min(returned-taken.Returned, taken.Full.Sub(taken.At)-interval)
	g := min(interval, taken.Full.Sub(now)-max(0, older))
	if !taken.Taken || returned < taken.Returned || g <= 0 || !full.After(now) {
		// returned below the take's: the item went with its TTL, which
		// comes only once the bucket is full again. With one clock, g is
		// never more than full - now; the last test and the clamp below
		// guard against the clocks of two tasks apart.
		return full, returned
	}
	next := full.Add(-g)
	if next.Before(now) {
		next = now
	}
	return next, returned + full.Sub(next)
}

// DayEnd is the end of now's day, in UTC, when a daily count starts again:
// 09:00 in Korea (KST).
func DayEnd(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}

// Counters is the maap-counters table. Every method is safe for
// concurrent use, also across tasks sharing a backend; a refused take
// changes nothing, so refused requests are not counted (§9). An error is
// a store failure, which callers answer 503, never 429.
//
// A chatbot's counters are not deleted with it: they last a day at most,
// under an ID that is never registered again (lead decision on #713).
type Counters interface {
	// TakeMinute takes one at now from the counter's bucket of perMinute.
	TakeMinute(ctx context.Context, c Counter, perMinute int64, now time.Time) (Take, error)
	// TakeDay takes one at now from the counter's count of now's UTC day,
	// up to perDay.
	TakeDay(ctx context.Context, c Counter, perDay int64, now time.Time) (Take, error)
	// GiveBackMinute and GiveBackDay return, at now, what taken took,
	// when a later counter refuses the request, so that a refused request
	// is not counted (§9): of a bucket, what GiveBackBucket says; of a
	// day, one from the day of the take while its count is above zero.
	// Each is called once for a take, and sent once: a give-back that is
	// lost counts the refused request, the safe side. A give-back of a
	// take that took nothing does nothing. The counter of a chatbot's
	// requests (all endpoints) is never given back: it bounds the rate of
	// refused requests too (lead decision on #713).
	GiveBackMinute(ctx context.Context, c Counter, perMinute int64, taken Take, now time.Time) error
	GiveBackDay(ctx context.Context, c Counter, taken Take) error
}
