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

// Take is the answer to a take of one from a counter.
type Take struct {
	Taken bool
	// Wait is, for a refused take, the time until one can be taken, for
	// Retry-After.
	Wait time.Duration
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
func TakeBucket(full time.Time, perMinute int64, now time.Time) (time.Time, Take) {
	interval, burst := Bucket(perMinute)
	if full.Before(now) {
		full = now
	}
	if edge := now.Add(time.Duration(burst-1) * interval); full.After(edge) {
		return full, Take{Wait: full.Sub(edge)}
	}
	return full.Add(interval), Take{Taken: true}
}

// GiveBackBucket returns a token to a bucket that is full again at full,
// for a take at at. Moving full earlier by an interval adds one token,
// and a time before at is a full bucket, so the burst bounds it.
func GiveBackBucket(full time.Time, perMinute int64, at time.Time) time.Time {
	if interval, _ := Bucket(perMinute); full.After(at) {
		return full.Add(-interval)
	}
	return full
}

// DayEnd is the end of now's day, in UTC, when a daily count starts again.
func DayEnd(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}

// Counters is the maap-counters table. Every method is safe for
// concurrent use, also across tasks sharing a backend; a refused take
// changes nothing, so refused requests are not counted (§9). An error is
// a store failure, which callers answer 503, never 429.
type Counters interface {
	// TakeMinute takes one at now from the counter's bucket of perMinute.
	TakeMinute(ctx context.Context, c Counter, perMinute int64, now time.Time) (Take, error)
	// TakeDay takes one at now from the counter's count of now's UTC day,
	// up to perDay.
	TakeDay(ctx context.Context, c Counter, perDay int64, now time.Time) (Take, error)
	// GiveBackMinute and GiveBackDay return what a take at at took, at
	// being the time that take was given, when a later counter refuses the
	// request, so that refused requests are not counted (§9). A bucket
	// never holds more than its burst, nor a day less than nothing: a
	// give-back to a full bucket or an empty day changes nothing.
	GiveBackMinute(ctx context.Context, c Counter, perMinute int64, at time.Time) error
	GiveBackDay(ctx context.Context, c Counter, at time.Time) error
	// DeleteChatbot deletes the chatbot's counters, not those of all
	// chatbots.
	ChatbotDeleter
}
