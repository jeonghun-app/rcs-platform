package maapclient

import (
	"sync"
	"time"
)

// The breaker of each kind of call (ADR 0009 §12).
const (
	breakerFailures = 5
	breakerOpenFor  = 10 * time.Second
)

// breaker opens after breakerFailures failures in a row and then answers at
// once for breakerOpenFor. After that it lets one call through, the trial:
// its success closes the breaker and its failure opens it again. Only the
// trial decides, so a call that started before the breaker opened neither
// closes it nor opens it again when it ends.
type breaker struct {
	mu       sync.Mutex
	failures int // in a row
	open     bool
	until    time.Time
	trial    bool // in flight
}

type result int

const (
	succeeded result = iota
	failed
	abandoned // the caller cancelled: no word on maap
)

type change int

const (
	unchanged change = iota
	opened
	closed
)

// allow reports whether a call may go to maap at now, and whether it is the
// trial.
func (b *breaker) allow(now time.Time) (trial, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case !b.open:
		return false, true
	case b.trial || now.Before(b.until):
		return false, false
	}
	b.trial = true
	return true, true
}

// done records how a call allow let through ended at now.
func (b *breaker) done(now time.Time, trial bool, r result) change {
	b.mu.Lock()
	defer b.mu.Unlock()
	if trial {
		b.trial = false
	} else if b.open {
		return unchanged
	}
	switch r {
	case abandoned:
		return unchanged // an abandoned trial leaves the next call to try
	case succeeded:
		b.failures = 0
		if b.open {
			b.open = false
			return closed
		}
		return unchanged
	}
	// While open, failures stays at breakerFailures or more, so a failed
	// trial opens it again.
	b.failures++
	if b.failures >= breakerFailures {
		b.open, b.until = true, now.Add(breakerOpenFor)
		return opened
	}
	return unchanged
}
