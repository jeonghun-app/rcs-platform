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
// trial decides: a call that started before the breaker last opened is from
// an older cycle, and its end changes nothing, even after the trial closed
// it (#747). Only closed breakers let other calls start, so counting the
// openings alone tells every older call apart.
type breaker struct {
	mu       sync.Mutex
	failures int // in a row
	open     bool
	until    time.Time
	trial    bool   // in flight
	cycle    uint64 // openings so far
}

// ticket is what allow gave a call, for done.
type ticket struct {
	cycle uint64
	trial bool
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

// allow reports whether a call may go to maap at now.
func (b *breaker) allow(now time.Time) (ticket, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case !b.open:
		return ticket{cycle: b.cycle}, true
	case b.trial || now.Before(b.until):
		return ticket{}, false
	}
	b.trial = true
	return ticket{cycle: b.cycle, trial: true}, true
}

// done records how a call allow let through ended at now.
func (b *breaker) done(now time.Time, t ticket, r result) change {
	b.mu.Lock()
	defer b.mu.Unlock()
	if t.trial {
		b.trial = false
	} else if t.cycle != b.cycle {
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
		b.cycle++
		return opened
	}
	return unchanged
}
