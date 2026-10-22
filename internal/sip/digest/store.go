package digest

import (
	"context"
	"sync"
	"time"
)

// sweepInterval is how often MemoryNonceCounts drops expired entries. Sweeping
// at most once per interval, rather than on every call, keeps Advance cheap.
const sweepInterval = time.Minute

// MemoryNonceCounts is a NonceCountStore in process memory, for tests, local
// runs and single-instance services. It is safe for concurrent use. Instances
// do not share it, so a service with several instances needs a shared store
// instead.
type MemoryNonceCounts struct {
	now func() time.Time

	mu        sync.Mutex
	entries   map[countKey]nonceCount
	lastSweep time.Time
}

type countKey struct{ username, nonce string }

type nonceCount struct {
	used    UsedCounts
	expires time.Time
}

// NewMemoryNonceCounts returns an empty store reading time from now
// (time.Now when nil).
func NewMemoryNonceCounts(now func() time.Time) *MemoryNonceCounts {
	if now == nil {
		now = time.Now
	}
	return &MemoryNonceCounts{now: now, entries: make(map[countKey]nonceCount), lastSweep: now()}
}

// Advance implements NonceCountStore.
func (m *MemoryNonceCounts) Advance(_ context.Context, username, nonce string, nc uint32, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if now.Sub(m.lastSweep) >= sweepInterval {
		for k, e := range m.entries {
			if now.After(e.expires) {
				delete(m.entries, k)
			}
		}
		m.lastSweep = now
	}
	key := countKey{username, nonce}
	var used UsedCounts
	if e, ok := m.entries[key]; ok && !now.After(e.expires) {
		used = e.used
	}
	next, ok := used.Use(nc)
	if !ok {
		return false, nil
	}
	m.entries[key] = nonceCount{used: next, expires: expires}
	return true, nil
}

// Len returns the number of (username, nonce) entries held, for tests and
// metrics.
func (m *MemoryNonceCounts) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// NonceCountWindow is how many nonce-counts, ending at the highest one used
// with a nonce, a NonceCountStore keeps track of. A count inside the window
// that has not been used is accepted even if a higher one came first: an
// HTTP client that gives up on a request whose body failed sends the next
// one at once, and the server may verify that one first (#66). A count below
// the window is refused, as one already used is (RFC 7616 §3.4 asks only
// that a count is not used twice). 32 covers the requests a client has in
// flight on one nonce and fits the record of the window in one uint32.
const NonceCountWindow = 32

// UsedCounts records which nonce-counts have been used with one nonce: the
// highest, and which of the NonceCountWindow counts ending at it. The zero
// value records none. It is what a NonceCountStore keeps per (username,
// nonce).
type UsedCounts struct {
	// Highest is the highest nonce-count used.
	Highest uint32
	// Window has bit i set when Highest-i has been used.
	Window uint32
}

// Use reports whether nc may be accepted after the counts u records, and
// returns the record with nc added. It refuses a count already used and one
// below the window, leaving the record as it is.
func (u UsedCounts) Use(nc uint32) (UsedCounts, bool) {
	switch {
	case u.Window == 0: // none used yet
		return UsedCounts{Highest: nc, Window: 1}, true
	case nc > u.Highest:
		// Shifting by the window's width or more leaves no bit set.
		return UsedCounts{Highest: nc, Window: u.Window<<(nc-u.Highest) | 1}, true
	}
	behind := u.Highest - nc
	if behind >= NonceCountWindow || u.Window&(1<<behind) != 0 {
		return u, false
	}
	u.Window |= 1 << behind
	return u, true
}
