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
	entries   map[string]nonceCount
	lastSweep time.Time
}

type nonceCount struct {
	nc      uint32
	expires time.Time
}

// NewMemoryNonceCounts returns an empty store reading time from now
// (time.Now when nil).
func NewMemoryNonceCounts(now func() time.Time) *MemoryNonceCounts {
	if now == nil {
		now = time.Now
	}
	return &MemoryNonceCounts{now: now, entries: make(map[string]nonceCount), lastSweep: now()}
}

// Advance implements NonceCountStore.
func (m *MemoryNonceCounts) Advance(_ context.Context, nonce string, nc uint32, expires time.Time) (bool, error) {
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
	if e, ok := m.entries[nonce]; ok && nc <= e.nc && !now.After(e.expires) {
		return false, nil
	}
	m.entries[nonce] = nonceCount{nc: nc, expires: expires}
	return true, nil
}

// Len returns the number of nonces held, for tests and metrics.
func (m *MemoryNonceCounts) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}
