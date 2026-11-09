package store

import (
	"context"
	"sync"
	"time"
)

// MemoryCounters is a Counters in process memory, for tests and local runs.
type MemoryCounters struct {
	mu      sync.Mutex
	buckets map[Counter]bucket
	days    map[dayKey]int64
}

// bucket is when a bucket is full again and what it was given back in all.
type bucket struct {
	full     time.Time
	returned time.Duration
}

type dayKey struct {
	c   Counter
	day time.Time
}

var _ Counters = (*MemoryCounters)(nil)

// NewMemoryCounters returns an empty table.
func NewMemoryCounters() *MemoryCounters {
	return &MemoryCounters{buckets: map[Counter]bucket{}, days: map[dayKey]int64{}}
}

// TakeMinute implements Counters.
func (m *MemoryCounters) TakeMinute(_ context.Context, c Counter, perMinute int64, now time.Time) (Take, error) {
	if err := CheckCounter(c, perMinute); err != nil {
		return Take{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// A refused take leaves the bucket's time as it was.
	b := m.buckets[c]
	full, take := TakeBucket(b.full, perMinute, now)
	m.buckets[c] = bucket{full, b.returned}
	if take.Taken {
		take.Returned = b.returned
	}
	return take, nil
}

// TakeDay implements Counters.
func (m *MemoryCounters) TakeDay(_ context.Context, c Counter, perDay int64, now time.Time) (Take, error) {
	if err := CheckCounter(c, perDay); err != nil {
		return Take{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := dayKey{c, DayEnd(now)}
	if m.days[k] >= perDay {
		return Take{Wait: k.day.Sub(now), At: now}, nil
	}
	m.days[k]++
	return Take{Taken: true, At: now}, nil
}

// GiveBackMinute implements Counters.
func (m *MemoryCounters) GiveBackMinute(_ context.Context, c Counter, perMinute int64, taken Take, now time.Time) error {
	if err := CheckCounter(c, perMinute); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.buckets[c]; ok {
		b.full, b.returned = GiveBackBucket(b.full, b.returned, perMinute, taken, now)
		m.buckets[c] = b
	}
	return nil
}

// GiveBackDay implements Counters.
func (m *MemoryCounters) GiveBackDay(_ context.Context, c Counter, taken Take) error {
	if err := CheckCounter(c, 1); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if k := (dayKey{c, DayEnd(taken.At)}); taken.Taken && m.days[k] > 0 {
		m.days[k]--
	}
	return nil
}
