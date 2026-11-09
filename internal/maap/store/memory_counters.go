package store

import (
	"context"
	"sync"
	"time"
)

// MemoryCounters is a Counters in process memory, for tests and local runs.
type MemoryCounters struct {
	mu      sync.Mutex
	buckets map[Counter]time.Time // when each is full again
	days    map[dayKey]int64
}

type dayKey struct {
	c   Counter
	day time.Time
}

var _ Counters = (*MemoryCounters)(nil)

// NewMemoryCounters returns an empty table.
func NewMemoryCounters() *MemoryCounters {
	return &MemoryCounters{buckets: map[Counter]time.Time{}, days: map[dayKey]int64{}}
}

// TakeMinute implements Counters.
func (m *MemoryCounters) TakeMinute(_ context.Context, c Counter, perMinute int64, now time.Time) (Take, error) {
	if err := CheckCounter(c, perMinute); err != nil {
		return Take{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// A refused take leaves the bucket's time as it was.
	full, take := TakeBucket(m.buckets[c], perMinute, now)
	m.buckets[c] = full
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
		return Take{Wait: k.day.Sub(now)}, nil
	}
	m.days[k]++
	return Take{Taken: true}, nil
}

// GiveBackMinute implements Counters.
func (m *MemoryCounters) GiveBackMinute(_ context.Context, c Counter, perMinute int64, at time.Time) error {
	if err := CheckCounter(c, perMinute); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if full, ok := m.buckets[c]; ok {
		m.buckets[c] = GiveBackBucket(full, perMinute, at)
	}
	return nil
}

// GiveBackDay implements Counters.
func (m *MemoryCounters) GiveBackDay(_ context.Context, c Counter, at time.Time) error {
	if err := CheckCounter(c, 1); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if k := (dayKey{c, DayEnd(at)}); m.days[k] > 0 {
		m.days[k]--
	}
	return nil
}

// DeleteChatbot implements ChatbotDeleter.
func (m *MemoryCounters) DeleteChatbot(_ context.Context, chatbotID string) error {
	if !ValidID(chatbotID) {
		return nil // never the counters of all chatbots, which have none
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for c := range m.buckets {
		if c.Chatbot == chatbotID {
			delete(m.buckets, c)
		}
	}
	for k := range m.days {
		if k.c.Chatbot == chatbotID {
			delete(m.days, k)
		}
	}
	return nil
}
