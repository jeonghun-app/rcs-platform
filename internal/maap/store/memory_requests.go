package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryRequests is a Requests in process memory, for tests and local
// runs.
type MemoryRequests struct {
	mu      sync.Mutex
	records map[[2]string]Idempotency // by (chatbot, key)
}

var _ Requests = (*MemoryRequests)(nil)

// NewMemoryRequests returns an empty table.
func NewMemoryRequests() *MemoryRequests {
	return &MemoryRequests{records: map[[2]string]Idempotency{}}
}

// Remember implements Requests.
func (m *MemoryRequests) Remember(_ context.Context, rec Idempotency, now time.Time) (Idempotency, bool, error) {
	if err := CheckIdempotency(rec); err != nil {
		return Idempotency{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := [2]string{rec.Chatbot, rec.Key}
	if old, ok := m.records[k]; ok && Live(old.Created, IdempotencyTTL, now) {
		if old.Digest != rec.Digest {
			return Idempotency{}, false, fmt.Errorf("store: remember request: %w", ErrKeyReused)
		}
		old.Answer = append([]byte(nil), old.Answer...)
		return old, false, nil
	}
	rec.Created, rec.Answer = Seconds(now), append([]byte(nil), rec.Answer...)
	m.records[k] = rec
	return rec, true, nil
}

// DeleteChatbot implements ChatbotDeleter.
func (m *MemoryRequests) DeleteChatbot(_ context.Context, chatbotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.records {
		if k[0] == chatbotID {
			delete(m.records, k)
		}
	}
	return nil
}
