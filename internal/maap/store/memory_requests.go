package store

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// MemoryRequests is a Requests in process memory, for tests and local
// runs.
type MemoryRequests struct {
	statusTTL time.Duration
	mu        sync.Mutex
	records   map[[2]string]Idempotency // by (chatbot, key)
	statuses  map[[2]string]Status      // by (chatbot, Message-ID)
}

var _ Requests = (*MemoryRequests)(nil)

// NewMemoryRequests returns an empty table that keeps statuses for
// statusTTL.
func NewMemoryRequests(statusTTL time.Duration) *MemoryRequests {
	return &MemoryRequests{statusTTL: statusTTL, records: map[[2]string]Idempotency{}, statuses: map[[2]string]Status{}}
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

// Accept implements Requests.
func (m *MemoryRequests) Accept(_ context.Context, chatbotID, messageID string, now time.Time) error {
	if err := checkStatusKey(chatbotID, messageID); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.live(chatbotID, messageID, now); !ok {
		now = Seconds(now)
		m.statuses[[2]string{chatbotID, messageID}] = Status{chatbotID, messageID, Accepted, now, now}
	}
	return nil
}

// Status implements Requests.
func (m *MemoryRequests) Status(_ context.Context, chatbotID, messageID string, now time.Time) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.live(chatbotID, messageID, now); ok {
		return st, nil
	}
	return Status{}, fmt.Errorf("store: status: %w", ErrNotFound)
}

// Advance implements Requests.
func (m *MemoryRequests) Advance(_ context.Context, chatbotID, messageID string, state StatusState, now time.Time) (bool, error) {
	if err := CheckAdvance(chatbotID, messageID, state); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.live(chatbotID, messageID, now)
	switch {
	case !ok:
		return false, fmt.Errorf("store: advance status: %w", ErrNotFound)
	case !slices.Contains(state.Before(), st.State):
		return false, nil
	}
	st.State, st.Updated = state, Seconds(now)
	m.statuses[[2]string{chatbotID, messageID}] = st
	return true, nil
}

func (m *MemoryRequests) live(chatbotID, messageID string, now time.Time) (Status, bool) {
	st, ok := m.statuses[[2]string{chatbotID, messageID}]
	return st, ok && Live(st.Accepted, m.statusTTL, now)
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
	for k := range m.statuses {
		if k[0] == chatbotID {
			delete(m.statuses, k)
		}
	}
	return nil
}
