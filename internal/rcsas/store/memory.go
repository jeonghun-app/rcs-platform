package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Memory is a Store in process memory, for tests and single-task local runs.
// Several engines sharing one Memory behave like tasks sharing a table.
type Memory struct {
	mu     sync.Mutex
	queues map[string]map[string]Message
	sent   map[sentKey]Sent
}

type sentKey struct{ sender, messageID string }

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{queues: map[string]map[string]Message{}, sent: map[sentKey]Sent{}}
}

// Enqueue implements Store.
func (s *Memory) Enqueue(_ context.Context, m Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.queues[m.Recipient]
	if q == nil {
		q = map[string]Message{}
		s.queues[m.Recipient] = q
	}
	if _, ok := q[m.ID]; ok {
		return fmt.Errorf("store: enqueue: %w", ErrExists)
	}
	m = m.Clone()
	m.Owner, m.LeaseUntil = "", time.Time{}
	q[m.ID] = m
	return nil
}

// Pending implements Store.
func (s *Memory) Pending(_ context.Context, recipient, after string, now time.Time, limit int) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for _, m := range s.queues[recipient] {
		if m.ID > after && m.Free(now) && m.Expires.After(now) {
			out = append(out, m.Clone())
		}
	}
	slices.SortFunc(out, func(a, b Message) int { return cmp.Compare(a.ID, b.ID) })
	return out[:min(len(out), limit)], nil
}

// Claim implements Store.
func (s *Memory) Claim(_ context.Context, recipient, id, owner string, now, until time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.queues[recipient][id]
	if !ok {
		return Message{}, fmt.Errorf("store: claim: %w", ErrNotFound)
	}
	if !m.Free(now) {
		return Message{}, fmt.Errorf("store: claim: %w", ErrConflict)
	}
	m.Owner, m.LeaseUntil = owner, until
	s.queues[recipient][id] = m
	return m.Clone(), nil
}

// Release implements Store.
func (s *Memory) Release(_ context.Context, recipient, id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.held(recipient, id, owner)
	if err != nil {
		return fmt.Errorf("store: release: %w", err)
	}
	m.Owner, m.LeaseUntil = "", time.Time{}
	s.queues[recipient][id] = m
	return nil
}

// Remove implements Store.
func (s *Memory) Remove(_ context.Context, recipient, id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.held(recipient, id, owner); err != nil {
		return fmt.Errorf("store: remove: %w", err)
	}
	delete(s.queues[recipient], id)
	if len(s.queues[recipient]) == 0 {
		delete(s.queues, recipient)
	}
	return nil
}

func (s *Memory) held(recipient, id, owner string) (Message, error) {
	m, ok := s.queues[recipient][id]
	switch {
	case !ok:
		return Message{}, ErrNotFound
	case m.Owner != owner:
		return Message{}, ErrConflict
	}
	return m, nil
}

// Expired implements Store.
func (s *Memory) Expired(_ context.Context, now time.Time, limit int) ([]Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for _, q := range s.queues {
		for _, m := range q {
			if !m.Expires.After(now) && m.Free(now) {
				out = append(out, m.Clone())
			}
		}
	}
	slices.SortFunc(out, func(a, b Message) int {
		return cmp.Or(a.Expires.Compare(b.Expires), cmp.Compare(a.Recipient, b.Recipient), cmp.Compare(a.ID, b.ID))
	})
	return out[:min(len(out), limit)], nil
}

// RecordSent implements Store.
func (s *Memory) RecordSent(_ context.Context, r Sent, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sentKey{r.Sender, r.MessageID}
	if old, ok := s.sent[k]; ok && old.Expires.After(now) {
		return fmt.Errorf("store: record sent: %w", ErrExists)
	}
	s.sent[k] = r.Clone()
	return nil
}

// Sent implements Store. An expired record is deleted on the way.
func (s *Memory) Sent(_ context.Context, sender, messageID string, now time.Time) (Sent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sentKey{sender, messageID}
	r, ok := s.sent[k]
	if !ok {
		return Sent{}, fmt.Errorf("store: sent: %w", ErrNotFound)
	}
	if !r.Expires.After(now) {
		delete(s.sent, k)
		return Sent{}, fmt.Errorf("store: sent: %w", ErrNotFound)
	}
	return r.Clone(), nil
}
