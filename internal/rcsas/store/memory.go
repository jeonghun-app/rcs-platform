package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Memory is a Store in process memory, for tests and single-task local runs.
// Several engines sharing one Memory behave like tasks sharing a table.
type Memory struct {
	mu     sync.Mutex
	queues map[string]map[string]Message
	sent   map[sentKey]*sentRecord
}

type sentKey struct{ sender, messageID string }

type sentRecord struct {
	Sent
	marks map[string]string // notification key → token
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{queues: map[string]map[string]Message{}, sent: map[sentKey]*sentRecord{}}
}

// Len reports how many messages recipient's queue holds, claimed, expired
// or not; Pending shows only those ready to deliver. For tests.
func (s *Memory) Len(recipient string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queues[recipient])
}

// Enqueue implements Store.
func (s *Memory) Enqueue(_ context.Context, m Message, l Limit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.queues[m.Recipient]
	if _, ok := q[m.ID]; ok {
		return fmt.Errorf("store: enqueue: %w", ErrExists)
	}
	var bytes, senderBytes, groupBytes int64
	senderCount, groupCount := 0, 0
	share, shared := m.ShareKey()
	for _, x := range q {
		bytes += x.Size()
		if k, ok := x.ShareKey(); ok && shared && k == share {
			senderCount, senderBytes = senderCount+1, senderBytes+x.Size()
		}
		if x.InGroupTotal() {
			groupCount, groupBytes = groupCount+1, groupBytes+x.Size()
		}
	}
	switch {
	case l.Count > 0 && len(q)+1 > l.Count, l.Bytes > 0 && bytes+m.Size() > l.Bytes:
		return fmt.Errorf("store: enqueue: %w", ErrQueueFull)
	case shared && (l.SenderCount > 0 && senderCount+1 > l.SenderCount || l.SenderBytes > 0 && senderBytes+m.Size() > l.SenderBytes):
		return fmt.Errorf("store: enqueue: %w", ErrSenderShareFull)
	case m.InGroupTotal() && (l.GroupCount > 0 && groupCount+1 > l.GroupCount || l.GroupBytes > 0 && groupBytes+m.Size() > l.GroupBytes):
		return fmt.Errorf("store: enqueue: %w", ErrSenderShareFull)
	}
	if q == nil {
		q = map[string]Message{}
		s.queues[m.Recipient] = q
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
	return out[:min(len(out), max(limit, 0))], nil
}

// Claim implements Store.
func (s *Memory) Claim(_ context.Context, recipient, id, owner string, now, until time.Time) (Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.queues[recipient][id]
	switch {
	case !ok:
		return Message{}, fmt.Errorf("store: claim: %w", ErrNotFound)
	case m.Owner == owner && m.LeaseUntil.Equal(until):
		// A repeat of a claim that took effect.
		return m.Clone(), nil
	case !m.Free(now):
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
	m, ok := s.queues[recipient][id]
	switch {
	case !ok || m.Owner == "":
		return nil
	case m.Owner != owner:
		return fmt.Errorf("store: release: %w", ErrConflict)
	}
	m.Owner, m.LeaseUntil = "", time.Time{}
	s.queues[recipient][id] = m
	return nil
}

// Remove implements Store.
func (s *Memory) Remove(_ context.Context, msg Message, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.queues[msg.Recipient][msg.ID]
	switch {
	case !ok:
		return nil
	case m.Owner != owner:
		return fmt.Errorf("store: remove: %w", ErrConflict)
	}
	delete(s.queues[msg.Recipient], msg.ID)
	if len(s.queues[msg.Recipient]) == 0 {
		delete(s.queues, msg.Recipient)
	}
	return nil
}

// Expired implements Store. The cursor is the last key returned.
func (s *Memory) Expired(_ context.Context, now time.Time, cursor string, limit int) ([]Message, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for _, q := range s.queues {
		for _, m := range q {
			if !m.Expires.After(now) && m.Free(now) && expiryKey(m) > cursor {
				out = append(out, Message{Recipient: m.Recipient, ID: m.ID, Expires: m.Expires})
			}
		}
	}
	slices.SortFunc(out, func(a, b Message) int { return strings.Compare(expiryKey(a), expiryKey(b)) })
	if limit <= 0 || len(out) <= limit {
		return out[:min(len(out), max(limit, 0))], "", nil
	}
	out = out[:limit]
	return out, expiryKey(out[limit-1]), nil
}

// expiryKey orders messages by expiry, then queue and ID.
func expiryKey(m Message) string {
	return fmt.Sprintf("%020d\x00%s\x00%s", m.Expires.UnixNano(), m.Recipient, m.ID)
}

// RecordSent implements Store.
func (s *Memory) RecordSent(_ context.Context, r Sent, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sentKey{r.Sender, r.MessageID}
	if old, ok := s.sent[k]; ok && old.Expires.After(now) {
		return fmt.Errorf("store: record sent: %w", ErrExists)
	}
	s.sent[k] = &sentRecord{Sent: r.Clone(), marks: map[string]string{}}
	return nil
}

// Sent implements Store. An expired record is deleted on the way.
func (s *Memory) Sent(_ context.Context, sender, messageID string, now time.Time) (Sent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.live(sender, messageID, now)
	if err != nil {
		return Sent{}, fmt.Errorf("store: sent: %w", err)
	}
	return r.Clone(), nil
}

// live needs s.mu.
func (s *Memory) live(sender, messageID string, now time.Time) (*sentRecord, error) {
	k := sentKey{sender, messageID}
	r, ok := s.sent[k]
	if !ok {
		return nil, ErrNotFound
	}
	if !r.Expires.After(now) {
		delete(s.sent, k)
		return nil, ErrNotFound
	}
	return r, nil
}

// MarkNotified implements Store.
func (s *Memory) MarkNotified(_ context.Context, sender, messageID, key, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.live(sender, messageID, now)
	if err != nil {
		return fmt.Errorf("store: mark notified: %w", err)
	}
	if t, ok := r.marks[key]; ok && t != token {
		return fmt.Errorf("store: mark notified: %w", ErrExists)
	}
	r.marks[key] = token
	return nil
}

// UnmarkNotified implements Store.
func (s *Memory) UnmarkNotified(_ context.Context, sender, messageID, key, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.sent[sentKey{sender, messageID}]; ok && r.marks[key] == token {
		delete(r.marks, key)
	}
	return nil
}
