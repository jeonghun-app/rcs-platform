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
	// reached holds the marks of MarkReached by recipient, task and kind.
	reached map[string]map[markKey]reachedMark
	// fenced reports whether a Fence holds, from the groups store this
	// one stands beside (SetFence); nil refuses every fenced enqueue.
	fenced func(Fence) bool
}

// SetFence gives s what tells whether a Fence holds (Message.Fence): in
// DynamoDB the groups table, read in the enqueue's own transaction; here
// the groups store, as groupstore.Memory.Fenced. It is called under s's
// lock, and must not call s.
func (s *Memory) SetFence(fenced func(Fence) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fenced = fenced
}

type sentKey struct{ sender, messageID string }

type sentRecord struct {
	Sent
	marks map[string]mark // notification key → the attempt and status
}

type mark struct{ token, status string }

type markKey struct {
	task string
	kind MarkKind
}

type reachedMark struct{ at, expires time.Time }

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{queues: map[string]map[string]Message{}, sent: map[sentKey]*sentRecord{}, reached: map[string]map[markKey]reachedMark{}}
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
	if f := m.Fence; f != nil {
		if s.fenced == nil || !s.fenced(*f) {
			return fmt.Errorf("store: enqueue: %w", ErrNotOwner)
		}
		m.Fence = nil
	}
	q := s.queues[m.Recipient]
	if _, ok := q[m.ID]; ok {
		return fmt.Errorf("store: enqueue: %w", ErrExists)
	}
	var bytes, senderBytes, groupBytes, summaryBytes int64
	senderCount, groupCount, summaryCount := 0, 0, 0
	share, shared := m.ShareKey()
	for _, x := range q {
		bytes += x.Size()
		if k, ok := x.ShareKey(); ok && shared && k == share {
			senderCount, senderBytes = senderCount+1, senderBytes+x.Size()
		}
		if x.InGroupTotal() {
			groupCount, groupBytes = groupCount+1, groupBytes+x.Size()
		}
		if x.InSummaryTotal() {
			summaryCount, summaryBytes = summaryCount+1, summaryBytes+x.Size()
		}
	}
	switch {
	case l.Count > 0 && len(q)+1 > l.Count, l.Bytes > 0 && bytes+m.Size() > l.Bytes:
		return fmt.Errorf("store: enqueue: %w", ErrQueueFull)
	case shared && (l.SenderCount > 0 && senderCount+1 > l.SenderCount || l.SenderBytes > 0 && senderBytes+m.Size() > l.SenderBytes):
		return fmt.Errorf("store: enqueue: %w", ErrSenderShareFull)
	case m.InGroupTotal() && (l.GroupCount > 0 && groupCount+1 > l.GroupCount || l.GroupBytes > 0 && groupBytes+m.Size() > l.GroupBytes):
		return fmt.Errorf("store: enqueue: %w", ErrSenderShareFull)
	case m.InSummaryTotal() && (l.SummaryCount > 0 && summaryCount+1 > l.SummaryCount || l.SummaryBytes > 0 && summaryBytes+m.Size() > l.SummaryBytes):
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

// RemoveSummary implements Store.
func (s *Memory) RemoveSummary(_ context.Context, msg Message, owner string, marks int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.queues[msg.Recipient][msg.ID]
	switch {
	case !ok:
		return nil
	case m.Owner != owner:
		return fmt.Errorf("store: remove summary: %w", ErrConflict)
	}
	if r, ok := s.sent[sentKey{msg.Sender, msg.MessageID}]; ok && r.MarkCount != marks {
		return fmt.Errorf("store: remove summary: %w", ErrMarksChanged)
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
	r = r.Clone()
	r.Marks, r.MarkCount = nil, 0
	s.sent[k] = &sentRecord{Sent: r, marks: map[string]mark{}}
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
	out := r.Sent.Clone()
	out.Marks = make(map[string]string, len(r.marks))
	for k, m := range r.marks {
		out.Marks[k] = m.status
	}
	return out, nil
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
func (s *Memory) MarkNotified(_ context.Context, sender, messageID, key, status, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.live(sender, messageID, now)
	if err != nil {
		return fmt.Errorf("store: mark notified: %w", err)
	}
	if m, ok := r.marks[key]; ok {
		if m.token != token {
			return fmt.Errorf("store: mark notified: %w", ErrExists)
		}
		return nil
	}
	r.marks[key] = mark{token: token, status: status}
	r.MarkCount++
	return nil
}

// UnmarkNotified implements Store.
func (s *Memory) UnmarkNotified(_ context.Context, sender, messageID, key, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.sent[sentKey{sender, messageID}]; ok && r.marks[key].token == token {
		delete(r.marks, key)
	}
	return nil
}

// MarkReached implements Store.
func (s *Memory) MarkReached(_ context.Context, recipient string, m Mark, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reached[recipient] == nil {
		s.reached[recipient] = map[markKey]reachedMark{}
	}
	s.reached[recipient][markKey{m.Task, m.Kind}] = reachedMark{at: m.At, expires: expires}
	return nil
}

// Reached implements Store. Expired marks are deleted on the way.
func (s *Memory) Reached(_ context.Context, recipient string, now time.Time) ([]Mark, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Mark
	for k, m := range s.reached[recipient] {
		if !m.expires.After(now) {
			delete(s.reached[recipient], k)
			continue
		}
		out = append(out, Mark{Task: k.task, Kind: k.kind, At: m.at})
	}
	if len(s.reached[recipient]) == 0 {
		delete(s.reached, recipient)
	}
	return out, nil
}
