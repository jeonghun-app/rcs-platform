package state

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Memory is a Store in process memory, for tests and for a single instance in
// development. Several S-CSCF handles sharing one Memory behave as instances
// sharing DynamoDB. It hands out copies, so callers cannot change what it holds.
type Memory struct {
	mu            sync.Mutex
	registrations map[string]*Registration
	challenges    map[challengeKey]*Challenge
	subscriptions map[string]*Subscription
}

type challengeKey struct{ impi, nonce string }

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		registrations: map[string]*Registration{},
		challenges:    map[challengeKey]*Challenge{},
		subscriptions: map[string]*Subscription{},
	}
}

// Registration implements Registrations.
func (m *Memory) Registration(_ context.Context, impu string) (*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.registrations[impu]
	if !ok {
		return nil, fmt.Errorf("state: registration: %w", ErrNotFound)
	}
	return r.Clone(), nil
}

// RegistrationsOf implements Registrations.
func (m *Memory) RegistrationsOf(_ context.Context, impi string) ([]*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Registration
	for _, r := range m.registrations {
		if r.IMPI == impi {
			out = append(out, r.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Registration) int { return strings.Compare(a.IMPU, b.IMPU) })
	return out, nil
}

// SaveRegistration implements Registrations.
func (m *Memory) SaveRegistration(_ context.Context, r *Registration) (*Registration, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.registrations[r.IMPU]
	if err := checkVersion("registration", ok, cur.versionOrZero(), r.Version); err != nil {
		return nil, err
	}
	saved := r.Clone()
	saved.Version = r.Version + 1
	m.registrations[r.IMPU] = saved
	return saved.Clone(), nil
}

func (r *Registration) versionOrZero() int64 {
	if r == nil {
		return 0
	}
	return r.Version
}

// checkVersion applies the optimistic concurrency rule of the Save methods.
func checkVersion(what string, exists bool, stored, given int64) error {
	switch {
	case given == 0 && exists:
		return fmt.Errorf("state: save %s: %w", what, ErrExists)
	case given != 0 && !exists:
		return fmt.Errorf("state: save %s: %w", what, ErrNotFound)
	case given != 0 && stored != given:
		return fmt.Errorf("state: save %s: %w", what, ErrConflict)
	}
	return nil
}

// DeleteRegistration implements Registrations.
func (m *Memory) DeleteRegistration(_ context.Context, r *Registration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.registrations[r.IMPU]
	if err := checkDelete("registration", ok, cur.versionOrZero(), r.Version); err != nil {
		return err
	}
	delete(m.registrations, r.IMPU)
	return nil
}

func checkDelete(what string, exists bool, stored, given int64) error {
	if !exists {
		return fmt.Errorf("state: delete %s: %w", what, ErrNotFound)
	}
	if stored != given {
		return fmt.Errorf("state: delete %s: %w", what, ErrConflict)
	}
	return nil
}

// ExpiringRegistrations implements Registrations, earliest expiry first.
func (m *Memory) ExpiringRegistrations(_ context.Context, now time.Time, limit int) ([]*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Registration
	for _, r := range m.registrations {
		if len(r.Contacts) == 0 || !r.NextExpiry().After(now) {
			out = append(out, r.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Registration) int { return a.NextExpiry().Compare(b.NextExpiry()) })
	return out[:min(len(out), max(limit, 0))], nil
}

// AddChallenge implements Challenges.
func (m *Memory) AddChallenge(_ context.Context, c *Challenge) error {
	if err := c.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := challengeKey{c.IMPI, c.Nonce}
	if _, ok := m.challenges[k]; ok {
		return fmt.Errorf("state: add challenge: %w", ErrExists)
	}
	m.challenges[k] = c.Clone()
	return nil
}

// Challenge implements Challenges.
func (m *Memory) Challenge(_ context.Context, impi, nonce string, now time.Time) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.live(impi, nonce, now)
	if !ok {
		return nil, fmt.Errorf("state: challenge: %w", ErrNotFound)
	}
	return c.Clone(), nil
}

// TakeChallenge implements Challenges.
func (m *Memory) TakeChallenge(_ context.Context, impi, nonce string, now time.Time) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.live(impi, nonce, now)
	if !ok {
		return nil, fmt.Errorf("state: take challenge: %w", ErrNotFound)
	}
	delete(m.challenges, challengeKey{impi, nonce})
	return c, nil
}

// live returns an unexpired challenge, and forgets an expired one, which is
// all the clean-up the memory store needs. m.mu must be held.
func (m *Memory) live(impi, nonce string, now time.Time) (*Challenge, bool) {
	k := challengeKey{impi, nonce}
	c, ok := m.challenges[k]
	if !ok {
		return nil, false
	}
	if !c.Expires.After(now) {
		delete(m.challenges, k)
		return nil, false
	}
	return c, true
}

// Subscription implements Subscriptions.
func (m *Memory) Subscription(_ context.Context, id string) (*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok {
		return nil, fmt.Errorf("state: subscription: %w", ErrNotFound)
	}
	return s.Clone(), nil
}

// SubscriptionsOf implements Subscriptions.
func (m *Memory) SubscriptionsOf(_ context.Context, impu string) ([]*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Subscription
	for _, s := range m.subscriptions {
		if s.IMPU == impu {
			out = append(out, s.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Subscription) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// SaveSubscription implements Subscriptions.
func (m *Memory) SaveSubscription(_ context.Context, s *Subscription) (*Subscription, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.subscriptions[s.ID]
	var stored int64
	if ok {
		stored = cur.Version
	}
	if err := checkVersion("subscription", ok, stored, s.Version); err != nil {
		return nil, err
	}
	saved := s.Clone()
	saved.Version = s.Version + 1
	m.subscriptions[s.ID] = saved
	return saved.Clone(), nil
}

// DeleteSubscription implements Subscriptions.
func (m *Memory) DeleteSubscription(_ context.Context, s *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.subscriptions[s.ID]
	var stored int64
	if ok {
		stored = cur.Version
	}
	if err := checkDelete("subscription", ok, stored, s.Version); err != nil {
		return err
	}
	delete(m.subscriptions, s.ID)
	return nil
}

// NextNotify implements Subscriptions.
func (m *Memory) NextNotify(_ context.Context, id string) (uint32, uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok {
		return 0, 0, fmt.Errorf("state: next notify: %w", ErrNotFound)
	}
	s.CSeq++
	s.ReginfoVersion++
	s.Version++
	return s.CSeq, s.ReginfoVersion, nil
}

// ExpiringSubscriptions implements Subscriptions, earliest expiry first.
func (m *Memory) ExpiringSubscriptions(_ context.Context, now time.Time, limit int) ([]*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Subscription
	for _, s := range m.subscriptions {
		if !s.Expires.After(now) {
			out = append(out, s.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Subscription) int { return a.Expires.Compare(b.Expires) })
	return out[:min(len(out), max(limit, 0))], nil
}
