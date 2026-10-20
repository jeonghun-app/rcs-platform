package state

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"
)

// purgeEvery is how many challenges are added between two purges of the
// expired ones, which no read ever asked for again.
const purgeEvery = 1024

// Memory is a Store in process memory, for tests and for a single instance in
// development. Several S-CSCF handles sharing one Memory behave as instances
// sharing DynamoDB. It hands out copies, so callers cannot change what it holds.
type Memory struct {
	rand io.Reader

	mu            sync.Mutex
	registrations map[SetKey]*Registration
	identities    map[string]*Identity
	profiles      map[SetKey]*Profile
	challenges    map[challengeKey]*Challenge
	added         int
	attempts      map[attemptKey]*attempt
	counted       int
	subscriptions map[string]*Subscription
}

type challengeKey struct{ impi, nonce string }

type attemptKey struct {
	impi, kind string
	window     time.Time
}

type attempt struct {
	n       int64
	expires time.Time
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		rand:          randReader,
		registrations: map[SetKey]*Registration{},
		identities:    map[string]*Identity{},
		profiles:      map[SetKey]*Profile{},
		challenges:    map[challengeKey]*Challenge{},
		attempts:      map[attemptKey]*attempt{},
		subscriptions: map[string]*Subscription{},
	}
}

// Registration implements Registrations.
func (m *Memory) Registration(_ context.Context, k SetKey) (*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.registrations[k]
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
		if r.Key.IMPI == impi {
			out = append(out, r.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Registration) int { return strings.Compare(a.Key.IMPU, b.Key.IMPU) })
	return out, nil
}

// SaveRegistration implements Registrations.
func (m *Memory) SaveRegistration(_ context.Context, r *Registration) (*Registration, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.registrations[r.Key]
	var stored int64
	if ok {
		stored = cur.Version
	}
	version, err := m.nextVersion("registration", ok, stored, r.Version)
	if err != nil {
		return nil, err
	}
	if ok && revivesIncarnation(cur, r) {
		return nil, fmt.Errorf("%w: a record brought back from a deregistration needs a new incarnation", ErrInvalid)
	}
	saved := r.Clone()
	saved.Version = version
	m.registrations[r.Key] = saved
	return saved.Clone(), nil
}

// Identity implements Registrations.
func (m *Memory) Identity(_ context.Context, impu string, now time.Time) (*Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.identities[impu]
	if !ok || !i.KeepUntil.After(now) {
		return nil, fmt.Errorf("state: identity: %w", ErrNotFound)
	}
	c := *i
	return &c, nil
}

// KeepIdentity implements Registrations.
func (m *Memory) KeepIdentity(_ context.Context, impu string, until, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i, ok := m.identities[impu]
	if !ok || !i.KeepUntil.After(now) {
		return fmt.Errorf("state: keep identity: %w", ErrNotFound)
	}
	if until = until.Truncate(time.Second); until.After(i.KeepUntil) {
		i.KeepUntil = until
		i.Version++
	}
	return nil
}

// SaveIdentity implements Registrations.
func (m *Memory) SaveIdentity(_ context.Context, i *Identity, now time.Time) (*Identity, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.identities[i.IMPU]
	if ok && i.Version == 0 && !cur.KeepUntil.After(now) {
		// Gone to Identity: a create takes its place.
		ok = false
	}
	var stored int64
	if ok {
		stored = cur.Version
	}
	version, err := m.nextVersion("identity", ok, stored, i.Version)
	if err != nil {
		return nil, err
	}
	saved := *i
	saved.Version = version
	saved.KeepUntil = saved.KeepUntil.Truncate(time.Second)
	m.identities[i.IMPU] = &saved
	out := saved
	return &out, nil
}

// DeleteIdentity implements Registrations.
func (m *Memory) DeleteIdentity(_ context.Context, i *Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.identities[i.IMPU]
	var stored int64
	if ok {
		stored = cur.Version
	}
	if err := checkDelete("identity", ok, stored, i.Version); err != nil {
		return err
	}
	delete(m.identities, i.IMPU)
	return nil
}

// nextVersion applies the optimistic concurrency rule of the Save methods and
// returns the version to store. m.mu must be held.
func (m *Memory) nextVersion(what string, exists bool, stored, given int64) (int64, error) {
	switch {
	case given == 0 && exists:
		return 0, fmt.Errorf("state: save %s: %w", what, ErrExists)
	case given != 0 && !exists:
		return 0, fmt.Errorf("state: save %s: %w", what, ErrNotFound)
	case given != 0 && stored != given:
		return 0, fmt.Errorf("state: save %s: %w", what, ErrConflict)
	case given == 0:
		return FirstVersion(m.rand)
	}
	return given + 1, nil
}

// DeleteRegistration implements Registrations.
func (m *Memory) DeleteRegistration(_ context.Context, r *Registration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.registrations[r.Key]
	var stored int64
	if ok {
		stored = cur.Version
	}
	if err := checkDelete("registration", ok, stored, r.Version); err != nil {
		return err
	}
	delete(m.registrations, r.Key)
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

// ExpiringRegistrations implements Registrations, earliest first.
func (m *Memory) ExpiringRegistrations(_ context.Context, now time.Time, limit int) ([]*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Registration
	for _, r := range m.registrations {
		if !r.SweepAt().After(now) {
			out = append(out, r.Clone())
		}
	}
	slices.SortFunc(out, func(a, b *Registration) int { return a.SweepAt().Compare(b.SweepAt()) })
	return out[:min(len(out), max(limit, 0))], nil
}

// Profile implements Profiles. A profile past its KeepUntil stays until it is
// deleted or saved again, as in DynamoDB before TTL removes it.
func (m *Memory) Profile(_ context.Context, k SetKey, now time.Time) (*Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[k]
	if !ok || !p.KeepUntil.After(now) {
		return nil, fmt.Errorf("state: profile: %w", ErrNotFound)
	}
	return p.Clone(), nil
}

// SaveProfile implements Profiles.
func (m *Memory) SaveProfile(_ context.Context, p *Profile) error {
	if err := ValidProfile(p); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.profiles[p.Key]; ok && cur.Received.After(p.Received) {
		// The newer profile stays, kept as long as either needs, as
		// KeepProfile would at p.Received.
		if keep := p.KeepUntil.Truncate(time.Second); keep.After(cur.KeepUntil) && cur.KeepUntil.After(p.Received) {
			cur.KeepUntil = keep
		}
		return fmt.Errorf("state: save profile: %w", ErrConflict)
	}
	c := p.Clone()
	c.KeepUntil = c.KeepUntil.Truncate(time.Second)
	if cur, ok := m.profiles[p.Key]; ok && cur.KeepUntil.After(c.KeepUntil) {
		// Never brought closer: a registration may have just extended it.
		c.KeepUntil = cur.KeepUntil
	}
	m.profiles[p.Key] = c
	return nil
}

// KeepProfile implements Profiles.
func (m *Memory) KeepProfile(_ context.Context, k SetKey, until, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[k]
	if !ok || !p.KeepUntil.After(now) {
		return fmt.Errorf("state: keep profile: %w", ErrNotFound)
	}
	if until = until.Truncate(time.Second); until.After(p.KeepUntil) {
		p.KeepUntil = until
	}
	return nil
}

// DeleteProfileIf implements Profiles.
func (m *Memory) DeleteProfileIf(_ context.Context, k SetKey, received time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.profiles[k]
	if !ok {
		return nil
	}
	if !p.Received.Equal(received) {
		return fmt.Errorf("state: delete profile: %w", ErrConflict)
	}
	delete(m.profiles, k)
	return nil
}

// DeleteProfile implements Profiles.
func (m *Memory) DeleteProfile(_ context.Context, k SetKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.profiles, k)
	return nil
}

// CountAttempt implements Challenges. Every purgeEvery counts it forgets the
// windows that have expired by the new one's start.
func (m *Memory) CountAttempt(_ context.Context, impi, kind string, window, expires time.Time) (int64, error) {
	if err := ValidAttempt(impi, kind, window, expires); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := attemptKey{impi, kind, window.UTC().Truncate(time.Second)}
	a := m.attempts[k]
	if a == nil {
		a = &attempt{expires: expires}
		m.attempts[k] = a
	}
	a.n++
	if m.counted++; m.counted%purgeEvery == 0 {
		for k, v := range m.attempts {
			if !v.expires.After(window) {
				delete(m.attempts, k)
			}
		}
	}
	return a.n, nil
}

// AddChallenge implements Challenges. Every purgeEvery challenges it forgets
// those that have expired by the new one's issue time, which nothing else
// would remove.
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
	if m.added++; m.added%purgeEvery == 0 {
		m.purge(c.Issued)
	}
	return nil
}

// TakeChallenge implements Challenges.
func (m *Memory) TakeChallenge(_ context.Context, impi, nonce string, now time.Time) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := challengeKey{impi, nonce}
	c, ok := m.challenges[k]
	if !ok || !c.Expires.After(now) {
		delete(m.challenges, k)
		return nil, fmt.Errorf("state: take challenge: %w", ErrNotFound)
	}
	delete(m.challenges, k)
	return c, nil
}

// purge forgets the challenges that have expired at now. m.mu must be held.
func (m *Memory) purge(now time.Time) {
	for k, c := range m.challenges {
		if !c.Expires.After(now) {
			delete(m.challenges, k)
		}
	}
}

// HeldChallenges returns the number of challenges held, expired ones included,
// for tests of the purge.
func (m *Memory) HeldChallenges() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.challenges)
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
	version, err := m.nextVersion("subscription", ok, stored, s.Version)
	if err != nil {
		return nil, err
	}
	saved := s.Clone()
	saved.Version = version
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
	if s.CSeq >= MaxCounter || s.ReginfoVersion >= MaxCounter {
		return 0, 0, fmt.Errorf("state: next notify: %w", ErrExhausted)
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

// revivesIncarnation reports whether saving next over stored brings back a
// record claimed for a deregistration under the incarnation it was claimed
// with (Registration.Incarnation).
func revivesIncarnation(stored, next *Registration) bool {
	return !stored.Deregistering.IsZero() && next.Deregistering.IsZero() && next.Incarnation == stored.Incarnation
}
