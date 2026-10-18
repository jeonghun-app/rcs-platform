package store

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
)

// Memory is a Store in process memory, for tests and single-task local
// runs (the HSS refuses it in staging and prod). It keeps the encoded form of
// each record, like the DynamoDB backend, so that every unit test also
// exercises the codec and a returned value never aliases a stored one.
type Memory struct {
	mu       sync.Mutex
	subs     map[string]stored // by IMPI
	impus    map[string]string // IMPU → IMPI
	profiles map[string]stored // by ID
	keys     []keyring.WrappedKey
}

type stored struct {
	doc     []byte
	version int64
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{subs: map[string]stored{}, impus: map[string]string{}, profiles: map[string]stored{}}
}

// CreateSubscription implements Store.
func (m *Memory) CreateSubscription(_ context.Context, s *Subscription) (*Subscription, error) {
	doc, err := EncodeSubscription(s)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.subs[s.IMPI]; ok {
		return nil, fmt.Errorf("store: create subscription: %w", ErrExists)
	}
	for _, p := range s.PublicIdentities {
		if _, ok := m.impus[p.IMPU]; ok {
			return nil, fmt.Errorf("store: create subscription: %w", ErrIdentityInUse)
		}
	}
	if _, ok := m.profiles[s.Profile]; !ok {
		return nil, fmt.Errorf("store: create subscription: %w", ErrProfileMissing)
	}
	m.subs[s.IMPI] = stored{doc, 1}
	for _, p := range s.PublicIdentities {
		m.impus[p.IMPU] = s.IMPI
	}
	return DecodeSubscription(doc, 1)
}

// Subscription implements Store.
func (m *Memory) Subscription(_ context.Context, impi string) (*Subscription, error) {
	m.mu.Lock()
	st, ok := m.subs[impi]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("store: subscription: %w", ErrNotFound)
	}
	return DecodeSubscription(st.doc, st.version)
}

// SubscriptionByIMPU implements Store.
func (m *Memory) SubscriptionByIMPU(ctx context.Context, impu string) (*Subscription, error) {
	m.mu.Lock()
	impi, ok := m.impus[impu]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("store: subscription by IMPU: %w", ErrNotFound)
	}
	return m.Subscription(ctx, impi)
}

// UpdateSubscription implements Store.
func (m *Memory) UpdateSubscription(_ context.Context, old, s *Subscription) (*Subscription, error) {
	if old.IMPI != s.IMPI {
		return nil, fmt.Errorf("%w: the IMPI of a subscription cannot change", ErrInvalid)
	}
	doc, err := EncodeSubscription(s)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.subs[s.IMPI]
	switch {
	case !ok:
		return nil, fmt.Errorf("store: update subscription: %w", ErrNotFound)
	case cur.version != old.Version:
		return nil, fmt.Errorf("store: update subscription: %w", ErrConflict)
	}
	added, removed := IdentityChanges(old, s)
	for _, impu := range added {
		if owner, ok := m.impus[impu]; ok && owner != s.IMPI {
			return nil, fmt.Errorf("store: update subscription: %w", ErrIdentityInUse)
		}
	}
	if _, ok := m.profiles[s.Profile]; !ok {
		return nil, fmt.Errorf("store: update subscription: %w", ErrProfileMissing)
	}
	for _, impu := range removed {
		delete(m.impus, impu)
	}
	for _, impu := range added {
		m.impus[impu] = s.IMPI
	}
	v := cur.version + 1
	m.subs[s.IMPI] = stored{doc, v}
	return DecodeSubscription(doc, v)
}

// IdentityChanges returns the IMPUs s has and old has not, and the reverse:
// the IMPU index entries a backend adds and removes with an update.
func IdentityChanges(old, s *Subscription) (added, removed []string) {
	for _, p := range s.PublicIdentities {
		if old.Identity(p.IMPU) == nil {
			added = append(added, p.IMPU)
		}
	}
	for _, p := range old.PublicIdentities {
		if s.Identity(p.IMPU) == nil {
			removed = append(removed, p.IMPU)
		}
	}
	return added, removed
}

// DeleteSubscription implements Store.
func (m *Memory) DeleteSubscription(_ context.Context, s *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.subs[s.IMPI]
	switch {
	case !ok:
		return fmt.Errorf("store: delete subscription: %w", ErrNotFound)
	case cur.version != s.Version:
		return fmt.Errorf("store: delete subscription: %w", ErrConflict)
	}
	stored, err := DecodeSubscription(cur.doc, cur.version)
	if err != nil {
		return err
	}
	for _, p := range stored.PublicIdentities {
		delete(m.impus, p.IMPU)
	}
	delete(m.subs, s.IMPI)
	return nil
}

// SubscriptionsByProfile implements Store. The cursor is the last IMPI of
// the previous page, in sorted order.
func (m *Memory) SubscriptionsByProfile(_ context.Context, profile, cursor string, limit int) (Page, error) {
	if limit <= 0 || limit > MaxPageSize {
		limit = MaxPageSize
	}
	m.mu.Lock()
	var impis []string
	for impi, st := range m.subs {
		if impi <= cursor && cursor != "" {
			continue
		}
		s, err := DecodeSubscription(st.doc, st.version)
		if err != nil {
			m.mu.Unlock()
			return Page{}, err
		}
		if s.Profile == profile {
			impis = append(impis, impi)
		}
	}
	m.mu.Unlock()
	slices.Sort(impis)
	var p Page
	if len(impis) > limit {
		impis = impis[:limit]
		p.Next = impis[limit-1]
	}
	p.IMPIs = impis
	return p, nil
}

// CreateProfile implements Store.
func (m *Memory) CreateProfile(_ context.Context, p *ServiceProfile) (*ServiceProfile, error) {
	doc, err := EncodeProfile(p)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[p.ID]; ok {
		return nil, fmt.Errorf("store: create profile: %w", ErrExists)
	}
	m.profiles[p.ID] = stored{doc, 1}
	return DecodeProfile(doc, 1)
}

// Profile implements Store.
func (m *Memory) Profile(_ context.Context, id string) (*ServiceProfile, error) {
	m.mu.Lock()
	st, ok := m.profiles[id]
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("store: profile: %w", ErrNotFound)
	}
	return DecodeProfile(st.doc, st.version)
}

// UpdateProfile implements Store.
func (m *Memory) UpdateProfile(_ context.Context, p *ServiceProfile) (*ServiceProfile, error) {
	doc, err := EncodeProfile(p)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.profiles[p.ID]
	switch {
	case !ok:
		return nil, fmt.Errorf("store: update profile: %w", ErrNotFound)
	case cur.version != p.Version:
		return nil, fmt.Errorf("store: update profile: %w", ErrConflict)
	}
	v := cur.version + 1
	m.profiles[p.ID] = stored{doc, v}
	return DecodeProfile(doc, v)
}

// DeleteProfile implements Store.
func (m *Memory) DeleteProfile(_ context.Context, p *ServiceProfile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.profiles[p.ID]
	switch {
	case !ok:
		return fmt.Errorf("store: delete profile: %w", ErrNotFound)
	case cur.version != p.Version:
		return fmt.Errorf("store: delete profile: %w", ErrConflict)
	}
	for _, st := range m.subs {
		s, err := DecodeSubscription(st.doc, st.version)
		if err != nil {
			return err
		}
		if s.Profile == p.ID {
			return fmt.Errorf("store: delete profile: %w", ErrProfileInUse)
		}
	}
	delete(m.profiles, p.ID)
	return nil
}

// DataKeys implements keyring.Store.
func (m *Memory) DataKeys(context.Context) ([]keyring.WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]keyring.WrappedKey, len(m.keys))
	for i, k := range m.keys {
		out[i] = keyring.WrappedKey{ID: k.ID, Ciphertext: slices.Clone(k.Ciphertext)}
	}
	return out, nil
}

// AddDataKey implements keyring.Store.
func (m *Memory) AddDataKey(_ context.Context, k keyring.WrappedKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, have := range m.keys {
		if have.ID == k.ID {
			return fmt.Errorf("store: add data key: %w", keyring.ErrExists)
		}
	}
	m.keys = append(m.keys, keyring.WrappedKey{ID: k.ID, Ciphertext: slices.Clone(k.Ciphertext)})
	return nil
}
