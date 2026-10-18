package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Memory is a Store in process memory. It serves tests and a single relay
// task in dev and test; relay tasks cannot share it, so msrp-relay refuses it
// in staging and prod. Expired bindings stay until Delete, the way DynamoDB
// keeps them until its TTL catches up.
type Memory struct {
	mu       sync.Mutex
	bindings map[string]Binding
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{bindings: map[string]Binding{}}
}

// Create implements Store.
func (m *Memory) Create(_ context.Context, b Binding) error {
	if b.ClaimedBy != "" {
		return fmt.Errorf("store: create: a new binding cannot be claimed")
	}
	b.ExpiresAt = b.ExpiresAt.Truncate(Precision)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.bindings[b.ID]; ok {
		return fmt.Errorf("store: create: %w", ErrExists)
	}
	m.bindings[b.ID] = b
	return nil
}

// live returns the binding if it exists and has not expired. m.mu is held.
func (m *Memory) live(id string, now time.Time) (Binding, bool) {
	b, ok := m.bindings[id]
	if !ok || b.Expired(now) {
		return Binding{}, false
	}
	return b, true
}

// Get implements Store.
func (m *Memory) Get(_ context.Context, id string, now time.Time) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.live(id, now)
	if !ok {
		return Binding{}, fmt.Errorf("store: get: %w", ErrNotFound)
	}
	return b, nil
}

// Update implements Store.
func (m *Memory) Update(_ context.Context, id string, u Update, now time.Time) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.live(id, now)
	if !ok {
		return Binding{}, fmt.Errorf("store: update: %w", ErrNotFound)
	}
	if !settable(b.CorePath, u.CorePath) || !settable(b.ClientEndpointPath, u.ClientEndpointPath) {
		return Binding{}, fmt.Errorf("store: update: %w", ErrConflict)
	}
	if u.CorePath != "" {
		b.CorePath = u.CorePath
	}
	if u.ClientEndpointPath != "" {
		b.ClientEndpointPath = u.ClientEndpointPath
	}
	if !u.ExpiresAt.IsZero() {
		b.ExpiresAt = u.ExpiresAt.Truncate(Precision)
	}
	m.bindings[id] = b
	return b, nil
}

// settable reports whether a path currently cur may be set to next.
func settable(cur, next string) bool {
	return next == "" || cur == "" || cur == next
}

// Claim implements Store.
func (m *Memory) Claim(_ context.Context, id, by string, now time.Time) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.live(id, now)
	switch {
	case !ok:
		return Binding{}, fmt.Errorf("store: claim: %w", ErrNotFound)
	case b.ClaimedBy != "":
		return Binding{}, fmt.Errorf("store: claim: %w", ErrClaimed)
	case !b.Complete():
		return Binding{}, fmt.Errorf("store: claim: %w", ErrIncomplete)
	}
	b.ClaimedBy = by
	m.bindings[id] = b
	return b, nil
}

// Delete implements Store.
func (m *Memory) Delete(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.live(id, now)
	delete(m.bindings, id)
	if !ok {
		return fmt.Errorf("store: delete: %w", ErrNotFound)
	}
	return nil
}

// Ready implements Store; memory is always reachable.
func (m *Memory) Ready(context.Context) error { return nil }

// Len returns how many bindings are held, expired ones included, for tests.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bindings)
}
