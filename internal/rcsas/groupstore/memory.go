package groupstore

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Memory is a Store in process memory, for tests and single-task local
// runs. Several services sharing one Memory behave like tasks sharing a
// table.
type Memory struct {
	mu     sync.Mutex
	groups map[string]stored
}

type stored struct {
	g     Group
	token string
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory { return &Memory{groups: map[string]stored{}} }

// Create implements Store.
func (s *Memory) Create(_ context.Context, g Group, token string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.groups[g.URI]; ok && old.g.Expires.After(now) {
		if old.g.Rev == 1 && old.token == token {
			return nil
		}
		return fmt.Errorf("groupstore: create: %w", ErrExists)
	}
	g = g.Clone()
	g.Rev = 1
	s.groups[g.URI] = stored{g: g, token: token}
	return nil
}

// Get implements Store.
func (s *Memory) Get(_ context.Context, uri string, now time.Time) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.groups[uri]
	if !ok || !st.g.Expires.After(now) {
		return Group{}, fmt.Errorf("groupstore: get: %w", ErrNotFound)
	}
	return st.g.Clone(), nil
}

// Update implements Store.
func (s *Memory) Update(_ context.Context, g Group, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.groups[g.URI]
	switch {
	case !ok:
		return fmt.Errorf("groupstore: update: %w", ErrNotFound)
	case st.g.Rev == g.Rev+1 && st.token == token:
		return nil
	case st.g.Rev != g.Rev:
		return fmt.Errorf("groupstore: update: %w", ErrConflict)
	}
	g = g.Clone()
	g.Rev++
	s.groups[g.URI] = stored{g: g, token: token}
	return nil
}

// Touch implements Store.
func (s *Memory) Touch(_ context.Context, uri string, active, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.groups[uri]
	if !ok || !st.g.Expires.After(active) {
		return fmt.Errorf("groupstore: touch: %w", ErrNotFound)
	}
	if active.After(st.g.Active) {
		st.g.Active = active
	}
	if expires.After(st.g.Expires) {
		st.g.Expires = expires
	}
	s.groups[uri] = st
	return nil
}
