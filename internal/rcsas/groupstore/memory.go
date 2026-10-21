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
	owners map[string]owned
	tasks  map[string]Task
}

type stored struct {
	g     Group
	token string
}

type owned struct {
	o     Owner
	token string
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty Memory.
func NewMemory() *Memory {
	return &Memory{groups: map[string]stored{}, owners: map[string]owned{}, tasks: map[string]Task{}}
}

// Create implements Store.
func (s *Memory) Create(_ context.Context, g Group, owner Owner, token string, now time.Time) error {
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
	owner.Epoch = 1
	s.owners[g.URI] = owned{o: owner, token: token}
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

// fenced reports whether owner is uri's stored owner; it needs s.mu. A
// group no task has taken has none, which no write is fenced by.
func (s *Memory) fenced(uri string, owner Owner) bool {
	o, ok := s.owners[uri]
	return ok && o.o.Task == owner.Task && o.o.Epoch == owner.Epoch
}

// Update implements Store.
func (s *Memory) Update(_ context.Context, g Group, owner Owner, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.groups[g.URI]
	switch {
	case !ok:
		return fmt.Errorf("groupstore: update: %w", ErrNotFound)
	case st.g.Rev == g.Rev+1 && st.token == token:
		return nil
	case !s.fenced(g.URI, owner):
		return fmt.Errorf("groupstore: update: %w", ErrNotOwner)
	case st.g.Rev != g.Rev:
		return fmt.Errorf("groupstore: update: %w", ErrConflict)
	}
	g = g.Clone()
	g.Rev++
	s.groups[g.URI] = stored{g: g, token: token}
	return nil
}

// Touch implements Store.
func (s *Memory) Touch(_ context.Context, uri string, owner Owner, active, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.groups[uri]
	if !ok || !st.g.Expires.After(active) {
		return fmt.Errorf("groupstore: touch: %w", ErrNotFound)
	}
	if !s.fenced(uri, owner) {
		return fmt.Errorf("groupstore: touch: %w", ErrNotOwner)
	}
	// Both move or neither, as in DynamoDB (awsstore.Groups.Touch): a
	// touch older than the last write, which may have ended the group,
	// must not move its expiry.
	if active.After(st.g.Active) && expires.After(st.g.Expires) {
		st.g.Active, st.g.Expires = active, expires
		s.groups[uri] = st
	}
	return nil
}

// Owner implements Store.
func (s *Memory) Owner(_ context.Context, uri string) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owners[uri].o, nil
}

// TakeOver implements Store.
func (s *Memory) TakeOver(_ context.Context, uri string, from, to Owner, _ time.Time, token string) (Owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.owners[uri]
	switch {
	case ok && cur.token == token && cur.o.Task == to.Task && cur.o.Epoch == from.Epoch+1:
		return cur.o, nil
	case cur.o.Task != from.Task || cur.o.Epoch != from.Epoch:
		return Owner{}, fmt.Errorf("groupstore: take over: %w", ErrConflict)
	}
	to.Epoch = from.Epoch + 1
	s.owners[uri] = owned{o: to, token: token}
	return to, nil
}

// Beat implements Store.
func (s *Memory) Beat(_ context.Context, t Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[t.ID] = t
	return nil
}

// Task implements Store.
func (s *Memory) Task(_ context.Context, id string) (Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return Task{}, fmt.Errorf("groupstore: task: %w", ErrNotFound)
	}
	return t, nil
}

// Disown forgets uri's owner, as for a group stored before #121, for
// tests.
func (s *Memory) Disown(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.owners, uri)
}
