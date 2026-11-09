package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemorySubscribers is a Subscribers in process memory, for tests and
// local runs, keyed both ways as the DynamoDB backend is.
type MemorySubscribers struct {
	mu     sync.Mutex
	byKind map[aliasKind]Alias
	byID   map[chatbotAlias]aliasKind
}

// aliasKind is what an alias is of: one per chatbot, subscriber and
// anonymity.
type aliasKind struct {
	chatbot, subscriber string
	anonymous           bool
}

type chatbotAlias struct{ chatbot, id string }

var _ Subscribers = (*MemorySubscribers)(nil)

// NewMemorySubscribers returns an empty table.
func NewMemorySubscribers() *MemorySubscribers {
	return &MemorySubscribers{byKind: map[aliasKind]Alias{}, byID: map[chatbotAlias]aliasKind{}}
}

func kindOf(a Alias) aliasKind { return aliasKind{a.Chatbot, a.Subscriber, a.Anonymous} }

// Alias implements Subscribers.
func (m *MemorySubscribers) Alias(_ context.Context, want Alias) (Alias, error) {
	if !want.valid() {
		return Alias{}, fmt.Errorf("%w: a malformed alias", ErrInvalid)
	}
	want.Created = Seconds(want.Created)
	want.LastUsed = want.Created
	m.mu.Lock()
	defer m.mu.Unlock()
	k := kindOf(want)
	cur, ok := m.byKind[k]
	switch {
	case ok && !cur.Expired(want.Created):
		return cur, nil
	case m.byID[chatbotAlias{want.Chatbot, want.ID}] != aliasKind{}:
		return Alias{}, fmt.Errorf("%w: the alias ID is taken", ErrInvalid)
	}
	delete(m.byID, chatbotAlias{cur.Chatbot, cur.ID})
	m.byKind[k] = want
	m.byID[chatbotAlias{want.Chatbot, want.ID}] = k
	return want, nil
}

// Resolve implements Subscribers.
func (m *MemorySubscribers) Resolve(_ context.Context, chatbotID, aliasID string, now time.Time) (Alias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.byID[chatbotAlias{chatbotID, aliasID}]
	if !ok || m.byKind[k].Expired(now) {
		return Alias{}, fmt.Errorf("store: resolve alias: %w", ErrNotFound)
	}
	return m.byKind[k], nil
}

// Used implements Subscribers.
func (m *MemorySubscribers) Used(_ context.Context, a Alias, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := kindOf(a)
	if cur, ok := m.byKind[k]; ok && cur.ID == a.ID && cur.LastUsed.Before(Seconds(at)) {
		cur.LastUsed = Seconds(at)
		m.byKind[k] = cur
	}
	return nil
}

// DeleteChatbot implements ChatbotDeleter.
func (m *MemorySubscribers) DeleteChatbot(_ context.Context, chatbotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ca, k := range m.byID {
		if ca.chatbot == chatbotID {
			delete(m.byID, ca)
			delete(m.byKind, k)
		}
	}
	return nil
}
