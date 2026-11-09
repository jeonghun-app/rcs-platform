package store

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
)

// MemoryRegistry is a Registry in process memory, for tests and local
// runs. It keeps each chatbot's encoded form, as the DynamoDB backend
// does, so that every unit test also exercises the codec.
type MemoryRegistry struct {
	mu       sync.Mutex
	chatbots map[string]stored // by ID
	uris     map[string]string // URI → ID
	deleted  map[string]bool   // tombstones, by ID
}

type stored struct {
	doc          []byte
	uri          string
	version      int64
	registration string
}

var _ Registry = (*MemoryRegistry)(nil)

// NewMemoryRegistry returns an empty registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{chatbots: map[string]stored{}, uris: map[string]string{}, deleted: map[string]bool{}}
}

func (st stored) chatbot() (Chatbot, error) {
	c, err := DecodeChatbot(st.doc, st.version)
	c.Registration = st.registration
	return c, err
}

// Register implements Registry.
func (m *MemoryRegistry) Register(_ context.Context, c Chatbot) (Chatbot, error) {
	doc, err := EncodeChatbot(c)
	if err != nil {
		return Chatbot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.chatbots[c.ID]; ok {
		return Chatbot{}, fmt.Errorf("store: register: %w", ErrExists)
	}
	if m.deleted[c.ID] {
		return Chatbot{}, fmt.Errorf("store: register: %w", ErrDeleted)
	}
	if _, ok := m.uris[c.URI]; ok {
		return Chatbot{}, fmt.Errorf("store: register: %w", ErrURITaken)
	}
	st := stored{doc, c.URI, 1, rand.Text()}
	m.chatbots[c.ID] = st
	m.uris[c.URI] = c.ID
	return st.chatbot()
}

// Chatbot implements Registry.
func (m *MemoryRegistry) Chatbot(_ context.Context, id string) (Chatbot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.chatbots[id]
	if !ok {
		return Chatbot{}, fmt.Errorf("store: chatbot: %w", ErrNotFound)
	}
	return st.chatbot()
}

// Update implements Registry. It compares with what it stored, never
// with old alone, which a caller may have got wrong.
func (m *MemoryRegistry) Update(_ context.Context, old, c Chatbot) (Chatbot, error) {
	doc, err := EncodeChatbot(c)
	if err != nil {
		return Chatbot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.chatbots[c.ID]
	switch {
	case old.ID != c.ID:
		return Chatbot{}, fmt.Errorf("%w: a chatbot's ID never changes", ErrInvalid)
	case !ok:
		return Chatbot{}, fmt.Errorf("store: update chatbot: %w", ErrNotFound)
	case st.version != old.Version || st.registration != old.Registration:
		return Chatbot{}, fmt.Errorf("store: update chatbot: %w", ErrConflict)
	case st.uri != c.URI:
		return Chatbot{}, fmt.Errorf("%w: a chatbot's URI never changes", ErrInvalid)
	}
	st = stored{doc, c.URI, old.Version + 1, st.registration}
	m.chatbots[c.ID] = st
	return st.chatbot()
}

// DeleteChatbot implements ChatbotDeleter.
func (m *MemoryRegistry) DeleteChatbot(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.chatbots[id]; ok {
		delete(m.uris, st.uri)
		delete(m.chatbots, id)
		m.deleted[id] = true
	}
	return nil
}
