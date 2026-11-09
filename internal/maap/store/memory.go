package store

import (
	"context"
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
}

type stored struct {
	doc     []byte
	uri     string
	version int64
}

var _ Registry = (*MemoryRegistry)(nil)

// NewMemoryRegistry returns an empty registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{chatbots: map[string]stored{}, uris: map[string]string{}}
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
	if _, ok := m.uris[c.URI]; ok {
		return Chatbot{}, fmt.Errorf("store: register: %w", ErrURITaken)
	}
	m.chatbots[c.ID] = stored{doc, c.URI, 1}
	m.uris[c.URI] = c.ID
	return DecodeChatbot(doc, 1)
}

// Chatbot implements Registry.
func (m *MemoryRegistry) Chatbot(_ context.Context, id string) (Chatbot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.chatbots[id]
	if !ok {
		return Chatbot{}, fmt.Errorf("store: chatbot: %w", ErrNotFound)
	}
	return DecodeChatbot(st.doc, st.version)
}

// Update implements Registry.
func (m *MemoryRegistry) Update(_ context.Context, old, c Chatbot) (Chatbot, error) {
	if old.ID != c.ID || old.URI != c.URI {
		return Chatbot{}, fmt.Errorf("%w: a chatbot's ID and URI never change", ErrInvalid)
	}
	doc, err := EncodeChatbot(c)
	if err != nil {
		return Chatbot{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.chatbots[c.ID]
	switch {
	case !ok:
		return Chatbot{}, fmt.Errorf("store: update chatbot: %w", ErrNotFound)
	case st.version != old.Version:
		return Chatbot{}, fmt.Errorf("store: update chatbot: %w", ErrConflict)
	}
	m.chatbots[c.ID] = stored{doc, c.URI, old.Version + 1}
	return DecodeChatbot(doc, old.Version+1)
}

// DeleteChatbot implements ChatbotDeleter.
func (m *MemoryRegistry) DeleteChatbot(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.chatbots[id]; ok {
		delete(m.uris, st.uri)
		delete(m.chatbots, id)
	}
	return nil
}
