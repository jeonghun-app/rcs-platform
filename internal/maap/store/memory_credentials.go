package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"
)

// MemoryCredentials are the credentials of a MemoryRegistry, under its
// lock, as the DynamoDB backend keeps them in the registry's table.
type MemoryCredentials struct{ m *MemoryRegistry }

var _ Credentials = MemoryCredentials{}

// Credentials returns the registry's credentials.
func (m *MemoryRegistry) Credentials() MemoryCredentials { return MemoryCredentials{m} }

// Issue implements Credentials.
func (mc MemoryCredentials) Issue(_ context.Context, cred Credential) error {
	if !ValidKeyID(cred.KeyID) {
		return fmt.Errorf("%w: a malformed key ID", ErrInvalid)
	}
	m := mc.m
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.chatbots[cred.Chatbot]
	switch {
	case !ok || st.registration != cred.Registration:
		return fmt.Errorf("store: issue credential: %w", ErrNotFound)
	case len(m.chatbotCredentials(cred.Chatbot)) >= MaxCredentials:
		return fmt.Errorf("store: issue credential: %w", ErrTooMany)
	case m.creds[cred.KeyID].KeyID != "":
		return fmt.Errorf("%w: the key ID is taken", ErrInvalid)
	}
	cred.Created, cred.LastUsed = Seconds(cred.Created), time.Time{}
	m.creds[cred.KeyID] = cred
	return nil
}

// Credential implements Credentials.
func (mc MemoryCredentials) Credential(_ context.Context, keyID string) (Credential, error) {
	mc.m.mu.Lock()
	defer mc.m.mu.Unlock()
	c, ok := mc.m.creds[keyID]
	if !ok {
		return Credential{}, fmt.Errorf("store: credential: %w", ErrNotFound)
	}
	return c, nil
}

// ChatbotCredentials implements Credentials.
func (mc MemoryCredentials) ChatbotCredentials(_ context.Context, chatbotID string) ([]Credential, error) {
	mc.m.mu.Lock()
	defer mc.m.mu.Unlock()
	return mc.m.chatbotCredentials(chatbotID), nil
}

// Revoke implements Credentials.
func (mc MemoryCredentials) Revoke(_ context.Context, chatbotID, keyID string) error {
	mc.m.mu.Lock()
	defer mc.m.mu.Unlock()
	if c, ok := mc.m.creds[keyID]; !ok || c.Chatbot != chatbotID {
		return fmt.Errorf("store: revoke credential: %w", ErrNotFound)
	}
	delete(mc.m.creds, keyID)
	return nil
}

// Used implements Credentials.
func (mc MemoryCredentials) Used(_ context.Context, keyID string, at time.Time) error {
	mc.m.mu.Lock()
	defer mc.m.mu.Unlock()
	if c, ok := mc.m.creds[keyID]; ok {
		c.LastUsed = Seconds(at)
		mc.m.creds[keyID] = c
	}
	return nil
}

// DeleteChatbot implements ChatbotDeleter.
func (mc MemoryCredentials) DeleteChatbot(_ context.Context, chatbotID string) error {
	mc.m.mu.Lock()
	defer mc.m.mu.Unlock()
	mc.m.deleteCredentials(chatbotID)
	return nil
}

// chatbotCredentials returns the chatbot's credentials, oldest first; the
// caller holds the lock.
func (m *MemoryRegistry) chatbotCredentials(chatbotID string) []Credential {
	var out []Credential
	for _, c := range m.creds {
		if c.Chatbot == chatbotID {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Credential) int {
		return cmp.Or(a.Created.Compare(b.Created), cmp.Compare(a.KeyID, b.KeyID))
	})
	return out
}

func (m *MemoryRegistry) deleteCredentials(chatbotID string) {
	for id, c := range m.creds {
		if c.Chatbot == chatbotID {
			delete(m.creds, id)
		}
	}
}
