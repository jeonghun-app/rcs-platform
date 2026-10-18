package sip

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// IDGenerator makes the random identifiers RFC 3261 asks every element to create.
// The zero value draws from crypto/rand; tests inject a deterministic Rand.
//
// Identifiers are lower-case hex, which is a valid token and word everywhere they
// are used.
type IDGenerator struct {
	Rand io.Reader
}

// Branch returns a new Via branch: the magic cookie and 16 random bytes, unique
// across space and time as RFC 3261 §8.1.1.7 requires.
func (g IDGenerator) Branch() (string, error) {
	s, err := g.random(16)
	if err != nil {
		return "", err
	}
	return MagicCookie + s, nil
}

// Tag returns a new From or To tag of 8 random bytes, above the 32 bits of
// randomness RFC 3261 §19.3 requires.
func (g IDGenerator) Tag() (string, error) { return g.random(8) }

// CallID returns a new Call-ID of 16 random bytes (RFC 3261 §8.1.1.4), followed by
// "@host" when host is not empty. host must be a valid word, such as a domain
// name; it is optional because the random part alone is unique.
func (g IDGenerator) CallID(host string) (string, error) {
	if host != "" && !isAll(host, classWord) {
		return "", errors.New("sip: Call-ID host is not a word")
	}
	s, err := g.random(16)
	if err != nil {
		return "", err
	}
	if host == "" {
		return s, nil
	}
	return s + "@" + host, nil
}

func (g IDGenerator) random(n int) (string, error) {
	r := g.Rand
	if r == nil {
		r = rand.Reader
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("sip: reading randomness: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
