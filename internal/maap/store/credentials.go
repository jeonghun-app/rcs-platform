package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

// ErrTooMany means Issue found the chatbot's live credentials at
// MaxCredentials: one is revoked before the next is issued (#710 answers
// 409).
var ErrTooMany = errors.New("store: the chatbot has its most credentials")

// MaxCredentials is how many credentials a chatbot may have live at once:
// issue the next, switch, revoke the old (ADR 0009 §7).
const MaxCredentials = 2

// KeyIDBytes is the length of a key ID: 128 random bits in base32
// (RFC 4648 §6) without padding, an alphabet without the "." that ends a
// key ID in a bearer token and without controls, so a key ID can be in an
// audit line or a header (the lead's decision on #710).
const KeyIDBytes = 26

const keyIDAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// ValidKeyID reports whether id has a key ID's form, which every backend
// checks before it reads, so that no other value reaches a key.
func ValidKeyID(id string) bool {
	return len(id) == KeyIDBytes && strings.Trim(id, keyIDAlphabet) == ""
}

// Credential is one of a chatbot's API credentials (ADR 0009 §7). The
// secret is never stored, only its SHA-256 digest, which no answer or log
// line carries.
type Credential struct {
	KeyID   string
	Chatbot string
	// Registration is the chatbot's registration token at issue: a
	// credential authenticates only the registration it was issued to.
	Registration string
	Digest       [sha256.Size]byte `json:"-"`
	// Created and LastUsed are in seconds; LastUsed is zero until a task
	// records a use, at most hourly (#710).
	Created  time.Time
	LastUsed time.Time
}

// Credentials are the chatbots' credentials in the maap-registry table.
// Every method is safe for concurrent use, also across tasks sharing a
// backend.
type Credentials interface {
	// Issue stores cred for the chatbot it names, on the condition that the
	// chatbot's stored registration is cred.Registration, in the same
	// write: ErrNotFound if the chatbot is gone or deleted, ErrTooMany at
	// MaxCredentials live, ErrConflict if another write on the chatbot
	// came at the same time, ErrInvalid for a malformed key ID.
	Issue(ctx context.Context, cred Credential) error
	// Credential returns the credential with the key ID, ErrNotFound if it
	// was never issued or is revoked. It does not read the chatbot, which
	// the caller does, and refuses a credential of a deleted one.
	Credential(ctx context.Context, keyID string) (Credential, error)
	// ChatbotCredentials returns the chatbot's live credentials, oldest
	// first; none for an unknown chatbot.
	ChatbotCredentials(ctx context.Context, chatbotID string) ([]Credential, error)
	// Revoke deletes the chatbot's credential with the key ID at once:
	// ErrNotFound if the chatbot has none with it.
	Revoke(ctx context.Context, chatbotID, keyID string) error
	// Used records at as the credential's last use; a revoked credential
	// is not written again.
	Used(ctx context.Context, keyID string, at time.Time) error
	// DeleteChatbot deletes the chatbot's credentials. The registry's
	// deletion deletes them too, after the tombstone; this one runs among
	// the other tables' deleters.
	ChatbotDeleter
}

// Seconds is t as a backend stores it: whole seconds, in UTC.
func Seconds(t time.Time) time.Time { return t.Truncate(time.Second).UTC() }
