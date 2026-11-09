package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrKeyReused means Remember found the chatbot's idempotency key live
// with the digest of another request (#683 answers 409).
var ErrKeyReused = errors.New("store: idempotency key used for another request")

// IdempotencyTTL is how long an idempotency record is kept (ADR 0009 §6).
const IdempotencyTTL = 24 * time.Hour

// MaxAnswerBytes bounds a stored answer: maap's own answer to a send,
// which is small; the bound keeps an item well under DynamoDB's 400 KB.
const MaxAnswerBytes = 8 << 10

// MessageIDBytes is the length of a Message-ID maap generates: 128 random
// bits (ADR 0009 §4, memo B3) in lower-case hex, the form of maap's other
// IDs, which a log carries as they are (#711).
const MessageIDBytes = 32

// ValidMessageID reports whether id has a Message-ID's form, which every
// backend checks before it reads, so that no other value reaches a key.
func ValidMessageID(id string) bool {
	return len(id) == MessageIDBytes && strings.Trim(id, "0123456789abcdef") == ""
}

// ValidIdempotencyKey reports whether key has an idempotency key's form:
// 1–64 characters of [A-Za-z0-9_-] (ADR 0009 §6), a chatbot ID's alphabet
// and bound, so no control character can reach a key or a header.
func ValidIdempotencyKey(key string) bool { return ValidID(key) }

// Idempotency is the record of the first request a chatbot sent with an
// idempotency key (ADR 0009 §4 step 2). The key is never logged (§10).
type Idempotency struct {
	Chatbot string
	Key     string
	// Digest is the SHA-256 of the request, which #683 computes; another
	// request with the key has another digest.
	Digest [sha256.Size]byte
	// MessageID is the Message-ID generated for the request, which a
	// retry after a lost answer sends again.
	MessageID string
	// Answer is the answer stored for the request, opaque to the store.
	Answer []byte
	// Created is in seconds; the record is live for IdempotencyTTL after.
	Created time.Time
}

// CheckIdempotency checks the rules every stored record keeps.
func CheckIdempotency(r Idempotency) error {
	switch {
	case !ValidID(r.Chatbot) || !ValidIdempotencyKey(r.Key):
		return fmt.Errorf("%w: a malformed chatbot ID or idempotency key", ErrInvalid)
	case !ValidMessageID(r.MessageID):
		return fmt.Errorf("%w: a malformed Message-ID", ErrInvalid)
	case len(r.Answer) > MaxAnswerBytes:
		return fmt.Errorf("%w: an answer over %d bytes", ErrInvalid, MaxAnswerBytes)
	}
	return nil
}

// Live reports whether a record created at created is still kept at now:
// expiry is judged by the times, never by an item's presence, since
// DynamoDB's TTL deletes late (ADR 0009 §10).
func Live(created time.Time, ttl time.Duration, now time.Time) bool {
	return now.Before(created.Add(ttl))
}

// Requests is the maap-requests table. Every method is safe for
// concurrent use, also across tasks sharing a backend.
type Requests interface {
	// Remember stores rec, with Created set to now, unless the chatbot
	// has a live record with rec.Key. It returns the record kept and
	// whether this call stored it: a live record with rec's digest is
	// returned as it is, one with another digest is ErrKeyReused.
	// ErrInvalid if rec breaks CheckIdempotency.
	Remember(ctx context.Context, rec Idempotency, now time.Time) (Idempotency, bool, error)
	// DeleteChatbot deletes the chatbot's records.
	ChatbotDeleter
}
