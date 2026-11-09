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
//
// A record starts pending, with the Message-ID generated for the request:
// a repeat then is neither replayed nor sent (#683 answers 409, or 503 to
// try again later). The writer that stored it settles it with the answer
// once rcs-as has answered, which repeats then get, or forgets it when the
// request was refused before it was sent (lead decision on #713).
type Idempotency struct {
	Chatbot string
	Key     string
	// Digest is the SHA-256 of the request, which #683 computes; another
	// request with the key has another digest. The DynamoDB backend keeps
	// only an HMAC of it, so that a reader of the table or a backup cannot
	// test guesses of a request (#749 security review).
	Digest [sha256.Size]byte
	// MessageID is the Message-ID generated for the request, which a
	// retry after a lost answer sends again.
	MessageID string
	// Pending says the record is not settled yet; Answer is the settled
	// answer, opaque to the store.
	Pending bool
	Answer  []byte
	// Writer is the token of the call that stored the record, which Settle
	// and Forget need; Remember returns it to that call only.
	Writer string
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

// CheckRemember checks a record Remember is to store, which is pending.
func CheckRemember(r Idempotency) error {
	if len(r.Answer) > 0 {
		return fmt.Errorf("%w: a new record is pending, without an answer", ErrInvalid)
	}
	return CheckIdempotency(r)
}

// CheckRecordKey checks a chatbot ID and idempotency key before any read.
func CheckRecordKey(chatbotID, key string) error {
	if !ValidID(chatbotID) || !ValidIdempotencyKey(key) {
		return fmt.Errorf("%w: a malformed chatbot ID or idempotency key", ErrInvalid)
	}
	return nil
}

// checkStatusKey checks a status's chatbot ID and Message-ID, before any
// read, so that no other value reaches a key.
func checkStatusKey(chatbotID, messageID string) error {
	if !ValidID(chatbotID) || !ValidMessageID(messageID) {
		return fmt.Errorf("%w: a malformed chatbot ID or Message-ID", ErrInvalid)
	}
	return nil
}

// CheckStatus checks the rules every stored status keeps.
func CheckStatus(s Status) error {
	if !s.State.Valid() {
		return fmt.Errorf("%w: an unknown status state", ErrInvalid)
	}
	return checkStatusKey(s.Chatbot, s.MessageID)
}

// CheckAdvance checks Advance's arguments.
func CheckAdvance(chatbotID, messageID string, state StatusState) error {
	if state.Before() == nil {
		return fmt.Errorf("%w: a status advances to delivered, displayed or failed only", ErrInvalid)
	}
	return checkStatusKey(chatbotID, messageID)
}

// Live reports whether a record created at created is still kept at now:
// expiry is judged by the times, never by an item's presence, since
// DynamoDB's TTL deletes late (ADR 0009 §10).
func Live(created time.Time, ttl time.Duration, now time.Time) bool {
	return now.Before(created.Add(ttl))
}

// StatusState is what a chatbot sees of a message it sent: accepted, then
// delivered, displayed or failed, without a reason (ADR 0009 §4).
type StatusState string

const (
	Accepted  StatusState = "accepted"
	Delivered StatusState = "delivered"
	Displayed StatusState = "displayed"
	Failed    StatusState = "failed"
)

// Before returns the states a status in s may come from: notifications
// arrive in any order and from any task, and a status never goes back.
// A display notification follows any other, since it shows delivery.
func (s StatusState) Before() []StatusState {
	switch s {
	case Delivered, Failed:
		return []StatusState{Accepted}
	case Displayed:
		return []StatusState{Accepted, Delivered, Failed}
	}
	return nil
}

// Valid reports whether s is a state.
func (s StatusState) Valid() bool { return s == Accepted || s.Before() != nil }

// Status is the status of a message a chatbot sent, kept with its owning
// chatbot for the table's status TTL (MAAP_STATUS_TTL) from Accepted.
type Status struct {
	Chatbot   string
	MessageID string
	State     StatusState
	// Accepted and Updated are in seconds.
	Accepted time.Time
	Updated  time.Time
}

// Requests is the maap-requests table. Every method is safe for
// concurrent use, also across tasks sharing a backend.
type Requests interface {
	// Remember stores rec as a pending record, with Created set to now and
	// a Writer of its own, unless the chatbot has a live record with
	// rec.Key. It returns the record kept and whether this call stored it:
	// a live record with rec's digest is returned as it is, pending or
	// settled, without its writer; one with another digest is
	// ErrKeyReused. ErrInvalid if rec breaks CheckIdempotency or has an
	// answer.
	Remember(ctx context.Context, rec Idempotency, now time.Time) (Idempotency, bool, error)
	// Settle stores answer in the live record of the chatbot's key that
	// writer stored, which is then no longer pending; settling again with
	// the same writer stores the answer again. ErrNotFound if there is no
	// live record, ErrConflict if another writer stored it.
	Settle(ctx context.Context, chatbotID, key, writer string, answer []byte, now time.Time) error
	// Forget deletes the record of the chatbot's key that writer stored,
	// so that a repeat of a request refused before it was sent is checked
	// again. It returns nil if there is none, ErrConflict if another
	// writer stored the one there.
	Forget(ctx context.Context, chatbotID, key, writer string) error
	// Accept stores the status of a send rcs-as accepted at now, as
	// Accepted. A live status of the message is left as it is: a retry
	// after a lost answer sends the same Message-ID again.
	Accept(ctx context.Context, chatbotID, messageID string, now time.Time) error
	// Status returns the chatbot's live status of the message, ErrNotFound
	// if it has none: another chatbot's message is not found.
	Status(ctx context.Context, chatbotID, messageID string, now time.Time) (Status, error)
	// Advance sets the live status to state if it is in one of
	// state.Before(), and reports whether this call changed it;
	// ErrNotFound if there is no live status, ErrInvalid for Accepted.
	Advance(ctx context.Context, chatbotID, messageID string, state StatusState, now time.Time) (bool, error)
	// DeleteChatbot deletes the chatbot's records and statuses.
	ChatbotDeleter
}
