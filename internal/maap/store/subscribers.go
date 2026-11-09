package store

import (
	"context"
	"strings"
	"time"
)

// AliasIDBytes is the length of an alias ID: 128 random bits in base32
// (RFC 4648 §6), lower case, without padding (the lead's decision on #711,
// the form #714 masks).
const AliasIDBytes = 26

const aliasIDAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// aliasIDFinals are the last characters 128 bits can end in: the 26th
// character holds 3 bits and 2 zero bits of padding (RFC 4648 §6).
const aliasIDFinals = "aeimquy4"

// AliasLifetime is how long an alias lives unused (ADR 0009 §10).
const AliasLifetime = 180 * 24 * time.Hour

// ValidAliasID reports whether id has an alias ID's form, which every
// backend checks before it reads, so that an ID no alias can have costs no
// read. Upper or mixed case is refused, never folded: pii.Redact masks an
// ID written in one case only (#721).
func ValidAliasID(id string) bool {
	return len(id) == AliasIDBytes && strings.Trim(id, aliasIDAlphabet) == "" &&
		strings.IndexByte(aliasIDFinals, id[len(id)-1]) >= 0
}

// ValidSubscriber reports whether s is a subscriber's key: a global
// number as messaging.UserOf writes it, "tel:+" and 1–15 digits (E.164).
func ValidSubscriber(s string) bool {
	digits, ok := strings.CutPrefix(s, "tel:+")
	return ok && digits != "" && len(digits) <= 15 && strings.Trim(digits, "0123456789") == ""
}

// Alias is what a chatbot sees of a subscriber in one kind of
// conversation, anonymous or not (ADR 0009 §10): only maap maps its ID
// back.
type Alias struct {
	ID      string
	Chatbot string
	// Subscriber is the subscriber's key (ValidSubscriber).
	Subscriber string
	Anonymous  bool
	// Created and LastUsed are in seconds; LastUsed starts at Created.
	Created  time.Time
	LastUsed time.Time
}

// Expired reports whether a was unused for AliasLifetime at now. Expiry is
// judged so when an alias is read, never by its item's presence, since
// DynamoDB's TTL deletes late.
func (a Alias) Expired(now time.Time) bool { return !now.Before(a.LastUsed.Add(AliasLifetime)) }

func (a Alias) valid() bool {
	return ValidAliasID(a.ID) && ValidID(a.Chatbot) && ValidSubscriber(a.Subscriber)
}

// Subscribers is the maap-subscribers table: subscribers' aliases (#711),
// keyed by the subscriber, so that one number's items are found without a
// scan (#712), and by the chatbot. Every method is safe for concurrent
// use, also across tasks sharing a backend.
type Subscribers interface {
	// Alias returns the alias of want's chatbot, subscriber and anonymity
	// that is live at want.Created. When there is none, or it expired, it
	// stores want, used at want.Created, by a conditional write: of
	// concurrent calls one alias is stored, and each returns it.
	// ErrInvalid for a malformed want, or an alias ID taken.
	Alias(ctx context.Context, want Alias) (Alias, error)
	// Resolve returns the chatbot's alias with the ID: ErrNotFound if the
	// chatbot has none with it, as for another chatbot's, or if it expired
	// at now.
	Resolve(ctx context.Context, chatbotID, aliasID string, now time.Time) (Alias, error)
	// Used records at as a's last use, unless a later one is stored; an
	// alias deleted or replaced, or expired at at, is not written again,
	// so that a late write cannot bring an expired alias back.
	Used(ctx context.Context, a Alias, at time.Time) error
	// DeleteChatbot deletes the chatbot's aliases.
	ChatbotDeleter
}
