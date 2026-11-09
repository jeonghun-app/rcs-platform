package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
)

// Errors every registry backend returns, possibly wrapped. Any other error
// is the store failing, which callers answer 503, never 404.
var (
	ErrNotFound = errors.New("store: not found")
	// ErrExists means Register found the chatbot ID taken.
	ErrExists = errors.New("store: chatbot ID already registered")
	// ErrURITaken means another chatbot holds the URI (#709 answers 409).
	ErrURITaken = errors.New("store: chatbot URI taken")
	// ErrConflict means the chatbot changed since it was read.
	ErrConflict = errors.New("store: changed by another writer")
	// ErrInvalid means a record breaks the rules of [CheckChatbot], or a
	// stored item is damaged.
	ErrInvalid = errors.New("store: invalid record")
)

// State is a chatbot's operator state (ADR 0009 §11).
type State string

const (
	Active    State = "active"
	Suspended State = "suspended"
)

// Bounds of a chatbot record (ADR 0009 §7, §8). The maxbytes tags below
// repeat them, since chatbot.DecodeEnvelope reads a tag, not a constant.
const (
	MaxIDBytes          = 64
	MaxDisplayNameBytes = 128
	MaxOutOfServiceText = 512
	MaxWebhookBytes     = 512
	// MaxSources is the most source networks a chatbot may list: the
	// longest array an envelope holds, the operator's included.
	MaxSources = chatbot.MaxEnvelopeArray
)

// Chatbot is one registered chatbot, as the operator set it (ADR 0009 §7).
// Fields only grow, and a reader learns a field a release before any
// writer stores it (ADR 0009 §6): decoding refuses what it does not know.
type Chatbot struct {
	// ID is the chatbot's key in every maap table: 1–64 bytes of letters,
	// digits, "-" and "_".
	ID string `json:"id" maxbytes:"64"`
	// URI is the chatbot's PSI in the normal form of chatbot.Domain's
	// Normalise, so that two spellings of one URI are one key (T13). It
	// never changes: a chatbot that needs another URI is deleted and
	// registered again.
	URI          string      `json:"uri" maxbytes:"255"`
	DisplayName  string      `json:"display_name,omitempty" maxbytes:"128"`
	OutOfService string      `json:"out_of_service,omitempty" maxbytes:"512"`
	Webhook      Webhook     `json:"webhook,omitzero"`
	Permissions  Permissions `json:"permissions,omitzero"`
	Limits       Limits      `json:"limits,omitzero"`
	// Sources is the allow-list of networks the chatbot's API calls may
	// come from, in canonical prefix form; empty allows any (ADR 0009 §7).
	Sources []string `json:"sources,omitempty" maxbytes:"43"`
	State   State    `json:"state" maxbytes:"9"`
	// Version is the stored version, which Update is conditional on; the
	// store sets it, outside the stored document.
	Version int64 `json:"-"`
}

// Webhook is where maap delivers the chatbot's events (ADR 0009 §8).
type Webhook struct {
	URL string `json:"url,omitempty" maxbytes:"512"`
	// Verified says the URL answered the signed challenge.
	Verified bool `json:"verified,omitempty"`
}

// Permissions widen what the chatbot may do (ADR 0009 §9, §10).
type Permissions struct {
	// MSISDN lets the chatbot see subscribers' numbers instead of aliases.
	MSISDN bool `json:"msisdn,omitempty"`
	// StartConversations lets it send outside the reply window.
	StartConversations bool `json:"start_conversations,omitempty"`
}

// Limits are the chatbot's own bounds, one per row of ADR 0009 §9's table
// that bounds a chatbot, which the operator may set below the platform's
// defaults, never above (#709 checks). Zero is the default.
type Limits struct {
	SendsPerMinute                 int64 `json:"sends_per_minute,omitempty"`
	SendsPerDay                    int64 `json:"sends_per_day,omitempty"`
	StartsPerMinute                int64 `json:"starts_per_minute,omitempty"`
	StartsPerDay                   int64 `json:"starts_per_day,omitempty"`
	SendsPerSubscriberPerMinute    int64 `json:"sends_per_subscriber_per_minute,omitempty"`
	SendsPerSubscriberPerDay       int64 `json:"sends_per_subscriber_per_day,omitempty"`
	ReceivedPerSubscriberPerMinute int64 `json:"received_per_subscriber_per_minute,omitempty"`
	ReceivedPerMinute              int64 `json:"received_per_minute,omitempty"`
	RequestsPerMinute              int64 `json:"requests_per_minute,omitempty"`
}

// Registry is the maap-registry table: chatbots, each with an item that
// reserves its URI, and (#710) their credentials. Every method is safe for
// concurrent use, also across tasks sharing a backend.
type Registry interface {
	// Register stores c at version 1 and reserves its URI, both in one
	// conditional write: ErrURITaken if another chatbot holds the URI,
	// ErrExists if the ID is taken, ErrInvalid if c breaks CheckChatbot.
	Register(ctx context.Context, c Chatbot) (Chatbot, error)
	// Chatbot returns the chatbot with the given ID, ErrNotFound if none.
	Chatbot(ctx context.Context, id string) (Chatbot, error)
	// Update replaces old, as read, with c at old.Version+1, if the stored
	// version is still old.Version: ErrConflict if another write came
	// first, ErrNotFound if the chatbot is gone, ErrInvalid if c has
	// another ID or URI than old.
	Update(ctx context.Context, old, c Chatbot) (Chatbot, error)
	// DeleteChatbot deletes the chatbot and every item of it, its URI's
	// included, which another chatbot may then register.
	ChatbotDeleter
}

// CheckChatbot checks the rules every stored chatbot keeps. The values'
// meaning (the URI's host, the webhook's form, limits under the defaults)
// is for the operator API to check before it writes (#709).
func CheckChatbot(c Chatbot) error {
	fail := func(reason string) error { return fmt.Errorf("%w: chatbot: %s", ErrInvalid, reason) }
	switch {
	case c.ID == "" || len(c.ID) > MaxIDBytes || strings.Trim(c.ID, idBytes) != "":
		return fail("ID is not 1–64 letters, digits, - or _")
	case !normal(c.URI):
		return fail("URI is not in normal form")
	case len(c.DisplayName) > MaxDisplayNameBytes || len(c.OutOfService) > MaxOutOfServiceText ||
		len(c.Webhook.URL) > MaxWebhookBytes:
		return fail("a text over its bound")
	case len(c.Sources) > MaxSources:
		return fail("too many source networks")
	case c.State != Active && c.State != Suspended:
		return fail("unknown state")
	case min(c.Limits.SendsPerMinute, c.Limits.SendsPerDay, c.Limits.StartsPerMinute, c.Limits.StartsPerDay,
		c.Limits.SendsPerSubscriberPerMinute, c.Limits.SendsPerSubscriberPerDay,
		c.Limits.ReceivedPerSubscriberPerMinute, c.Limits.ReceivedPerMinute, c.Limits.RequestsPerMinute) < 0:
		return fail("a negative limit")
	}
	for _, s := range c.Sources {
		if p, err := netip.ParsePrefix(s); err != nil || p != p.Masked() || p.String() != s {
			return fail("a source network not in canonical prefix form")
		}
	}
	return nil
}

const idBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

// normal reports whether uri is a chatbot URI in normal form at its own
// host, which keeps one spelling per URI whatever RCS_CHATBOT_DOMAIN is.
func normal(uri string) bool {
	d, err := chatbot.NewDomain(uri[strings.LastIndexByte(uri, '@')+1:], "")
	if err != nil {
		return false
	}
	n, err := d.Normalise(uri)
	return err == nil && n == uri
}

// The stored form of a chatbot is a JSON document with a schema number,
// which both backends keep as is beside the version.
const chatbotSchema = 1

// MaxRecordBytes bounds a stored document: every text at its bound, each
// byte of it written as a six-byte \u escape, stays under it
// (TestTheLongestChatbotRoundTrips).
const MaxRecordBytes = 16 << 10

type chatbotRecord struct {
	Schema  int     `json:"schema"`
	Chatbot Chatbot `json:"chatbot"`
}

// EncodeChatbot returns the stored form of c, without its version.
func EncodeChatbot(c Chatbot) ([]byte, error) {
	if err := CheckChatbot(c); err != nil {
		return nil, err
	}
	data, err := json.Marshal(chatbotRecord{Schema: chatbotSchema, Chatbot: c})
	if err != nil || len(data) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: chatbot does not encode within %d bytes", ErrInvalid, MaxRecordBytes)
	}
	return data, nil
}

// DecodeChatbot reads a stored chatbot strictly and checks it as
// CheckChatbot does; version is the one the backend stored with it.
func DecodeChatbot(data []byte, version int64) (Chatbot, error) {
	var r chatbotRecord
	if err := chatbot.DecodeEnvelope(bytes.NewReader(data), MaxRecordBytes, &r); err != nil {
		return Chatbot{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if r.Schema != chatbotSchema {
		return Chatbot{}, fmt.Errorf("%w: unknown chatbot schema", ErrInvalid)
	}
	if err := CheckChatbot(r.Chatbot); err != nil {
		return Chatbot{}, err
	}
	if len(r.Chatbot.Sources) == 0 {
		r.Chatbot.Sources = nil // as EncodeChatbot leaves it out
	}
	r.Chatbot.Version = version
	return r.Chatbot, nil
}
