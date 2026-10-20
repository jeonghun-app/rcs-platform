package messaging

import (
	"errors"
	"strings"
)

// The SIP headers that identify a conversation (RCC.07, conversation and
// contribution identities). The SIP layer reads them from INVITE and MESSAGE
// requests and gives their values to ParseConversationHeaders.
const (
	HeaderConversationID = "Conversation-ID"
	HeaderContributionID = "Contribution-ID"
	HeaderInReplyTo      = "InReplyTo-Contribution-ID"
)

// MaxIDLength bounds each conversation identifier. Real ones are UUIDs or
// hex strings of a few dozen characters; the bound keeps a client from
// making every stored message carry kilobytes of identifier.
const MaxIDLength = 256

// ErrInvalidConversation reports conversation headers outside the accepted
// grammar.
var ErrInvalidConversation = errors.New("messaging: invalid conversation identifiers")

// Conversation identifies the 1-to-1 conversation a message belongs to.
// The values are opaque and compared exactly.
type Conversation struct {
	// ID is the Conversation-ID, shared by every session and message of
	// the conversation.
	ID string
	// Contribution is the Contribution-ID of one session or standalone
	// message.
	Contribution string
	// InReplyTo is the InReplyTo-Contribution-ID, the contribution being
	// answered; empty when absent.
	InReplyTo string
}

// ParseConversationHeaders reads the values of the three conversation
// headers, each the empty string when the header is absent.
//
// RCC.07 defines no grammar beyond the SIP header syntax, so each value is
// taken as one RFC 3261 token, the form clients generate (hex strings and
// UUIDs), of at most MaxIDLength characters, with surrounding white space
// removed. A request with none of the three gives the zero Conversation:
// rcsjta sends pager-mode messages and notifications without them, and the
// engine does not need them. Otherwise Contribution-ID is required, since
// a Conversation-ID or a reply means nothing without the contribution it
// belongs to. Conversation-ID is optional: rcsjta sends a Contribution-ID
// alone (#298). It stays empty then rather than being made up: one made
// for each request would put every message of one conversation in a
// different one. InReplyTo-Contribution-ID is optional.
func ParseConversationHeaders(conversationID, contributionID, inReplyTo string) (Conversation, error) {
	c := Conversation{
		ID:           trimSpace(conversationID),
		Contribution: trimSpace(contributionID),
		InReplyTo:    trimSpace(inReplyTo),
	}
	if c == (Conversation{}) {
		return c, nil
	}
	if c.ID != "" && !isID(c.ID) || !isID(c.Contribution) || c.InReplyTo != "" && !isID(c.InReplyTo) {
		return Conversation{}, ErrInvalidConversation
	}
	return c, nil
}

// trimSpace removes SP and HTAB, the only white space a SIP header value
// can carry around it (RFC 3261 §25.1, LWS).
func trimSpace(s string) string { return strings.Trim(s, " \t") }

// ValidID reports whether s is a conversation identifier the engine takes
// (Conversation-ID, Contribution-ID, InReplyTo-Contribution-ID): one
// RFC 3261 token of at most MaxIDLength characters, as received or
// generated elsewhere in rcs-as.
func ValidID(s string) bool { return isID(s) }

func isID(s string) bool {
	if s == "" || len(s) > MaxIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isTokenChar is the RFC 3261 §25.1 token alphabet.
func isTokenChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-.!%*_+`'~", c) >= 0
}
