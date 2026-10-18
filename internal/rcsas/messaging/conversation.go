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
// removed. Conversation-ID and Contribution-ID are required, since a
// message without them cannot be put in any conversation;
// InReplyTo-Contribution-ID is optional.
func ParseConversationHeaders(conversationID, contributionID, inReplyTo string) (Conversation, error) {
	c := Conversation{
		ID:           trimSpace(conversationID),
		Contribution: trimSpace(contributionID),
		InReplyTo:    trimSpace(inReplyTo),
	}
	if !isID(c.ID) || !isID(c.Contribution) || c.InReplyTo != "" && !isID(c.InReplyTo) {
		return Conversation{}, ErrInvalidConversation
	}
	return c, nil
}

// trimSpace removes SP and HTAB, the only white space a SIP header value
// can carry around it (RFC 3261 §25.1, LWS).
func trimSpace(s string) string { return strings.Trim(s, " \t") }

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
