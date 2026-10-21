package messaging

import (
	"crypto/sha1"
	"encoding/hex"
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
	// the conversation. It is empty for a request that came without any of
	// the conversation headers (rcsjta's pager mode); one that came with a
	// Contribution-ID alone gets the pair's (PairConversationID) when the
	// engine takes it.
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
// belongs to. InReplyTo-Contribution-ID is optional.
//
// Conversation-ID is required of a sender by OMA CPM (Conversation
// Functions, Appendix C.1.1), but rcsjta, a pre-CPM client, sends a
// Contribution-ID alone with its INVITEs (#298). That is taken as a
// leniency, with the ID left empty here; the engine then gives the request
// its pair's Conversation-ID (PairConversationID), which rcs-as, the sender
// of what it delivers, must include.
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

// pairNamespace is the UUID namespace of PairConversationID's name-based
// UUIDs, chosen for rcs-as.
var pairNamespace = [16]byte{0x93, 0x33, 0xb4, 0xd3, 0xf0, 0xc3, 0x44, 0x0b, 0x85, 0xcf, 0x39, 0xb4, 0x27, 0x42, 0x92, 0x81}

// PairConversationID is the Conversation-ID rcs-as gives a 1-to-1 request
// that came with a Contribution-ID and no Conversation-ID (#298): a
// name-based UUID (RFC 9562 §5.5, version 5), in the UUID form OMA CPM
// Appendix C.1.1 asks of a Conversation-ID, of the two users' keys
// (UserOf) in sorted order. Every message between the same two users, in
// either direction, so has one Conversation-ID, and threads together on a
// client that reads it, as the client that left it out would not see.
func PairConversationID(a, b string) string {
	if b < a {
		a, b = b, a
	}
	h := sha1.New()
	h.Write(pairNamespace[:])
	h.Write([]byte(a + "\x00" + b))
	u := h.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x50 // version 5
	u[8] = u[8]&0x3f | 0x80 // the RFC 9562 variant
	x := hex.EncodeToString(u)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}
