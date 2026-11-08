package chatbot

import (
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
)

// Body limits (ADR 0009 §9): of a POST /v1/chatbot/messages (1,496 KiB),
// of a POST /v1/chatbot/notifications, and of every answer of rcs-as's and
// maap's internal APIs.
// Content may write each character as a six-byte \uXXXX escape, so a body
// that carries content is six times its bound plus envelopeBytes for the
// other fields, which come to under 7 KiB escaped.
const (
	envelopeBytes           = 8 << 10
	MaxBotMessageBytes      = 6*MaxContentBytes + envelopeBytes
	MaxBotNotificationBytes = 8 << 10
	MaxAnswerBytes          = 8 << 10
)

// MaxMessageIDBytes bounds an imdn.Message-ID; MaxContentTypeBytes a
// content type: an RFC 6838 §4.2 type and subtype of 127 characters each,
// the slash, and charset=utf-8.
const (
	MaxMessageIDBytes   = 128
	MaxContentTypeBytes = 255 + len(";charset=utf-8")
)

// Dispositions are the notifications a message asks for, its CPIM
// Disposition-Notification (RFC 5438 §7.1.1.3). An absent member is false.
type Dispositions struct {
	// PositiveDelivery asks for a delivered notification.
	PositiveDelivery bool `json:"positive_delivery"`
	// NegativeDelivery asks for a failed notification.
	NegativeDelivery bool `json:"negative_delivery"`
	// Display asks for a displayed notification.
	Display bool `json:"display"`
}

// BotMessage is the body of POST /v1/chatbot/messages: maap hands rcs-as a
// chatbot's message to one subscriber (ADR 0009 §4, chatbot → subscriber
// step 3). rcs-as answers 202 with a [BotMessageAnswer].
type BotMessage struct {
	// Sender is the chatbot's URI from the registry, never one the chatbot
	// chose; rcs-as refuses one outside the chatbot range.
	Sender string `json:"sender" maxbytes:"255"`
	// DisplayName is the registry display name, before rcs-as escapes it
	// into CPIM From.
	DisplayName *string `json:"display_name" maxbytes:"128"`
	// Recipient is the subscriber's canonical tel URI.
	Recipient string `json:"recipient" maxbytes:"255"`
	// MessageID is the imdn.Message-ID maap generated: 1 to
	// MaxMessageIDBytes of [A-Za-z0-9._~-].
	MessageID string `json:"message_id" maxbytes:"128"`
	// ContentType is the entry of the chatbot content types that
	// MatchContentType returned.
	ContentType string `json:"content_type" maxbytes:"269"`
	// Body is the content.
	Body *string `json:"body" maxbytes:"253952"`
	// ChipList is the optional suggested chip list, the second part of a
	// multipart CPIM (RCC.07 v13.0 §3.6.10.1). It is content too: Body and
	// ChipList together are at most MaxContentBytes (§5), and
	// ValidateContent, not Validate, checks what it holds.
	ChipList string `json:"chip_list,omitempty" maxbytes:"253952"`
	// Dispositions are the notifications the chatbot asked for.
	Dispositions *Dispositions `json:"dispositions"`
	// Anonymous is the conversation's anonymity flag (§10).
	Anonymous *bool `json:"anonymous"`
}

// BotNotification is the body of POST /v1/chatbot/notifications: a
// chatbot's display notification for a message it received (§4
// Notifications). rcs-as answers 202 with a [BotNotificationAnswer].
type BotNotification struct {
	// Chatbot is the URI of the chatbot that read the message.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the canonical tel URI of the message's sender.
	Subscriber string `json:"subscriber" maxbytes:"255"`
	// MessageID is the imdn.Message-ID of the message the chatbot received,
	// which the subscriber's client chose: a CPIM token (RFC 3862 §3.6) of 1
	// to MaxMessageIDBytes that XML can carry, the rule by which rcs-as
	// builds an IMDN. rcs-as builds it from the ID of the sent record it
	// finds (T10), not from this string.
	MessageID string `json:"message_id" maxbytes:"128"`
	// Kind is imdn.DisplayNotification, the only kind a chatbot sends; its
	// status is displayed.
	Kind imdn.Kind `json:"kind" maxbytes:"32"`
}

// The answers of a 202 that carry nothing yet. Each is an object, so a
// field can be added (§6); an error answer is {"error": "<reason>"}.
type (
	BotMessageAnswer      struct{}
	BotNotificationAnswer struct{}
)

// botNotificationKinds are the kinds a chatbot sends. A new value ships in
// the receiver a release before any sender uses it (§6).
var botNotificationKinds = []imdn.Kind{imdn.DisplayNotification}

// Validate checks the fields of m, as of every wire type: see the package
// documentation.
func (m BotMessage) Validate() error {
	switch err := pair(m.Sender, "sender", m.Recipient, "recipient"); {
	case err != nil:
		return err
	case m.DisplayName == nil || !isText(*m.DisplayName, MaxDisplayNameBytes):
		return invalid("display_name")
	case !isGeneratedID(m.MessageID):
		return invalid("message_id")
	case !isRequired(m.ContentType, MaxContentTypeBytes):
		return invalid("content_type")
	case m.Body == nil || len(*m.Body)+len(m.ChipList) > MaxContentBytes:
		return invalid("body")
	case m.Dispositions == nil:
		return invalid("dispositions")
	case m.Anonymous == nil:
		return invalid("anonymous")
	}
	return nil
}

// Validate checks n's fields.
func (n BotNotification) Validate() error {
	switch err := pair(n.Chatbot, "chatbot", n.Subscriber, "subscriber"); {
	case err != nil:
		return err
	case !isClientID(n.MessageID):
		return invalid("message_id")
	case !slices.Contains(botNotificationKinds, n.Kind):
		return invalid("kind")
	}
	return nil
}

// Validate of an answer without fields accepts it.
func (BotMessageAnswer) Validate() error      { return nil }
func (BotNotificationAnswer) Validate() error { return nil }

// pair checks the two URIs every request names, a chatbot's and a
// subscriber's, as named on the wire.
func pair(bot, botField, subscriber, subscriberField string) error {
	switch {
	case !isRequired(bot, MaxURIBytes):
		return invalid(botField)
	case !isRequired(subscriber, MaxURIBytes):
		return invalid(subscriberField)
	}
	return nil
}

func invalid(field string) error { return refuse(ErrInvalidEnvelope, "invalid "+field) }

// isText reports whether s is at most maxBytes without a C0 control or DEL.
func isText(s string, maxBytes int) bool {
	return len(s) <= maxBytes && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// isRequired is isText for a field that must not be empty.
func isRequired(s string, maxBytes int) bool { return s != "" && isText(s, maxBytes) }

// isClientID reports whether s is a Message-ID rcs-as could write into an
// IMDN (imdn.Notification checks the same): a CPIM token, which holds no
// ASCII control or space, that XML can carry (no U+FFFE or U+FFFF).
func isClientID(s string) bool {
	return len(s) <= MaxMessageIDBytes && cpim.IsToken(s) && xmlsafe.IsText(s)
}

// isGeneratedID reports whether s has the form of a Message-ID maap
// generates: unreserved URI characters only (RFC 3986 §2.3), safe as it is
// in a header, a path and a log.
func isGeneratedID(s string) bool {
	if s == "" || len(s) > MaxMessageIDBytes {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._~-", c) >= 0) {
			return false
		}
	}
	return true
}
