package chatbot

import (
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

// Body limits (ADR 0009 §9): of a POST /v1/chatbot/messages (1,496 KiB),
// of a POST /v1/chatbot/notifications, and of every answer of both APIs.
// Content may write each character as a six-byte \uXXXX escape, so a body
// that carries content is six times its bound plus envelopeBytes for the
// other fields, which come to under 7 KiB escaped.
const (
	envelopeBytes           = 8 << 10
	MaxBotMessageBytes      = 6*MaxContentBytes + envelopeBytes
	MaxBotNotificationBytes = 8 << 10
	MaxAnswerBytes          = 8 << 10
)

// MaxRCSBodyBytes bounds a /v1/rcs/* request body when rcs-as's
// RCSAS_MAX_MESSAGE_SIZE, the most content it takes from a subscriber, is
// maxMessageSize.
func MaxRCSBodyBytes(maxMessageSize int64) int64 { return 6*maxMessageSize + envelopeBytes }

// MaxMessageIDBytes bounds an imdn.Message-ID; MaxContentTypeBytes a
// content type: an RFC 6838 §4.2 type and subtype of 127 characters each,
// the slash, and charset=utf-8.
const (
	MaxMessageIDBytes   = 128
	MaxContentTypeBytes = 255 + len(";charset=utf-8")
)

// Dispositions are the notifications a message asks for, its CPIM
// Disposition-Notification (RFC 5438 §7.1.1.3).
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
	DisplayName string `json:"display_name" maxbytes:"128"`
	// Recipient is the subscriber's canonical tel URI.
	Recipient string `json:"recipient" maxbytes:"255"`
	// MessageID is the imdn.Message-ID maap generated: 1 to
	// MaxMessageIDBytes of [A-Za-z0-9._~-].
	MessageID string `json:"message_id" maxbytes:"128"`
	// ContentType is the entry of the chatbot content types that
	// MatchContentType returned.
	ContentType string `json:"content_type" maxbytes:"269"`
	// Body is the content.
	Body string `json:"body" maxbytes:"253952"`
	// ChipList is the optional suggested chip list, the second part of a
	// multipart CPIM (RCC.07 v13.0 §3.6.10.1). It is content too: Body and
	// ChipList together are at most MaxContentBytes (§5), and
	// ValidateContent, not Validate, checks what it holds.
	ChipList string `json:"chip_list,omitempty" maxbytes:"253952"`
	// Dispositions are the notifications the chatbot asked for.
	Dispositions Dispositions `json:"dispositions"`
	// Anonymous is the conversation's anonymity flag (§10).
	Anonymous bool `json:"anonymous"`
}

// BotNotification is the body of POST /v1/chatbot/notifications: a
// chatbot's display notification for a message it received (§4
// Notifications). rcs-as answers 202 with a [BotNotificationAnswer].
type BotNotification struct {
	// Chatbot is the URI of the chatbot that read the message.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the canonical tel URI of the message's sender.
	Subscriber string `json:"subscriber" maxbytes:"255"`
	// MessageID is the imdn.Message-ID of the message the chatbot received.
	// The subscriber's client chose it, so the rule of SubscriberMessage
	// applies, not BotMessage's.
	MessageID string `json:"message_id" maxbytes:"128"`
	// Kind is imdn.DisplayNotification, the only kind a chatbot sends; its
	// status is displayed.
	Kind imdn.Kind `json:"kind" maxbytes:"32"`
}

// Admission is the body of POST /v1/rcs/admissions: may a subscriber's
// message or session reach a chatbot (§4, subscriber → chatbot step 3)?
// maap answers 200 with an [AdmissionAnswer].
type Admission struct {
	// Chatbot is the chatbot URI in normal form.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the asserted identity in canonical form.
	Subscriber string `json:"subscriber" maxbytes:"255"`
	// Anonymous says the request's Privacy held tk (§10).
	Anonymous bool `json:"anonymous"`
}

// The states of a chatbot (§11).
const (
	StateActive    = "active"
	StateSuspended = "suspended"
)

// AdmissionAnswer is the body of a 200 to POST /v1/rcs/admissions.
type AdmissionAnswer struct {
	// State is StateActive or StateSuspended.
	State string `json:"state" maxbytes:"16"`
	// OutOfServiceText is the text/plain a suspended chatbot's subscribers
	// get (§11). rcs-as checks it again with ValidateContent before it
	// sends it (security F-1).
	OutOfServiceText string `json:"out_of_service_text,omitempty" maxbytes:"512"`
}

// DeliveryCheck is the body of POST /v1/rcs/delivery-checks, made before
// each attempt to deliver a chatbot's message (§4, chatbot → subscriber
// step 5). maap answers 200 with a [DeliveryCheckAnswer].
type DeliveryCheck struct {
	// Chatbot is the sender's URI.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the recipient's canonical tel URI.
	Subscriber string `json:"subscriber" maxbytes:"255"`
}

// The reasons a delivery check does not deliver.
const (
	ReasonSuspended = "suspended"
	ReasonBlocked   = "blocked"
	ReasonUnknown   = "unknown"
)

// DeliveryCheckAnswer is the body of a 200 to POST /v1/rcs/delivery-checks.
type DeliveryCheckAnswer struct {
	// Deliver is true only if the message may be delivered now.
	Deliver bool `json:"deliver"`
	// Reason is empty if Deliver is true, else ReasonSuspended,
	// ReasonBlocked or ReasonUnknown.
	Reason string `json:"reason,omitempty" maxbytes:"16"`
}

// SubscriberMessage is the body of POST /v1/rcs/messages: rcs-as hands maap
// a subscriber's message to a chatbot (§4, subscriber → chatbot step 4).
// maap answers 200 with a [SubscriberMessageAnswer] once the webhook took it.
type SubscriberMessage struct {
	// Chatbot is the URI of the chatbot the message is for.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the asserted identity in canonical form
	// (messaging.UserOf), never a CPIM or SIP From.
	Subscriber string `json:"subscriber" maxbytes:"255"`
	// Anonymous is the conversation's anonymity flag (§10).
	Anonymous bool `json:"anonymous"`
	// MessageID is the imdn.Message-ID the subscriber's client chose: 1 to
	// MaxMessageIDBytes without C0 control or DEL.
	MessageID string `json:"message_id" maxbytes:"128"`
	// DateTimeMS is the CPIM DateTime, or 0 if the message had none.
	DateTimeMS int64 `json:"date_time_ms,omitempty"`
	// ContentType is the entry of the subscriber content types that
	// MatchContentType returned.
	ContentType string `json:"content_type" maxbytes:"269"`
	// Body is the content as rcs-as accepted it. Its bound,
	// RCSAS_MAX_MESSAGE_SIZE, is configuration, so MaxRCSBodyBytes bounds
	// it rather than this tag.
	Body string `json:"body" maxbytes:"1073741824"`
	// Dispositions are the notifications the subscriber asked for.
	Dispositions Dispositions `json:"dispositions"`
	// AcceptedAtMS is when rcs-as accepted the message; maap's 24-hour
	// reply window counts from it (§9).
	AcceptedAtMS int64 `json:"accepted_at_ms"`
}

// SubscriberNotification is the body of POST /v1/rcs/notifications: a
// subscriber's delivery or display notification about a chatbot's message,
// or a negative one rcs-as generated (§4 Notifications). maap answers 200
// with a [SubscriberNotificationAnswer].
type SubscriberNotification struct {
	// Chatbot is the URI of the chatbot that sent the message.
	Chatbot string `json:"chatbot" maxbytes:"255"`
	// Subscriber is the recipient's canonical tel URI.
	Subscriber string `json:"subscriber" maxbytes:"255"`
	// Anonymous is the conversation's anonymity flag (§10).
	Anonymous bool `json:"anonymous"`
	// MessageID is the imdn.Message-ID of the chatbot's message.
	MessageID string `json:"message_id" maxbytes:"128"`
	// Kind is imdn.DeliveryNotification or imdn.DisplayNotification.
	Kind imdn.Kind `json:"kind" maxbytes:"32"`
	// Status is one that RFC 5438 §11.1.7 allows for Kind.
	Status imdn.Status `json:"status" maxbytes:"16"`
}

// The answers of a 202 or 200 that carry nothing yet. Each is an object, so
// a field can be added (§6); an error answer is {"error": "<reason>"}.
type (
	BotMessageAnswer             struct{}
	BotNotificationAnswer        struct{}
	SubscriberMessageAnswer      struct{}
	SubscriberNotificationAnswer struct{}
)

// Validate checks the fields of m, as of every wire type: see the package
// documentation.
func (m BotMessage) Validate() error {
	switch {
	case !isText(m.Sender, MaxURIBytes):
		return invalid("sender")
	case !isText(m.DisplayName, MaxDisplayNameBytes):
		return invalid("display_name")
	case !isText(m.Recipient, MaxURIBytes):
		return invalid("recipient")
	case !isGeneratedID(m.MessageID):
		return invalid("message_id")
	case !isText(m.ContentType, MaxContentTypeBytes):
		return invalid("content_type")
	case len(m.Body)+len(m.ChipList) > MaxContentBytes:
		return invalid("body and chip_list together")
	}
	return nil
}

// Validate checks n's fields.
func (n BotNotification) Validate() error {
	switch err := pair(n.Chatbot, n.Subscriber); {
	case err != nil:
		return err
	case !isClientID(n.MessageID):
		return invalid("message_id")
	case n.Kind != imdn.DisplayNotification:
		return invalid("kind")
	}
	return nil
}

// Validate checks a's fields.
func (a Admission) Validate() error { return pair(a.Chatbot, a.Subscriber) }

// Validate checks c's fields.
func (c DeliveryCheck) Validate() error { return pair(c.Chatbot, c.Subscriber) }

// Validate checks a's fields.
func (a AdmissionAnswer) Validate() error {
	switch {
	case a.State != StateActive && a.State != StateSuspended:
		return invalid("state")
	case !isText(a.OutOfServiceText, MaxOutOfServiceTextBytes):
		return invalid("out_of_service_text")
	}
	return nil
}

// Validate checks a's fields.
func (a DeliveryCheckAnswer) Validate() error {
	if a.Deliver != (a.Reason == "") || a.Reason != "" && !slices.Contains([]string{ReasonSuspended, ReasonBlocked, ReasonUnknown}, a.Reason) {
		return invalid("reason")
	}
	return nil
}

// Validate checks m's fields.
func (m SubscriberMessage) Validate() error {
	switch err := pair(m.Chatbot, m.Subscriber); {
	case err != nil:
		return err
	case !isClientID(m.MessageID):
		return invalid("message_id")
	case !isText(m.ContentType, MaxContentTypeBytes):
		return invalid("content_type")
	}
	return nil
}

// notificationStatuses are the statuses RFC 5438 §11.1.7 allows each kind
// that reaches a chatbot.
var notificationStatuses = map[imdn.Kind][]imdn.Status{
	imdn.DeliveryNotification: {imdn.Delivered, imdn.Failed, imdn.Forbidden, imdn.Error},
	imdn.DisplayNotification:  {imdn.Displayed, imdn.Forbidden, imdn.Error},
}

// Validate checks n's fields.
func (n SubscriberNotification) Validate() error {
	statuses, ok := notificationStatuses[n.Kind]
	switch err := pair(n.Chatbot, n.Subscriber); {
	case err != nil:
		return err
	case !isClientID(n.MessageID):
		return invalid("message_id")
	case !ok:
		return invalid("kind")
	case !slices.Contains(statuses, n.Status):
		return invalid("status")
	}
	return nil
}

// Validate of an answer without fields accepts it.
func (BotMessageAnswer) Validate() error             { return nil }
func (BotNotificationAnswer) Validate() error        { return nil }
func (SubscriberMessageAnswer) Validate() error      { return nil }
func (SubscriberNotificationAnswer) Validate() error { return nil }

func pair(chatbot, subscriber string) error {
	switch {
	case !isText(chatbot, MaxURIBytes):
		return invalid("chatbot")
	case !isText(subscriber, MaxURIBytes):
		return invalid("subscriber")
	}
	return nil
}

func invalid(field string) error { return refuse(ErrInvalidEnvelope, "invalid "+field) }

// isText reports whether s is at most maxBytes without a C0 control or DEL.
func isText(s string, maxBytes int) bool {
	return len(s) <= maxBytes && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// isClientID reports whether s may be a Message-ID a subscriber's client
// chose. CPIM carries it as a token (RFC 5438 §6.3), which rcs-as checks
// where it reads it; this rule keeps only what makes it safe to carry.
func isClientID(s string) bool { return s != "" && isText(s, MaxMessageIDBytes) }

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
