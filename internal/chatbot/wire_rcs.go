package chatbot

import (
	"math"
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

// MaxRCSBodyBytes bounds a /v1/rcs/* request body when rcs-as's
// RCSAS_MAX_MESSAGE_SIZE, the most content it takes from a subscriber, is
// maxMessageSize; a size whose limit overflows gets math.MaxInt64. The
// limit bounds the encoded body, so the receiver still checks the decoded
// content against maxMessageSize (see SubscriberMessage.Body).
func MaxRCSBodyBytes(maxMessageSize int64) int64 {
	if maxMessageSize > (math.MaxInt64-envelopeBytes)/6 {
		return math.MaxInt64
	}
	return 6*maxMessageSize + envelopeBytes
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
	Anonymous *bool `json:"anonymous"`
}

// The states of a chatbot (§11).
const (
	StateActive    = "active"
	StateSuspended = "suspended"
)

// The reasons an admission is refused or a delivery check does not
// deliver. A reason is a value of a 200, never an HTTP status, so that a
// 404 from a misrouted call cannot read as an unknown chatbot.
const (
	ReasonBlocked   = "blocked"    // the subscriber blocked the chatbot (§11)
	ReasonOverLimit = "over_limit" // a subscriber limit of §9; admission only
	ReasonSuspended = "suspended"  // delivery checks only
	ReasonUnknown   = "unknown"    // no such chatbot
)

// AdmissionAnswer is the body of a 200 to POST /v1/rcs/admissions: either a
// State, or a Reason the request is refused. rcs-as answers ReasonUnknown
// 404, ReasonBlocked 403 with the Warning of RCC.07 v13.0 §3.6.6, and
// ReasonOverLimit 403 without it (§4 step 3).
type AdmissionAnswer struct {
	// State is StateActive or StateSuspended when Reason is empty.
	State string `json:"state,omitempty" maxbytes:"16"`
	// OutOfServiceText is the text/plain a suspended chatbot's subscribers
	// get (§11). rcs-as checks it again with ValidateContent before it
	// sends it (security F-1).
	OutOfServiceText string `json:"out_of_service_text,omitempty" maxbytes:"512"`
	// Reason is ReasonBlocked, ReasonOverLimit or ReasonUnknown when the
	// request is refused; State and OutOfServiceText are then empty.
	Reason string `json:"reason,omitempty" maxbytes:"16"`
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

// DeliveryCheckAnswer is the body of a 200 to POST /v1/rcs/delivery-checks.
type DeliveryCheckAnswer struct {
	// Deliver is true only if the message may be delivered now.
	Deliver *bool `json:"deliver"`
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
	Anonymous *bool `json:"anonymous"`
	// MessageID is the imdn.Message-ID the subscriber's client chose: a
	// CPIM token (RFC 3862 §3.6) of 1 to MaxMessageIDBytes that XML can
	// carry, the rule by which rcs-as builds an IMDN.
	MessageID string `json:"message_id" maxbytes:"128"`
	// DateTimeMS is the CPIM DateTime, or 0 if the message had none.
	DateTimeMS int64 `json:"date_time_ms,omitempty"`
	// ContentType is the entry of the subscriber content types that
	// MatchContentType returned.
	ContentType string `json:"content_type" maxbytes:"269"`
	// Body is the content as rcs-as accepted it. Its bound,
	// RCSAS_MAX_MESSAGE_SIZE, is configuration, so this tag does not bound
	// it, and MaxRCSBodyBytes bounds only its encoding: the receiver checks
	// len(*Body) against RCSAS_MAX_MESSAGE_SIZE itself.
	Body *string `json:"body" maxbytes:"1073741824"`
	// Dispositions are the notifications the subscriber asked for.
	Dispositions *Dispositions `json:"dispositions"`
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
	Anonymous *bool `json:"anonymous"`
	// MessageID is the imdn.Message-ID of the chatbot's message.
	MessageID string `json:"message_id" maxbytes:"128"`
	// Kind is imdn.DeliveryNotification or imdn.DisplayNotification.
	Kind imdn.Kind `json:"kind" maxbytes:"32"`
	// Status is one that RFC 5438 §11.1.7 allows for Kind.
	Status imdn.Status `json:"status" maxbytes:"16"`
}

// The reasons of a DeliveryRefusal that ask for a retry (§4, §12): the
// chatbot's webhook failed or timed out, or its deliveries are all in use or
// its webhook breaker is open.
const (
	ReasonWebhookFailed = "webhook_failed"
	ReasonChatbotBusy   = "chatbot_busy"
)

// DeliveryRefusal is the body of a 404 or 503 to POST /v1/rcs/messages and
// /v1/rcs/notifications (§4, subscriber → chatbot step 5). It is what tells
// maap's answer about one chatbot from a 404 or 503 of anything else on the
// way, such as a mux that does not serve the path or a server too busy to
// read the request, which rcs-as reads as maap unavailable (#747).
type DeliveryRefusal struct {
	// Reason is ReasonSuspended, ReasonBlocked or ReasonUnknown with a 404
	// (undeliverable), ReasonWebhookFailed or ReasonChatbotBusy with a 503
	// (retry).
	Reason string `json:"reason" maxbytes:"16"`
}

// Undeliverable reports whether r is a reason for a 404 rather than a 503.
func (r DeliveryRefusal) Undeliverable() bool { return slices.Contains(deliveryReasons, r.Reason) }

// Validate checks r's fields.
func (r DeliveryRefusal) Validate() error {
	if !r.Undeliverable() && !slices.Contains(retryReasons, r.Reason) {
		return invalid("reason")
	}
	return nil
}

// The values of each enumerated field. A new value ships in the receiver a
// release before any sender uses it (§6).
var (
	chatbotStates    = []string{StateActive, StateSuspended}
	admissionReasons = []string{ReasonBlocked, ReasonOverLimit, ReasonUnknown}
	deliveryReasons  = []string{ReasonSuspended, ReasonBlocked, ReasonUnknown}
	retryReasons     = []string{ReasonWebhookFailed, ReasonChatbotBusy}
	// notificationStatuses are the statuses RFC 5438 §11.1.7 allows each
	// kind that reaches a chatbot.
	notificationStatuses = map[imdn.Kind][]imdn.Status{
		imdn.DeliveryNotification: {imdn.Delivered, imdn.Failed, imdn.Forbidden, imdn.Error},
		imdn.DisplayNotification:  {imdn.Displayed, imdn.Forbidden, imdn.Error},
	}
)

// Validate checks a's fields.
func (a Admission) Validate() error {
	switch err := pair(a.Chatbot, "chatbot", a.Subscriber, "subscriber"); {
	case err != nil:
		return err
	case a.Anonymous == nil:
		return invalid("anonymous")
	}
	return nil
}

// Validate checks a's fields.
func (a AdmissionAnswer) Validate() error {
	switch {
	case a.Reason != "" && !slices.Contains(admissionReasons, a.Reason):
		return invalid("reason")
	case a.Reason == "" && !slices.Contains(chatbotStates, a.State),
		a.Reason != "" && a.State != "":
		return invalid("state")
	case !isText(a.OutOfServiceText, MaxOutOfServiceTextBytes) || a.Reason != "" && a.OutOfServiceText != "":
		return invalid("out_of_service_text")
	}
	return nil
}

// Validate checks c's fields.
func (c DeliveryCheck) Validate() error {
	return pair(c.Chatbot, "chatbot", c.Subscriber, "subscriber")
}

// Validate checks a's fields.
func (a DeliveryCheckAnswer) Validate() error {
	switch {
	case a.Deliver == nil:
		return invalid("deliver")
	case *a.Deliver != (a.Reason == ""), a.Reason != "" && !slices.Contains(deliveryReasons, a.Reason):
		return invalid("reason")
	}
	return nil
}

// Validate checks m's fields.
func (m SubscriberMessage) Validate() error {
	switch err := pair(m.Chatbot, "chatbot", m.Subscriber, "subscriber"); {
	case err != nil:
		return err
	case m.Anonymous == nil:
		return invalid("anonymous")
	case !isClientID(m.MessageID):
		return invalid("message_id")
	case m.DateTimeMS < 0:
		return invalid("date_time_ms")
	case !isRequired(m.ContentType, MaxContentTypeBytes):
		return invalid("content_type")
	case m.Body == nil:
		return invalid("body")
	case m.Dispositions == nil:
		return invalid("dispositions")
	case m.AcceptedAtMS <= 0:
		return invalid("accepted_at_ms")
	}
	return nil
}

// Validate checks n's fields.
func (n SubscriberNotification) Validate() error {
	statuses, ok := notificationStatuses[n.Kind]
	switch err := pair(n.Chatbot, "chatbot", n.Subscriber, "subscriber"); {
	case err != nil:
		return err
	case n.Anonymous == nil:
		return invalid("anonymous")
	case !isClientID(n.MessageID):
		return invalid("message_id")
	case !ok:
		return invalid("kind")
	case !slices.Contains(statuses, n.Status):
		return invalid("status")
	}
	return nil
}

// The answers of a 200 that carry nothing yet, as BotMessageAnswer.
type (
	SubscriberMessageAnswer      struct{}
	SubscriberNotificationAnswer struct{}
)

// Validate of an answer without fields accepts it.
func (SubscriberMessageAnswer) Validate() error      { return nil }
func (SubscriberNotificationAnswer) Validate() error { return nil }
