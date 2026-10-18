package messaging

import (
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// Reason says why the engine refused a message. The values are a fixed set
// that never contains input, so they name metrics and appear in logs as
// they are.
type Reason string

// The reasons Submit and ParseMessage report.
const (
	// ReasonTooLarge: the body exceeds the size limit, or the pager limit
	// for a message that arrived in a SIP MESSAGE.
	ReasonTooLarge Reason = "too_large"
	// ReasonRateLimited: the sender has used up its allowance.
	ReasonRateLimited Reason = "rate_limited"
	// ReasonContentType: the body is not message/cpim.
	ReasonContentType Reason = "content_type"
	// ReasonMalformed: the CPIM message cannot be parsed.
	ReasonMalformed Reason = "malformed"
	// ReasonFromMismatch: the CPIM From is neither one of the sender's
	// asserted identities nor the anonymous URI.
	ReasonFromMismatch Reason = "from_mismatch"
	// ReasonMessageIDReused: the sender used one IMDN Message-ID for
	// messages to different recipients, which would let it collect
	// notifications from the second about the first (RFC 5438 §6.3).
	ReasonMessageIDReused Reason = "message_id_reused"
	// ReasonIMDNMalformed: a notification whose document cannot be read.
	ReasonIMDNMalformed Reason = "imdn_malformed"
	// ReasonIMDNUnknown: a notification about a message the recipient of
	// the notification never sent, or whose record has expired.
	ReasonIMDNUnknown Reason = "imdn_unknown"
	// ReasonIMDNForged: a notification from someone who neither received
	// the message nor is an intermediary allowed to report on it.
	ReasonIMDNForged Reason = "imdn_forged"
	// ReasonIMDNNotRequested: a notification the sender did not ask for.
	ReasonIMDNNotRequested Reason = "imdn_not_requested"
)

// Rejection is the error Submit returns for a message it refuses, as
// opposed to a failure of its own (for example of the store).
type Rejection struct {
	Reason Reason
	// err is the parser's error, kept for errors.Is; its message never
	// contains input (cpim and imdn guarantee that).
	err error
}

func reject(r Reason, err error) *Rejection { return &Rejection{Reason: r, err: err} }

func (r *Rejection) Error() string {
	if r.err != nil {
		return "messaging: rejected (" + string(r.Reason) + "): " + r.err.Error()
	}
	return "messaging: rejected (" + string(r.Reason) + ")"
}

func (r *Rejection) Unwrap() error { return r.err }

// MSRPStatus is the MSRP status code that answers a message refused for
// r (RFC 4975 §10): 413 for size, 415 for type, 400 for what cannot be
// parsed and 403 for the rest, which a client must not retry unchanged.
func (r *Rejection) MSRPStatus() int {
	switch r.Reason {
	case ReasonTooLarge:
		return msrp.StatusMessageTooLarge
	case ReasonContentType:
		return msrp.StatusUnsupportedMediaType
	case ReasonMalformed, ReasonIMDNMalformed:
		return msrp.StatusBadRequest
	}
	return msrp.StatusForbidden
}

// cpimReason is the cpim package's reason for a malformed message, or ""
// when the rejection did not come from the CPIM parser.
func (r *Rejection) cpimReason() cpim.Reason { return cpim.ReasonOf(r.err) }
