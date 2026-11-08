// Package chatbot holds the rules about chatbots that more than one service
// must apply the same way (ADR 0009): the one normal form of a chatbot URI
// and the ERE of its user part that hss stores (§2, §3), RCS_CHATBOT_DOMAIN,
// the size bounds and default content types (§5, §7), the validation of
// chatbot content (§5), the strict decoder of JSON envelopes (§9), and the
// wire types of the internal APIs between rcs-as and maap (§4, §6).
//
// hss, icscf, scscf, rcs-as and maap all use it, so that a URI two of them
// read differently, or a body one of them refuses and another takes, cannot
// cross a trust boundary.
//
// The wire types are the bodies of rcs-as's chatbot API (/v1/chatbot/*,
// which maap calls). Both sides decode them with [DecodeEnvelope] under the
// limits here, which calls their Validate method. Validate refuses a C0
// control or DEL in every string but the content, since those strings reach
// SIP and CPIM headers and logs; its errors wrap ErrInvalidEnvelope (400)
// and name the field. Rules that need configuration
// stay with the caller: [Domain.Normalise], [MatchContentType] and
// [ValidateContent]. Times are Unix milliseconds (DecodeEnvelope refuses
// time.Time). Every field of the first contract must be present, but those
// tagged omitempty: a pointer for a bool, struct or string whose zero value
// means something, so that a missing one is refused rather than read as
// false or empty (the anonymity flag above all).
//
// Rolling updates (§6): rcs-as and maap share these types, and
// DecodeEnvelope refuses unknown fields, so a field added later
//   - is tagged omitempty, and senders leave it zero until every receiver
//     knows it;
//   - means the old behaviour when zero or absent, since a new receiver
//     reads bodies from old senders;
//   - is never required.
//
// A new value of an enumerated field also ships in the receiver first.
// TestWireContractIsPinned lists every key and value, so that a change to
// them meets this rule.
//
// Callers pass [Domain.Normalise] a URI exactly as they received it, and
// never trim, unwrap or re-parse it after the check: the check holds for
// that text only. A SIP service, whose parsed message keeps no raw text,
// passes m.URI.String(), the form it sends on; an HTTP API passes the JSON
// string as decoded. ErrNotChatbot means only that the value is not a
// chatbot URI, not that it is a valid URI of any kind; the caller's own
// checks still apply to it.
//
// No error of this package repeats the URI, key or value it refused: a URI
// names a chatbot or a subscriber, and a body is chatbot free text. Callers
// log identifiers only through internal/pii.
package chatbot
