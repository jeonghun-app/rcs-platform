// Package chatbot holds the rules about chatbots that more than one service
// must apply the same way (ADR 0009): the one normal form of a chatbot URI
// and the ERE of its user part that hss stores (§2, §3), RCS_CHATBOT_DOMAIN,
// and the size bounds and default content types (§5, §7).
//
// hss, icscf, scscf, rcs-as and maap all use it, so that a URI two of them
// read differently cannot cross a trust boundary.
//
// Callers pass [Domain.Normalise] a URI exactly as they received it, and
// never trim, unwrap or re-parse it after the check: the check holds for
// that text only. ErrNotChatbot means only that the value is not a chatbot
// URI, not that it is a valid URI of any kind; the caller's own checks
// still apply to it.
//
// No error of this package repeats the value it refused: a URI names a
// chatbot or a subscriber. Callers log identifiers only through
// internal/pii.
package chatbot
