// Package chatbot holds the rules about chatbots that more than one service
// must apply the same way (ADR 0009): the one normal form of a chatbot URI
// and the ERE of its user part that hss stores (§2, §3), RCS_CHATBOT_DOMAIN,
// the size bounds and default content types (§5, §7), the validation of
// chatbot content (§5), and the strict decoder of JSON envelopes (§9).
//
// hss, icscf, scscf, rcs-as and maap all use it, so that a URI two of them
// read differently, or a body one of them refuses and another takes, cannot
// cross a trust boundary.
//
// No error of this package repeats the URI, key or value it refused: a URI
// names a chatbot or a subscriber, and a body is chatbot free text. Callers
// log identifiers only through internal/pii.
package chatbot
