// Package sdp parses, builds and rewrites SDP session descriptions (RFC 8866),
// with typed access to the media attributes MSRP sessions use (RFC 4975 §8,
// RFC 6135, RFC 5547).
//
// Two services depend on it. pcscf anchors MSRP through msrp-relay by rewriting
// the m=message line of every offer and answer (ADR 0004), and rcs-as answers
// MSRP offers for chat and file transfer. Both handle descriptions written by
// other parties, so the package keeps everything it does not interpret: unknown
// attributes, attribute order and media lines other than MSRP pass through
// unchanged, and a helper touches only the lines it is asked to change.
//
// Parsing is strict. Line order, the at-most-once rules and the syntax of each
// field follow RFC 8866 §5 and §9; anything else is rejected with a
// *SyntaxError naming the line, never repaired, because a proxy that guesses
// at a malformed description forwards something the peer did not send. Two
// deviations are tolerated because deployed stacks produce them and they are
// unambiguous: lines ending in LF alone, and a last line with no line ending.
// Output always uses CRLF. Input larger than Parser.MaxSize is refused without
// being parsed.
//
// Values are validated again when a description is serialized, so a field
// filled in from elsewhere (a relay address from the relay control API, say)
// cannot smuggle a line break or an extra line into the output.
//
// Codec negotiation for audio and video is out of scope: those lines are
// preserved, not interpreted. So is ICE.
package sdp
