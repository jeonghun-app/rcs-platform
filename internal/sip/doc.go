// Package sip is the SIP message layer every IMS service in this repository is
// built on: the request and response model, a parser for stream and datagram
// transports, a serializer, SIP, SIPS and tel URIs, and typed views of the header
// fields the CSCFs and the RCS application server act on.
//
// The project implements its own SIP stack (ADR 0001), so this package is where the
// framing rules of RFC 3261 §7 and the grammar of RFC 3261 §25 are enforced for
// everything above it. Transport, transactions, dialogs and digest authentication
// are separate packages that build on this one.
//
// Parsing happens at two levels. ParseDatagram and Reader frame a message, check its
// start line and split it into header fields, but keep field values as text. Typed
// accessors such as Header.Via parse a value only when it is asked for. A proxy
// forwards header fields it does not understand and must not refuse a request over
// a malformed field it never reads (RFC 3261 §16.3), so only framing errors fail a
// parse; Validate checks the fields every transaction depends on.
//
// A parsed header field keeps its original bytes and is written back unchanged
// until it is replaced, so a forwarded message differs from the received one only
// where a service changed it. Content-Length is always recomputed from the body.
//
// Following docs/architecture.md §8, input that is ambiguous or a security risk is
// rejected, never repaired: control characters and invalid UTF-8 in a header
// value, any line end but CRLF, and anything over a limit, each limit with its
// own error. §8 allows a receiver to accept a bare LF where interoperability
// needs it; this package does not, because RFC 3261 §7 requires CRLF and §28.1
// records that LF line ends were dropped on purpose, and no client is known to
// need them. What is sent is held to the same rules: Header.Add refuses a value
// that breaks them.
//
// Errors never contain message bytes: header values carry subscriber identities
// and an error is likely to be logged. For the same reason a message prints
// under fmt as it logs, its method or status and sizes without header values
// or the body (String, Format), its Body prints as redacted, and the value
// types implement slog.LogValuer with identities and credentials left out.
package sip
