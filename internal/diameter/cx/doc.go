// Package cx implements the Diameter application of the Cx reference point
// (TS 29.229), over which `icscf` and `scscf` ask `hss` to authorise a
// registration (UAR), authenticate a user (MAR), assign an S-CSCF and download
// the user profile (SAR) and locate the serving S-CSCF (LIR), and over which
// `hss` deregisters users (RTR) and pushes changed profiles (PPR). The
// procedures behind the commands are in TS 29.228.
//
// The package turns the commands into typed structs and back, on top of the
// base protocol in package diameter, so that services handle fields rather than
// AVPs:
//
//   - A request struct builds its message with Message(node); the node supplies
//     Session-Id, Origin-Host and Origin-Realm. Parse functions such as
//     [ParseUAR] read a received request and fail with a [*diameter.Error]
//     (missing, repeated or malformed AVP) that a handler can return as it is,
//     so the node answers with the right Result-Code and Failed-AVP. Register
//     [ErrorAVPs] with [diameter.Node.SetErrorAVPs] so those answers carry the
//     AVPs every Cx answer needs.
//   - An answer struct builds its message with Message(node, request), with
//     either a Result-Code or, for the Cx-specific codes, an
//     Experimental-Result (TS 29.229 §6.2).
//
// Every message carries Vendor-Specific-Application-Id and Auth-Session-State
// NO_STATE_MAINTAINED, as the command formats of TS 29.229 §6.1 require, and
// requests are proxiable. A receiver does not insist on those two AVPs: they
// carry nothing the receiver needs, and RFC 6733 has deprecated the first.
//
// User-Data stays bytes here. Its content, the IMSSubscription document of
// TS 29.228 Annex E, is modelled and parsed by package ifc, which also
// evaluates the initial filter criteria it contains.
//
// [Fields], [Request], [Answer] and [Result] are exported because Sh (package
// sh) is built on the same conventions: TS 29.329 §5 applies TS 29.229 §5 to it
// and reuses several Cx AVPs.
//
// Left out, until a service needs them: the restoration procedures
// (SCSCF-Restoration-Info, TS 23.380), emergency registration, P-CSCF
// restoration, the WebRTC AVPs, overload and load control (OC-*, Load, DRMP)
// and the Dx-only behaviour of an SLF. Their AVPs, if received, are kept by the
// base decoder as unknown AVPs without the M bit, which is how TS 29.229
// defines them.
package cx
