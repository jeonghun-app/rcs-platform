// Package msrp implements the Message Session Relay Protocol (RFC 4975) as
// rcs-as and msrp-relay need it: Chat, Group Chat and large-mode Standalone
// Messaging content all travel over MSRP once SIP has set up the session.
//
// The package is layered so each part can be tested without a network:
//
//   - URI, Message, Reader and Message.Marshal are the wire codec (RFC 4975
//     §6, §7 and the §9 grammar). The parser rejects rather than repairs, and
//     every limit is explicit.
//   - Split and Reassembler cut outgoing content into chunks and put incoming
//     chunks back together by Message-ID and Byte-Range (§5.1, §7.1.1,
//     §7.3.1).
//   - NewResponse, NewReport and ShouldRespond decide which transaction
//     responses and REPORTs the Success-Report and Failure-Report values
//     allow (§7.1.2–§7.2).
//   - Conn, Session, Registry and Pool are the connection layer: several
//     sessions share one connection (§5.4), the active side dials and binds
//     with an immediate SEND, the passive side binds a session when its first
//     request arrives, transactions time out on an injected clock, and idle
//     sessions are kept alive with bodiless SENDs (ADR 0003).
//   - Bridge joins two sessions on different connections so msrp-relay can
//     forward between a client and rcs-as one bounded piece at a time
//     (ADR 0004, RFC 4976 §6.4 for the forwarding rules a relay follows).
//
// The package never logs: session ids are the only secret that ties a
// connection to a session (ADR 0004), and message bodies must not reach a
// log, so reporting is left to callers through returned errors.
//
// RFC 4976 AUTH, TLS fingerprint checks and CPIM/IMDN are out of scope.
package msrp
