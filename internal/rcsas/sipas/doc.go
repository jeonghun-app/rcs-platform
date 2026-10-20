// Package sipas is the SIP side of rcs-as: it takes the requests scscf's
// iFC route to rcs-as (TS 24.229 §5.7) into the messaging engine, and sends
// the requests rcs-as originates itself.
//
// rcs-as is a proxy.Proxy whose Router (Server) serves what it terminates
// as a user agent server and forwards what it only passes on:
//
//   - A pager-mode MESSAGE (RFC 3428) is the engine's Submit with
//     Origin.Pager set, answered 202 Accepted once stored (RFC 3428 §7).
//     The sender is the user the core asserted in P-Asserted-Identity, one
//     identity or one user's SIP and tel pair, never a header the client
//     wrote; the core SIP port admits only platform services (ADR 0007 §2,
//     §7).
//   - OPTIONS, which the default profile hands to rcs-as with
//     SESSION_CONTINUED, goes on along its Route, so capability discovery
//     does not stop at rcs-as.
//   - Every other method is refused with 405 for now; sessions (INVITE) and
//     the group chat focus come in later parts of #137.
//
// Server is also the engine's Deliverer. Pager sends a MESSAGE to scscf
// (Config.Core) as a terminating request: without the orig parameter, and
// with P-Served-User naming the recipient, which the default profile's
// triggers exclude, so it goes on to the recipient's contacts rather than
// back to rcs-as (docs/hss.md).
//
// Users are named in one form throughout (messaging.UserOf): the engine
// keys queues, shares and sent-message records by that string.
//
// Logs and metrics carry no identity, URI or message content.
package sipas
