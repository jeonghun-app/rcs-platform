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
//   - An INVITE for a chat session or a large-mode message opens a leg on
//     the engine (OpenLeg) and is answered a=setup:passive with the leg's
//     path: msrp-relay, which pcscf put in the media path, offers active
//     and connects to rcs-as's MSRP listener (ADR 0004). rcs-as is a B2BUA,
//     with one SIP session and one leg per client.
//   - The requests in a session (BYE, re-INVITE, UPDATE, OPTIONS) are
//     served in it: session timers as RFC 4028 has a UAS that never
//     refreshes, and a leg that never moves.
//   - scscf's third-party REGISTER tells the engine a user registered.
//   - A request to the conference factory or to a conference URI is a group
//     chat's, told apart before anything else, so that none is taken for a
//     1-to-1 chat: an INVITE to the factory with a resource list creates the
//     group (group.Service.Create) and has the focus invite its members, one
//     to a conference URI joins it (Join). rcs-as is the focus of every
//     session with a group: its Contact is the conference URI, marked
//     isfocus (RFC 4579). The conference event package and REFER come in a
//     later part of #137.
//   - Every other method is refused with 405.
//
// Server is also the engine's Deliverer. Pager sends a MESSAGE to scscf
// (Config.Core) as a terminating request: without the orig parameter, and
// with P-Served-User naming the recipient, which the default profile's
// triggers exclude, so it goes on to the recipient's contacts rather than
// back to rcs-as (docs/hss.md). Invite sends an INVITE the same way, with
// an actpass offer of a leg from Engine.Offer, and gives the leg the path of
// the 2xx's answer.
//
// Users are named in one form throughout (messaging.UserOf): the engine
// keys queues, shares and sent-message records by that string.
//
// Logs and metrics carry no identity, URI or message content.
package sipas
