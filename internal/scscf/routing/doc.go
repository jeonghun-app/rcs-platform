// Package routing is the S-CSCF's router for the requests it neither
// registers nor serves itself: the requests of the users it serves, which
// it routes along their iFC chains through application servers (TS 24.229
// §5.4.3.2, §5.4.3.3), and those inside a dialog it stays on the route of
// (RFC 3261 §16.12), and it registers the users with the application
// servers their criteria name (Registered). cmd/scscf puts the parts behind
// one proxy.Router, the registrar and the reg event notifier taking
// REGISTER and SUBSCRIBE for reg before Initial.
//
// A request outside a dialog is one of three kinds (Initial). One back from
// an application server carries, in the Route that names the S-CSCF, its
// place in its served user's chain (odi): the served user, the session
// case, whether the user was registered, and the priority of the criterion
// applied last, under an HMAC with the keys that sign the dialogs' routes
// (Config.DialogKeys), over those, the Call-ID and an expiry (ADR 0005). Any instance goes on with the
// next criterion; a position that was not signed for the request, or has
// expired, is 403. One along a Service-Route (orig) is originating, for the
// registered user its P-Asserted-Identity names. Any other is terminating,
// for the user its Request-URI names: a request from the I-CSCF, or one an
// application server sends for its user, which names the user in
// P-Served-User (#137).
//
// Each step of the chain is the next criterion that applies to the request
// as it is (ifc.Set.Next), in the user's profile as the registrar stored it
// for the set: the request goes to its application server, the Request-URI
// unchanged, with P-Served-User naming the served user and the session
// case, and a Route back to the S-CSCF. A server that does not answer, by
// a timeout (Config.ASTimeout, for any request but INVITE) or a transport
// failure, or answers 408 or 5xx, without a provisional response first and
// before it sent the request back, has its criterion's default handling
// apply: SESSION_CONTINUED passes it over, SESSION_TERMINATED sends its
// answer upstream, a 500 with Retry-After included. Whether it sent the
// request back is settled in the store, as the request may come back to
// another instance (state.Challenges.ClaimODI): the first of the two to go
// on with the position does, and the other is refused, while every copy the
// server sends back goes on once one has (TS 24.229 §5.4.3.2 NOTE 8). Any other answer of a
// server's goes upstream unchanged. The position is bound to the Call-ID,
// so a B2BUA application server that sends the request on in a dialog of
// its own is not supported (ADR 0005). Nor is a proxy server that records
// the route on a terminating chain: the callee's requests in the dialog
// then come from its P-CSCF with the server's Record-Route value next, not
// the S-CSCF's, which signs nothing they carry, and are refused. rcs-as, a
// B2BUA that sends its legs as new requests (#137), is neither. The SDP iFC see is a request's
// application/sdp body, or the first such part of a multipart one, as
// rcsjta's chat INVITE with its first message has. iFC see the request without a
// P-Served-User unless it came with one of its own and not from a P-CSCF:
// the one the S-CSCF inserted comes back with the request, and must not
// make rcs-as's triggers, which skip requests rcs-as sends for its users
// (docs/hss.md), miss it after another server.
//
// The chain of an originating request ends at the I-CSCF (Config.ICSCF),
// which finds the S-CSCF of the user it is for: a tel URI of a global number
// is sent as the SIP URI of the number in the home domain, without ENUM, and
// a request for another domain is 404. The P-Served-User toward the servers
// is removed, or the terminating side would take the request for one an
// application server sent for its user.
//
// A terminating request names the user by its Request-URI, a public
// identity in SIP or tel form, which the router looks up in the state every
// scscf instance shares (internal/scscf/state): the identity's item, then
// the record of its implicit registration set. The record counts if it
// lists the identity and has a live binding, which one being deregistered
// never has, or is an unregistered user's that has not ended, even if the
// item names another of its incarnations: the item is then repaired in the
// background, and the request is not lost to a pointer an interrupted
// REGISTER left behind (#196). An identity with no record listing it is
// asked of the HSS (SAR UNREGISTERED_USER, Config.Registrar), which makes it
// an unregistered user served here, for the criteria of that state; one the
// HSS does not know is 404. At the end of its chain the request is forked to
// every live binding of the set, along the binding's Path, keeping only the
// bindings the caller's preferences accept (RFC 3841: Accept-Contact with
// require, Reject-Contact, at most eight of each; a binding that states no
// feature is kept), with the Request-URI it was sent to in
// P-Called-Party-ID. A binding whose edge proxy answers 430 Flow Failed is
// ended, as an expired one is, for the sweep to finish, and the request
// tried over the instance's other flows (RFC 5626 §7), unless it is an
// INVITE the device already answered with a provisional. A barred identity,
// or a Request-URI that is no public identity, is 404; a user without a live
// binding is 480. A server that sends the request on to another user ends
// the chain, and the request goes to the I-CSCF for that user.
//
// A dialog's requests come back along the S-CSCF's Record-Route value,
// which it writes only on a request that sets up a dialog (INVITE,
// SUBSCRIBE, REFER) and signs as the dialog is set up (#322): with a key ID and a MAC,
// under a key every scscf instance shares, over the Call-ID, the S-CSCF's
// name and each of the dialog's hops next to it, scheme, user, host, port
// and transport. The value in the request the callee gets signs the hop
// toward the caller, the Record-Route value below the S-CSCF's or the
// caller's Contact; the value in the response the caller gets signs that
// hop and the one toward the callee, the value above or the callee's
// Contact. A request inside a dialog is forwarded as its Route says only if
// the next hop is one its value signs, at a P-CSCF's core port or an
// application server's, and is never the S-CSCF itself; any other is 403.
// The Route below the S-CSCF's own entry is the client's to write, and
// every task of the core shares one network, so without this a client
// could reach any address the S-CSCF reaches (#208, docs/threat-model.md
// T2). The P-CSCF's public address as the next hop ends the route set:
// rcsjta puts it after the route set of its session refreshes, and the
// request goes by its Request-URI.
//
// The registrar tells the router of every registration, refresh and end of a
// set (registrar.ThirdParty), and the router sends a third-party REGISTER to
// each application server whose criterion takes the REGISTER, its
// RegistrationType included (TS 24.229 §5.4.1.7, TS 29.228 B.2.3): from the
// S-CSCF, for the user in To, with an Expires that is how long the set stays
// registered, 0 once it has no binding, and, as the criterion asks, the UE's
// REGISTER and the 200 for it in the body. An end the network made, a
// sweep's or an RTR's, has no REGISTER to show the criteria or the server:
// one for the user stands in, and the body is empty. The REGISTERs go off
// the registrar's goroutine, to each server apart, those of one identity of
// a set in order, at most MaxThirdParty at a server at a time; an end is
// never dropped for a full queue but past MaxThirdParty more. A server that
// does not answer is counted, and one whose default handling ends the
// session only logged: deregistering the user for it waits on a decision
// (#14).
//
// Logs carry no identity or URI.
package routing
