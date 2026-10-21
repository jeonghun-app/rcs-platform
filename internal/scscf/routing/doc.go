// Package routing is the S-CSCF's router for the requests it neither
// registers nor serves itself: the requests of the users it serves, which
// it routes along their iFC chains through application servers (TS 24.229
// §5.4.3.2, §5.4.3.3), and those inside a dialog it stays on the route of
// (RFC 3261 §16.12). Third-party registration comes in a later part of #14;
// cmd/scscf puts the parts behind one proxy.Router, the registrar and the
// reg event notifier taking REGISTER and SUBSCRIBE for reg before Initial.
//
// A request outside a dialog is one of three kinds (Initial). One back from
// an application server carries, in the Route that names the S-CSCF, its
// place in its served user's chain (odi): the served user, the session
// case, whether the user was registered, and the priority of the criterion
// applied last, under an HMAC with a key every scscf instance shares, over
// those, the Call-ID and an expiry (ADR 0005). Any instance goes on with the
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
// a timeout (Config.ASTimeout, for any request but INVITE), a transport
// failure or a 408, is passed over if its criterion's default handling
// continues the session; any answer of its own goes upstream unchanged, a
// 500 with Retry-After included. iFC see the request without a
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
// require, Reject-Contact), with the Request-URI it was sent to in
// P-Called-Party-ID. A binding whose edge proxy answers 430 Flow Failed is
// ended, as an expired one is, for the sweep to finish, and the request
// tried over the instance's other flows (RFC 5626 §7). A barred identity,
// or a Request-URI that is no public identity, is 404; a user without a live
// binding is 480. A server that sends the request on to another user ends
// the chain, and the request goes to the I-CSCF for that user.
//
// A request inside a dialog is forwarded as its Route says, but only to a
// next hop the platform runs past the S-CSCF: an application server
// (Config.ApplicationServers), or a P-CSCF's core
// listener (Config.EdgeProxyHosts, EdgeProxyNets) with a flow token in its
// user part. The Route below the S-CSCF's own entry is the client's to
// write, so without this a client could reach any address the S-CSCF
// reaches, the I-CSCF and the network's private addresses included (#208,
// docs/threat-model.md T2). A hop naming the S-CSCF itself is refused too.
//
// Logs carry no identity or URI.
package routing
