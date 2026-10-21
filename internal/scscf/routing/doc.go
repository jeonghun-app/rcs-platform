// Package routing is the S-CSCF's router for the requests it neither
// registers nor serves itself: those for a user it serves, which it
// delivers to the user's registered contacts (TS 24.229 §5.4.3.3), and those
// inside a dialog it stays on the route of (RFC 3261 §16.12). The
// originating requests of its users and the iFC chain through application
// servers come in a later part of #14; cmd/scscf puts the parts behind one
// proxy.Router.
//
// A terminating request names the user by its Request-URI, a public
// identity in SIP or tel form, which the router looks up in the state every
// scscf instance shares (internal/scscf/state): the identity's item, then
// the record of its implicit registration set. The record counts if it
// lists the identity and has a live binding, which one being deregistered
// never has, even if the item names another of its incarnations: the item is then
// repaired in the background, and the request is not lost to a pointer an
// interrupted REGISTER left behind (#196). The request is forked to every
// live binding of the set, along the binding's Path, keeping only the
// bindings the caller's preferences accept (RFC 3841: Accept-Contact with
// require, Reject-Contact), with the Request-URI it was sent to in
// P-Called-Party-ID. A binding whose edge proxy answers 430 Flow Failed is
// ended, as an expired one is, for the sweep to finish, and the request
// tried over the instance's other flows (RFC 5626 §7). A barred identity,
// or a Request-URI that is no public identity, is 404; a user without a
// live binding is 480 until the unregistered user's iFC come (§5.4.3.3).
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
