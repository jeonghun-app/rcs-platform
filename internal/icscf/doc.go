// Package icscf is the Interrogating-CSCF (TS 24.229 §5.3): the home
// network's contact point that asks the HSS which S-CSCF serves a user and
// sends the request there. It is a proxy.Router; the proxy core (RFC 3261
// §16) does the forwarding, cancelling and choice of responses, and a
// cxclient.Client asks the HSS (TS 29.228, TS 29.229).
//
// The I-CSCF keeps no state about users. Every REGISTER is preceded by a
// UAR, every initial request for a user by an LIR, and nothing is cached,
// so any instance can take any request and a restart loses nothing. It
// inserts no Record-Route, so requests inside a dialog do not pass it.
//
// # REGISTER (§5.3.1)
//
// The UAR carries the IMPU of To, the IMPI of the Digest credentials or, in
// a REGISTER without them, the IMPU without its scheme (§5.3.1.2), the first
// P-Visited-Network-ID or else the home domain, and DE_REGISTRATION when
// every binding the REGISTER names expires now. The REGISTER's Request-URI
// becomes the S-CSCF's URI (§5.3.1.2), and the branch has
// Config.RegisterTimeout to answer.
//
// # Initial requests for a user (§5.3.2)
//
// A request with no Route left below this I-CSCF's own and no To tag is
// for a user of the home network. A SIP URI for a telephone number
// (user=phone) is turned into its tel URI (§5.3.2.1 step 1 b), and the LIR
// asks for that identity. The S-CSCF becomes the topmost Route, with lr;
// the Request-URI stays. A request with a Route left, or one inside a
// dialog, is forwarded where it says without asking the HSS (§5.3.2.1,
// RFC 3261 §16.12). A pres: or im: Request-URI is refused 416 by the proxy
// before the Router sees it.
//
// # Answers
//
// "Success" is any 2xxx result, DIAMETER_FIRST_REGISTRATION,
// DIAMETER_SUBSEQUENT_REGISTRATION and DIAMETER_UNREGISTERED_SERVICE
// included (TS 29.229 §6.2.1). "Could not be completed" is no answer at all
// (time-out, transport failure, no HSS task connected, after cxclient's one
// retry on another task), a protocol error or 4xxx such as
// DIAMETER_TOO_BUSY, or an answer naming an S-CSCF that is not a SIP URI.
//
//	request      HSS answer                                SIP                       clause
//	REGISTER     success, Server-Name                      forward, R-URI = name     TS 24.229 §5.3.1.2
//	REGISTER     success, capabilities or none             forward, R-URI = chosen   §5.3.1.2
//	REGISTER     success, no S-CSCF has the mandatory ones 600                       §5.3.1.3
//	REGISTER     5001, 5002, 5003, 5004, other negatives   403                       §5.3.1.3
//	REGISTER     could not be completed                    480 + Retry-After         §5.3.1.3
//	REGISTER     (S-CSCF silent for RegisterTimeout)       504                       §5.3.1.3
//	REGISTER     (To is not an IMPU, or a bad username)    403, no UAR               §5.3.1.3
//	terminating  success, Server-Name                      forward, Route = name     §5.3.2.1
//	terminating  success, capabilities or none             forward, Route = chosen   §5.3.2.1
//	terminating  success, no S-CSCF has the mandatory ones 480, counted              decided on #274
//	terminating  (the S-CSCF cannot be reached)            503 + Retry-After         decided on #274
//	terminating  5001, other negatives                     404                       §5.3.2.1, §5.3.2.2
//	terminating  5003                                      480                       §5.3.2.1
//	terminating  could not be completed                    480 + Retry-After         §5.3.1.3 by analogy
//	terminating  (Request-URI is not an IMPU)              404, no LIR               §5.3.2.2
//	any          (CANCEL while the HSS is asked)           487, CANCEL 200           §5.3.2.2
//
// An S-CSCF is chosen from Config.SCSCFs: those with every mandatory
// capability of the answer, the one with the most optional ones first,
// configuration order among equals (§5.3.1.2 step 1). An answer with
// neither Server-Name nor Server-Capabilities means any S-CSCF will do
// (TS 29.228 §6.7), and the first configured one is chosen. Server-Name
// values inside Server-Capabilities are not used. Retry-After is
// Config.RetryAfter, also on the 503 the proxy answers a terminating
// request with when the S-CSCF cannot be reached: the S-CSCF the user needs
// exists and will be back, unlike one no configured S-CSCF can stand for.
// The I-CSCF's own overload, the transaction layer's cap, is answered 503
// with the layer's Retry-After.
//
// P-Profile-Key is removed from every request forwarded and every response
// passed back (§5.3.2.1): this I-CSCF does not set it from a wildcarded
// identity, and the S-CSCF must not trust one a sender wrote.
//
// # Limitations
//
// These parts of TS 24.229 §5.3 are not implemented:
//
//   - S-CSCF re-selection (§5.3.1.3, §5.3.2.2). The platform runs one S-CSCF
//     service name, behind which Cloud Map and the load balancer replace a
//     failed task, so there is no other S-CSCF to choose. A REGISTER whose
//     S-CSCF does not answer gets 504, and its 3xx or 480 is passed back.
//     rank orders every eligible S-CSCF, which is where re-selection would
//     take the next one.
//   - The trusted-domain check (§5.3.1.2, §5.3.2.1). The I-CSCF has only
//     core listeners, reached from the P-CSCF and S-CSCF security groups
//     (ADR 0007); the boundary is there.
//   - P-Charging-Vector (icid, IOI), P-Charging-Function-Addresses and
//     P-User-Database.
//   - Originating requests with "orig" (§5.3.2.1A), PSI subdomains, and the
//     transit routing of a tel URI the HSS does not know (§5.3.2.1).
//   - pres: and im: Request-URIs (§5.3.2.1 step 1 a), recursion on 3xx and
//     the 305 of §5.3.2.2.
//
// # Metrics
//
// Counters, through Config.Metrics; none names a user:
//
//	icscf.<kind>.forwarded      requests forwarded, kind register,
//	                            terminating or routed (Route or dialog)
//	icscf.<kind>.<code>         requests answered with code (403, 404,
//	                            480, 600) by the I-CSCF
//	icscf.<kind>.cancelled      requests cancelled while the HSS was asked
//	icscf.hss.unavailable       HSS queries that could not be completed
//	icscf.hss.bad_server_name   answers naming an S-CSCF that is not a SIP
//	                            URI
//	icscf.scscf.no_capable      answers whose capabilities no configured
//	                            S-CSCF has (600 or 480): a provisioning
//	                            problem, to alarm on
//	icscf.scscf.unreachable     terminating requests answered 503 because
//	                            the proxy could not reach the S-CSCF
//
// cxclient counts the Cx answers by result code, and the proxy and the
// transaction layer the SIP side, the 504 to a REGISTER included.
package icscf
