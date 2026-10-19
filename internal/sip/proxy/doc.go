// Package proxy is the proxy core of RFC 3261 §16, which pcscf, icscf, scscf
// and rcs-as share: all four route requests by loose routing, insert
// Record-Route, fork, cancel and choose among responses in the same way, and
// differ only in where a request goes. This package does what they share; the
// service supplies a Router, the location service of §16.5, and hooks.
//
// The proxy is transaction stateful. It is the transaction user (TU) of a
// transaction.Layer it owns, and for every request the layer passes up it:
//
//   - validates it (§16.3): the Request-URI scheme (416), Max-Forwards (483),
//     loops (482) and Proxy-Require (420);
//   - preprocesses its Route (§16.4): it undoes a strict router's rewrite and
//     removes the Route values naming itself (Config.Self), two in a row when
//     it recorded two (RFC 5658 §5), and hands them to the Router;
//   - asks the Router for a Decision: an answer, or targets;
//   - forwards to each target (§16.6) with a new Via whose branch ID carries a
//     keyed loop-detection hash (RFC 5393 §4.2), the Record-Route values of
//     the decision, the routes of the target, and Decision.Prepare's changes;
//   - forks: targets of equal q in parallel, lower q only once every higher
//     one has failed;
//   - forwards provisional responses and every 2xx at once and keeps the
//     other finals, then sends the best of them (§16.7): a 6xx over all, then
//     the lowest class, preferring 401, 407, 415, 420 and 484 within 4xx, with
//     the challenges of every 401 and 407 gathered into the one sent, and a
//     503 from downstream turned into 500;
//   - cancels the INVITE branches still pending after a 2xx, a 6xx or a
//     CANCEL from upstream, each only once it has a provisional response
//     (§9.1), and terminates a branch whose CANCEL is not answered within
//     64*T1;
//   - runs Timer C on every INVITE branch (§16.8): a branch that has had a
//     provisional response is cancelled, one that has not counts as a 408.
//
// An ACK for a 2xx belongs to no transaction and is forwarded statelessly
// (§16.11). Every other request, in-dialog ones included, has a server
// transaction the proxy must answer, so it goes through a response context;
// Forward is the Decision that sends an in-dialog request where its Route says
// (§16.12). A response that matches no client transaction is dropped (RFC 6026
// §7.3), so responses follow Via through the transaction that sent the request.
//
// # Robustness
//
// Nothing that can block runs on the goroutine reading the network: the
// transaction layer calls the TU from it, and while the TU runs nothing more is
// read from that connection or UDP socket. Routing, Prepare and every send
// downstream run on a goroutine per request or branch, and the responses of a
// request go upstream in order on a goroutine of their own, so a peer that is
// slow to take what it is sent delays only the messages addressed to it. The
// exceptions are the 503 sent at MaxContexts and the answers to a CANCEL: they
// go back to the peer the request just came from and wait only if that peer
// has stopped reading, for at most the transport's WriteTimeout.
//
// Memory is bounded by MaxContexts response contexts of at most MaxBranches
// branches, each holding a copy of the request: about MaxContexts ×
// (MaxBranches + 1) messages, plus as many CANCELs and the final responses
// kept for the choice. A context lives until every branch has ended. Timer C
// ends a silent INVITE branch; one that receives a provisional response at
// least every TimerC keeps its context, as ringing does, and holds a
// MaxContexts slot as long.
//
// A branch the transport cannot send because the next hop's connection has no
// room, or no connection can be opened (transport.ErrQueueFull,
// ErrTooManyConnections), counts as a 503 with Retry-After that is passed on
// as such, so the client backs off. Other transport failures count as a 503
// from the next hop (§16.9), which becomes a 500 if chosen, and a vanished
// flow as 430 (RFC 5626 §5.3.1). In every case the next fork group, or a
// replacement target from OnBranchFailure, may still succeed.
//
// Logs carry no message content, URIs or flow IDs.
package proxy
