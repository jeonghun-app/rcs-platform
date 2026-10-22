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
//     a malformed Max-Breadth (400) on anything but a 2xx's ACK, which goes
//     on with MaxBreadth in its place, loops (482) and Proxy-Require (420);
//   - preprocesses its Route (§16.4): it undoes a strict router's rewrite and
//     removes the Route values naming itself (Config.Self), two in a row when
//     it recorded two (RFC 5658 §5), and hands them to the Router;
//   - asks the Router for a Decision: an answer, targets, or to hand the
//     request to the service (Serve), which answers it as a UAS and has its
//     2xx retransmitted until the ACK, which is delivered to it (RFC 6026
//     §8.1);
//   - forwards to each target (§16.6) with a new Via whose branch ID carries a
//     keyed loop-detection hash (RFC 5393 §4.2), the Record-Route values of
//     the decision, the routes of the target, and Decision.Prepare's changes;
//   - forks: targets of equal q in parallel, lower q only once every higher
//     one has failed. The parallel branches share the request's Max-Breadth
//     (RFC 5393 §5): its own, at most MaxBreadth (60), or 60 when it has
//     none, split among the branches that go out together and carried in
//     each, a branch's share free again once it is final, even one that
//     Target.Timeout ended before its transaction did, an intended deviation
//     from RFC 5393 §5.4.1 (see Target.Timeout). A target with no share left
//     fails at once as 440 Max-Breadth Exceeded, the answer only when no
//     other branch, nor another answer of the proxy's own, does better;
//   - forwards provisional responses and every 2xx at once and keeps the
//     other finals, then sends the best of them (§16.7): a 6xx over all, then
//     the lowest class, preferring 401, 407, 415, 420 and 484 within 4xx, with
//     the challenges of every 401 and 407 gathered into the one sent, a 503
//     from downstream turned into 500, and a 430 into 480 unless OnFinal
//     keeps it (RFC 5626 §11.5);
//   - sends no 408 to a non-INVITE request that got no response, which would
//     arrive after the client gave up (RFC 4320 §4.2);
//   - cancels the INVITE branches still pending after a 2xx, a 6xx or a
//     CANCEL from upstream, each only once it has a provisional response
//     (§9.1), and terminates a branch whose CANCEL is not answered within
//     64*T1; a branch not yet sent when the CANCEL came, its Prepare or
//     Resolver still running, is never sent, as the CANCEL's 200 goes only
//     once the request counts as cancelled (#361). The INVITE's 487 may
//     then be written before the CANCEL's 200: they are two transactions,
//     which RFC 3261 does not order;
//   - runs Timer C on every INVITE branch (§16.8): a branch that has had a
//     provisional response is cancelled, one that has not counts as a 408;
//     Target.Timeout bounds a branch more tightly where a service needs it.
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
// slow to take what it is sent delays only the messages addressed to it; while
// it is, at most 16 provisional responses or 2xx retransmissions of a request
// wait for it, and later ones are dropped and counted (the first 2xx of a
// branch and the final response never are; the UAS resends a 2xx until its
// ACK). The exceptions are
// the 503 sent at MaxContexts and the answers to a CANCEL: they go back to the
// peer the request just came from and wait only if that peer has stopped
// reading, for at most the transport's WriteTimeout.
//
// Memory is bounded by MaxContexts response contexts of at most MaxBranches
// branches. A context holds its request once, with its body shared by every
// copy, plus a copy of the header and a CANCEL per branch, and the final
// responses kept for the choice: about
//
//	body + (2 + 2 × branches) × header + branches × response
//
// per context. MaxContextBytes bounds the request part over all contexts
// together, and keeps it charged for 64*T1 after a 2xx, or while a branch's
// CANCEL waits for an answer, since the transactions hold the request that
// long. Requests from client-facing listeners may use only the transaction
// layer's ClientShare of it, as they may of the layer's own bounds (#489).
// The responses are bounded by MaxBranches and the transport's message
// limits. A context lives until every branch has ended. Timer C ends a
// silent INVITE branch; one that receives a provisional response at least
// every TimerC keeps its context, as ringing does, and holds a MaxContexts
// slot as long. A Router, Resolver or hook that stalls is met by the
// transaction layer's safety net (#156): the layer answers 500 once Timer C or
// F, the wait for a CANCEL's answer and a margin have passed since the proxy
// last made progress (a provisional response forwarded, a fork group or a
// replacement started), and the context then stops: its hooks see their
// context cancelled, no branch starts, and the INVITE branches still pending
// are cancelled.
//
// A branch the transport cannot send because the next hop's connection has no
// room, or no connection can be opened (transport.ErrQueueFull,
// ErrTooManyConnections), counts as a 503 with Retry-After that is passed on
// as such, so the client backs off. Other transport failures count as a 503
// from the next hop (§16.9), which becomes a 500 if chosen, and a vanished
// flow as 430 (RFC 5626 §5.3.1). So does a flow that closes after the
// request was written onto it but before a final response, once the service
// passes the transport's OnFlowClosed to FlowClosed: the branch ends then,
// not at Timer B or F. In every case the next fork group, or a replacement
// target from OnBranchFailure, may still succeed.
//
// Logs carry no message content, URIs or flow IDs.
package proxy
