// Package msrprelay is the msrp-relay service: the MSRP media anchor at the
// edge of the platform, which pcscf controls the way a P-CSCF controls an
// IMS access gateway (ADR 0004, TS 23.334). Clients on the internet cannot
// reach rcs-as in the private subnets, and rcs-as must not accept
// connections from them, so every chat session crosses the relay: the
// client connects to the relay, and the relay connects to rcs-as.
//
// The package has two halves around a shared binding store:
//
//   - The control API (internal HTTP, ADR 0007) lets pcscf allocate a
//     binding while it rewrites the SDP of a session: the relay's URI for the
//     client (client_path), its URI for the core (core_path_local), and the
//     paths of the two endpoints as pcscf learns them from the offer and
//     the answer. Only pcscf's token is accepted.
//   - The data path accepts client connections behind the NLB (PROXY
//     protocol v2, TLS ended at the NLB) and never dials a client. When a
//     client's first SEND names a session, Bind finds the binding, claims it
//     so no other connection on any task can use it, opens the session
//     toward rcs-as, and bridges the two with internal/msrp's Bridge.
//
// Bindings live in DynamoDB (internal/msrprelay/dynamostore) so that the
// task that allocated a binding and the task a client reaches need not be
// the same (ADR 0005); the memory store serves tests and single-task runs.
//
// Everything a client can make the relay hold is bounded: connections per
// task and per source address, lookups in flight, requests for unknown
// sessions per connection (internal/msrp), and the time each store call and
// core connection may take. No session id reaches a log or a metric, and
// the one that lets a client connection into a session is not stored
// either: bindings are keyed by its SHA-256. docs/msrp-relay.md has the
// settings, metrics and limits.
package msrprelay
