// Package transport carries SIP messages over UDP, TCP and TLS for every SIP
// service in the repository, and keeps the table of client connections (flows)
// that terminating requests are routed back over.
//
// It is the RFC 3261 §18 layer of the stack the project builds itself (ADR 0001):
// framing on stream transports through the sip package's Reader, the received and
// rport parameters a server adds to the top Via (RFC 3261 §18.2.1, RFC 3581 §4),
// response routing (RFC 3261 §18.2.2), the sent-by a client inserts and checks
// (RFC 3261 §18.1.1, §18.1.2), and the server side of the CRLF keep-alive of
// RFC 5626 §4.4.1 and §5.4.
// Transactions, dialogs and routing decisions belong to the layers above.
//
// # Flows
//
// Every connection, and every UDP source that has sent a message, is a flow named
// by a FlowID. The ID is an HMAC-SHA256 over the connection identity (transport,
// listener, client address and port, and a per-flow counter) under a key drawn at
// every start (ADR 0005), so it can be put in a Path or Record-Route as the RFC
// 5626 §5.2 flow token. An ID from a previous process, a forged ID and the ID of a
// closed connection all resolve to no flow, which the caller answers with 430 Flow
// Failed (RFC 5626 §5.3.1).
//
// # Load balancers
//
// Behind the AWS NLB the socket peer is the load balancer, not the client, so a
// stream listener can require a PROXY protocol v2 header (ADR 0003). The client
// address in that header is then the address received, rport and the flow
// identity use. A connection without a valid header is closed and counted, so a
// misconfigured target group fails loudly; a LOCAL header, which NLB health checks
// send, is accepted and the connection closed without creating a flow.
//
// # Resource limits
//
// A stream connection may be idle between messages for IdleTimeout, but once the
// first byte of a message has arrived the whole message must arrive within
// ReadTimeout, so a peer cannot hold a connection by trickling a header. The same
// ReadTimeout bounds the PROXY header and the TLS handshake. Writes have their own
// deadline, and the number of accepted connections and of UDP flows is bounded.
//
// Nothing here logs message content or flow IDs: both identify subscribers or
// let an attacker address their flows.
package transport
