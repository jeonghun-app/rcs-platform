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
// # Client-facing and core listeners
//
// A listener clients reach (ListenerConfig.ClientFacing, implied by
// ProxyProtocol) never opens a connection to deliver a response whose connection
// has closed, and sends no TCP keep-alive probes, leaving the keep-alive interval
// to the client (RFC 5626 §4.4). Core-facing listeners and dialed connections
// probe every 15 s. Admit and OnFlowClosed let a service see every inbound flow
// come and go, to enforce per-client limits and to forget bindings of a closed
// flow; CloseFlow and StopListening let it shut down gradually (ADR 0003).
//
// # Resource limits
//
// A stream connection may be idle between messages for IdleTimeout, but once the
// first byte of a message has arrived the whole message must arrive within
// ReadTimeout, so a peer cannot hold a connection by trickling a header. An
// accepted connection must also complete its first message within ReadTimeout.
// The same ReadTimeout bounds the PROXY header and the TLS handshake. Writes have
// their own deadline. Accepted connections, dialed connections and UDP flows (in
// total and per source IP) are bounded; a full UDP table displaces its least
// recently seen flow rather than refusing a new client.
//
// Writes never happen on the caller's goroutine. Each stream connection has a
// send queue and a writer goroutine; a sender waits, for at most WriteTimeout,
// only while the queue is over SendQueueBytes, and a NoWait sender, such as the
// goroutine that reads the same connection, never waits. Two peers that both
// send faster than they read therefore cannot deadlock each other, and a peer
// that stops reading loses its connection without slowing anyone else.
//
// Memory: a stream connection holds a 4 KiB read buffer, up to twice
// SendQueueBytes of queued output if its peer stops reading, and while reading a
// message up to Limits.MaxHeaderBytes plus the body bytes that have arrived, at
// most Limits.MaxBodyBytes (16 KiB and 1 MiB by default). The worst case is
// therefore about MaxConnections times 1.02 MiB, over 10 GiB with the defaults,
// although reaching it needs every client to send a maximal body at once; size
// the task, MaxConnections and MaxBodyBytes together. Each UDP socket has one
// 64 KiB buffer.
//
// Nothing here logs message content or flow IDs: both identify subscribers or
// let an attacker address their flows.
package transport
