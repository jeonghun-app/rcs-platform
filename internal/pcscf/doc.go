// Package pcscf is the Proxy-CSCF (TS 24.229 §5.2): the only SIP entry point
// for clients. It runs the proxy core of internal/sip/proxy on two kinds of
// listener (ADR 0007): client listeners behind the NLB, which require the
// PROXY protocol v2 header (ADR 0003) and trust nothing a client sends, and a
// core listener on its own port, which only scscf reaches.
//
// A client's connection lives on one pcscf task, so pcscf names its instance
// address and the flow in Path and in the core-facing Record-Route (ADR
// 0005); the flow token is the transport's FlowID, an HMAC under a key drawn
// at every start, so a token from an earlier task on a recycled address is
// unknown and answered 430 Flow Failed (RFC 5626 §5.3).
//
// This version serves the edge only: it opens the listeners, recognises
// itself in Route by its public FQDN, the NLB's addresses or its own, removes
// the headers only the network may set from every message a client sends
// (TS 24.229 §5.2.1, ADR 0007 §7), limits the client flows of one client and
// in all, and drains client flows gradually on shutdown while the core
// listener stays open. Registration, originating and terminating routing
// follow in later changes (#16); until then a client's request is refused
// with 403 and one from the core with 430.
package pcscf
