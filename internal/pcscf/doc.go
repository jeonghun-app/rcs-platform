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
// This version serves the edge and registration: it opens the listeners,
// recognises itself in Route by its public FQDN, the NLB's addresses or its
// own, removes the headers only the network may set from every message a
// client sends (TS 24.229 §5.2.1, ADR 0007 §7), limits the client flows of
// one client and in all, routes REGISTER to icscf with a Path naming the
// flow and keeps the 200 in instance memory (§5.2.2.1), and drains client
// flows gradually on shutdown while the core listener stays open.
//
// A client's other requests go to the core along its Service-Route, or
// inside a dialog along the route pcscf recorded, to scscf alone
// (originate.go); a request from the core goes to the client flow its
// Route names and nowhere else (terminate.go). The reg event follows in a
// later change (#16).
package pcscf
