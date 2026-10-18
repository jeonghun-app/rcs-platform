// Package diameter implements the Diameter base protocol (RFC 6733) that the
// IMS core uses on its Cx and Sh reference points: `icscf` and `scscf` talk to
// `hss`, and `rcs-as` may query it over Sh (TS 29.229, TS 29.329). The project
// writes its own stack instead of using freeDiameter or a Go library (ADR 0001),
// so this package is the foundation those applications build on.
//
// The package has four layers:
//
//   - The codec ([Message], [AVP], [DecodeMessage], [ReadMessage]) frames
//     messages and validates every length before reading, so a malformed
//     message is rejected with the result code RFC 6733 §7 assigns to it rather
//     than repaired.
//   - The [Dictionary] maps an AVP code and vendor to a name and a data type.
//     It holds the base AVPs; application packages (Cx, Sh) pass their own
//     definitions to [NewDictionary].
//   - A [Node] runs the peer state machine over TCP: capabilities exchange
//     (CER/CEA, §5.3), the RFC 3539 watchdog (DWR/DWA, §5.5), disconnection
//     (DPR/DPA, §5.4) and reconnection with backoff for peers it initiates.
//   - The request/answer API: [Peer.Send] waits for the answer matched by
//     hop-by-hop identifier, and handlers registered with [Node.Handle] answer
//     requests per application and command code.
//
// Each service instance has its own Origin-Host (ADR 0005), so a responder such
// as `hss` cannot list every peer by name. [PeerRule] therefore accepts peers by
// exact host, by a single-label host pattern (`scscf-*.<namespace>`), by realm,
// and optionally only from given source networks.
//
// Limitations, by design for the first release: TCP only (no SCTP), no TLS or
// DTLS (Diameter stays inside the VPC, where security groups restrict who can
// reach the port), no relay, proxy or redirect agent behaviour, no DNS-based peer
// discovery (§5.2), and no election (§5.6.4): configure each pair of nodes so
// that only one side initiates.
package diameter
