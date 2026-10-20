// Package cxclient is the Cx client of icscf and scscf (TS 29.228, TS 29.229):
// typed UAR, LIR, MAR and SAR calls to the HSS, and the RTR and PPR the HSS
// sends back.
//
// The HSS runs as several tasks, each with its own Origin-Host (ADR 0005), and
// it only answers connections: it can send an RTR or PPR only over a
// connection a CSCF opened to that very task. So the client discovers the HSS
// tasks, with Cloud Map's DiscoverInstances on AWS (CloudMapDiscovery: a DNS
// answer names at most eight of them) or by resolving hss.<namespace>, keeps a
// Diameter connection to every address, and discovers again every
// ResolveInterval. A new task is connected at once; a task is dropped only
// when it has been missing from three answers in a row and its connection is
// down, so a task a partial answer leaves out keeps its connection. A failed or
// empty answer keeps the connections it has.
//
// A request goes to the available tasks in turn, skipping for
// TimeoutExclusion a task whose attempt timed out, which may have stopped
// answering long before its watchdog notices. When the task answers
// DIAMETER_TOO_BUSY, or DIAMETER_UNABLE_TO_DELIVER while it shuts down, or
// the request fails in transport or times out, it is sent once more to another
// task with the same Session-Id and End-to-End Identifier and the T flag (RFC
// 6733 §5.5.4). One retry, not more: the HSS tasks share their store, so a
// second busy task means the HSS as a whole is loaded, and the CSCF's own
// SIP transaction is waiting. The retry goes to the next task after the failed
// one and leaves the turn alone, so a failing task gets no more first attempts
// than any other.
//
// HSSHostPattern, if set, pins the Origin-Host of the tasks (hss-*.<namespace>):
// a peer that claims another gets no requests and its RTR and PPR are refused
// (threat model T1).
//
// Every instance has its own Origin-Host (OriginHostFor), and every scscf
// instance sends the shared S-CSCF name as Server-Name, so any instance can
// serve any user and the HSS can push to any of them.
//
// Results are returned as the answers carry them; Classify turns one into an
// Outcome a CSCF maps to its SIP response. Schemes and Authenticate apply the
// S-CSCF's choice of authentication scheme (AKA first, SIP Digest on 5006,
// the client's algorithm when it names one).
//
// Nothing here logs an identity, a Session-Id or a credential; metrics carry
// command names and result codes only.
package cxclient
