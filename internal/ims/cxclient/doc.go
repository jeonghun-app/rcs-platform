// Package cxclient is the Cx client of icscf and scscf (TS 29.228, TS 29.229):
// typed UAR, LIR, MAR and SAR calls to the HSS, and the RTR and PPR the HSS
// sends back.
//
// The HSS runs as several tasks, each with its own Origin-Host (ADR 0005), and
// it only answers connections: it can send an RTR or PPR only over a
// connection a CSCF opened to that very task. So the client resolves the
// Cloud Map name of the HSS (hss.<namespace>, one A record per task), keeps a
// Diameter connection to every address, and resolves again every
// ResolveInterval, connecting to new tasks and dropping vanished ones. A
// failed or empty resolution keeps the connections it has.
//
// A request goes to the available tasks in turn. When the task answers
// DIAMETER_TOO_BUSY, or DIAMETER_UNABLE_TO_DELIVER while it shuts down, or
// the request fails in transport or times out, it is sent once more to another
// task with the same Session-Id and End-to-End Identifier and the T flag (RFC
// 6733 §5.5.4). One retry, not more: the HSS tasks share their store, so a
// second busy task means the HSS as a whole is loaded, and the CSCF's own
// SIP transaction is waiting.
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
