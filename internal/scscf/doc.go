// Package scscf runs the Serving-CSCF (TS 24.229 §5.4) as a service: it
// reads its settings (docs/scscf.md) and wires the registrar, the reg event
// notifier and the service router of its subpackages to the shared state,
// the Cx client toward the HSS and one SIP core listener.
//
// The proxy hands each request to the part that serves it (dispatcher):
// REGISTER to the registrar, a SUBSCRIBE for the reg event to the notifier,
// and anything else to the router, outside a dialog along the user's iFC
// chain and inside one along its route. What scscf sends itself, NOTIFYs
// and third-party REGISTERs, goes in client transactions of the same layer
// (sender).
//
// Every task names itself to the HSS, in a Route and in a Record-Route by
// its service name, sip:scscf.<namespace>, never a task's own (ADR 0005), so
// that any task serves what another started. At a stop it drains the
// requests in progress, stops the sweeps, then the third-party
// registrations, and waits for the NOTIFYs it queued no longer than the
// shutdown allows: what is left is the other tasks' sweeps' to finish.
package scscf
