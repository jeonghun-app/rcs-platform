// Package messaging is the core of rcs-as, the RCS messaging application
// server (docs/architecture.md §2): it accepts 1-to-1 chat and standalone
// messages from the originating side, keeps what cannot be delivered yet
// (store-and-forward), delivers to the terminating side, and carries
// disposition notifications (IMDN, RFC 5438) back to senders. docs/rcs-as.md
// describes the design; this comment gives the shape.
//
// The package has no SIP code. The SIP layer (internal/rcsas/sipas) drives
// it:
//
//   - When it answers a client's INVITE it opens a Leg (OpenLeg): an MSRP
//     session on which rcs-as is the passive endpoint (ADR 0004), bound when
//     msrp-relay connects through Serve. When it offers a session itself it
//     creates the leg first (Offer), so that the relay may connect before
//     the answer arrives, and completes it with Leg.Answer. Messages
//     arriving on a leg go into the pipeline.
//   - When a SIP MESSAGE arrives (pager mode, RFC 3428) it calls Submit with
//     the CPIM body, which runs through the same pipeline.
//   - It implements Deliverer, through which the engine sends pager-mode
//     MESSAGEs and asks for terminating sessions.
//   - It reports registrations (UserRegistered) and failed terminating
//     sessions (InviteFailed), which make the engine try stored messages
//     again.
//
// The pipeline checks size, rate per sender and the CPIM From against the
// sender's asserted identities, then either records the message as sent and
// queues it for its recipient, or, for a notification, checks that it
// answers a message its recipient really received from the notified party
// before queueing it for that party, once. Each recipient's queue is
// bounded, across tasks. Everything is queued first and delivered from the
// queue, so a message is never lost between accepting it and delivering
// it, and two tasks sharing a store deliver each message once
// (store.Store.Claim).
//
// Content is forwarded byte for byte (docs/architecture.md §8). The one
// exception is a notification whose top IMDN-Route names rcs-as itself:
// that entry is removed, as RFC 5438 §8 has an intermediary do.
//
// Metrics are counts with fixed names (Counter); identities never become
// part of a name. Logs carry identities only through internal/pii and never
// message content.
package messaging
