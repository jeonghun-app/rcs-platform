package messaging

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// Errors a Deliverer returns to say what became of a delivery. Any other
// error is taken as a passing failure, like ErrOffline.
var (
	// ErrOffline means the recipient cannot be reached now (not
	// registered, or every contact failed, ADR 0005); the message stays
	// stored until the next registration or session.
	ErrOffline = errors.New("messaging: recipient offline")
	// ErrUndeliverable means the recipient will never take the message (for
	// example the identity does not exist); the engine gives up on it and
	// sends a negative delivery notification if one was requested.
	ErrUndeliverable = errors.New("messaging: undeliverable")
	// ErrLooped, an ErrUndeliverable, means the invitation came back to
	// rcs-as (482), as it does for a group invitee at the conference host
	// every time: unlike a 404 or 604, no registration of the recipient
	// changes that.
	ErrLooped = fmt.Errorf("messaging: the invitation came back: %w", ErrUndeliverable)
	// ErrNoSessions, from Invite, means the recipient's contact cannot take
	// sessions from the network: it answered an earlier terminating offer
	// with a=setup:passive, which msrp-relay never dials (ADR 0004). The
	// engine then uses pager mode for what fits and keeps the rest until
	// the client opens a session itself or registers again.
	ErrNoSessions = errors.New("messaging: recipient takes no terminating sessions")
)

// Deliverer is what the engine needs from the SIP layer to reach a
// recipient that has no open leg.
type Deliverer interface {
	// Pager sends d as a pager-mode MESSAGE (RFC 3428) with d.CPIM as its
	// message/cpim body. It returns once the request has been answered: nil
	// for a 2xx.
	Pager(ctx context.Context, d Delivery) error
	// Invite starts a terminating session to inv.Recipient on behalf of
	// inv.Peer: rcs-as offers actpass and its instance address (ADR 0004),
	// in the SDP of a leg from Engine.Offer (Direction Terminating, with
	// inv's QueueID). It returns once the INVITE is on its way; the answer
	// goes to Leg.Answer, a failure to Engine.InviteFailed and Leg.Close.
	// A large-mode session is ended once the leg is Finished.
	Invite(ctx context.Context, inv Invitation) error
}

// Delivery is one message for Deliverer.Pager.
type Delivery struct {
	// Recipient is the request target; Sender the identity to assert.
	Recipient string
	Sender    string
	// SenderName is the CPIM From formal name, escaped with
	// EscapeDisplayName so it can be a SIP display name as it is. The
	// sender chose it, whatever its identity, so it may only be shown: the
	// display name of From, never of P-Asserted-Identity or any other
	// header the network vouches for.
	SenderName   string
	Conversation Conversation
	Mode         store.Mode
	// Notification marks a disposition notification.
	Notification bool
	// Route is the next IMDN-Route of a notification, which the request
	// goes through, when it is one of Config.TrustedRoutes;
	// empty otherwise. The engine has checked it; the SIP layer routes
	// through Route only when it is set and never through a route header
	// it reads from the body itself.
	Route string
	// CPIM is the body, as the sender sent it.
	CPIM []byte
}

// Invitation asks Deliverer.Invite for a session.
type Invitation struct {
	Recipient    string
	Peer         string
	Conversation Conversation
	Mode         store.Mode
	// QueueID names, for a large-mode session, the one queued message it
	// is for; empty for a chat session.
	QueueID string
	// Subject is a group's subject, for the INVITE that brings a new
	// participant into it (Engine.Invite); empty otherwise.
	Subject string
	// Referrer is, for a group, who brings the recipient in: the creator
	// or whoever added it, or the author of the message the invitation is
	// for (RFC 3892 Referred-By, which rcsjta names the inviter by).
	Referrer string
	// flow is the recipient's registration on a new flow the engine had
	// heard of when it asked for the session (Engine.flows), so that
	// InviteFailed can tell a failure that a later registration overtook.
	flow uint64
}
