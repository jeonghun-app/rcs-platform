package messaging

import (
	"context"
	"errors"

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
	// with a local URI from Engine.LocalURI. It returns once the INVITE is
	// on its way; when the answer comes the SIP layer opens the leg with
	// Engine.OpenLeg, or reports the failure with Engine.InviteFailed.
	Invite(ctx context.Context, inv Invitation) error
}

// Delivery is one message for Deliverer.Pager.
type Delivery struct {
	// Recipient is the request target; Sender the identity to assert.
	Recipient string
	Sender    string
	// SenderName is the CPIM From formal name, escaped with
	// EscapeDisplayName so it can be a SIP display name as it is.
	SenderName   string
	Conversation Conversation
	Mode         store.Mode
	// Notification marks a disposition notification.
	Notification bool
	// Route is the next IMDN-Route of a notification that names another
	// intermediary, which the request goes through; empty otherwise.
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
}
