// Package groupstore defines what rcs-as keeps about each group chat: its
// conference URI, subject, participants with their roles and states, and
// the version of its roster, in the DynamoDB groupchats table
// (docs/architecture.md §7) or in memory for tests.
//
// Any rcs-as task may handle any group (ADR 0005), so two tasks may change
// one group at once. Every change is a conditional write on the revision
// the change was computed from, so exactly one of two concurrent changes
// lands and the other is computed again; that is also what makes the
// roster version a counter shared by all tasks. storetest checks that every
// backend meets the same contract.
package groupstore

import (
	"context"
	"errors"
	"slices"
	"time"
)

// Errors every backend returns, possibly wrapped.
var (
	// ErrNotFound means there is no such group, or it has expired.
	ErrNotFound = errors.New("groupstore: not found")
	// ErrExists means Create found the conference URI taken.
	ErrExists = errors.New("groupstore: already exists")
	// ErrConflict means the group changed since it was read: Update's
	// revision is not the stored one.
	ErrConflict = errors.New("groupstore: changed by another writer")
)

// Role is a participant's role in a group, as the roster names it (RFC
// 4575 §5.6.3 roles).
type Role string

const (
	// Chairman is the participant who may remove others: the group's
	// creator, or whom the role passed to (see the group package).
	Chairman Role = "chairman"
	// Member is any other participant.
	Member Role = "participant"
)

// State is where a participant stands in a group.
type State uint8

const (
	// Invited: added, and asked to join; messages are kept for it.
	Invited State = iota + 1
	// Joined: in the group with a session of its own.
	Joined
	// Left: left of its own accord.
	Left
	// Removed: removed by the chairman.
	Removed
)

func (s State) String() string {
	switch s {
	case Invited:
		return "invited"
	case Joined:
		return "joined"
	case Left:
		return "left"
	case Removed:
		return "removed"
	}
	return "unknown"
}

// Active reports whether a participant in state s belongs to the group:
// messages go to it and it counts toward the size limit.
func (s State) Active() bool { return s == Invited || s == Joined }

// Participant is one member of a group, current or former.
type Participant struct {
	// Identity is the participant's asserted identity, in the form the SIP
	// layer names users.
	Identity    string
	DisplayName string
	Role        Role
	State       State
	// AddedBy is who added the participant; empty for the creator.
	AddedBy string
	// Since is when the participant entered its state.
	Since time.Time
}

// Group is one group chat.
type Group struct {
	// URI is the conference URI, the group's identity.
	URI string
	// Conversation is the group's Conversation-ID (RCC.07).
	Conversation string
	Subject      string
	Creator      string
	// Participants are everyone ever in the group, in the order they were
	// added; former ones stay, so that the roster can say they left.
	Participants []Participant
	// Version is the conference-info version of the last roster change
	// (RFC 4575 §4.3), one more with every change.
	Version uint32
	Created time.Time
	// Active is when the group was last used, and Expires when it ends for
	// want of use (RCSAS_GROUP_IDLE_TTL).
	Active  time.Time
	Expires time.Time
	// Rev is the stored revision, which Update is conditional on; the
	// store sets it.
	Rev int64
}

// Participant returns the participant identity, if it was ever in g.
func (g Group) Participant(identity string) (Participant, bool) {
	i := slices.IndexFunc(g.Participants, func(p Participant) bool { return p.Identity == identity })
	if i < 0 {
		return Participant{}, false
	}
	return g.Participants[i], true
}

// Clone returns a copy of g that shares no memory with it.
func (g Group) Clone() Group {
	g.Participants = slices.Clone(g.Participants)
	return g
}

// Store is where rcs-as keeps groups. Every method is safe for concurrent
// use, also across processes sharing a backend.
type Store interface {
	// Create stores g at revision 1; ErrExists if its URI is taken by a
	// group that has not expired at now. token identifies the attempt, as
	// for Update, so that a repeat of a create that took effect succeeds.
	Create(ctx context.Context, g Group, token string, now time.Time) error
	// Get returns the group, ErrNotFound if there is none or it has
	// expired at now.
	Get(ctx context.Context, uri string, now time.Time) (Group, error)
	// Update replaces the group if its stored revision is still g.Rev,
	// storing revision g.Rev+1: ErrConflict if another write came first,
	// ErrNotFound if the group is gone. token identifies the attempt, so
	// that a repeat of an update that took effect (an SDK retry) succeeds.
	Update(ctx context.Context, g Group, token string) error
	// Touch records that the group was used at active, moving Active and
	// Expires forward and never back; ErrNotFound if it is gone or has
	// expired at active. It does
	// not change the revision, so it never makes an Update fail.
	Touch(ctx context.Context, uri string, active, expires time.Time) error
}
