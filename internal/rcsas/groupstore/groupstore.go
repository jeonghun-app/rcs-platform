// Package groupstore defines what rcs-as keeps about each group chat: its
// conference URI, subject, participants with their roles and states, and
// the version of its roster, in the DynamoDB groupchats table
// (docs/architecture.md §7) or in memory for tests.
//
// Every change is a conditional write on the revision the change was
// computed from, so exactly one of two concurrent changes lands and the
// other is computed again; that is also what makes the roster version a
// counter shared by all tasks.
//
// One task owns each group (#121, ADR 0005): its sessions, subscriptions
// and fan-out live there. The store keeps the group's Owner, which every
// change and Touch is fenced by: a write under an owner the store no
// longer holds, as by a task that lost the group while paused, is refused
// (ErrNotOwner), never applied. A task takes a group over with TakeOver,
// once the owner's heartbeat (Task) has lapsed. storetest checks that
// every backend meets the same contract.
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
	// revision is not the stored one, or TakeOver's owner is not.
	ErrConflict = errors.New("groupstore: changed by another writer")
	// ErrNotOwner means the write's owner is not the group's: another task
	// took the group over.
	ErrNotOwner = errors.New("groupstore: not the group's owner")
)

// Owner is the task that serves a group (#121).
type Owner struct {
	// Task is the owner's task id, random at every start, so that a task
	// that comes up on a dead one's address is never taken for it.
	Task string
	// SIP is the owner's SIP instance address (host:port), where another
	// task forwards the group's requests.
	SIP string
	// Epoch is raised by every takeover: a write fenced by an older one is
	// refused.
	Epoch int64
}

// Task is one rcs-as task's heartbeat: the task owns its groups while
// AliveUntil has not passed.
type Task struct {
	ID         string
	SIP        string
	AliveUntil time.Time
}

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

// MaxRemoved is the most identities one group keeps in Group.Removed.
const MaxRemoved = 200

// MaxEntries is the most participants, current and former, one group
// holds. Every backend must store a group of this many with every field
// at its longest: in DynamoDB that is the whole roster in one item, under
// the 400 KB item limit.
const MaxEntries = 400

// Group is one group chat.
type Group struct {
	// URI is the conference URI, the group's identity.
	URI string
	// Conversation is the group's Conversation-ID (RCC.07).
	Conversation string
	Subject      string
	Creator      string
	// Participants are the group's current participants and its most
	// recent former ones, in the order they were added; former ones stay,
	// so that the roster can say they left, up to MaxEntries in all.
	Participants []Participant
	// Removed are identities the chairman removed that Participants no
	// longer lists, oldest first, up to MaxRemoved: the roster forgets
	// former participants, but who was removed stays known, so that only
	// the chairman adds them back. They are not part of the roster.
	Removed []string
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
	g.Removed = slices.Clone(g.Removed)
	return g
}

// Store is where rcs-as keeps groups. Every method is safe for concurrent
// use, also across processes sharing a backend.
type Store interface {
	// Create stores g at revision 1, owned by owner at epoch 1, whatever
	// owner.Epoch says; ErrExists if its URI is taken by a group that has
	// not expired at now. token identifies the attempt, as for Update, so
	// that a repeat of a create that took effect succeeds.
	Create(ctx context.Context, g Group, owner Owner, token string, now time.Time) error
	// Get returns the group, ErrNotFound if there is none or it has
	// expired at now.
	Get(ctx context.Context, uri string, now time.Time) (Group, error)
	// Update replaces the group if its stored revision is still g.Rev and
	// its owner still owner (task and epoch), storing revision g.Rev+1:
	// ErrConflict if another write came first, ErrNotOwner if another task
	// took the group over, ErrNotFound if the group is gone. token
	// identifies the attempt, so that a repeat of an update that took
	// effect (an SDK retry) succeeds.
	Update(ctx context.Context, g Group, owner Owner, token string) error
	// Touch records that the group was used at active, moving Active and
	// Expires forward together, and only when active is later than the
	// stored Active: a touch older than the last write, which may have
	// ended the group, changes nothing. ErrNotFound if the group is gone
	// or has expired at active, ErrNotOwner as for Update. It does not
	// change the revision, so it never makes an Update fail.
	Touch(ctx context.Context, uri string, owner Owner, active, expires time.Time) error
	// Owner returns the group's owner, the zero Owner for a group stored
	// before #121 that no task has taken yet.
	Owner(ctx context.Context, uri string) (Owner, error)
	// TakeOver makes to the group's owner at from.Epoch+1, if from is
	// still the stored one (the zero Owner: none), and returns it:
	// ErrConflict if another task took the group first. expires is the
	// group's, which the owner record must outlive. token identifies the
	// attempt, so that a repeat that took effect succeeds.
	TakeOver(ctx context.Context, uri string, from, to Owner, expires time.Time, token string) (Owner, error)
	// Beat stores t's heartbeat, AliveUntil a time it renews ahead of
	// itself; a task that stops beats one at its present time, so that
	// another may take its groups at once.
	Beat(ctx context.Context, t Task) error
	// Task returns task id's last heartbeat, ErrNotFound if it never beat
	// or its record has gone.
	Task(ctx context.Context, id string) (Task, error)
}
