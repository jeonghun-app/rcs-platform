// Package store defines what rcs-as keeps between accepting a message and
// delivering it: a queue of messages per recipient (store-and-forward) and a
// record of every message a sender sent, which is what lets rcs-as tell a
// genuine disposition notification from a forged one.
//
// rcs-as talks only to the Store interface, so the messaging engine runs
// against Memory in unit tests and against DynamoDB
// (internal/rcsas/awsstore) in production; storetest checks that both meet
// the same contract.
//
// Any rcs-as task may serve any recipient (ADR 0005), so two tasks can try to
// deliver the same queued message at once. Claim is what stops that: a
// conditional write that exactly one caller wins, with a lease that ends
// the claim of a task that died mid-delivery. Remove and Release name the
// claim's owner, so a task whose lease ran out cannot delete or hand back a
// message another task now holds.
package store

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
)

// Errors every backend returns, possibly wrapped.
var (
	// ErrNotFound means no message or record exists under the key, or it
	// has expired.
	ErrNotFound = errors.New("store: not found")
	// ErrExists means Enqueue, RecordSent or MarkNotified found the key
	// taken.
	ErrExists = errors.New("store: already exists")
	// ErrConflict means a claim is held by someone else: Claim found it
	// taken, or Release or Remove was called by a caller that does not hold
	// it.
	ErrConflict = errors.New("store: claimed by another owner")
	// ErrQueueFull means Enqueue would take the recipient's queue past its
	// Limit.
	ErrQueueFull = errors.New("store: recipient's queue is full")
	// ErrSenderShareFull means Enqueue would take the sender's share of the
	// recipient's queue past its Limit.
	ErrSenderShareFull = errors.New("store: sender's share of the queue is full")
)

// Limit bounds one recipient's queue, and the share of it one sender may
// hold, so that a sender cannot fill a queue and lock every other sender
// out. A zero field is no bound. Whose share an item counts against is
// Message.ShareKey: a 1-to-1 notification counts toward the queue only,
// since what one notifier may put in a queue is already bounded by the
// messages the queue's owner sent it, each answered once per kind.
type Limit struct {
	Count       int
	Bytes       int64
	SenderCount int
	SenderBytes int64
}

// Mode is how a message was sent, which decides how it may be delivered.
type Mode uint8

const (
	// Chat messages travel in an MSRP chat session (RCC.07 Chat).
	Chat Mode = iota + 1
	// Standalone messages are pager-mode (SIP MESSAGE, RFC 3428) or
	// large-mode (an MSRP session of its own) standalone messages.
	Standalone
	// Group messages travel in a participant's session with a group chat
	// (RCC.07 Group Chat): Sender is the group's conference URI, the peer
	// of that session, and Author the participant who wrote the message.
	Group
)

func (m Mode) String() string {
	switch m {
	case Chat:
		return "chat"
	case Standalone:
		return "standalone"
	case Group:
		return "group"
	}
	return "unknown"
}

// Message is one queued message.
type Message struct {
	// Recipient is the queue: the recipient's public identity as the SIP
	// layer names users.
	Recipient string
	// ID identifies the message within its recipient's queue. Engines make
	// it sort in enqueue order (see the messaging package), so Pending
	// returns a queue oldest first.
	ID string
	// Sender is the asserted identity of the sender: for a Group message,
	// the group's conference URI.
	Sender string
	// Author is, for a Group message, the asserted identity of the
	// participant who wrote it, or for a group notification the
	// participant it reports for; empty otherwise.
	Author string
	// Conversation, Contribution and InReplyTo are the RCC.07 conversation
	// identifiers the message belongs to; InReplyTo may be empty.
	Conversation string
	Contribution string
	InReplyTo    string
	Mode         Mode
	// Notification marks a disposition notification (RFC 5438), which is
	// never itself the subject of one.
	Notification bool
	// MessageID is the IMDN Message-ID of the CPIM message, or empty.
	MessageID string
	// CPIM is the message/cpim body exactly as received: rcs-as forwards
	// content byte for byte (docs/architecture.md §8).
	CPIM []byte
	// Enqueued is when the message was accepted; Expires is when it is
	// given up on and, if the sender asked, a negative delivery
	// notification goes back.
	Enqueued time.Time
	Expires  time.Time

	// Owner and LeaseUntil describe a claim; Owner is empty when the
	// message is free.
	Owner      string
	LeaseUntil time.Time
}

// GroupNotifications is the share of a queue that notifications about
// group messages count against, whichever group and notifier they come
// from. It is not an identity: those are URIs.
const GroupNotifications = "#group-notifications"

// ShareKey returns whose share of the recipient's queue m counts against,
// and false when it counts against none:
//
//   - a message counts against its writer's share: the sender, or for a
//     group message its author, so that one person holds one share of a
//     queue whichever way they write;
//   - a group notification counts against GroupNotifications: each
//     message an author writes is answered by every other participant,
//     so the bound that makes a 1-to-1 notification need no share (one
//     recipient answers it, once per kind) does not hold, and without one
//     the receipts for a few messages to a large group would fill the
//     author's queue;
//   - a 1-to-1 notification counts against none.
func (m Message) ShareKey() (string, bool) {
	switch {
	case m.Mode == Group && m.Notification:
		return GroupNotifications, true
	case m.Mode == Group && m.Author != "":
		return m.Author, true
	case !m.Notification:
		return m.Sender, true
	}
	return "", false
}

// Size is what m counts for against its queue's Limit.
func (m Message) Size() int64 { return int64(len(m.CPIM)) }

// Clone returns a copy of m that shares no memory with it.
func (m Message) Clone() Message {
	m.CPIM = slices.Clone(m.CPIM)
	return m
}

// Free reports whether m can be claimed at now: unclaimed, or its lease
// over.
func (m Message) Free(now time.Time) bool {
	return m.Owner == "" || !m.LeaseUntil.After(now)
}

// Sent records a message a sender sent, for as long as notifications about
// it may come back.
type Sent struct {
	// Sender is the sender's identity, or for a group message the group's
	// conference URI: a notification in a group answers a message by its
	// Message-ID within the group, whatever form of the author's identity
	// the notifier's client writes.
	Sender    string
	MessageID string
	// Author is, for a group message, the participant who wrote it, whom
	// its notifications go to; empty otherwise.
	Author string
	// Group is set on the author's own record of a group message (Sender
	// the author), which a notification sent outside the group's session
	// finds: the group's conference URI, whose record holds the marks of
	// the notifications already accepted. Empty otherwise.
	Group string
	// Recipients are the identities a notification about the message may
	// come from.
	Recipients []string
	// Dispositions are the notifications the sender asked for.
	Dispositions imdn.Disposition
	Expires      time.Time
}

// Clone returns a copy of s that shares no memory with it.
func (s Sent) Clone() Sent {
	s.Recipients = slices.Clone(s.Recipients)
	return s
}

// Store is where rcs-as keeps queued messages and sent records. Every
// method is safe for concurrent use, also across processes sharing a
// backend.
//
// Every write may be repeated with the same arguments, as an SDK does when
// an answer is lost, and the repeat of one that took effect succeeds:
// Claim by the same owner with the same lease, Release of a message no one
// holds, Remove of a message already gone, MarkNotified with the same token.
type Store interface {
	// Enqueue adds m, unclaimed, to its recipient's queue: ErrExists if the
	// queue already holds m.ID, ErrQueueFull if the queue would then be
	// beyond l, ErrSenderShareFull if what counts against m's share
	// (Message.ShareKey) would.
	Enqueue(ctx context.Context, m Message, l Limit) error
	// Pending returns up to limit messages of recipient's queue that are
	// free at now and not expired, oldest first, starting after the ID
	// after ("" for the start), so that a caller can page past messages it
	// leaves queued.
	Pending(ctx context.Context, recipient, after string, now time.Time, limit int) ([]Message, error)
	// Claim gives the message to owner until until, if it is free at now,
	// and returns it whole. Exactly one of several concurrent callers
	// succeeds; the others get ErrConflict. ErrNotFound if there is no
	// such message.
	Claim(ctx context.Context, recipient, id, owner string, now, until time.Time) (Message, error)
	// Release frees a message owner holds, for another delivery attempt.
	Release(ctx context.Context, recipient, id, owner string) error
	// Remove deletes m, which owner holds: delivered, or given up on. m is
	// the message as Claim returned it; its size is taken off the queue's.
	Remove(ctx context.Context, m Message, owner string) error
	// Expired returns up to limit messages, of any recipient, whose expiry
	// is at or before now and that are free at now, starting at cursor
	// ("" for the start), and the cursor to go on from: "" once the end is
	// reached. Only Recipient, ID and Expires are filled in: Claim returns
	// the rest. When it fails part-way it returns what it found, with the
	// cursor to resume from, and the error.
	Expired(ctx context.Context, now time.Time, cursor string, limit int) ([]Message, string, error)
	// RecordSent stores s: ErrExists if the sender already has a record for
	// the Message-ID that has not expired at now. An expired one is
	// replaced, since a backend may keep it for a while (DynamoDB TTL).
	RecordSent(ctx context.Context, s Sent, now time.Time) error
	// Sent returns the record of sender's message, ErrNotFound if there is
	// none or it has expired at now.
	Sent(ctx context.Context, sender, messageID string, now time.Time) (Sent, error)
	// MarkNotified records on sender's record of messageID that the
	// notification named key has been accepted, so that it is accepted
	// once. token identifies the attempt: ErrExists if key is marked with
	// another token, ErrNotFound if there is no live record.
	MarkNotified(ctx context.Context, sender, messageID, key, token string, now time.Time) error
	// UnmarkNotified undoes MarkNotified with the same token, when what the
	// mark stood for could not be done. Without such a mark it does
	// nothing.
	UnmarkNotified(ctx context.Context, sender, messageID, key, token string) error
}
