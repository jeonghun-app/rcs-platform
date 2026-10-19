// Package storetest checks that a store.Store meets the contract the
// messaging engine relies on. The memory backend runs it in unit tests and
// the DynamoDB backend against DynamoDB Local (make test-integration).
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

var none store.Limit

// Recipients and senders use the fictional numbers of
// .github/allowed-test-identifiers.txt.
const (
	alice = "tel:+15550100001"
	bob   = "tel:+15550100002"
	carol = "tel:+15550100003"
)

func message(recipient, id string, enqueued time.Time) store.Message {
	return store.Message{
		Recipient: recipient, ID: id, Sender: alice,
		Conversation: "conv-1", Contribution: "contrib-1", Mode: store.Chat,
		MessageID: "m-" + id, CPIM: []byte("From: <" + alice + ">\r\n\r\nContent-Type: text/plain\r\n\r\nhi " + id),
		Enqueued: enqueued, Expires: enqueued.Add(time.Hour),
	}
}

// Run runs every check against stores from newStore, which must return an
// empty store each time.
func Run(t *testing.T, newStore func(t *testing.T) store.Store) {
	t.Run("PendingListsFreeMessagesOldestFirst", func(t *testing.T) { pendingOrder(t, newStore(t)) })
	t.Run("EnqueueRefusesADuplicateID", func(t *testing.T) { duplicate(t, newStore(t)) })
	t.Run("GroupMessagesKeepTheirAuthor", func(t *testing.T) { groupMessage(t, newStore(t)) })
	t.Run("OnlyOneOfConcurrentClaimsWins", func(t *testing.T) { concurrentClaims(t, newStore(t)) })
	t.Run("ALapsedLeaseCanBeClaimedAgain", func(t *testing.T) { lapsedLease(t, newStore(t)) })
	t.Run("OnlyTheOwnerReleasesOrRemoves", func(t *testing.T) { ownership(t, newStore(t)) })
	t.Run("ExpiredListsFreeExpiredMessagesOfEveryRecipient", func(t *testing.T) { expired(t, newStore(t)) })
	t.Run("SentRecordsAreKeptUntilTheyExpire", func(t *testing.T) { sent(t, newStore(t)) })
	t.Run("RepeatedWritesSucceed", func(t *testing.T) { retriedWrites(t, newStore(t)) })
	t.Run("QueuesAreBoundedByCountAndBytes", func(t *testing.T) { limits(t, newStore(t)) })
	t.Run("EachSenderHasAShareOfAQueue", func(t *testing.T) { senderShares(t, newStore(t)) })
	t.Run("AGroupMessageCountsAgainstItsAuthorsShare", func(t *testing.T) { groupShares(t, newStore(t)) })
	t.Run("RemovingAGroupNotificationFreesTheTotal", func(t *testing.T) { groupTotalFreed(t, newStore(t)) })
	t.Run("LongestKeysRoundTrip", func(t *testing.T) { longKeys(t, newStore(t)) })
	t.Run("EachNotificationIsMarkedOnce", func(t *testing.T) { marks(t, newStore(t)) })
}

func pendingOrder(t *testing.T, s store.Store) {
	ctx := context.Background()
	for i, id := range []string{"0003", "0001", "0002"} {
		if err := s.Enqueue(ctx, message(bob, id, t0.Add(time.Duration(i)*time.Second)), none); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Enqueue(ctx, message(carol, "0000", t0), none); err != nil {
		t.Fatal(err)
	}
	got, err := s.Pending(ctx, bob, "", t0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if ids := idsOf(got); fmt.Sprint(ids) != "[0001 0002 0003]" {
		t.Fatalf("Pending = %v", ids)
	}
	want := message(bob, "0001", t0.Add(time.Second))
	if g := got[0]; g.Sender != want.Sender || g.Conversation != want.Conversation || g.Contribution != want.Contribution ||
		g.Mode != want.Mode || g.MessageID != want.MessageID || !bytes.Equal(g.CPIM, want.CPIM) ||
		!g.Enqueued.Equal(want.Enqueued) || !g.Expires.Equal(want.Expires) || g.Owner != "" {
		t.Fatalf("Pending returned %+v, want %+v", g, want)
	}
	if got, _ := s.Pending(ctx, bob, "", t0, 2); len(got) != 2 {
		t.Fatalf("limit 2 returned %d", len(got))
	}
	if got, _ := s.Pending(ctx, bob, "0001", t0, 10); fmt.Sprint(idsOf(got)) != "[0002 0003]" {
		t.Fatalf("Pending after 0001 = %v", idsOf(got))
	}
	if got, _ := s.Pending(ctx, bob, "0003", t0, 10); len(got) != 0 {
		t.Fatalf("Pending after the last = %v", idsOf(got))
	}
	// A claimed message is not pending; an expired one neither.
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pending(ctx, bob, "", t0, 10); fmt.Sprint(idsOf(got)) != "[0002 0003]" {
		t.Fatalf("Pending after a claim = %v", idsOf(got))
	}
	if got, _ := s.Pending(ctx, bob, "", t0.Add(2*time.Hour), 10); len(got) != 0 {
		t.Fatalf("Pending after expiry = %v", idsOf(got))
	}
}

func duplicate(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second Enqueue = %v, want ErrExists", err)
	}
	// The same id in another queue is another message.
	if err := s.Enqueue(ctx, message(carol, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
}

func concurrentClaims(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Claim(ctx, bob, "0001", fmt.Sprintf("task-%d", i), t0, t0.Add(time.Minute))
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 7 {
		t.Fatalf("%d claims won, %d refused", wins.Load(), conflicts.Load())
	}
	if _, err := s.Claim(ctx, bob, "nope", "task-a", t0, t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claiming nothing = %v", err)
	}
}

func lapsedLease(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-b", t0.Add(30*time.Second), t0.Add(2*time.Minute)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("claim during the lease = %v", err)
	}
	later := t0.Add(time.Minute)
	if got, _ := s.Pending(ctx, bob, "", later, 10); len(got) != 1 {
		t.Fatal("a message whose lease ended is not pending")
	}
	m, err := s.Claim(ctx, bob, "0001", "task-b", later, later.Add(time.Minute))
	if err != nil || m.Owner != "task-b" {
		t.Fatalf("claim after the lease = %+v, %v", m, err)
	}
	// The task that lost its lease can no longer act on the message.
	if err := s.Remove(ctx, m, "task-a"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Remove by the former owner = %v", err)
	}
}

func ownership(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
	// Nobody holds it: a release is a repeat of one that took effect.
	if err := s.Release(ctx, bob, "0001", "task-a"); err != nil {
		t.Fatalf("Release of an unclaimed message = %v", err)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]func(owner string) error{
		"Release": func(o string) error { return s.Release(ctx, bob, "0001", o) },
		"Remove":  func(o string) error { return s.Remove(ctx, message(bob, "0001", t0), o) },
	} {
		if err := op("task-b"); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("%s by another task = %v", name, err)
		}
	}
	if err := s.Release(ctx, bob, "0001", "task-a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pending(ctx, bob, "", t0, 10); len(got) != 1 {
		t.Fatal("a released message is not pending")
	}
	held, err := s.Claim(ctx, bob, "0001", "task-b", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pending(ctx, bob, "", t0, 10); len(got) != 0 {
		t.Fatal("a removed message is still pending")
	}
}

func expired(t *testing.T, s store.Store) {
	ctx := context.Background()
	old := message(bob, "0001", t0.Add(-2*time.Hour))
	other := message(carol, "0002", t0.Add(-90*time.Minute))
	fresh := message(bob, "0003", t0)
	for _, m := range []store.Message{old, other, fresh} {
		if err := s.Enqueue(ctx, m, none); err != nil {
			t.Fatal(err)
		}
	}
	got, cursor, err := s.Expired(ctx, t0, "", 10)
	if err != nil || cursor != "" {
		t.Fatalf("Expired = %v, %q, %v", idsOf(got), cursor, err)
	}
	// Oldest expiry first, whatever the queue; only the keys and expiry
	// are promised.
	if fmt.Sprint(idsOf(got)) != "[0001 0002]" || got[0].Recipient != bob || !got[0].Expires.Equal(old.Expires) {
		t.Fatalf("Expired = %+v", got)
	}
	// One at a time: each call resumes where the last stopped, and the
	// end gives an empty cursor.
	first, cursor, err := s.Expired(ctx, t0, "", 1)
	if err != nil || len(first) != 1 || first[0].ID != "0001" || cursor == "" {
		t.Fatalf("Expired page 1 = %v, %q, %v", idsOf(first), cursor, err)
	}
	// A backend may need one more call to see that the end is reached.
	var rest []store.Message
	for page := 0; cursor != "" && page < 3; page++ {
		var got []store.Message
		got, cursor, err = s.Expired(ctx, t0, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		rest = append(rest, got...)
	}
	if fmt.Sprint(idsOf(rest)) != "[0002]" || cursor != "" {
		t.Fatalf("Expired after page 1 = %v, cursor %q", idsOf(rest), cursor)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Expired(ctx, t0, "", 10); len(got) != 1 || got[0].ID != "0002" {
		t.Fatalf("Expired with one claimed = %v", idsOf(got))
	}
	if got, _, _ := s.Expired(ctx, t0, "", 0); len(got) != 0 {
		t.Fatalf("limit 0 returned %d", len(got))
	}
}

func retriedWrites(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0), none); err != nil {
		t.Fatal(err)
	}
	until := t0.Add(time.Minute)
	m, err := s.Claim(ctx, bob, "0001", "task-a", t0, until)
	if err != nil {
		t.Fatal(err)
	}
	// The repeat of a claim that took effect gets the message again; the
	// same owner with another lease is a new claim, which is refused.
	if again, err := s.Claim(ctx, bob, "0001", "task-a", t0, until); err != nil || again.Owner != "task-a" || !bytes.Equal(again.CPIM, m.CPIM) {
		t.Fatalf("repeated Claim = %+v, %v", again, err)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, until.Add(time.Second)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Claim with another lease = %v", err)
	}
	for range 2 {
		if err := s.Release(ctx, bob, "0001", "task-a"); err != nil {
			t.Fatalf("Release = %v", err)
		}
	}
	if m, err = s.Claim(ctx, bob, "0001", "task-b", t0, until); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Remove(ctx, m, "task-b"); err != nil {
			t.Fatalf("Remove = %v", err)
		}
	}
}

func limits(t *testing.T, s store.Store) {
	ctx := context.Background()
	m := message(bob, "0001", t0)
	size := m.Size()
	byCount := store.Limit{Count: 2}
	for _, id := range []string{"0001", "0002"} {
		if err := s.Enqueue(ctx, message(bob, id, t0), byCount); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Enqueue(ctx, message(bob, "0003", t0), byCount); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("Enqueue beyond the count = %v", err)
	}
	// Another queue has a bound of its own.
	if err := s.Enqueue(ctx, message(carol, "0003", t0), byCount); err != nil {
		t.Fatal(err)
	}
	// Removing makes room.
	held, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, message(bob, "0003", t0), byCount); err != nil {
		t.Fatalf("Enqueue after a removal = %v", err)
	}
	// Bytes: bob holds two messages; room for exactly one more.
	byBytes := store.Limit{Bytes: 3*size + size/2}
	if err := s.Enqueue(ctx, message(bob, "0004", t0), byBytes); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, message(bob, "0005", t0), byBytes); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("Enqueue beyond the bytes = %v", err)
	}
	if err := s.Enqueue(ctx, message(alice, "0001", t0), store.Limit{Bytes: size - 1}); !errors.Is(err, store.ErrQueueFull) {
		t.Fatalf("a message larger than the whole bound = %v", err)
	}
}

func senderShares(t *testing.T, s store.Store) {
	ctx := context.Background()
	from := func(sender, id string) store.Message {
		m := message(bob, id, t0)
		m.Sender = sender
		return m
	}
	l := store.Limit{Count: 10, SenderCount: 2}
	for _, id := range []string{"0001", "0002"} {
		if err := s.Enqueue(ctx, from(alice, id), l); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Enqueue(ctx, from(alice, "0003"), l); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("beyond alice's share = %v", err)
	}
	// Another sender still gets through.
	if err := s.Enqueue(ctx, from(carol, "0004"), l); err != nil {
		t.Fatalf("carol = %v", err)
	}
	// A removal gives alice room again.
	held, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, from(alice, "0005"), l); err != nil {
		t.Fatalf("alice after a removal = %v", err)
	}
	size := from(alice, "x").Size()
	if err := s.Enqueue(ctx, from(carol, "0006"), store.Limit{SenderBytes: 2*size - 1}); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("beyond carol's bytes = %v", err)
	}
	// Notifications from a sender at its share still go in, and do not
	// use up the share.
	for _, id := range []string{"n1", "n2", "n3"} {
		n := from(alice, id)
		n.Notification = true
		if err := s.Enqueue(ctx, n, l); err != nil {
			t.Fatalf("notification %s = %v", id, err)
		}
	}
	if err := s.Enqueue(ctx, from(alice, "0007"), l); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("alice at her share = %v", err)
	}
	// With a message of hers gone she has room again, notifications or not.
	m, err := s.Claim(ctx, bob, "0002", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, m, "task-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, from(alice, "0007"), l); err != nil {
		t.Fatalf("alice below her share, with notifications queued = %v", err)
	}
	// Removing a notification frees nothing of the share.
	n, err := s.Claim(ctx, bob, "n1", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, n, "task-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, from(alice, "0008"), l); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("alice after a notification went = %v", err)
	}
}

// One person holds one share of a queue whether they write 1-to-1 or in
// groups, and notifications about one group's messages share one bound of
// their own, whoever sends them; another group's have another.
func groupShares(t *testing.T, s store.Store) {
	ctx := context.Background()
	const group, other = "sip:chat-1@conf.example.net", "sip:chat-2@conf.example.net"
	l := store.Limit{Count: 20, SenderCount: 3}
	direct := func(id string) store.Message {
		m := message(bob, id, t0)
		m.Sender = alice
		return m
	}
	inGroup := func(g, id string) store.Message {
		m := message(bob, id, t0)
		m.Sender, m.Author, m.Mode = g, alice, store.Group
		return m
	}
	notice := func(g, id string) store.Message {
		m := message(bob, id, t0)
		m.Sender, m.Author, m.Mode, m.Notification = g, carol, store.Group, true
		return m
	}
	for _, m := range []store.Message{direct("0001"), inGroup(group, "0002"), inGroup(other, "0003")} {
		if err := s.Enqueue(ctx, m, l); err != nil {
			t.Fatalf("%s = %v", m.ID, err)
		}
	}
	for _, m := range []store.Message{direct("0004"), inGroup(group, "0005"), inGroup(other, "0006")} {
		if err := s.Enqueue(ctx, m, l); !errors.Is(err, store.ErrSenderShareFull) {
			t.Fatalf("%s beyond alice's share = %v", m.ID, err)
		}
	}
	// A group's notifications have a share of their own, which alice's
	// messages do not use up; another group's notifications have another.
	for _, n := range []store.Message{notice(group, "n1"), notice(group, "n2"), notice(other, "n3"), notice(group, "n4")} {
		if err := s.Enqueue(ctx, n, l); err != nil {
			t.Fatalf("notification %s = %v", n.ID, err)
		}
	}
	if err := s.Enqueue(ctx, notice(group, "n5"), l); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("beyond the group's notification share = %v", err)
	}
	if err := s.Enqueue(ctx, notice(other, "n6"), l); err != nil {
		t.Fatalf("another group's notification = %v", err)
	}
	// All groups' notifications together are bounded too.
	total := l
	total.GroupCount = 5 // n1-n4 and n6
	if err := s.Enqueue(ctx, notice("sip:chat-3@conf.example.net", "n7"), total); !errors.Is(err, store.ErrSenderShareFull) {
		t.Fatalf("beyond the group notifications' total = %v", err)
	}
	if err := s.Enqueue(ctx, direct("0008"), total); !errors.Is(err, store.ErrSenderShareFull) {
		// alice is at her share still; anyone else's 1-to-1 goes in.
		t.Fatalf("alice at her share = %v", err)
	}
	other1 := message(bob, "0009", t0)
	other1.Sender = carol
	if err := s.Enqueue(ctx, other1, total); err != nil {
		t.Fatalf("carol beside the full total = %v", err)
	}
	// Removing alice's group message frees her share, for any path.
	held, err := s.Claim(ctx, bob, "0002", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, held, "task-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, direct("0007"), l); err != nil {
		t.Fatalf("alice after a removal = %v", err)
	}
}

// QA's test (PR #118, round 4): delivering (removing) a group
// notification frees its place in the total of group notifications, or a
// connected author's receipts would be dropped until the next recount.
func groupTotalFreed(t *testing.T, s store.Store) {
	ctx := context.Background()
	l := store.Limit{Count: 100, GroupCount: 3}
	for i := range 12 {
		m := message(bob, fmt.Sprintf("n%03d", i), t0)
		m.Sender, m.Author, m.Mode, m.Notification = fmt.Sprintf("sip:chat-%d@conf.example.net", i), carol, store.Group, true
		if err := s.Enqueue(ctx, m, l); err != nil {
			t.Fatalf("notification %d after %d delivered: %v", i, i, err)
		}
		held, err := s.Claim(ctx, bob, m.ID, "task-a", t0, t0.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Remove(ctx, held, "task-a"); err != nil {
			t.Fatal(err)
		}
	}
}

func longKeys(t *testing.T, s store.Store) {
	ctx := context.Background()
	// The longest identity and Message-ID the engine lets through.
	who := "sip:" + strings.Repeat("a", 240) + "@example.net"
	id := strings.Repeat("m", 128)
	m := message(who, id, t0)
	m.Sender = who
	if err := s.Enqueue(ctx, m, none); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Pending(ctx, who, "", t0, 1); err != nil || len(got) != 1 || got[0].ID != id || got[0].Recipient != who {
		t.Fatalf("Pending = %+v, %v", got, err)
	}
	r := store.Sent{Sender: who, MessageID: id, Recipients: []string{who}, Dispositions: imdn.Display, Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotified(ctx, who, id, "display-notification "+who, "t1", t0); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Sent(ctx, who, id, t0); err != nil || got.Recipients[0] != who {
		t.Fatalf("Sent = %+v, %v", got, err)
	}
}

func marks(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.MarkNotified(ctx, alice, "m-1", "k", "t1", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkNotified without a record = %v", err)
	}
	r := store.Sent{Sender: alice, MessageID: "m-1", Recipients: []string{bob}, Dispositions: imdn.Display, Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "display "+bob, "t1", t0); err != nil {
		t.Fatal(err)
	}
	// The same attempt again succeeds; another attempt is a duplicate.
	if err := s.MarkNotified(ctx, alice, "m-1", "display "+bob, "t1", t0); err != nil {
		t.Fatalf("repeated MarkNotified = %v", err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "display "+bob, "t2", t0); !errors.Is(err, store.ErrExists) {
		t.Fatalf("a second notification = %v", err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "delivery "+bob, "t2", t0); err != nil {
		t.Fatalf("another kind = %v", err)
	}
	// Undone by another attempt: nothing happens; by its own: free again.
	if err := s.UnmarkNotified(ctx, alice, "m-1", "display "+bob, "t2"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "display "+bob, "t3", t0); !errors.Is(err, store.ErrExists) {
		t.Fatalf("after another attempt's unmark = %v", err)
	}
	if err := s.UnmarkNotified(ctx, alice, "m-1", "display "+bob, "t1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "display "+bob, "t3", t0); err != nil {
		t.Fatalf("after its own unmark = %v", err)
	}
	if err := s.UnmarkNotified(ctx, carol, "m-9", "k", "t1"); err != nil {
		t.Fatalf("UnmarkNotified without a record = %v", err)
	}
	if err := s.MarkNotified(ctx, alice, "m-1", "processing", "t4", t0.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("MarkNotified after expiry = %v", err)
	}
}

func sent(t *testing.T, s store.Store) {
	ctx := context.Background()
	r := store.Sent{Sender: alice, MessageID: "m-1", Recipients: []string{bob}, Dispositions: imdn.PositiveDelivery | imdn.Display,
		Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSent(ctx, r, t0); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second RecordSent = %v", err)
	}
	got, err := s.Sent(ctx, alice, "m-1", t0)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.Recipients) != fmt.Sprint(r.Recipients) || got.Dispositions != r.Dispositions || !got.Expires.Equal(r.Expires) || got.Author != "" {
		t.Fatalf("Sent = %+v", got)
	}
	// A group's record names the author.
	g := store.Sent{Sender: "sip:chat-1@conf.example.net", MessageID: "m-1", Author: alice, Recipients: []string{bob, carol},
		Dispositions: imdn.Display, Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, g, t0); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Sent(ctx, g.Sender, "m-1", t0); err != nil || got.Author != alice || len(got.Recipients) != 2 || got.Group != "" {
		t.Fatalf("group Sent = %+v, %v", got, err)
	}
	// The author's own record of it names the group.
	own := store.Sent{Sender: alice, MessageID: "m-own", Group: g.Sender, Recipients: []string{bob, carol},
		Dispositions: imdn.Display, Expires: t0.Add(time.Hour)}
	if err := s.RecordSent(ctx, own, t0); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Sent(ctx, alice, "m-own", t0); err != nil || got.Group != g.Sender || got.Author != "" {
		t.Fatalf("author's Sent = %+v, %v", got, err)
	}
	// The record is the sender's: another sender with the same Message-ID
	// has none.
	if _, err := s.Sent(ctx, carol, "m-1", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Sent of another sender = %v", err)
	}
	if _, err := s.Sent(ctx, alice, "m-1", t0.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Sent after expiry = %v", err)
	}
	// An expired record, which a backend may still hold, gives way to a new
	// one with the same Message-ID.
	r.Recipients, r.Expires = []string{carol}, t0.Add(3*time.Hour)
	if err := s.RecordSent(ctx, r, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("RecordSent over an expired record = %v", err)
	}
	if got, err := s.Sent(ctx, alice, "m-1", t0.Add(2*time.Hour)); err != nil || fmt.Sprint(got.Recipients) != "["+carol+"]" {
		t.Fatalf("Sent = %+v, %v", got, err)
	}
}

func idsOf(ms []store.Message) []string {
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.ID
	}
	return ids
}

func groupMessage(t *testing.T, s store.Store) {
	ctx := context.Background()
	m := message(bob, "0001", t0)
	m.Sender, m.Author, m.Mode = "sip:chat-1@conf.example.net", alice, store.Group
	if err := s.Enqueue(ctx, m, none); err != nil {
		t.Fatal(err)
	}
	got, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Sender != m.Sender || got.Author != alice || got.Mode != store.Group || store.Group.String() != "group" {
		t.Fatalf("Claim = %+v", got)
	}
}
