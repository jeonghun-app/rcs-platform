// Package storetest checks that a store.Store meets the contract the
// messaging engine relies on. The memory backend runs it in unit tests and
// the DynamoDB backend against DynamoDB Local (make test-integration).
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

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
	t.Run("OnlyOneOfConcurrentClaimsWins", func(t *testing.T) { concurrentClaims(t, newStore(t)) })
	t.Run("ALapsedLeaseCanBeClaimedAgain", func(t *testing.T) { lapsedLease(t, newStore(t)) })
	t.Run("OnlyTheOwnerReleasesOrRemoves", func(t *testing.T) { ownership(t, newStore(t)) })
	t.Run("ExpiredListsFreeExpiredMessagesOfEveryRecipient", func(t *testing.T) { expired(t, newStore(t)) })
	t.Run("SentRecordsAreKeptUntilTheyExpire", func(t *testing.T) { sent(t, newStore(t)) })
}

func pendingOrder(t *testing.T, s store.Store) {
	ctx := context.Background()
	for i, id := range []string{"0003", "0001", "0002"} {
		if err := s.Enqueue(ctx, message(bob, id, t0.Add(time.Duration(i)*time.Second))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Enqueue(ctx, message(carol, "0000", t0)); err != nil {
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
	if err := s.Enqueue(ctx, message(bob, "0001", t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Enqueue(ctx, message(bob, "0001", t0)); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second Enqueue = %v, want ErrExists", err)
	}
	// The same id in another queue is another message.
	if err := s.Enqueue(ctx, message(carol, "0001", t0)); err != nil {
		t.Fatal(err)
	}
}

func concurrentClaims(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0)); err != nil {
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
	if err := s.Enqueue(ctx, message(bob, "0001", t0)); err != nil {
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
	if err := s.Remove(ctx, bob, "0001", "task-a"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Remove by the former owner = %v", err)
	}
}

func ownership(t *testing.T, s store.Store) {
	ctx := context.Background()
	if err := s.Enqueue(ctx, message(bob, "0001", t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ctx, bob, "0001", "task-a"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Release of an unclaimed message = %v", err)
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for name, op := range map[string]func(owner string) error{
		"Release": func(o string) error { return s.Release(ctx, bob, "0001", o) },
		"Remove":  func(o string) error { return s.Remove(ctx, bob, "0001", o) },
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
	if _, err := s.Claim(ctx, bob, "0001", "task-b", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(ctx, bob, "0001", "task-b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pending(ctx, bob, "", t0, 10); len(got) != 0 {
		t.Fatal("a removed message is still pending")
	}
	if err := s.Remove(ctx, bob, "0001", "task-b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second Remove = %v", err)
	}
}

func expired(t *testing.T, s store.Store) {
	ctx := context.Background()
	old := message(bob, "0001", t0.Add(-2*time.Hour))
	other := message(carol, "0002", t0.Add(-90*time.Minute))
	fresh := message(bob, "0003", t0)
	for _, m := range []store.Message{old, other, fresh} {
		if err := s.Enqueue(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Expired(ctx, t0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("Expired = %v", idsOf(got))
	}
	if _, err := s.Claim(ctx, bob, "0001", "task-a", t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Expired(ctx, t0, 10); len(got) != 1 || got[0].ID != "0002" {
		t.Fatalf("Expired with one claimed = %v", idsOf(got))
	}
	if got, _ := s.Expired(ctx, t0, 0); len(got) != 0 {
		t.Fatalf("limit 0 returned %d", len(got))
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
	if fmt.Sprint(got.Recipients) != fmt.Sprint(r.Recipients) || got.Dispositions != r.Dispositions || !got.Expires.Equal(r.Expires) {
		t.Fatalf("Sent = %+v", got)
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
