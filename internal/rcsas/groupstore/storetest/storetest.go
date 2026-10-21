// Package storetest checks that a groupstore.Store meets the contract the
// group package relies on. The memory backend runs it in unit tests and
// the DynamoDB backend against DynamoDB Local (make test-integration).
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// The identities of .github/allowed-test-identifiers.txt.
const (
	alice = "tel:+15550100001"
	bob   = "tel:+15550100002"
)

var seq atomic.Int64

// group returns a fresh group, so that a backend shared by subtests never
// sees a URI twice.
func group() groupstore.Group {
	return groupstore.Group{
		URI: fmt.Sprintf("sip:chat-%d-%d@conf.example.net", time.Now().UnixNano(), seq.Add(1)), Conversation: "conv-1",
		Subject: "Lunch", Creator: alice,
		Participants: []groupstore.Participant{
			{Identity: alice, DisplayName: "Alice", Role: groupstore.Chairman, State: groupstore.Joined, Since: t0},
			{Identity: bob, Role: groupstore.Member, State: groupstore.Invited, AddedBy: alice, Since: t0},
		},
		Version: 1, Created: t0, Active: t0, Expires: t0.Add(time.Hour),
	}
}

// The owners of the checks: a, which creates every group, and b.
var (
	ownerA = groupstore.Owner{Task: "task-a", SIP: "10.0.1.1:5060", Epoch: 1}
	ownerB = groupstore.Owner{Task: "task-b", SIP: "10.0.1.2:5060"}
)

// Run runs every check against stores from newStore. disown forgets a
// group's owner in s, as for a group stored before #121.
func Run(t *testing.T, newStore func(t *testing.T) groupstore.Store, disown func(t *testing.T, s groupstore.Store, uri string)) {
	t.Run("CreatedGroupReadsBack", func(t *testing.T) { readsBack(t, newStore(t)) })
	t.Run("CreateRefusesATakenURI", func(t *testing.T) { taken(t, newStore(t)) })
	t.Run("UpdateNeedsTheStoredRevision", func(t *testing.T) { revisions(t, newStore(t)) })
	t.Run("OnlyOneOfConcurrentUpdatesWins", func(t *testing.T) { concurrent(t, newStore(t)) })
	t.Run("RepeatedUpdateSucceeds", func(t *testing.T) { repeated(t, newStore(t)) })
	t.Run("TouchOnlyMovesForwardAndKeepsTheRevision", func(t *testing.T) { touch(t, newStore(t)) })
	t.Run("ExpiredGroupIsGone", func(t *testing.T) { expiry(t, newStore(t)) })
	t.Run("ALargeGroupRoundTrips", func(t *testing.T) { large(t, newStore(t)) })
	t.Run("WritesAreFencedByTheOwner", func(t *testing.T) { fenced(t, newStore(t)) })
	t.Run("TakeOverRaisesTheEpochOnce", func(t *testing.T) { takeOver(t, newStore(t)) })
	t.Run("OnlyOneOfConcurrentTakeOversWins", func(t *testing.T) { concurrentTakeOvers(t, newStore(t)) })
	t.Run("AnUnownedGroupIsTakenFromNone", func(t *testing.T) {
		s := newStore(t)
		unowned(t, s, func(uri string) { disown(t, s, uri) })
	})
	t.Run("AnExpiredGroupsURIGetsANewOwner", func(t *testing.T) { recreated(t, newStore(t)) })
	t.Run("ALateWriteOfAnExpiredGroupMissesItsSuccessor", func(t *testing.T) { recreatedBySameTask(t, newStore(t)) })
	t.Run("HeartbeatsReadBack", func(t *testing.T) { heartbeats(t, newStore(t)) })
}

func equal(t *testing.T, got, want groupstore.Group) {
	t.Helper()
	if got.URI != want.URI || got.Conversation != want.Conversation || got.Subject != want.Subject || got.Creator != want.Creator ||
		got.Version != want.Version || !got.Created.Equal(want.Created) || !got.Active.Equal(want.Active) ||
		!got.Expires.Equal(want.Expires) || len(got.Participants) != len(want.Participants) || !slices.Equal(got.Removed, want.Removed) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	for i, p := range got.Participants {
		w := want.Participants[i]
		if p.Identity != w.Identity || p.DisplayName != w.DisplayName || p.Role != w.Role || p.State != w.State ||
			p.AddedBy != w.AddedBy || !p.Since.Equal(w.Since) {
			t.Fatalf("participant %d = %+v, want %+v", i, p, w)
		}
	}
}

func readsBack(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, g.URI, t0)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, g)
	if got.Rev != 1 {
		t.Fatalf("Rev = %d", got.Rev)
	}
	if _, err := s.Get(ctx, "sip:nobody@conf.example.net", t0); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Get of nothing = %v", err)
	}
}

func taken(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	// The same attempt again is a repeat; another one finds it taken.
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatalf("repeated Create = %v", err)
	}
	if err := s.Create(ctx, g, ownerA, "c2", t0); !errors.Is(err, groupstore.ErrExists) {
		t.Fatalf("second Create = %v", err)
	}
	// An expired group's URI may be used again.
	if err := s.Create(ctx, g, ownerA, "c3", t0.Add(time.Hour)); err != nil {
		t.Fatalf("Create over an expired group = %v", err)
	}
}

func revisions(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	got.Participants[1].State = groupstore.Joined
	got.Version++
	if err := s.Update(ctx, got, ownerA, "t1"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get(ctx, g.URI, t0)
	if after.Rev != 2 || after.Version != 2 || after.Participants[1].State != groupstore.Joined {
		t.Fatalf("after Update = %+v", after)
	}
	// Computed from the old revision: refused.
	got.Subject = "Dinner"
	if err := s.Update(ctx, got, ownerA, "t2"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("Update from a stale revision = %v", err)
	}
	missing := group()
	if err := s.Update(ctx, missing, ownerA, "t3"); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Update of nothing = %v", err)
	}
}

func concurrent(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	base, _ := s.Get(ctx, g.URI, t0)
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := base.Clone()
			u.Subject = fmt.Sprint("subject ", i)
			switch err := s.Update(ctx, u, ownerA, fmt.Sprint("t", i)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, groupstore.ErrConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 7 {
		t.Fatalf("%d updates won, %d refused", wins.Load(), conflicts.Load())
	}
}

func repeated(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	got.Subject = "Dinner"
	for range 2 {
		if err := s.Update(ctx, got, ownerA, "same"); err != nil {
			t.Fatalf("Update = %v", err)
		}
	}
	// The same revision with another token is another writer.
	if err := s.Update(ctx, got, ownerA, "other"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("Update by another writer = %v", err)
	}
	if after, _ := s.Get(ctx, g.URI, t0); after.Rev != 2 || after.Subject != "Dinner" {
		t.Fatalf("after = %+v", after)
	}
}

func touch(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(30 * time.Minute)
	if err := s.Touch(ctx, g.URI, ownerA, later, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(ctx, g.URI, ownerA, t0.Add(time.Minute), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, later)
	if !got.Active.Equal(later) || !got.Expires.Equal(later.Add(time.Hour)) || got.Rev != 1 {
		t.Fatalf("after Touch = %+v", got)
	}
	// An Update computed before the touch still lands.
	got.Subject = "Dinner"
	if err := s.Update(ctx, got, ownerA, "t1"); err != nil {
		t.Fatalf("Update after Touch = %v", err)
	}
	if err := s.Touch(ctx, "sip:nobody@conf.example.net", ownerA, later, later); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Touch of nothing = %v", err)
	}
	if err := s.Touch(ctx, g.URI, ownerA, t0.Add(3*time.Hour), t0.Add(4*time.Hour)); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Touch of an expired group = %v", err)
	}
	// A touch older than the last write moves nothing, not even a later
	// expiry: a message's touch that arrives after the last participant
	// left must not bring the group back.
	g2 := group()
	g2.URI = "sip:chat-2@conf.example.net"
	if err := s.Create(ctx, g2, ownerA, "c2", t0); err != nil {
		t.Fatal(err)
	}
	stale := t0.Add(time.Minute)
	ended, _ := s.Get(ctx, g2.URI, t0)
	ended.Active, ended.Expires = t0.Add(2*time.Minute), t0.Add(2*time.Minute)
	if err := s.Update(ctx, ended, ownerA, "end"); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(ctx, g2.URI, ownerA, stale, stale.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("a stale Touch = %v", err)
	}
	if got, err := s.Get(ctx, g2.URI, t0.Add(2*time.Minute)); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("a stale Touch revived the group: %+v, %v", got, err)
	}
}

func expiry(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, g.URI, t0.Add(time.Hour)); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Get after expiry = %v", err)
	}
}

func large(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	g.Participants = nil
	for i := range 200 {
		id := "sip:" + strings.Repeat("u", 200) + fmt.Sprint(i) + "@example.net"
		g.Participants = append(g.Participants, groupstore.Participant{
			Identity: id, DisplayName: strings.Repeat("N", 64), Role: groupstore.Member, State: groupstore.Joined, AddedBy: alice, Since: t0,
		})
	}
	for i := range groupstore.MaxRemoved {
		g.Removed = append(g.Removed, fmt.Sprintf("sip:removed%d@example.net", i))
	}
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, g.URI, t0)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, g)
}

func fenced(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	if o, err := s.Owner(ctx, g.URI); err != nil || o != ownerA {
		t.Fatalf("Owner = %+v, %v", o, err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	got.Subject = "Dinner"
	stale := ownerA
	stale.Epoch = 2
	for _, o := range []groupstore.Owner{ownerB, stale, {}} {
		if err := s.Update(ctx, got, o, "u-"+o.Task); !errors.Is(err, groupstore.ErrNotOwner) {
			t.Fatalf("Update by %+v = %v", o, err)
		}
		if err := s.Touch(ctx, g.URI, o, t0.Add(time.Minute), t0.Add(2*time.Hour)); !errors.Is(err, groupstore.ErrNotOwner) {
			t.Fatalf("Touch by %+v = %v", o, err)
		}
	}
	if after, _ := s.Get(ctx, g.URI, t0); after.Rev != 1 || after.Subject != g.Subject || !after.Expires.Equal(g.Expires) {
		t.Fatalf("a refused write changed the group: %+v", after)
	}
	if err := s.Update(ctx, got, ownerA, "u1"); err != nil {
		t.Fatalf("the owner's Update = %v", err)
	}
}

func takeOver(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	b, err := s.TakeOver(ctx, g.URI, ownerA, ownerB, g.Expires, "t1")
	if err != nil || b.Task != ownerB.Task || b.SIP != ownerB.SIP || b.Epoch != 2 {
		t.Fatalf("TakeOver = %+v, %v", b, err)
	}
	// A repeat of the same attempt is the same takeover.
	if again, err := s.TakeOver(ctx, g.URI, ownerA, ownerB, g.Expires, "t1"); err != nil || again != b {
		t.Fatalf("repeated TakeOver = %+v, %v", again, err)
	}
	if o, _ := s.Owner(ctx, g.URI); o != b {
		t.Fatalf("Owner = %+v", o)
	}
	// From the old owner again: another task came first.
	if _, err := s.TakeOver(ctx, g.URI, ownerA, groupstore.Owner{Task: "task-c"}, g.Expires, "t2"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("TakeOver from a stale owner = %v", err)
	}
	// a, which lost the group, can no longer write it; b can.
	got, _ := s.Get(ctx, g.URI, t0)
	got.Subject = "Dinner"
	if err := s.Update(ctx, got, ownerA, "u1"); !errors.Is(err, groupstore.ErrNotOwner) {
		t.Fatalf("the old owner's Update = %v", err)
	}
	if err := s.Update(ctx, got, b, "u2"); err != nil {
		t.Fatalf("the new owner's Update = %v", err)
	}
	if err := s.Touch(ctx, g.URI, b, t0.Add(time.Minute), t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("the new owner's Touch = %v", err)
	}
	// a takes it back from b: the epoch only grows.
	if a, err := s.TakeOver(ctx, g.URI, b, ownerA, g.Expires, "t3"); err != nil || a.Epoch != 3 {
		t.Fatalf("TakeOver back = %+v, %v", a, err)
	}
	// a's first epoch is stale, though the task is the same.
	if _, err := s.TakeOver(ctx, g.URI, ownerA, groupstore.Owner{Task: "task-c"}, g.Expires, "t4"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("TakeOver from a stale epoch of the owning task = %v", err)
	}
}

func concurrentTakeOvers(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	var wins, conflicts atomic.Int32
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			to := groupstore.Owner{Task: fmt.Sprint("task-", i)}
			switch _, err := s.TakeOver(ctx, g.URI, ownerA, to, g.Expires, fmt.Sprint("t", i)); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, groupstore.ErrConflict):
				conflicts.Add(1)
			default:
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 7 {
		t.Fatalf("%d takeovers won, %d refused", wins.Load(), conflicts.Load())
	}
	if o, _ := s.Owner(ctx, g.URI); o.Epoch != 2 {
		t.Fatalf("Owner = %+v", o)
	}
}

func unowned(t *testing.T, s groupstore.Store, disown func(uri string)) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	disown(g.URI)
	if o, err := s.Owner(ctx, g.URI); err != nil || o != (groupstore.Owner{}) {
		t.Fatalf("Owner of an unowned group = %+v, %v", o, err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	if err := s.Update(ctx, got, groupstore.Owner{}, "u0"); !errors.Is(err, groupstore.ErrNotOwner) {
		t.Fatalf("an unfenced Update = %v", err)
	}
	b, err := s.TakeOver(ctx, g.URI, groupstore.Owner{}, ownerB, g.Expires, "t1")
	if err != nil || b.Epoch != 1 || b.Task != ownerB.Task {
		t.Fatalf("TakeOver of an unowned group = %+v, %v", b, err)
	}
	if err := s.Update(ctx, got, b, "u1"); err != nil {
		t.Fatalf("Update after taking it = %v", err)
	}
}

func recreated(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	b, err := s.TakeOver(ctx, g.URI, ownerA, ownerB, g.Expires, "t1")
	if err != nil {
		t.Fatal(err)
	}
	// Expired, its URI is made again (as from the same Contribution-ID) by
	// another task: that task owns the new group, and the old owner's
	// fence no longer holds.
	later := t0.Add(time.Hour)
	g2 := g
	g2.Created, g2.Active, g2.Expires = later, later, later.Add(time.Hour)
	c := groupstore.Owner{Task: "task-c", SIP: "10.0.1.3:5060"}
	if err := s.Create(ctx, g2, c, "c2", later); err != nil {
		t.Fatal(err)
	}
	// The epoch goes on from the old group's (a 1, b 2).
	if o, _ := s.Owner(ctx, g.URI); o.Task != c.Task || o.Epoch != 3 {
		t.Fatalf("Owner of the new group = %+v", o)
	}
	got, _ := s.Get(ctx, g.URI, later)
	if err := s.Update(ctx, got, b, "u1"); !errors.Is(err, groupstore.ErrNotOwner) {
		t.Fatalf("the old group's owner's Update = %v", err)
	}
}

// Code review on #431: the same task makes a URI again after its group
// expired. A write of the old group that comes late (an SDK retry, a
// delay), at revision 1 and under the old owner, must not land on the new
// group, also at revision 1: the epoch tells the two apart.
func recreatedBySameTask(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, ownerA, "c1", t0); err != nil {
		t.Fatal(err)
	}
	old, _ := s.Get(ctx, g.URI, t0)
	old.Subject = "the old group's"
	later := t0.Add(time.Hour)
	g2 := g
	g2.Subject, g2.Created, g2.Active, g2.Expires = "the new group's", later, later, later.Add(time.Hour)
	if err := s.Create(ctx, g2, ownerA, "c2", later); err != nil {
		t.Fatal(err)
	}
	if o, _ := s.Owner(ctx, g.URI); o.Task != ownerA.Task || o.Epoch != 2 {
		t.Fatalf("Owner of the new group = %+v", o)
	}
	if err := s.Update(ctx, old, ownerA, "late"); !errors.Is(err, groupstore.ErrNotOwner) {
		t.Fatalf("the old group's late Update = %v", err)
	}
	if got, _ := s.Get(ctx, g.URI, later); got.Subject != "the new group's" {
		t.Fatalf("the old group's write landed on the new group: %q", got.Subject)
	}
}

func heartbeats(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	id := fmt.Sprint("task-", seq.Add(1))
	if _, err := s.Task(ctx, id); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Task of none = %v", err)
	}
	beat := groupstore.Task{ID: id, SIP: "10.0.1.1:5060", AliveUntil: t0.Add(20 * time.Second)}
	if err := s.Beat(ctx, beat); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Task(ctx, id); err != nil || got.ID != id || got.SIP != beat.SIP || !got.AliveUntil.Equal(beat.AliveUntil) {
		t.Fatalf("Task = %+v, %v", got, err)
	}
	// Stopping beats once more, at its present time.
	beat.AliveUntil = t0.Add(5 * time.Second)
	if err := s.Beat(ctx, beat); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Task(ctx, id); !got.AliveUntil.Equal(beat.AliveUntil) {
		t.Fatalf("Task after the last beat = %+v", got)
	}
}
