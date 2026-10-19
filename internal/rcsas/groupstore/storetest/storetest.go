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

// Run runs every check against stores from newStore.
func Run(t *testing.T, newStore func(t *testing.T) groupstore.Store) {
	t.Run("CreatedGroupReadsBack", func(t *testing.T) { readsBack(t, newStore(t)) })
	t.Run("CreateRefusesATakenURI", func(t *testing.T) { taken(t, newStore(t)) })
	t.Run("UpdateNeedsTheStoredRevision", func(t *testing.T) { revisions(t, newStore(t)) })
	t.Run("OnlyOneOfConcurrentUpdatesWins", func(t *testing.T) { concurrent(t, newStore(t)) })
	t.Run("RepeatedUpdateSucceeds", func(t *testing.T) { repeated(t, newStore(t)) })
	t.Run("TouchOnlyMovesForwardAndKeepsTheRevision", func(t *testing.T) { touch(t, newStore(t)) })
	t.Run("ExpiredGroupIsGone", func(t *testing.T) { expiry(t, newStore(t)) })
	t.Run("ALargeGroupRoundTrips", func(t *testing.T) { large(t, newStore(t)) })
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
	if err := s.Create(ctx, g, "c1", t0); err != nil {
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
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatal(err)
	}
	// The same attempt again is a repeat; another one finds it taken.
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatalf("repeated Create = %v", err)
	}
	if err := s.Create(ctx, g, "c2", t0); !errors.Is(err, groupstore.ErrExists) {
		t.Fatalf("second Create = %v", err)
	}
	// An expired group's URI may be used again.
	if err := s.Create(ctx, g, "c3", t0.Add(time.Hour)); err != nil {
		t.Fatalf("Create over an expired group = %v", err)
	}
}

func revisions(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	got.Participants[1].State = groupstore.Joined
	got.Version++
	if err := s.Update(ctx, got, "t1"); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Get(ctx, g.URI, t0)
	if after.Rev != 2 || after.Version != 2 || after.Participants[1].State != groupstore.Joined {
		t.Fatalf("after Update = %+v", after)
	}
	// Computed from the old revision: refused.
	got.Subject = "Dinner"
	if err := s.Update(ctx, got, "t2"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("Update from a stale revision = %v", err)
	}
	missing := group()
	if err := s.Update(ctx, missing, "t3"); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Update of nothing = %v", err)
	}
}

func concurrent(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, "c1", t0); err != nil {
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
			switch err := s.Update(ctx, u, fmt.Sprint("t", i)); {
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
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, t0)
	got.Subject = "Dinner"
	for range 2 {
		if err := s.Update(ctx, got, "same"); err != nil {
			t.Fatalf("Update = %v", err)
		}
	}
	// The same revision with another token is another writer.
	if err := s.Update(ctx, got, "other"); !errors.Is(err, groupstore.ErrConflict) {
		t.Fatalf("Update by another writer = %v", err)
	}
	if after, _ := s.Get(ctx, g.URI, t0); after.Rev != 2 || after.Subject != "Dinner" {
		t.Fatalf("after = %+v", after)
	}
}

func touch(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(30 * time.Minute)
	if err := s.Touch(ctx, g.URI, later, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(ctx, g.URI, t0.Add(time.Minute), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, g.URI, later)
	if !got.Active.Equal(later) || !got.Expires.Equal(later.Add(time.Hour)) || got.Rev != 1 {
		t.Fatalf("after Touch = %+v", got)
	}
	// An Update computed before the touch still lands.
	got.Subject = "Dinner"
	if err := s.Update(ctx, got, "t1"); err != nil {
		t.Fatalf("Update after Touch = %v", err)
	}
	if err := s.Touch(ctx, "sip:nobody@conf.example.net", later, later); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Touch of nothing = %v", err)
	}
	if err := s.Touch(ctx, g.URI, t0.Add(3*time.Hour), t0.Add(4*time.Hour)); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("Touch of an expired group = %v", err)
	}
	// A touch older than the last write moves nothing, not even a later
	// expiry: a message's touch that arrives after the last participant
	// left must not bring the group back.
	g2 := group()
	g2.URI = "sip:chat-2@conf.example.net"
	if err := s.Create(ctx, g2, "c2", t0); err != nil {
		t.Fatal(err)
	}
	stale := t0.Add(time.Minute)
	ended, _ := s.Get(ctx, g2.URI, t0)
	ended.Active, ended.Expires = t0.Add(2*time.Minute), t0.Add(2*time.Minute)
	if err := s.Update(ctx, ended, "end"); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(ctx, g2.URI, stale, stale.Add(30*24*time.Hour)); err != nil {
		t.Fatalf("a stale Touch = %v", err)
	}
	if got, err := s.Get(ctx, g2.URI, t0.Add(2*time.Minute)); !errors.Is(err, groupstore.ErrNotFound) {
		t.Fatalf("a stale Touch revived the group: %+v, %v", got, err)
	}
}

func expiry(t *testing.T, s groupstore.Store) {
	ctx := context.Background()
	g := group()
	if err := s.Create(ctx, g, "c1", t0); err != nil {
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
	if err := s.Create(ctx, g, "c1", t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, g.URI, t0)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, got, g)
}
