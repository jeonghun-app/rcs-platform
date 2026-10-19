package group

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// A subscriber that applies every partial document to the first full one
// (RFC 4575 §4.6) holds the same roster as a fresh full document.
func TestPartialRosterUpdatesAddUpToTheFullRoster(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	ctx := t.Context()
	steps := []func() error{
		func() error { return r.s.Add(ctx, g.URI, bob, []Invitee{{Identity: dave, DisplayName: "Dave"}}) },
		func() error { _, err := r.s.Join(ctx, g.URI, dave, "Dave D."); return err },
		func() error { return r.s.Remove(ctx, g.URI, alice, carol) },
		func() error { return r.s.Leave(ctx, g.URI, alice) },
		// bob, chairman now, adds back the carol alice removed.
		func() error { return r.s.Add(ctx, g.URI, bob, []Invitee{{Identity: carol}}) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	updates := r.n.all()
	var state *conference.Info
	for i, u := range updates {
		if u.Version != uint32(i+1) || u.Full != (i == 0) {
			t.Fatalf("update %d: version %d, full %v", i, u.Version, u.Full)
		}
		doc := roster(t, u.Document)
		if doc.Version != u.Version || doc.Entity != g.URI {
			t.Fatalf("update %d: document %+v", i, doc)
		}
		var err error
		if state, err = conference.Merge(state, doc); err != nil {
			t.Fatalf("merging update %d: %v", i, err)
		}
	}
	full, version, err := r.s.Roster(ctx, g.URI, bob)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := state.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if version != updates[len(updates)-1].Version || !bytes.Equal(merged, full) {
		t.Fatalf("merged roster\n%s\nfull roster v%d\n%s", merged, version, full)
	}
	// What the roster says about each participant.
	byEntity := map[string]conference.User{}
	for _, u := range state.Users.List {
		byEntity[u.Entity] = u
	}
	for who, want := range map[string]struct {
		role   string
		status conference.EndpointStatus
		method conference.DisconnectionMethod
	}{
		alice: {"participant", conference.Disconnected, conference.Departed},
		bob:   {"chairman", conference.Connected, ""},
		carol: {"participant", conference.DialingOut, ""},
		dave:  {"participant", conference.Connected, ""},
	} {
		u := byEntity[who]
		e := u.Endpoints[0]
		if !slices.Equal(u.Roles, []string{want.role}) || e.Status != want.status || e.DisconnectionMethod != want.method {
			t.Errorf("%s: %+v", who, u)
		}
	}
	if byEntity[dave].DisplayText != "Dave D." || state.Description.Subject != "Lunch" {
		t.Errorf("dave %+v, description %+v", byEntity[dave], state.Description)
	}
}

func TestAPartialRosterNamesOnlyWhoChanged(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	if err := r.s.Remove(t.Context(), g.URI, alice, carol); err != nil {
		t.Fatal(err)
	}
	u := r.n.all()
	last := roster(t, u[len(u)-1].Document)
	if last.State != conference.Partial || last.Users.State != conference.Partial || len(last.Users.List) != 1 ||
		last.Users.List[0].Entity != carol || last.Users.List[0].Endpoints[0].DisconnectionMethod != conference.Booted {
		t.Fatalf("partial %+v", last)
	}
	// Nothing to change, nothing sent.
	before := len(r.n.all())
	if _, err := r.s.Join(t.Context(), g.URI, bob, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: alice}}); err != nil {
		t.Fatal(err)
	}
	if len(r.n.all()) != before {
		t.Fatal("a change that changed nothing was sent")
	}
}

// Two rcs-as tasks changing one group at once: every change gets its own
// version, one above the last, and none is lost.
func TestTheRosterVersionCountsAcrossTasks(t *testing.T) {
	groups, clock := slowReads{groupstore.NewMemory()}, newFakeClock()
	r1 := newRigWith(t, Config{AddRate: rateOff}, engineConfig(), store.NewMemory(), groups, clock, 1)
	r2 := newRigWith(t, Config{AddRate: rateOff}, engineConfig(), store.NewMemory(), groups, clock, 2)
	g := r1.create(bob)
	const each = 20
	var wg sync.WaitGroup
	for i, r := range []*rig{r1, r2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range each {
				who := fmt.Sprintf("sip:u%d-%d@example.net", i, j)
				if err := r.s.Add(t.Context(), g.URI, bob, []Invitee{{Identity: who}}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	var versions []uint32
	for _, r := range []*rig{r1, r2} {
		for _, u := range r.n.all() {
			versions = append(versions, u.Version)
		}
	}
	slices.Sort(versions)
	// Creation (1), bob joining (2), and one version per add.
	for i, v := range versions {
		if v != uint32(i+1) {
			t.Fatalf("versions %v", versions)
		}
	}
	final, _ := r1.s.Get(t.Context(), g.URI)
	if len(versions) != 2+2*each || final.Version != uint32(len(versions)) || len(final.Participants) != 2+2*each {
		t.Fatalf("%d updates, final version %d with %d participants", len(versions), final.Version, len(final.Participants))
	}
	if r1.m.get("group.update_conflict")+r2.m.get("group.update_conflict") == 0 {
		t.Fatal("no update met another's: the test did not contend")
	}
}

// slowReads widens the window between reading a group and writing it
// back, so that two tasks' changes meet.
type slowReads struct{ groupstore.Store }

func (s slowReads) Get(ctx context.Context, uri string, now time.Time) (groupstore.Group, error) {
	g, err := s.Store.Get(ctx, uri, now)
	time.Sleep(200 * time.Microsecond)
	return g, err
}

// A chairman who adds and removes stranger after stranger must not grow
// the group's item past DynamoDB's limit: beyond MaxParticipants former
// participants, the oldest leave the roster, as deleted users, and a
// subscriber's merged roster still matches the full one.
func TestTheOldestFormerParticipantsLeaveTheRosterBeyondTheSizeLimit(t *testing.T) {
	const max = 3
	r := newRig(t, Config{MaxParticipants: max, AddRate: rateOff})
	g := r.create(bob)
	ctx := t.Context()
	for i := range 10 {
		r.clock.Advance(time.Minute)
		who := fmt.Sprintf("sip:x%d@example.net", i)
		if err := r.s.Add(ctx, g.URI, alice, []Invitee{{Identity: who}}); err != nil {
			t.Fatal(err)
		}
		r.clock.Advance(time.Minute)
		if err := r.s.Remove(ctx, g.URI, alice, who); err != nil {
			t.Fatal(err)
		}
	}
	final, err := r.s.Get(ctx, g.URI)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, p := range final.Participants {
		kept = append(kept, p.Identity)
	}
	if want := []string{alice, bob, "sip:x7@example.net", "sip:x8@example.net", "sip:x9@example.net"}; !slices.Equal(kept, want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	var state *conference.Info
	var deleted []string
	for _, u := range r.n.all() {
		doc := roster(t, u.Document)
		if doc.Users != nil {
			for _, us := range doc.Users.List {
				if us.State == conference.Deleted {
					deleted = append(deleted, us.Entity)
				}
			}
		}
		if state, err = conference.Merge(state, doc); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"sip:x0@example.net", "sip:x1@example.net", "sip:x2@example.net", "sip:x3@example.net",
		"sip:x4@example.net", "sip:x5@example.net", "sip:x6@example.net"}; !slices.Equal(deleted, want) {
		t.Fatalf("deleted %v, want %v", deleted, want)
	}
	full, _, err := r.s.Roster(ctx, g.URI, alice)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := state.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(merged, full) {
		t.Fatalf("merged roster\n%s\nfull roster\n%s", merged, full)
	}
}
