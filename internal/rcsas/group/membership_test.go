package group

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// quiet gives the engine's workers time to do what they would: what
// follows checks that they did not.
func (r *rig) quiet() { time.Sleep(50 * time.Millisecond) }

// invitesOf counts the engine's invitations of who into g.
func (r *rig) invitesOf(g groupstore.Group, who string) int {
	_, invites := r.d.counts()
	n := 0
	for _, inv := range invites {
		if inv.Recipient == who && inv.Peer == g.URI && inv.Mode == store.Group {
			n++
		}
	}
	return n
}

// QA's reproduction (PR #118): a participant who declined (Leave, as the
// SIP layer maps 603) or was removed has a copy queued; for the store's
// lifetime the engine must never ask it back into the group.
func TestAFormerParticipantIsNeverInvitedBack(t *testing.T) {
	for name, depart := range map[string]func(r *rig, g groupstore.Group) error{
		"declined": func(r *rig, g groupstore.Group) error { return r.s.Leave(r.t.Context(), g.URI, bob) },
		"removed":  func(r *rig, g groupstore.Group) error { return r.s.Remove(r.t.Context(), g.URI, alice, bob) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, Config{})
			g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}, {Identity: carol}}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.s.Join(t.Context(), g.URI, carol, ""); err != nil {
				t.Fatal(err)
			}
			a := r.connect(g, alice, nil)
			r.connect(g, carol, nil)
			if code := a.send(t, message(t, alice, "m1", "hi", imdn.NegativeDelivery)); code != msrp.StatusOK {
				t.Fatal(code)
			}
			waitFor(t, "bob invited", func() bool { return r.invitesOf(g, bob) == 1 })
			if err := depart(r, g); err != nil {
				t.Fatal(err)
			}
			// The copy is given up at once, and alice told so.
			waitFor(t, "bob's copy given up", func() bool { return r.queues.Len(bob) == 0 })
			n, err := imdn.ParseNotificationMessage(asSeen(t, a.next(t)))
			if err != nil || n.MessageID != "m1" || n.Status != imdn.Failed {
				t.Fatalf("alice got %+v, %v", n, err)
			}
			for range 7 * 24 * 6 {
				r.clock.Advance(10 * time.Minute)
				r.e.UserRegistered(bob, true)
			}
			r.quiet()
			if got := r.invitesOf(g, bob); got != 1 {
				t.Fatalf("bob was asked back %d times", got-1)
			}
			if r.m.get("delivery.not_participant") != 1 {
				t.Fatalf("metrics %v", r.m)
			}
		})
	}
}

// Another task (or this one after a restart) does not know who left: it
// asks the group before inviting, and gives up the copy of someone who is
// no longer in it. A removed participant who accepts an invitation sent
// before its removal is refused, and its copy goes too.
func TestTheGroupIsAskedBeforeAParticipantIsInvitedBack(t *testing.T) {
	queues, groups, clock := store.NewMemory(), groupstore.NewMemory(), newFakeClock()
	a := newRigWith(t, Config{}, messaging.Config{}, queues, groups, clock, 1)
	g := a.create(carol)
	if err := a.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: bob}}); err != nil {
		t.Fatal(err)
	}
	if err := a.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: g.URI, Sender: alice, CPIM: message(t, alice, "m1", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob invited", func() bool { return a.invitesOf(g, bob) == 1 })
	// Task b removes bob. Its engine is stopped, so that what happens to
	// bob's copy is task a's doing.
	b := newRigWith(t, Config{}, messaging.Config{}, queues, groups, clock, 2)
	b.e.Close()
	if err := b.s.Remove(t.Context(), g.URI, alice, bob); err != nil {
		t.Fatal(err)
	}
	// Task a never heard of it. bob registers there again.
	clock.Advance(time.Hour)
	a.e.UserRegistered(bob, true)
	waitFor(t, "bob's copy given up", func() bool { return queues.Len(bob) == 0 })
	a.quiet()
	if got := a.invitesOf(g, bob); got != 1 {
		t.Fatalf("bob was asked back %d times", got-1)
	}
	// bob answers the invitation from before: Join refuses him, and task
	// a gives up anything queued for him since.
	if err := queues.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "late", Sender: g.URI, Author: alice, Mode: store.Group,
		CPIM: message(t, alice, "m2", "late", 0), Enqueued: clock.Now(), Expires: clock.Now().Add(time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.s.Join(t.Context(), g.URI, bob, ""); !errors.Is(err, ErrNotParticipant) {
		t.Fatalf("Join after removal = %v", err)
	}
	waitFor(t, "the late copy given up", func() bool { return queues.Len(bob) == 0 })
	a.quiet()
	if got := a.invitesOf(g, bob); got != 1 {
		t.Fatalf("bob was asked back %d times", got-1)
	}
	if a.m.get("delivery.not_participant") != 2 {
		t.Fatalf("metrics %v", a.m)
	}
}

// Someone added back after leaving gets what is written to it from then
// on, on the task that saw it leave too.
func TestAParticipantAddedBackGetsItsMessagesAgain(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	if err := r.s.Leave(t.Context(), g.URI, bob); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Add(t.Context(), g.URI, carol, []Invitee{{Identity: bob}}); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: g.URI, Sender: alice, CPIM: message(t, alice, "m1", "back?", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob invited back", func() bool { return r.invitesOf(g, bob) == 1 })
	if _, err := r.s.Join(t.Context(), g.URI, bob, ""); err != nil {
		t.Fatal(err)
	}
	if got := asSeen(t, r.connect(g, bob, nil).next(t)); string(got.Body) != "back?" {
		t.Fatalf("bob got %q", got.Body)
	}
}

func TestMemberSaysWhoIsInTheGroup(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob)
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: carol}}); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Leave(t.Context(), g.URI, bob); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string]bool{alice: true, carol: true, bob: false, dave: false} {
		if got, err := r.s.Member(t.Context(), g.URI, who); err != nil || got != want {
			t.Errorf("Member(%s) = %v, %v", who, got, err)
		}
	}
	if got, err := r.s.Member(t.Context(), "sip:chat-none@"+host, alice); err != nil || got {
		t.Fatalf("Member of no group = %v, %v", got, err)
	}
	broken := newRigWith(t, Config{}, messaging.Config{}, store.NewMemory(), failingGroups{groupstore.NewMemory()}, newFakeClock(), 1)
	if _, err := broken.s.Member(t.Context(), g.URI, alice); err == nil {
		t.Fatal("a failing store said who is in the group")
	}
}

type failingGroups struct{ groupstore.Store }

var errGroups = errors.New("groups store unavailable")

func (failingGroups) Get(context.Context, string, time.Time) (groupstore.Group, error) {
	return groupstore.Group{}, errGroups
}

// QA's reproduction (PR #118, round 2): bob joins, and opens his session,
// under a spelling of his number with separators. The group names him in
// canonical form, and so does his leg, so his copy goes on his session
// rather than to an invitation.
func TestALegInAnotherSpellingGetsItsParticipantsMessages(t *testing.T) {
	r := newRig(t, Config{})
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: []Invitee{{Identity: bob}}})
	if err != nil {
		t.Fatal(err)
	}
	const spelled = "tel:+1-555-010-0002"
	if _, err := r.s.Join(t.Context(), g.URI, spelled, ""); err != nil {
		t.Fatal(err)
	}
	b := r.connect(g, spelled, nil)
	if err := r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: g.URI, Sender: alice, CPIM: message(t, alice, "m1", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	if got := asSeen(t, b.next(t)); string(got.Body) != "hi" {
		t.Fatalf("bob got %q", got.Body)
	}
	if n := r.invitesOf(g, bob); n != 0 {
		t.Fatalf("bob was invited %d times with his session open", n)
	}
	// What he writes there is his, in canonical form.
	a := r.connect(g, alice, nil)
	if code := b.send(t, message(t, messaging.AnonymousURI, "m2", "hello", 0)); code != msrp.StatusOK {
		t.Fatalf("answered %d", code)
	}
	if from, _ := fromTo(t, asSeen(t, a.next(t))); from.URI != bob {
		t.Fatalf("alice got it from %v", from)
	}
	if _, err := r.e.OpenLeg(messaging.LegParams{Remote: []msrp.URI{{Host: "127.0.0.1", Port: 1, SessionID: "x", Transport: "tcp"}},
		User: "not a URI", Peer: g.URI, Mode: store.Group, Direction: messaging.Originating}); err == nil {
		t.Fatal("a group leg for no URI opened")
	}
}
