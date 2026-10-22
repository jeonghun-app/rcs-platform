package messaging

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// otherGroupURI is a second group, owned by another task than groupURI's.
const otherGroupURI = "sip:chat-2@conf.ims.example.net"

// ownerOf runs the groups for one of two engines: it owns group, and its
// wakes for the other group go to the other engine, as sipas sends them,
// counted when they tell of a registration.
type ownerOf struct {
	group      string
	other      *atomic.Pointer[Engine]
	registered *atomic.Int64
}

func (h ownerOf) Owns(_ context.Context, group string) (bool, error) { return group == h.group, nil }
func (h ownerOf) Lost(string)                                        {}

func (h ownerOf) WakeOwner(_ context.Context, group, user string, registered bool) {
	if registered {
		h.registered.Add(1)
	}
	if e := h.other.Load(); e != nil {
		e.Wake(user, group, registered)
	}
}

func (h ownerOf) Recipients(_ context.Context, _, sender string, _ GroupKind) (Audience, error) {
	if sender == bob {
		return Audience{Recipients: []string{alice}}, nil
	}
	return Audience{Recipients: []string{bob}}, nil
}

func (h ownerOf) Member(_ context.Context, _, user string) (bool, error) {
	return user == alice || user == bob, nil
}

// settled waits until no engine has work queued or a wake on its way.
func settled(t *testing.T, rs ...*rig) {
	t.Helper()
	quiet := func() bool {
		for _, r := range rs {
			r.e.mu.Lock()
			out := r.e.wakesOut
			r.e.mu.Unlock()
			if out > 0 || !r.idle() {
				return false
			}
		}
		return true
	}
	for range 3 {
		waitFor(t, "the engines settled", quiet)
		time.Sleep(5 * time.Millisecond)
	}
}

// TestARelayedRegistrationIsNotRelayedBack (code review of #576): task A
// owns one group and task B another, and bob, offline, has a copy of each.
// bob registers once, on B. B tells A, A invites bob at once; after that
// neither tells the other of a registration again, and each owner invites
// bob once per InviteTimeout, as before the registration.
func TestARelayedRegistrationIsNotRelayedBack(t *testing.T) {
	cfg := Config{InviteTimeout: time.Minute, RetryInterval: time.Minute}
	st, clock := store.NewMemory(), newFakeClock()
	ca, cb := cfg, cfg
	ca.InstanceID, cb.InstanceID = "task-a", "task-b"
	ca.Rand, cb.Rand = seeded(1), seeded(2)
	a, b := newRigWith(t, ca, st, clock), newRigWith(t, cb, st, clock)
	var ea, eb atomic.Pointer[Engine]
	ea.Store(a.e)
	eb.Store(b.e)
	var aToB, bToA atomic.Int64
	a.e.SetGroupHandler(ownerOf{group: groupURI, other: &eb, registered: &aToB})
	b.e.SetGroupHandler(ownerOf{group: otherGroupURI, other: &ea, registered: &bToA})
	for _, r := range []*rig{a, b} {
		r.d.onInvite(func(Invitation) error { return ErrOffline })
		r.d.discardInvites.Store(true)
	}
	if err := a.e.SubmitGroup(t.Context(), GroupOrigin{Group: groupURI, Sender: alice, Conversation: conv, CPIM: chat(t, "m1", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	if err := b.e.SubmitGroup(t.Context(), GroupOrigin{Group: otherGroupURI, Sender: alice, Conversation: conv, CPIM: chat(t, "m2", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	settled(t, a, b)
	b.e.UserRegistered(bob, true)
	settled(t, a, b)
	invitesA, invitesB := a.m.get("invite.failed"), b.m.get("invite.failed")
	for range 5 {
		clock.Advance(time.Minute)
		settled(t, a, b)
	}
	if got := aToB.Load() + bToA.Load(); got != 1 {
		t.Errorf("wakes that told of a registration: A to B %d, B to A %d; want the one B sent", aToB.Load(), bToA.Load())
	}
	// One invitation a minute, and one more where a retry and the
	// invitation's own timeout meet.
	for name, n := range map[string]int64{"A": a.m.get("invite.failed") - invitesA, "B": b.m.get("invite.failed") - invitesB} {
		if n > 6 {
			t.Errorf("%s invited bob %d times in 5 minutes, want one a minute", name, n)
		}
	}
}

// TestAWakeLeavesAOneToOneInvitationsFailureToCount (code review of #576):
// a wake for a group overtakes only that group's invitation: bob's client,
// which takes no session, answers a 1-to-1 invitation asked before the
// wake, and the message goes by pager at once.
func TestAWakeLeavesAOneToOneInvitationsFailureToCount(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Hour, RetryInterval: time.Hour})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m1", "hi", 0)}
	if err := r.e.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	r.e.Wake(bob, groupURI, true)
	r.e.InviteFailed(inv, ErrNoSessions)
	if d := r.d.nextPager(t); d.Recipient != bob {
		t.Fatalf("pager %+v", d)
	}
	if r.m.get("invite.no_sessions") != 1 || r.m.get("invite.failed_overtaken") != 0 {
		t.Errorf("no_sessions %d, overtaken %d", r.m.get("invite.no_sessions"), r.m.get("invite.failed_overtaken"))
	}
}

// TestAWakeOvertakesTheFailureOfAnInvitationStillBeingAsked (#568, as the
// group chat developer reproduced it): the owner's queue pass is still in
// Invite when the wake telling of bob's registration elsewhere comes, and
// the invitation's 486 is handled after it. The failure is overtaken, and
// bob is invited again at once.
func TestAWakeOvertakesTheFailureOfAnInvitationStillBeingAsked(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Hour, RetryInterval: time.Hour})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	asked, release := make(chan Invitation, 1), make(chan struct{})
	var held atomic.Bool
	r.d.onInvite(func(inv Invitation) error {
		if held.CompareAndSwap(false, true) {
			asked <- inv
			<-release
		}
		return nil
	})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	first := <-asked // the pass waits in Invite
	r.e.Wake(bob, groupURI, true)
	r.e.InviteFailed(first, ErrOffline) // the 486, come late
	close(release)
	r.d.nextInvite(t) // the first
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v", inv)
	}
	if n := r.m.get("invite.failed_overtaken"); n != 1 {
		t.Fatalf("%d overtaken failures", n)
	}
}

// TestAnInvitationAskedRightAfterAWakeStillCounts (code review of #576):
// the wake overtakes only invitations asked before it. One asked right
// after it, with nothing between, that the group cannot reach (a 404)
// still gives up the group's copies queued for bob.
func TestAnInvitationAskedRightAfterAWakeStillCounts(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Hour, RetryInterval: time.Hour})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.Wake(bob, groupURI, true)
	waitFor(t, "idle", r.idle)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	r.e.InviteFailed(inv, ErrUndeliverable)
	mem := r.store.(*store.Memory)
	waitFor(t, "bob's copy given up", func() bool { return mem.Len(bob) == 0 })
	if r.m.get("invite.failed_overtaken") != 0 || r.m.get("invite.undeliverable") != 1 {
		t.Errorf("overtaken %d, undeliverable %d", r.m.get("invite.failed_overtaken"), r.m.get("invite.undeliverable"))
	}
}
