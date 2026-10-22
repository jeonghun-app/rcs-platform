package messaging

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// Tests of #605: a recipient that one task holds, after a failed attempt,
// and another task reaches.

// twoTasks is two engines sharing one store and one clock, as two rcs-as
// tasks share the messages table. Each store may be wrapped.
func twoTasks(t *testing.T, wrap1, wrap2 func(store.Store) store.Store) (*rig, *rig) {
	t.Helper()
	st := store.NewMemory()
	clock := newFakeClock()
	s1, s2 := store.Store(st), store.Store(st)
	if wrap1 != nil {
		s1 = wrap1(st)
	}
	if wrap2 != nil {
		s2 = wrap2(st)
	}
	r1 := newRigWith(t, Config{InstanceID: "task-1"}, s1, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2)}, s2, clock)
	return r1, r2
}

// reachable has both tasks' pager deliveries reach bob only while online
// is set, and counts those that did.
func reachable(r1, r2 *rig) (online *atomic.Bool, got *atomic.Int64) {
	online, got = &atomic.Bool{}, &atomic.Int64{}
	pager := func(d Delivery) error {
		if !online.Load() {
			return ErrOffline
		}
		got.Add(1)
		return nil
	}
	r1.d.onPager(pager)
	r2.d.onPager(pager)
	return online, got
}

// QA on #602: bob is unreachable when task-1 tries him, and stays away for
// five of its retries, so that its wait has doubled to 32 min. He comes
// back by a registration that one of the tasks takes; alice's next message
// goes to task-1. Wherever the registration went, it goes out at once,
// with the clock where it is.
func TestARegistrationOnEitherTaskReleasesTheOthersHold(t *testing.T) {
	for _, regOn := range []string{"same task", "other task"} {
		t.Run(regOn, func(t *testing.T) {
			r1, r2 := twoTasks(t, nil, nil)
			online, got := reachable(r1, r2)
			if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") >= 1 })
			wait := DefaultRetryInterval
			for i := 2; i <= 6; i++ {
				waitFor(t, "the retry timer armed", func() bool { return r1.clock.armed(wait) })
				r1.clock.Advance(wait)
				waitFor(t, "task-1's next failed try", func() bool { return r1.m.get("delivery.pager_failed") >= int64(i) })
				wait *= 2
			}
			online.Store(true)
			if regOn == "same task" {
				r1.e.UserRegistered(bob, true)
			} else {
				r2.e.UserRegistered(bob, true)
			}
			waitFor(t, "m1 delivered", func() bool { return got.Load() == 1 })
			if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "m2 delivered with task-1's retry timer still "+wait.String()+" away", func() bool { return got.Load() == 2 })
			waitFor(t, "both idle", func() bool { return r1.idle() && r2.idle() })
			if got.Load() != 2 || r1.queued(t, bob) != 0 {
				t.Fatalf("%d delivered, %d queued; want 2 and none", got.Load(), r1.queued(t, bob))
			}
		})
	}
}

// claimGate holds the first Claim, once armed, until release closes.
type claimGate struct {
	store.Store
	armed    atomic.Bool
	held     atomic.Bool
	claiming chan struct{}
	release  chan struct{}
}

func (g *claimGate) Claim(ctx context.Context, recipient, id, owner string, now, until time.Time) (store.Message, error) {
	if g.armed.Load() && g.held.CompareAndSwap(false, true) {
		close(g.claiming)
		<-g.release
	}
	return g.Store.Claim(ctx, recipient, id, owner, now, until)
}

// reachedReads counts the reads of reached marks.
type reachedReads struct {
	store.Store
	n atomic.Int64
}

func (s *reachedReads) Reached(ctx context.Context, recipient string, now time.Time) (map[string]time.Time, error) {
	defer s.n.Add(1)
	return s.Store.Reached(ctx, recipient, now)
}

// Both tasks at once: task-2's registration pass has read bob's queue,
// m1 alone, and is about to claim m1, when task-1, which holds bob, takes
// m2 and looks for a mark: there is none yet, so task-1 leaves m2 queued.
// m2 sorts after where task-2 read. Once task-2 has delivered m1 and
// marked bob reached, it reads the queue again, and m2 goes, once.
func TestAMessageQueuedWhileAnotherTaskDeliversIsNotLeftBehind(t *testing.T) {
	gate := &claimGate{claiming: make(chan struct{}), release: make(chan struct{})}
	reads := &reachedReads{}
	r1, r2 := twoTasks(t,
		func(s store.Store) store.Store { reads.Store = s; return reads },
		func(s store.Store) store.Store { gate.Store = s; return gate })
	// Registered after the rigs, so it runs before their Close, which a
	// held claim would otherwise keep waiting when the test fails early.
	var released sync.Once
	release := func() { released.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	online, got := reachable(r1, r2)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	online.Store(true)
	gate.armed.Store(true)
	r2.e.UserRegistered(bob, true)
	select {
	case <-gate.claiming:
	case <-time.After(hangGuard):
		t.Fatal("task-2 never claimed m1")
	}
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's look for a mark", func() bool { return reads.n.Load() == 1 && r1.idle() })
	if got.Load() != 0 || r1.m.get("delivery.reached_elsewhere") != 0 {
		t.Fatalf("before task-2's delivery: %d delivered, metrics %v", got.Load(), r1.m)
	}
	release()
	waitFor(t, "m1 and m2 delivered with task-1's retry timer still to come", func() bool { return got.Load() == 2 })
	waitFor(t, "both idle", func() bool { return r1.idle() && r2.idle() })
	if got.Load() != 2 || r1.queued(t, bob) != 0 {
		t.Fatalf("%d delivered, %d queued; want 2 and none", got.Load(), r1.queued(t, bob))
	}
}

// The invitation's way: task-1 invited bob for alice's chat message, and
// waits for that session. bob registers on task-2, which invites him too,
// and the session he accepts opens there and carries the message. alice's
// next message reaches task-1: bob was reached elsewhere since its
// invitation, so it does not wait out RCSAS_INVITE_TIMEOUT for an answer
// that will not come, and invites him again at once.
func TestASessionOpenedOnAnotherTaskEndsTheWaitForTheInvitationHere(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	l1, l2 := r1.listen(t), r2.listen(t)
	_, a := r1.connect(t, l1, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	a.send(t, chat(t, "c1", "one", 0))
	if inv := r1.d.nextInvite(t); inv.Recipient != bob || inv.Mode != store.Chat {
		t.Fatalf("task-1 invited %+v", inv)
	}
	waitFor(t, "task-1 idle", r1.idle)
	r2.e.UserRegistered(bob, true)
	inv := r2.d.nextInvite(t)
	leg, err := r2.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	u := clientURI()
	b := r2.dial(t, l2, u, leg.Local())
	if err := leg.Answer([]msrp.URI{u}); err != nil {
		t.Fatal(err)
	}
	if m := b.next(t); !strings.Contains(string(m.Body.Bytes()), "one") {
		t.Fatalf("bob got %q on task-2's session", m.Body.Bytes())
	}
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.reached_marked") == 1 })
	a.send(t, chat(t, "c2", "two", 0))
	if inv := r1.d.nextInvite(t); inv.Recipient != bob || inv.Mode != store.Chat {
		t.Fatalf("task-1 invited %+v", inv)
	}
	if n := r1.m.get("delivery.reached_elsewhere"); n != 1 {
		t.Fatalf("task-1 found bob reached elsewhere %d times, want once", n)
	}
}

// The pager-only marker is cleared the same way: bob took no session from
// task-1, which then sends him only what fits in pager mode, and keeps a
// larger message for a session he opens himself. Once he registers on
// task-2 and is reached there, a larger message to task-1 has it invite him
// again, as a registration on task-1 would.
func TestReachedElsewhereClearsThePagerOnlyMarker(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	online, _ := reachable(r1, r2)
	large := chat(t, "big1", strings.Repeat("x", DefaultPagerLimit), 0)
	if err := r1.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: content.BodyOf(large)}); err != nil {
		t.Fatal(err)
	}
	inv := r1.d.nextInvite(t)
	r1.e.InviteFailed(inv, ErrNoSessions) // bob's client takes no sessions
	waitFor(t, "task-1 idle", func() bool { return r1.m.get("invite.no_sessions") == 1 && r1.idle() })
	r1.d.onInvite(func(Invitation) error { return nil })
	// bob registers on task-2, which reaches him with a message that fits.
	online.Store(true)
	r2.e.UserRegistered(bob, true)
	if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "small", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.reached_marked") >= 1 })
	large2 := chat(t, "big2", strings.Repeat("y", DefaultPagerLimit), 0)
	if err := r1.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: content.BodyOf(large2)}); err != nil {
		t.Fatal(err)
	}
	if inv := r1.d.nextInvite(t); inv.Recipient != bob || inv.Mode != store.Standalone {
		t.Fatalf("task-1 invited %+v", inv)
	}
}
