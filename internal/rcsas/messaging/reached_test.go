package messaging

import (
	"context"
	"errors"
	"fmt"
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
	return twoTasksWith(t, Config{}, wrap1, wrap2)
}

// twoTasksWith is twoTasks with task-1 configured as cfg.
func twoTasksWith(t *testing.T, cfg Config, wrap1, wrap2 func(store.Store) store.Store) (*rig, *rig) {
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
	cfg.InstanceID = "task-1"
	r1 := newRigWith(t, cfg, s1, clock)
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

func (s *reachedReads) Reached(ctx context.Context, recipient string, now time.Time) ([]store.Mark, error) {
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
	// The registration on a new flow there is what clears the invitation
	// asked for here.
	if n := r1.m.get("delivery.registered_elsewhere"); n != 1 {
		t.Fatalf("task-1 found bob registered on a new flow elsewhere %d times, want once", n)
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
	if n := r1.m.get("delivery.registered_elsewhere"); n != 1 {
		t.Fatalf("task-1 found bob registered on a new flow elsewhere %d times, want once", n)
	}
}

// Code review on #624, its case A: bob was just reached on task-2; alice
// chats with him through task-1, which invited him and waits for his
// answer. Her next four messages do not invite him again: task-2's mark
// counts once, and a delivery elsewhere releases a hold without clearing
// the invitation asked for, which only a registration on a new flow does.
func TestAMarkCountsOnceSoAnInvitationOutIsNotAskedAgain(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	var invites atomic.Int64
	r1.d.onInvite(func(inv Invitation) error {
		if inv.Recipient == bob && inv.Peer == alice {
			invites.Add(1)
		}
		return nil // asked for; bob's client answers later
	})
	drainInvites(t, r1.d)
	r2.d.onPager(func(Delivery) error { return nil })
	if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2 delivered to bob", func() bool { return r2.m.get("delivery.pager") == 1 && r2.idle() })
	l1 := r1.listen(t)
	_, a := r1.connect(t, l1, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	for i := range 5 {
		a.send(t, chat(t, fmt.Sprint("c", i), "hi", 0))
		waitFor(t, "task-1 idle", func() bool { return r1.m.get("message.accepted") == int64(i+1) && r1.idle() })
	}
	if n := invites.Load(); n != 1 {
		t.Errorf("task-1 asked for bob's session with alice %d times while the first INVITE was out, want 1", n)
	}
	if n := r1.m.get("delivery.reached_elsewhere"); n > 1 {
		t.Errorf("task-2's one mark counted %d times, want once at most", n)
	}
}

// Code review on #624, its case B: TestALiveChatDoesNotReReadAQueueHeldByAnotherSender
// with a second task that delivers bob one message by pager meanwhile.
// carol's 100 chat messages still wait for a session; alice's 100 live
// ones read the whole queue twice, once for task-2's mark, counted once,
// and once for task-1's own (as in the one-task test), and invite bob for
// carol's no more.
func TestALiveChatIsNotReReadForAnotherTasksDelivery(t *testing.T) {
	st := &readCounter{}
	r1, r2 := twoTasksWith(t, Config{SenderRate: Rate{PerMinute: -1}}, func(s store.Store) store.Store { st.Store = s; return st }, nil)
	var invites atomic.Int64
	r1.d.onInvite(func(inv Invitation) error {
		if inv.Peer == carol {
			invites.Add(1)
		}
		return ErrOffline
	})
	drainInvites(t, r1.d)
	r2.d.onPager(func(Delivery) error { return nil })
	l := r1.listen(t)
	for i := range 100 {
		if err := r1.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, fmt.Sprint("c", i), "from carol", 0))}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "idle", r1.idle)
	_, b := r1.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	waitFor(t, "idle", r1.idle)
	if err := r2.e.Submit(t.Context(), standalone(intermediary, bob, chat(t, "p1", "by pager", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2's delivery", func() bool { return r2.m.get("delivery.pager") == 1 && r2.idle() })
	before, invited := st.items.Load(), invites.Load()
	for i := range 100 {
		if err := r1.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, fmt.Sprint("a", i), "live", 0))}); err != nil {
			t.Fatal(err)
		}
		b.next(t)
	}
	waitFor(t, "idle", r1.idle)
	if got := st.items.Load() - before; got > 100+2*101 {
		t.Errorf("100 live messages read %d queue items", got)
	}
	if n := r1.m.get("delivery.reached_elsewhere"); n != 1 {
		t.Errorf("task-2's mark counted %d times, want once", n)
	}
	if n := invites.Load() - invited; n != 0 {
		t.Errorf("task-1 invited bob for carol's chat %d more times", n)
	}
}

// Code review on #624, its M5: task-2 marked bob at 0 s; task-1 finds him
// unreachable at 30 s; task-2 reaches him at 40 s again, on a refresh, and
// leaves the mark out, within reachedEvery of the last. The mark of 0 s
// still counts against task-1's hold of 30 s, which reachedSlack's minute
// is for. A refresh writes no mark of a registration, so the delivery mark
// alone releases the hold (QA on #624).
func TestAMarkLeftOutWithinAMinuteStillCounts(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	online, got := reachable(r1, r2)
	online.Store(true)
	if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.reached_marked") == 1 && r2.idle() })
	online.Store(false)
	r1.clock.Advance(30 * time.Second)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	r1.clock.Advance(10 * time.Second)
	online.Store(true)
	r2.e.UserRegistered(bob, false)
	waitFor(t, "m1 delivered by task-2", func() bool { return got.Load() == 2 && r2.idle() })
	if n := r2.m.get("delivery.reached_marked"); n != 1 {
		t.Fatalf("task-2 stored %d marks of a delivery, want 1 (the second within reachedEvery)", n)
	}
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2 delivered with task-1's retry timer 50 s away", func() bool { return got.Load() == 3 })
	if d, f := r1.m.get("delivery.reached_elsewhere"), r1.m.get("delivery.registered_elsewhere"); d != 1 || f != 0 {
		t.Errorf("task-1 acted on %d delivery marks and %d registration marks, want 1 and 0", d, f)
	}
}

// QA on #624: bob is unreachable when task-1 tries him, then comes back by
// a refresh that task-2 takes, which marks only the delivery. alice's next
// message to task-1 goes out with task-1's retry timer still to come: the
// clock does not move.
func TestADeliveryMarkAloneReleasesAHold(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	online, got := reachable(r1, r2)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	online.Store(true)
	r2.e.UserRegistered(bob, false)
	waitFor(t, "m1 out by task-2", func() bool { return got.Load() == 1 && r2.m.get("delivery.reached_marked") == 1 && r2.idle() })
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2 delivered with task-1's retry timer still to come", func() bool { return got.Load() == 2 })
	if d, f := r1.m.get("delivery.reached_elsewhere"), r1.m.get("delivery.registered_elsewhere"); d != 1 || f != 0 {
		t.Errorf("task-1 acted on %d delivery marks and %d registration marks, want 1 and 0", d, f)
	}
}

// Code review on #624, its M6: the mark outlives the registration it came
// with long enough. alice's next message to task-1 comes five minutes after
// bob came back on task-2, with task-1's retry timer 27 min away, and still
// goes at once.
func TestAMarkStillCountsMinutesLater(t *testing.T) {
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
	waitFor(t, "task-1 idle", r1.idle)
	online.Store(true)
	r2.e.UserRegistered(bob, true)
	waitFor(t, "m1 delivered", func() bool { return got.Load() == 1 && r2.idle() })
	r1.clock.Advance(5 * time.Minute)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2 delivered five minutes on", func() bool { return got.Load() == 2 })
}

// markExpiries keeps the expiry of each mark stored.
type markExpiries struct {
	store.Store
	mu  sync.Mutex
	got []time.Duration // from the mark's time
}

func (s *markExpiries) MarkReached(ctx context.Context, recipient string, m store.Mark, expires time.Time) error {
	s.mu.Lock()
	s.got = append(s.got, expires.Sub(m.At))
	s.mu.Unlock()
	return s.Store.MarkReached(ctx, recipient, m, expires)
}

// QA on #624: a mark lives as long as a hold it counts against may still
// look for it, until that hold's retry timer reads the queue anyway:
// MaxRetryInterval and reachedSlack after it.
func TestAMarkLivesAsLongAsAHoldMayLookForIt(t *testing.T) {
	st := &markExpiries{}
	r := newRigWith(t, Config{InstanceID: "task-1", MaxRetryInterval: 2 * time.Hour, ClockSkew: 5 * time.Second},
		markExpiriesOver(st), newFakeClock())
	r.d.onPager(func(Delivery) error { return nil })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the mark", func() bool { return r.m.get("delivery.reached_marked") == 1 })
	st.mu.Lock()
	defer st.mu.Unlock()
	want := 2*time.Hour + time.Minute + 5*time.Second
	if len(st.got) != 1 || st.got[0] != want {
		t.Fatalf("marks stored to expire %v after them, want %v", st.got, want)
	}
}

func markExpiriesOver(st *markExpiries) store.Store {
	st.Store = store.NewMemory()
	return st
}

// QA on #624, and code review's M12: a hold waiting for a session counts
// only marks from after it began, less reachedSlack. bob was reached on
// task-2 ten minutes before task-1 invited him for alice's chat; her next
// message does not take that old mark for news.
func TestAMarkFromLongBeforeTheHoldDoesNotCount(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	drainInvites(t, r1.d)
	r2.d.onPager(func(Delivery) error { return nil })
	if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.reached_marked") == 1 && r2.idle() })
	r1.clock.Advance(10 * time.Minute)
	l1 := r1.listen(t)
	_, a := r1.connect(t, l1, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	for i := range 2 {
		a.send(t, chat(t, fmt.Sprint("c", i), "hi", 0))
		waitFor(t, "task-1 idle", func() bool { return r1.m.get("message.accepted") == int64(i+1) && r1.idle() })
	}
	if n := r1.m.get("delivery.reached_elsewhere"); n != 0 {
		t.Errorf("a mark ten minutes older than the hold counted %d times", n)
	}
}

// reachedSlack takes the margin for the tasks' clocks from ClockSkew,
// RCSAS_TASK_SKEW (code review on #624): with 10 s, a mark 65 s before the
// hold still counts; with the default 2 s it would not.
func TestTheMarksSlackTakesTheTasksClockSkew(t *testing.T) {
	for _, c := range []struct {
		skew  time.Duration
		count bool
	}{{10 * time.Second, true}, {0, false}} {
		t.Run(fmt.Sprint(c.skew), func(t *testing.T) {
			r1, r2 := twoTasksWith(t, Config{ClockSkew: c.skew}, nil, nil)
			online, got := reachable(r1, r2)
			online.Store(true)
			if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "hi", 0))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.reached_marked") == 1 && r2.idle() })
			online.Store(false)
			r1.clock.Advance(65 * time.Second)
			if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
			online.Store(true)
			if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "task-1 idle", func() bool { return r1.m.get("message.accepted") == 2 && r1.idle() })
			if counted := r1.m.get("delivery.reached_elsewhere") == 1; counted != c.count {
				t.Fatalf("the mark 65 s before the hold counted: %v, want %v (delivered %d)", counted, c.count, got.Load())
			}
		})
	}
}

// Code review on #624: another task's mark does not make this task tell
// group owners of a registration it did not take (wakeOwner): only its
// own registrations move its flows.
func TestAMarkFromElsewhereIsNotToldOnAsARegistration(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	r1.d.onInvite(func(Invitation) error { return nil })
	drainInvites(t, r1.d)
	r1.e.UserRegistered(bob, true)
	r1.e.mu.Lock()
	flow := r1.e.flows[bob]
	r1.e.mu.Unlock()
	l1 := r1.listen(t)
	_, a := r1.connect(t, l1, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	a.send(t, chat(t, "c0", "hi", 0))
	waitFor(t, "task-1 idle", func() bool { return r1.m.get("message.accepted") == 1 && r1.idle() })
	r2.e.UserRegistered(bob, true) // task-2's pass finds c0 and marks the registration
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.registered_marked") == 1 && r2.idle() })
	a.send(t, chat(t, "c1", "hi", 0))
	waitFor(t, "task-1's look", func() bool { return r1.m.get("delivery.registered_elsewhere") == 1 && r1.idle() })
	r1.e.mu.Lock()
	defer r1.e.mu.Unlock()
	if got := r1.e.flows[bob]; got != flow {
		t.Errorf("task-1's own registration number for bob moved from %d to %d", flow, got)
	}
}

// pendingCalls counts the reads of a queue.
type pendingCalls struct {
	store.Store
	n atomic.Int64
}

func (s *pendingCalls) PendingHeld(ctx context.Context, r, after, owner string, now time.Time, limit int) ([]store.Message, time.Time, error) {
	s.n.Add(1)
	return s.Store.PendingHeld(ctx, r, after, owner, now, limit)
}

// Code review on #624, its M10: a large-mode session delivers its message
// apart from any pass; the mark it stores still has the queue read once
// more, as a pass's mark does.
func TestAMarkMadeApartFromAPassStillHasTheQueueRead(t *testing.T) {
	st := &pendingCalls{Store: store.NewMemory()}
	r := newRigWith(t, Config{PagerLimit: 600}, st, newFakeClock())
	l := r.listen(t)
	big := chat(t, "L1", strings.Repeat("L1", 400), 0)
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: content.BodyOf(big)}); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	before := st.n.Load()
	b, leg := r.largeMode(t, l, inv)
	b.next(t)
	waitDone(t, leg.Finished())
	waitFor(t, "the mark", func() bool { return r.m.get("delivery.reached_marked") == 1 })
	waitFor(t, "the queue read again", func() bool { return st.n.Load() > before && r.idle() })
}

// Code review on #624, its M8: a summary that goes marks its recipient
// reached. The receipt queued whole ahead of it is refused, so the summary
// is the only delivery that could mark alice.
func TestADeliveredSummaryMarksItsRecipient(t *testing.T) {
	r, _ := offlineSummary(t, smallQueue, store.NewMemory())
	var taken atomic.Int32
	l := r.listen(t)
	r.connectAnswering(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if taken.Add(1) == 1 {
			return &msrp.StatusError{Code: msrp.StatusBadRequest, Comment: "refused"} // bob's receipt, given up
		}
		return nil
	})
	waitFor(t, "the summary expanded", func() bool { return r.m.get("group.summary.expanded") == 1 && r.idle() })
	if n := r.m.get("delivery.reached_marked"); n != 1 {
		t.Fatalf("%d marks after the summary went, want 1; metrics %v", n, r.m)
	}
}

// QA on #624: task-1 already acted on task-2's delivery mark; bob is lost
// again and back within the minute by a registration on a new flow that
// task-2 takes. Its delivery mark is left out within reachedEvery, so only
// the registration mark tells task-1, and it alone releases the hold.
func TestARegistrationMarkAloneReleasesAHold(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	online, got := reachable(r1, r2)
	online.Store(true)
	if err := r2.e.Submit(t.Context(), standalone(carol, bob, chat(t, "s1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-2's delivery mark", func() bool { return r2.m.get("delivery.reached_marked") == 1 && r2.idle() })
	online.Store(false)
	r1.clock.Advance(10 * time.Second)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1 used the delivery mark", func() bool { return r1.m.get("delivery.reached_elsewhere") == 1 && r1.idle() })
	r1.clock.Advance(10 * time.Second)
	online.Store(true)
	r2.e.UserRegistered(bob, true)
	waitFor(t, "task-2's registration pass", func() bool { return r2.m.get("delivery.registered_marked") == 1 && r2.idle() })
	if n := r2.m.get("delivery.reached_marked"); n != 1 {
		t.Fatalf("task-2 stored %d delivery marks, want 1 (the second within reachedEvery)", n)
	}
	before := got.Load()
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m3", "three", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m3 delivered with task-1's retry timer still to come", func() bool { return got.Load() == before+1 })
	if d, f := r1.m.get("delivery.reached_elsewhere"), r1.m.get("delivery.registered_elsewhere"); d != 1 || f != 1 {
		t.Errorf("task-1 acted on %d delivery marks and %d registration marks, want 1 and 1", d, f)
	}
}

// Code review and QA on #624: task-1 invited bob for alice's chat (inv1);
// bob then registered on a new flow with task-2, whose mark had task-1
// invite him again (inv2). A late ErrNoSessions for inv1 is of the old
// flow and is overtaken, as after a registration here; one for inv2 marks
// bob pager-only. Otherwise his large messages would wait for a session
// he never opens (#384, across tasks).
func TestALateFailureBeforeARegistrationMarkedElsewhereIsOvertaken(t *testing.T) {
	r1, r2 := twoTasks(t, nil, nil)
	r1.d.onInvite(func(Invitation) error { return nil })
	r2.d.onInvite(func(Invitation) error { return nil })
	drainInvites(t, r2.d)
	l1 := r1.listen(t)
	_, a := r1.connect(t, l1, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	a.send(t, chat(t, "c1", "one", 0))
	inv1 := r1.d.nextInvite(t)
	waitFor(t, "task-1 idle", func() bool { return r1.m.get("message.accepted") == 1 && r1.idle() })
	r2.e.UserRegistered(bob, true)
	waitFor(t, "task-2's mark", func() bool { return r2.m.get("delivery.registered_marked") == 1 && r2.idle() })
	a.send(t, chat(t, "c2", "two", 0))
	inv2 := r1.d.nextInvite(t)
	waitFor(t, "task-1's look", func() bool { return r1.m.get("delivery.registered_elsewhere") == 1 && r1.idle() })
	r1.e.InviteFailed(inv1, ErrNoSessions)
	if r1.m.get("invite.failed_overtaken") != 1 || r1.m.get("invite.no_sessions") != 0 {
		t.Fatalf("old invitation's failure: metrics %v, want overtaken", r1.m)
	}
	r1.e.InviteFailed(inv2, ErrNoSessions)
	if r1.m.get("invite.no_sessions") != 1 {
		t.Fatalf("new invitation's failure: metrics %v, want no_sessions", r1.m)
	}
}

// QA on #624: a registration on a new flow is marked by the pass it ran,
// not by every full pass after it, each of which would count on the other
// tasks as one more registration.
func TestARegistrationIsMarkedOnce(t *testing.T) {
	r := newRig(t, Config{})
	r.d.onPager(func(Delivery) error { return ErrOffline })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first try", func() bool { return r.m.get("delivery.pager_failed") == 1 && r.idle() })
	r.e.UserRegistered(bob, true)
	waitFor(t, "the registration's pass", func() bool { return r.m.get("delivery.pager_failed") == 2 && r.idle() })
	waitFor(t, "the retry timer armed", func() bool { return r.clock.armed(DefaultRetryInterval) })
	r.clock.Advance(DefaultRetryInterval)
	waitFor(t, "the retry's pass", func() bool { return r.m.get("delivery.pager_failed") == 3 && r.idle() })
	if n := r.m.get("delivery.registered_marked"); n != 1 {
		t.Errorf("registered_marked = %d after one registration and a retry, want 1", n)
	}
}

// QA on #624: a registration whose pass found nothing queued has nothing
// for another task to release, and costs no write.
func TestARegistrationWithNothingQueuedIsNotMarked(t *testing.T) {
	st := &pendingCalls{Store: store.NewMemory()}
	r := newRigWith(t, Config{}, st, newFakeClock())
	r.e.UserRegistered(bob, true)
	waitFor(t, "the registration's pass", func() bool { return st.n.Load() > 0 && r.idle() })
	if n := r.m.get("delivery.registered_marked"); n != 0 {
		t.Errorf("registered_marked = %d with an empty queue, want 0", n)
	}
}

// failMarkOnce fails the first mark stored, as a throttled write would.
type failMarkOnce struct {
	store.Store
	n atomic.Int32
}

func (s *failMarkOnce) MarkReached(ctx context.Context, recipient string, m store.Mark, expires time.Time) error {
	if s.n.Add(1) == 1 {
		return errors.New("throttled")
	}
	return s.Store.MarkReached(ctx, recipient, m, expires)
}

// QA on #624: a mark that failed to store is tried again with the next
// delivery, not a minute later.
func TestAFailedMarkIsTriedAgain(t *testing.T) {
	st := &failMarkOnce{Store: store.NewMemory()}
	r := newRigWith(t, Config{}, st, newFakeClock())
	r.d.onPager(func(Delivery) error { return nil })
	for i, id := range []string{"s1", "s2"} {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, id, "x", 0))); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "delivered", func() bool { return r.m.get("delivery.pager") == int64(i+1) && r.idle() })
		r.clock.Advance(time.Second)
	}
	if n := r.m.get("delivery.reached_marked"); n != 1 {
		t.Errorf("reached_marked = %d after a failed mark and a second delivery, want 1", n)
	}
}
