package messaging

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// heldAttempt is a pager stub whose first call is held until release, and
// then fails as an attempt sent while the recipient was away does. Later
// calls deliver. The first call is taken with a CAS, not a sync.Once: a
// second caller must not wait on the first.
type heldAttempt struct {
	taken     atomic.Bool
	in        chan struct{}
	release   func()
	released  chan struct{}
	delivered atomic.Int64
}

func newHeldAttempt(t *testing.T) *heldAttempt {
	h := &heldAttempt{in: make(chan struct{}), released: make(chan struct{})}
	h.release = sync.OnceFunc(func() { close(h.released) })
	// Released on every way out, before the engines close (cleanups run
	// last first), so that a failed check does not leave Close waiting on
	// the held attempt.
	t.Cleanup(h.release)
	return h
}

func (h *heldAttempt) pager(Delivery) error {
	if h.taken.CompareAndSwap(false, true) {
		close(h.in)
		<-h.released
		return ErrOffline
	}
	h.delivered.Add(1)
	return nil
}

// stepUntil moves the fake clock a second at a time, up to limit, until
// cond holds, letting the engines settle after each step; it reports how
// far the clock moved.
func stepUntil(t *testing.T, clock *fakeClock, limit time.Duration, idle func() bool, cond func() bool) (time.Duration, bool) {
	t.Helper()
	moved := time.Duration(0)
	for !cond() && moved < limit {
		clock.Advance(time.Second)
		moved += time.Second
		waitFor(t, "idle", idle)
	}
	return moved, cond()
}

// #632: bob registers on task-2 while task-1's attempt at m1 is under way,
// sent on the flow bob has just left. task-2's pass finds m1 claimed and
// so not pending, and delivers nothing; task-1's attempt then fails and
// holds the queue for its retry timer, an hour here. task-2 knows bob is
// back, so it reads the queue again once m1 is free, in seconds.
func TestARegistrationElsewhereDuringAnAttemptDeliversOnceTheAttemptFails(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	r1 := newRigWith(t, Config{InstanceID: "task-1", RetryInterval: time.Hour}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2), RetryInterval: time.Hour}, st, clock)
	h := newHeldAttempt(t)
	r1.d.onPager(h.pager)
	r2.d.onPager(h.pager)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitDone(t, h.in)
	r2.e.UserRegistered(bob, true)
	waitFor(t, "task-2's registration pass", r2.idle)
	h.release()
	waitFor(t, "task-1's failed attempt", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	idle := func() bool { return r1.idle() && r2.idle() }
	moved, ok := stepUntil(t, clock, 10*time.Minute, idle, func() bool { return h.delivered.Load() == 1 })
	if !ok {
		t.Fatalf("m1 not delivered %v after the attempt failed, with bob registered on task-2 (task-1's retry timer: 1 h)", moved)
	}
	if moved > 5*time.Second || r2.m.get("delivery.pager") != 1 {
		t.Errorf("m1 delivered %v after task-1's attempt failed, by task-2: %v", moved, r2.m.get("delivery.pager") == 1)
	}
	if n := r1.queued(t, bob); n != 0 {
		t.Errorf("%d messages still queued", n)
	}
}

// claimHold holds the first Claim made through it, once armed, until
// released, before it reaches the store.
type claimHold struct {
	store.Store
	armed   atomic.Bool
	in      chan struct{}
	release func()
	gate    chan struct{}
}

func (s *claimHold) Claim(ctx context.Context, recipient, id, owner string, now, until time.Time) (store.Message, error) {
	if s.armed.CompareAndSwap(true, false) {
		close(s.in)
		<-s.gate
	}
	return s.Store.Claim(ctx, recipient, id, owner, now, until)
}

// The race the compose stack of #602 met (QA on #624): task-2's
// registration pass reads m1 while it is free, and task-1 claims it for a
// retry before task-2 does. task-2's claim fails, and task-1's attempt
// then fails too.
func TestARegistrationPassThatLosesTheClaimDeliversOnceTheAttemptFails(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	gate := &claimHold{Store: st, in: make(chan struct{}), gate: make(chan struct{})}
	gate.release = sync.OnceFunc(func() { close(gate.gate) })
	r1 := newRigWith(t, Config{InstanceID: "task-1", RetryInterval: time.Minute, MaxRetryInterval: time.Hour}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2), RetryInterval: time.Hour}, gate, clock)
	t.Cleanup(gate.release)
	h := newHeldAttempt(t)
	var away atomic.Bool
	away.Store(true)
	r1.d.onPager(func(d Delivery) error {
		if away.CompareAndSwap(true, false) {
			return ErrOffline
		}
		return h.pager(d)
	})
	r2.d.onPager(h.pager)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1's failed try", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	gate.armed.Store(true)
	r2.e.UserRegistered(bob, true)
	waitDone(t, gate.in) // task-2 has read m1 and is about to claim it
	waitFor(t, "task-1's retry timer", func() bool { return clock.armed(time.Minute) })
	clock.Advance(time.Minute)
	waitDone(t, h.in) // task-1's retry has claimed m1
	gate.release()
	waitFor(t, "task-2's lost claim", func() bool { return r2.m.get("delivery.claimed_elsewhere") == 1 && r2.idle() })
	h.release()
	waitFor(t, "task-1's failed retry", func() bool { return r1.m.get("delivery.pager_failed") == 2 && r1.idle() })
	idle := func() bool { return r1.idle() && r2.idle() }
	moved, ok := stepUntil(t, clock, 10*time.Minute, idle, func() bool { return h.delivered.Load() == 1 })
	if !ok || moved > 5*time.Second {
		t.Fatalf("m1 delivered %v (%v after task-1's retry failed; its next retry is 2 min away)", ok, moved)
	}
}

// A message another task keeps holding has the queue read a few times, with
// backoff, and then no more: by then any attempt begun before the
// registration is over, and one begun after it went to the new flow.
func TestAMessageHeldElsewhereIsLookedForAFewTimesOnly(t *testing.T) {
	st := store.NewMemory()
	r := newRigWith(t, Config{InstanceID: "task-2"}, st, newFakeClock())
	// m1 is held by a task that never lets it go, as long as the test runs.
	if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "0001", Sender: alice, Mode: store.Standalone,
		CPIM: standalone(alice, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.e.UserRegistered(bob, true)
	waitFor(t, "idle", r.idle)
	stepUntil(t, r.clock, 15*time.Minute, r.idle, func() bool { return false })
	// 1, 2, 4 … 128 s: the last wait is past the 90 s lease.
	if got := r.m.get("delivery.held_elsewhere"); got != 8 {
		t.Errorf("the queue was read again %d times for the held message, want 8", got)
	}
	// Code review on #646: once the looks have run out, no look keeps
	// bob's state; a look that fired and stayed recorded would keep it
	// for the task's life. The read for the end of task-9's claim keeps
	// it until then (#651), and then nothing does.
	r.e.mu.Lock()
	x := r.e.recipients[bob]
	r.e.mu.Unlock()
	if x == nil || x.lookTimer != nil || x.leaseTimer == nil {
		t.Fatalf("after the looks ran out, bob's state: kept %v, look waiting %v, read for the lease's end waiting %v",
			x != nil, x != nil && x.lookTimer != nil, x != nil && x.leaseTimer != nil)
	}
	r.clock.Advance(12 * time.Hour)
	waitFor(t, "m1 once task-9's claim was over", func() bool { return r.m.get("delivery.pager") == 1 && r.idle() })
	r.e.mu.Lock()
	x = r.e.recipients[bob]
	r.e.mu.Unlock()
	if x != nil {
		t.Errorf("bob's state kept once m1 went (look waiting: %v, read waiting: %v)", x.lookTimer != nil, x.leaseTimer != nil)
	}
}

// Only a registration has the queue looked at for held messages: a new
// message says nothing about whether the recipient is back.
func TestANewMessageDoesNotLookForMessagesHeldElsewhere(t *testing.T) {
	st := store.NewMemory()
	r := newRigWith(t, Config{InstanceID: "task-2"}, st, newFakeClock())
	r.d.onPager(func(Delivery) error { return nil })
	if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "0001", Sender: alice, Mode: store.Standalone,
		CPIM: standalone(alice, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2", func() bool { return r.m.get("delivery.pager") == 1 && r.idle() })
	if got := r.m.get("delivery.held_elsewhere"); got != 0 {
		t.Errorf("a new message had the queue read again %d times for a message held elsewhere", got)
	}
}

// The same-task half of #632, which main already handles: a registration
// on the task whose attempt is under way has the queue read again as soon
// as the attempt fails, and a message that comes in next goes at once.
// (The probe in the issue failed here because its stub failed that second
// read too.)
func TestARegistrationHereDuringAnAttemptDeliversOnceTheAttemptFails(t *testing.T) {
	r := newRig(t, Config{InstanceID: "task-1", RetryInterval: time.Hour})
	h := newHeldAttempt(t)
	r.d.onPager(h.pager)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitDone(t, h.in)
	r.e.UserRegistered(bob, true)
	h.release()
	waitFor(t, "m1 on the registration's read", func() bool { return h.delivered.Load() == 1 && r.idle() })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2", func() bool { return h.delivered.Load() == 2 && r.idle() })
	if got := r.m.get("delivery.pager_failed"); got != 1 {
		t.Errorf("%d failed attempts, want the one held", got)
	}
}

// A registration's pass that starts over, because a chat leg opened while
// it ran and older messages wait for it, still looks on its second go.
func TestALookSurvivesAPassThatStartsOverForALeg(t *testing.T) {
	st := store.NewMemory()
	r := newRigWith(t, Config{InstanceID: "task-2", SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour}, st, newFakeClock())
	l := r.listen(t)
	drainInvites(t, r.d)
	r.d.onPager(func(Delivery) error { return ErrOffline })
	chatFrom := func(id string) Origin {
		return Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, id, id, 0))}
	}
	// a1 waits for a session, carol's x finds bob away, a2 waits behind.
	for _, o := range []Origin{chatFrom("a1"), standalone(carol, bob, chat(t, "x", "x", 0)), chatFrom("a2")} {
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "idle", r.idle)
	}
	if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "0001", Sender: carol, Mode: store.Standalone,
		CPIM: standalone(carol, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entered, proceed := make(chan struct{}), make(chan struct{})
	r.d.onPager(func(Delivery) error { close(entered); <-proceed; return nil })
	t.Cleanup(sync.OnceFunc(func() { close(proceed) }))
	r.e.UserRegistered(bob, true)
	waitDone(t, entered) // the pass is at x, past a1
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	proceed <- struct{}{}
	for _, want := range []string{"a1", "a2"} {
		if got := b.next(t); !bytes.HasSuffix(got.Body.Bytes(), []byte(want)) {
			t.Fatalf("got %q, want %s", got.Body.Bytes(), want)
		}
	}
	waitFor(t, "idle", r.idle)
	if got := r.m.get("delivery.held_elsewhere"); got != 1 {
		t.Errorf("the queue was set to be read again %d times for the held message, want 1", got)
	}
}

// A message this task's own attempt holds is not looked for: that attempt
// knows how it ends, and puts the message back itself (retryReleased).
func TestAMessageThisTaskHoldsIsNotLookedFor(t *testing.T) {
	r := newRigWith(t, Config{InstanceID: "task-2", PagerLimit: 600}, store.NewMemory(), newFakeClock())
	l := r.listen(t)
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: content.BodyOf(chat(t, "L1", strings.Repeat("L", 800), 0))}); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation,
		Mode: store.Standalone, Direction: Terminating, QueueID: inv.QueueID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	in, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	var taken atomic.Bool
	u := clientURI()
	r.dialAnswering(t, l, u, leg.Local(), func(*msrp.Message) error {
		if taken.CompareAndSwap(false, true) {
			close(in)
			<-gate
		}
		return nil
	})
	if err := leg.Answer([]msrp.URI{u}); err != nil {
		t.Fatal(err)
	}
	waitDone(t, in) // the leg's attempt holds L1
	r.e.UserRegistered(bob, true)
	waitFor(t, "the registration's pass", r.idle)
	release()
	waitDone(t, leg.Finished())
	waitFor(t, "idle", r.idle)
	if got := r.m.get("delivery.held_elsewhere"); got != 0 {
		t.Errorf("the queue was set to be read again %d times for this task's own attempt", got)
	}
}

// A registration starts the backoff over, also when it comes while a look
// the backoff asked for is still to be made.
func TestARegistrationStartsTheLooksOver(t *testing.T) {
	st := store.NewMemory()
	r := newRigWith(t, Config{InstanceID: "task-2"}, st, newFakeClock())
	if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "0001", Sender: alice, Mode: store.Standalone,
		CPIM: standalone(alice, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}
	r.e.UserRegistered(bob, true)
	for _, wait := range []time.Duration{time.Second, 2 * time.Second} {
		waitFor(t, "the next look", func() bool { return r.idle() && r.clock.armed(wait) })
		r.clock.Advance(wait)
	}
	waitFor(t, "the look after 4 s", func() bool { return r.idle() && r.clock.armed(4*time.Second) })
	// carol's x holds the worker while that look comes due, and bob
	// registers again before the pass it asked for has begun.
	entered, proceed := make(chan struct{}), make(chan struct{})
	r.d.onPager(func(Delivery) error { close(entered); <-proceed; return nil })
	t.Cleanup(sync.OnceFunc(func() { close(proceed) }))
	if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, "x", "x", 0))); err != nil {
		t.Fatal(err)
	}
	waitDone(t, entered)
	r.clock.Advance(4 * time.Second)
	r.e.UserRegistered(bob, true)
	proceed <- struct{}{}
	waitFor(t, "a look 1 s on, not 8 s", func() bool { return r.idle() && r.clock.armed(time.Second) })
	if r.clock.armed(8 * time.Second) {
		t.Error("the look after the registration kept the backoff of the one before")
	}
}

// The claim race on a chat leg: task-2's registration pass reads c1 and,
// with a leg of its own to bob, is about to claim it when task-1's leg
// takes it first. task-1's attempt then fails, and task-2 sends c1 on its
// leg once it is free.
func TestARegistrationPassThatLosesALegsClaimDeliversOnceTheAttemptFails(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	gate := &claimHold{Store: st, in: make(chan struct{}), gate: make(chan struct{})}
	gate.release = sync.OnceFunc(func() { close(gate.gate) })
	r1 := newRigWith(t, Config{InstanceID: "task-1", RetryInterval: time.Hour}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2), RetryInterval: time.Hour}, gate, clock)
	t.Cleanup(gate.release)
	drainInvites(t, r1.d)
	drainInvites(t, r2.d)
	l1, l2 := r1.listen(t), r2.listen(t)
	_, b2 := r2.connect(t, l2, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	waitFor(t, "task-2 idle", r2.idle)
	// c1 then waits on task-1 for a session to bob; task-2 is not told.
	if err := r1.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-1 idle", r1.idle)
	gate.armed.Store(true)
	r2.e.UserRegistered(bob, true)
	waitDone(t, gate.in) // task-2 has read c1 and is about to claim it
	in, failNow := make(chan struct{}), make(chan struct{})
	var taken atomic.Bool
	r1.connectAnswering(t, l1, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat}, func(*msrp.Message) error {
		if taken.CompareAndSwap(false, true) {
			close(in)
			<-failNow
			return &msrp.StatusError{Code: msrp.StatusRequestTimeout, Comment: "gone"}
		}
		return nil
	})
	t.Cleanup(sync.OnceFunc(func() { close(failNow) }))
	waitDone(t, in) // task-1's leg holds c1
	gate.release()
	waitFor(t, "task-2's lost claim", func() bool { return r2.m.get("delivery.claimed_elsewhere") == 1 && r2.idle() })
	failNow <- struct{}{}
	waitFor(t, "task-1's failed attempt", func() bool { return r1.m.get("delivery.msrp_failed") == 1 && r1.idle() })
	moved, ok := stepUntil(t, clock, 10*time.Minute, func() bool { return r1.idle() && r2.idle() }, func() bool { return len(b2.got) > 0 })
	if !ok || moved > 5*time.Second {
		t.Fatalf("c1 on task-2's leg: %v, %v after task-1's attempt failed (its retry timer: 1 h)", ok, moved)
	}
	if m := b2.next(t); !bytes.HasSuffix(m.Body.Bytes(), []byte("c1")) {
		t.Fatalf("task-2's leg got %q", m.Body.Bytes())
	}
}

// heldReadCounter counts the engine's reads of a queue.
type heldReadCounter struct {
	store.Store
	n atomic.Int64
}

func (s *heldReadCounter) PendingHeld(ctx context.Context, r, after, owner string, now time.Time, limit int) ([]store.Message, time.Time, error) {
	s.n.Add(1)
	return s.Store.PendingHeld(ctx, r, after, owner, now, limit)
}

// Code review on #646: a client that registers again and again while
// another task keeps holding a message has one series of looks, which
// each registration starts over, not a series per registration. With
// registrations 1.7 s apart, each costs its own pass and the 1 s look
// after it; the last one's series runs out as usual.
func TestRegistrationsThatComeOftenShareOneSeriesOfLooks(t *testing.T) {
	for _, regs := range []int{1, 18} {
		st := &heldReadCounter{Store: store.NewMemory()}
		r := newRigWith(t, Config{InstanceID: "task-2"}, st, newFakeClock())
		if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "0001", Sender: alice, Mode: store.Standalone,
			CPIM: standalone(alice, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}, store.Limit{}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(12*time.Hour)); err != nil {
			t.Fatal(err)
		}
		const step = 100 * time.Millisecond
		next, done := time.Duration(0), 0
		for moved := time.Duration(0); moved < 15*time.Minute; moved += step {
			if done < regs && moved >= next {
				r.e.UserRegistered(bob, true)
				done++
				next += 1700 * time.Millisecond
			}
			waitFor(t, "idle", r.idle)
			r.clock.Advance(step)
		}
		waitFor(t, "idle", r.idle)
		// One registration: its pass and 8 looks. Each earlier one: its
		// pass and one look.
		if got, want := st.n.Load(), int64(2*(regs-1)+9); got > want {
			t.Errorf("%d registrations read the queue %d times, want at most %d", regs, got, want)
		}
	}
}

// Code review on #646: a refresh on a task whose queue for bob waits for a
// session read no queue, and so neither looked for m1, which task-1's
// attempt held, nor delivered it once that attempt had failed. A client
// that moves to a new flow before its registration runs out comes in as a
// refresh (sipas).
func TestARefreshOfAWaitingQueueDeliversAMessageHeldElsewhere(t *testing.T) {
	for _, newFlow := range []bool{true, false} {
		for _, failedFirst := range []bool{false, true} {
			name := map[bool]string{true: "new flow", false: "refresh"}[newFlow] + map[bool]string{true: ", attempt failed first", false: ""}[failedFirst]
			t.Run(name, func(t *testing.T) {
				st := store.NewMemory()
				clock := newFakeClock()
				r1 := newRigWith(t, Config{InstanceID: "task-1", RetryInterval: time.Hour}, st, clock)
				r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2), RetryInterval: time.Hour}, st, clock)
				drainInvites(t, r1.d)
				drainInvites(t, r2.d)
				h := newHeldAttempt(t)
				r1.d.onPager(h.pager)
				r2.d.onPager(h.pager)
				// carol's c1 waits on task-2 for a session.
				if err := r2.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "task-2 idle", r2.idle)
				if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
					t.Fatal(err)
				}
				waitDone(t, h.in)
				if failedFirst {
					h.release()
					waitFor(t, "task-1's failed attempt", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
				}
				r2.e.UserRegistered(bob, newFlow)
				waitFor(t, "task-2's registration pass", r2.idle)
				h.release()
				waitFor(t, "task-1's failed attempt", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
				idle := func() bool { return r1.idle() && r2.idle() }
				moved, ok := stepUntil(t, clock, 10*time.Minute, idle, func() bool { return h.delivered.Load() == 1 })
				if !ok || moved > 5*time.Second {
					t.Fatalf("m1 delivered %v, %v after task-1's attempt failed (its retry timer: 1 h)", ok, moved)
				}
			})
		}
	}
}

// Code review on #646: a registration ends the series of looks it finds
// waiting. Once nothing is held any more, its pass starts none, and the
// earlier series reads the queue no more. The same for a refresh of a
// queue that waits for a session.
func TestARegistrationEndsTheLooksBeforeIt(t *testing.T) {
	for _, waiting := range []bool{false, true} {
		t.Run(map[bool]string{false: "new flow", true: "refresh of a waiting queue"}[waiting], func(t *testing.T) {
			st := &heldReadCounter{Store: store.NewMemory()}
			r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour, InviteTimeout: time.Hour}, st, newFakeClock())
			drainInvites(t, r.d)
			if waiting {
				if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "idle", r.idle)
			}
			m := store.Message{Recipient: bob, ID: "0001", Sender: alice, Mode: store.Standalone,
				CPIM: standalone(alice, bob, chat(t, "m1", "one", 0)).CPIM, Enqueued: r.clock.Now(), Expires: r.clock.Now().Add(24 * time.Hour)}
			if err := st.Enqueue(t.Context(), m, store.Limit{}); err != nil {
				t.Fatal(err)
			}
			c, err := st.Claim(t.Context(), bob, "0001", "task-9", r.clock.Now(), r.clock.Now().Add(12*time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			r.e.UserRegistered(bob, !waiting)
			waitFor(t, "the first look", func() bool { return r.idle() && r.clock.armed(time.Second) })
			// task-9 delivers m1; bob registers again before the look is due.
			if err := st.Remove(t.Context(), c, "task-9"); err != nil {
				t.Fatal(err)
			}
			r.e.UserRegistered(bob, !waiting)
			waitFor(t, "idle", r.idle)
			before := st.n.Load()
			stepUntil(t, r.clock, 5*time.Minute, r.idle, func() bool { return false })
			if got := st.n.Load() - before; got != 0 {
				t.Errorf("the series the first registration began read the queue %d more times", got)
			}
		})
	}
}

// The read a refresh has a waiting queue make leaves its retry timer
// alone: the refresh says nothing about the session the messages wait for,
// so the backoff goes on.
func TestARefreshOfAWaitingQueueKeepsItsBackoff(t *testing.T) {
	r := newRig(t, Config{InstanceID: "task-2", RetryInterval: time.Minute, InviteTimeout: time.Hour})
	drainInvites(t, r.d)
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first retry armed", func() bool { return r.idle() && r.clock.armed(time.Minute) })
	r.clock.Advance(time.Minute)
	waitFor(t, "the second retry armed", func() bool { return r.idle() && r.clock.armed(2*time.Minute) })
	asked := r.m.get("invite.sent")
	r.e.UserRegistered(bob, false)
	waitFor(t, "idle", r.idle)
	if got := r.m.get("invite.sent") - asked; got != 0 {
		t.Errorf("the refresh asked %d invitations, within RCSAS_INVITE_TIMEOUT of the last", got)
	}
	if !r.clock.armed(2*time.Minute) || r.clock.armed(time.Minute) {
		t.Errorf("after the refresh: 2 min retry armed %v, 1 min retry armed %v", r.clock.armed(2*time.Minute), r.clock.armed(time.Minute))
	}
}

// Code review on #646, as docs/rcs-as.md says: the read a refresh has a
// waiting queue make asks again an invitation older than
// RCSAS_INVITE_TIMEOUT, however far the retry timer has backed off.
func TestARefreshOfAWaitingQueueAsksAnInvitationPastItsTimeout(t *testing.T) {
	r := newRig(t, Config{InstanceID: "task-2", RetryInterval: time.Hour, InviteTimeout: 2 * time.Minute})
	drainInvites(t, r.d)
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first invitation", func() bool { return r.idle() && r.m.get("invite.sent") == 1 })
	r.clock.Advance(time.Minute)
	r.e.UserRegistered(bob, false)
	waitFor(t, "idle", r.idle)
	r.clock.Advance(2 * time.Minute)
	r.e.UserRegistered(bob, false)
	waitFor(t, "idle", r.idle)
	if got := r.m.get("invite.sent"); got != 2 {
		t.Errorf("%d invitations after refreshes 1 and 3 min after the first, want 2", got)
	}
	if !r.clock.armed(time.Hour) {
		t.Error("the refreshes stopped the retry timer")
	}
}

// QA on #646: a client that moves to a new flow before its registration
// runs out reaches rcs-as as a refresh (sipas register.go), most often on
// a task that has no state for it. So a refresh on task-2 during task-1's
// attempt has the queue read again too.
func TestARefreshElsewhereDuringAnAttemptDeliversOnceTheAttemptFails(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	r1 := newRigWith(t, Config{InstanceID: "task-1", RetryInterval: time.Hour}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2), RetryInterval: time.Hour}, st, clock)
	h := newHeldAttempt(t)
	r1.d.onPager(h.pager)
	r2.d.onPager(h.pager)
	if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	waitDone(t, h.in)
	r2.e.UserRegistered(bob, false)
	waitFor(t, "task-2's refresh pass", r2.idle)
	h.release()
	waitFor(t, "task-1's failed attempt", func() bool { return r1.m.get("delivery.pager_failed") == 1 && r1.idle() })
	idle := func() bool { return r1.idle() && r2.idle() }
	moved, ok := stepUntil(t, clock, 10*time.Minute, idle, func() bool { return h.delivered.Load() == 1 })
	if !ok || moved > 5*time.Second {
		t.Fatalf("m1 delivered %v, %v after task-1's attempt failed, with bob refreshed on task-2 (task-1's retry timer: 1 h)", ok, moved)
	}
}

// QA on #646, what failed #602's compose run ("message never arrived"):
// task-y keeps a stale wait for bob, from a pass whose chat message then
// went another way. task-x queues m1, and its invitation finds bob away.
// bob's REGISTER lands on task-y as a refresh, as task-y never had his
// de-registration. That refresh used to return at the stale wait, and m1
// waited for the next event; now its read invites bob for m1 at once.
func TestARefreshOnATaskWithAStaleWaitInvitesForAMessageQueuedElsewhere(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	x := newRigWith(t, Config{InstanceID: "task-x"}, st, clock)
	y := newRigWith(t, Config{InstanceID: "task-y", Rand: seeded(2)}, st, clock)
	drainInvites(t, x.d)
	drainInvites(t, y.d)
	x.d.onInvite(func(Invitation) error { return ErrOffline })
	var asked atomic.Int64
	y.d.onInvite(func(inv Invitation) error {
		if inv.Peer == alice {
			asked.Add(1)
		}
		return nil
	})
	y.e.UserRegistered(bob, true)
	waitFor(t, "idle", y.idle)
	if err := y.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c0", "c0", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-y's wait for a session", func() bool { return y.m.get("invite.sent") == 1 && y.idle() })
	// c0 goes another way, delivered by task-z.
	ms, err := st.Pending(t.Context(), bob, "", clock.Now(), 10)
	if err != nil || len(ms) != 1 {
		t.Fatal(ms, err)
	}
	c, err := st.Claim(t.Context(), bob, ms[0].ID, "task-z", clock.Now(), clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Remove(t.Context(), c, "task-z"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Second)
	if err := x.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "m1", "m1", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "task-x's failed invitation", func() bool { return x.m.get("invite.failed") == 1 && x.idle() })
	y.e.UserRegistered(bob, false)
	waitFor(t, "task-y's invitation for m1", func() bool { return asked.Load() == 1 && x.idle() && y.idle() })
}

// queueHeld queues a standalone message from alice for bob under id, and
// has task-9 claim it at now until until, as an attempt a task makes
// before it dies does.
func queueHeld(t *testing.T, st store.Store, id, text string, now, until time.Time) {
	t.Helper()
	if err := st.Enqueue(t.Context(), store.Message{Recipient: bob, ID: id, Sender: alice, Mode: store.Standalone,
		CPIM: standalone(alice, bob, chat(t, id, text, 0)).CPIM, Enqueued: now, Expires: now.Add(24 * time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(t.Context(), bob, id, "task-9", now, until); err != nil {
		t.Fatal(err)
	}
}

// pagerTimes has r's pager deliver, and returns when each delivery came,
// counted from now.
func pagerTimes(r *rig) func() []time.Duration {
	var mu sync.Mutex
	var at []time.Duration
	t0 := r.clock.Now()
	r.d.onPager(func(Delivery) error {
		mu.Lock()
		defer mu.Unlock()
		at = append(at, r.clock.Now().Sub(t0))
		return nil
	})
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(at)
	}
}

// #651: a task that dies while its attempts hold messages leaves their
// claims for the rest of their leases. The read a takeover asks for passes
// them over, and nothing else reads the queue: once each lease is over,
// the queue is read again, with no other event, and the message goes. No
// read is made before.
func TestMessagesACrashedTaskHeldGoWhenTheirLeasesEnd(t *testing.T) {
	st := &heldReadCounter{Store: store.NewMemory()}
	clock := newFakeClock()
	r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour}, st, clock)
	sent := pagerTimes(r)
	lease := r.e.lease()
	queueHeld(t, st, "0001", "m1", clock.Now(), clock.Now().Add(lease))
	clock.Advance(30 * time.Second)
	queueHeld(t, st, "0002", "m2", clock.Now(), clock.Now().Add(lease))
	clock.Advance(10 * time.Second)
	r.e.ReadQueues([]string{bob})
	waitFor(t, "the takeover's read", func() bool { return st.n.Load() > 0 && r.idle() })
	reads := st.n.Load()
	stepUntil(t, clock, lease-41*time.Second, r.idle, func() bool { return false })
	if got := st.n.Load() - reads; got != 0 || len(sent()) != 0 {
		t.Fatalf("before m1's lease ended: %d more reads, deliveries at %v", got, sent())
	}
	if _, ok := stepUntil(t, clock, 10*time.Minute, r.idle, func() bool { return len(sent()) == 2 }); !ok {
		t.Fatalf("deliveries at %v; m1's lease ended at %v, m2's at %v", sent(), lease, 30*time.Second+lease)
	}
	for i, end := range []time.Duration{lease, 30*time.Second + lease} {
		if at := sent()[i]; at < end || at > end+time.Second {
			t.Errorf("m%d delivered %v after it was claimed, its lease %v", i+1, at-end+lease, lease)
		}
	}
	if n := r.queued(t, bob); n != 0 {
		t.Errorf("%d messages still queued", n)
	}
	r.e.mu.Lock()
	x := r.e.recipients[bob]
	r.e.mu.Unlock()
	if x != nil {
		t.Error("bob's state kept once nothing was held")
	}
}

// #651, a claim lost rather than read: task-2's pass reads m1 free, and
// task-9 claims it first and then dies. That claim was made no later than
// the lost one, by a clock up to the skew ahead, as task-9's is here: the
// queue is read again a lease and the skew after, once.
func TestAPassThatLosesAClaimToATaskThatDiesDeliversOnceTheLeaseEnds(t *testing.T) {
	for _, waiting := range []bool{false, true} {
		t.Run(map[bool]string{false: "pass over the queue", true: "pass of a new message"}[waiting], func(t *testing.T) {
			st := store.NewMemory()
			clock := newFakeClock()
			gate := &claimHold{Store: st, in: make(chan struct{}), gate: make(chan struct{})}
			gate.release = sync.OnceFunc(func() { close(gate.gate) })
			t.Cleanup(gate.release)
			r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour, InviteTimeout: time.Hour}, gate, clock)
			drainInvites(t, r.d)
			if waiting {
				// carol's c1 waits for a session, so that m1 is tried on
				// its own (trySingles).
				if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "c1's invitation", func() bool { return r.m.get("invite.sent") == 1 && r.idle() })
			}
			gate.armed.Store(true)
			if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "one", 0))); err != nil {
				t.Fatal(err)
			}
			waitDone(t, gate.in)
			ms, err := st.Pending(t.Context(), bob, "", clock.Now(), 10)
			if err != nil || len(ms) == 0 {
				t.Fatal(ms, err)
			}
			m1 := ms[len(ms)-1]
			ahead := clock.Now().Add(DefaultClockSkew)
			if _, err := st.Claim(t.Context(), bob, m1.ID, "task-9", ahead, ahead.Add(r.e.lease())); err != nil {
				t.Fatal(err)
			}
			gate.release()
			waitFor(t, "task-2's lost claim", func() bool { return r.m.get("delivery.claimed_elsewhere") == 1 && r.idle() })
			moved, ok := stepUntil(t, clock, 10*time.Minute, r.idle, func() bool { return r.m.get("delivery.pager") == 1 })
			if end := r.e.lease() + DefaultClockSkew; !ok || moved != end {
				t.Fatalf("m1 delivered %v, %v after task-2 lost its claim; task-9's lease ended after %v", ok, moved, end)
			}
			if got := r.m.get("delivery.lease_read"); got != 1 {
				t.Errorf("%d reads set for the end of task-9's lease, want 1", got)
			}
		})
	}
}

// #651: of the claims passes leave, the read waits for the first to end,
// whether one pass left them all or each came from a pass of its own: m1's
// claim, which the first read passed over, ends before the one task-2
// loses on m2 after it.
func TestTheReadWaitsForTheFirstLeaseToEnd(t *testing.T) {
	for _, apart := range []bool{false, true} {
		t.Run(map[bool]string{false: "one pass", true: "passes apart"}[apart], func(t *testing.T) {
			st := store.NewMemory()
			clock := newFakeClock()
			gate := &claimHold{Store: st, in: make(chan struct{}), gate: make(chan struct{})}
			gate.release = sync.OnceFunc(func() { close(gate.gate) })
			t.Cleanup(gate.release)
			r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour, InviteTimeout: time.Hour}, gate, clock)
			drainInvites(t, r.d)
			sent := pagerTimes(r)
			lease := r.e.lease()
			queueHeld(t, st, "0001", "m1", clock.Now(), clock.Now().Add(lease))
			if apart {
				// carol's c1 waits for a session: a read finds m1 held, and
				// m2 is then tried on its own, with no read of the queue.
				if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
					t.Fatal(err)
				}
				waitFor(t, "c1's invitation", func() bool { return r.m.get("invite.sent") == 1 && r.idle() })
			}
			clock.Advance(40 * time.Second)
			gate.armed.Store(true)
			if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
				t.Fatal(err)
			}
			waitDone(t, gate.in)
			ms, err := st.Pending(t.Context(), bob, "", clock.Now(), 10)
			if err != nil || len(ms) == 0 {
				t.Fatal(ms, err)
			}
			if _, err := st.Claim(t.Context(), bob, ms[len(ms)-1].ID, "task-9", clock.Now(), clock.Now().Add(lease)); err != nil {
				t.Fatal(err)
			}
			gate.release()
			waitFor(t, "task-2's lost claim", func() bool { return r.m.get("delivery.claimed_elsewhere") == 1 && r.idle() })
			if _, ok := stepUntil(t, clock, 10*time.Minute, r.idle, func() bool { return len(sent()) > 0 }); !ok || sent()[0] != lease {
				t.Fatalf("deliveries at %v; m1's lease ended at %v", sent(), lease)
			}
		})
	}
}

// A pass that found bob unreachable reads the queue for a message held
// elsewhere no sooner than for the rest: that one would find bob
// unreachable too. The retry timer, an hour here, reads it.
func TestAPassThatFindsTheRecipientAwayReadsNoSoonerForAHeldMessage(t *testing.T) {
	st := &heldReadCounter{Store: store.NewMemory()}
	clock := newFakeClock()
	r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour}, st, clock)
	r.d.onPager(func(Delivery) error { return ErrOffline })
	queueHeld(t, st, "0001", "m1", clock.Now(), clock.Now().Add(r.e.lease()))
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "m2's failed attempt", func() bool { return r.m.get("delivery.pager_failed") == 1 && r.idle() })
	reads := st.n.Load()
	stepUntil(t, clock, 10*time.Minute, r.idle, func() bool { return false })
	if got := st.n.Load() - reads; got != 0 {
		t.Errorf("the queue was read %d more times within 10 min, its retry timer an hour", got)
	}
}

// QA on #659: a read already waiting gives way to one for a claim that
// ends sooner, whichever pass came first. task-2 first loses its claim to
// m2, which sets a read for a lease and the skew after; a pass over the
// whole queue then passes over m1, which a dead task holds for 30 s more.
// The queue is read when m1's claim ends, not when m2's does.
func TestAClaimEndingSoonerSeenAfterALostOneHasTheQueueReadSooner(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	gate := &claimHold{Store: st, in: make(chan struct{}), gate: make(chan struct{})}
	gate.release = sync.OnceFunc(func() { close(gate.gate) })
	t.Cleanup(gate.release)
	r := newRigWith(t, Config{InstanceID: "task-2", RetryInterval: time.Hour, InviteTimeout: time.Hour}, gate, clock)
	drainInvites(t, r.d)
	sent := pagerTimes(r)
	lease := r.e.lease()
	// carol's c1 waits for a session, so that m2 is tried on its own.
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "c1", "c1", 0))}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "c1's invitation", func() bool { return r.m.get("invite.sent") == 1 && r.idle() })
	gate.armed.Store(true)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitDone(t, gate.in)
	ms, err := st.Pending(t.Context(), bob, "", clock.Now(), 10)
	if err != nil || len(ms) == 0 {
		t.Fatal(ms, err)
	}
	if _, err := st.Claim(t.Context(), bob, ms[len(ms)-1].ID, "task-9", clock.Now(), clock.Now().Add(lease)); err != nil {
		t.Fatal(err)
	}
	gate.release()
	waitFor(t, "task-2's lost claim", func() bool { return r.m.get("delivery.claimed_elsewhere") == 1 && r.idle() })
	queueHeld(t, st, "0001", "m1", clock.Now(), clock.Now().Add(30*time.Second))
	r.e.ReadQueues([]string{bob})
	waitFor(t, "the read that passes m1 over", r.idle)
	if _, ok := stepUntil(t, clock, 10*time.Minute, r.idle, func() bool { return len(sent()) > 0 }); !ok || sent()[0] != 30*time.Second {
		t.Fatalf("deliveries at %v; m1's claim ended at 30s, the one task-2 lost at %v", sent(), lease)
	}
}
