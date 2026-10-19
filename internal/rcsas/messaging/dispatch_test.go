package messaging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// readCounter counts the queue items Pending returns.
type readCounter struct {
	store.Store
	items atomic.Int64
}

func (s *readCounter) Pending(ctx context.Context, r, after string, now time.Time, limit int) ([]store.Message, error) {
	ms, err := s.Store.Pending(ctx, r, after, now, limit)
	s.items.Add(int64(len(ms)))
	return ms, err
}

// drainInvites is for a test that does not look at invitations: from now
// on they are only counted (fakeDeliverer.invited), and those already sent
// are dropped.
func drainInvites(_ *testing.T, d *fakeDeliverer) {
	d.mu.Lock()
	d.unread = true
	d.mu.Unlock()
	for {
		select {
		case <-d.invites:
		default:
			return
		}
	}
}

// Messages that wait for a session are not read again for each new one:
// the reads grow with the messages, not with their square.
func TestAnOfflineChatQueueIsNotReReadForEveryNewMessage(t *testing.T) {
	const n = 400
	st := &readCounter{Store: store.NewMemory()}
	r := newRigWith(t, Config{SenderRate: Rate{PerMinute: -1}, QueueSenderShare: 1}, st, newFakeClock())
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	drainInvites(t, r.d)
	for i := range n {
		o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, fmt.Sprint("m", i), "hi", 0)}
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "idle", r.idle)
	}
	if got := st.items.Load(); got > int64(n) {
		t.Fatalf("%d messages to an offline recipient read %d queue items", n, got)
	}
	// What can let them go reads the queue once.
	before := st.items.Load()
	r.e.UserRegistered(bob, true)
	waitFor(t, "idle", r.idle)
	if got := st.items.Load() - before; got != n {
		t.Fatalf("a registration on a new flow read %d items", got)
	}
}

func TestAQueueThatCannotBeDeliveredIsTriedAgainWithBackoff(t *testing.T) {
	r := newRig(t, Config{RetryInterval: time.Minute, MaxRetryInterval: 3 * time.Minute})
	var attempts atomic.Int32
	r.d.onPager(func(Delivery) error { attempts.Add(1); return errors.New("503 Service Unavailable") })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first attempt", func() bool { return attempts.Load() == 1 && r.idle() })
	for i, wait := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 3 * time.Minute} {
		r.clock.Advance(wait - time.Second)
		waitFor(t, "idle", r.idle)
		if got := attempts.Load(); got != int32(i+1) {
			t.Fatalf("retry %d came early: %d attempts", i+1, got)
		}
		r.clock.Advance(time.Second)
		waitFor(t, "the retry", func() bool { return attempts.Load() == int32(i+2) && r.idle() })
	}
	// Once it goes, nothing is held.
	r.d.onPager(nil)
	r.clock.Advance(3 * time.Minute)
	waitFor(t, "the delivery", func() bool { return r.m.get("delivery.pager") == 1 && r.idle() })
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	if len(r.e.recipients) != 0 {
		t.Fatalf("state kept for %d recipients", len(r.e.recipients))
	}
}

func TestARegistrationOnANewFlowInvitesAgainAtOnce(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Hour, RetryInterval: time.Hour})
	o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m1", "hi", 0)}
	if err := r.e.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	r.e.UserRegistered(bob, true)
	if inv := r.d.nextInvite(t); inv.Recipient != bob {
		t.Fatalf("invitation %+v", inv)
	}
}

// cancelStore fails what records an outcome on a cancelled context, as
// the SDK does.
type cancelStore struct{ store.Store }

func (s cancelStore) Remove(ctx context.Context, m store.Message, owner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.Remove(ctx, m, owner)
}

func (s cancelStore) Release(ctx context.Context, recipient, id, owner string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.Release(ctx, recipient, id, owner)
}

func TestAMessageDeliveredWhileClosingIsNotDeliveredAgain(t *testing.T) {
	st, clock := cancelStore{store.NewMemory()}, newFakeClock()
	r := newRigWith(t, Config{InstanceID: "task-1"}, st, clock)
	entered, answered := make(chan struct{}), make(chan struct{})
	r.d.onPagerCtx(func(ctx context.Context, _ Delivery) error {
		close(entered)
		select {
		case <-answered:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	<-entered
	closed := make(chan struct{})
	go func() { r.e.Close(); close(closed) }()
	waitFor(t, "Close to begin", r.e.isClosed)
	// Close waits for the attempt instead of cancelling it.
	select {
	case <-closed:
		t.Fatal("Close returned while a delivery was in progress")
	case <-time.After(20 * time.Millisecond):
	}
	close(answered) // the MESSAGE got its 200 OK
	<-closed
	<-r.d.pagers
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "late", 0))); err != nil {
		t.Fatalf("Submit after Close = %v", err)
	}
	clock.Advance(3*DefaultDeliveryTimeout + time.Second)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2)}, st, clock)
	r2.e.UserRegistered(bob, false)
	d := r2.d.nextPager(t)
	if !bytes.Contains(d.CPIM, []byte("late")) {
		t.Fatalf("task-2 delivered %q again", d.CPIM)
	}
	select {
	case d := <-r2.d.pagers:
		t.Fatalf("task-2 delivered %q too", d.CPIM)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCloseCancelsAnAttemptThatOutlastsItsBound(t *testing.T) {
	st := cancelStore{store.NewMemory()}
	r := newRigWith(t, Config{DeliveryTimeout: time.Hour, StoreTimeout: time.Second}, st, newFakeClock())
	entered := make(chan struct{})
	r.d.onPagerCtx(func(ctx context.Context, _ Delivery) error { close(entered); <-ctx.Done(); return ctx.Err() })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	<-entered
	closed := make(chan struct{})
	go func() { r.e.Close(); close(closed) }()
	// Close's bound is a delivery and two store calls. Only it fires: the
	// attempt's own deadline (an hour) would end the attempt too, and
	// advancing the clock to the bound passes it first (QA on #147, #149).
	bound := time.Hour + 2*time.Second
	waitFor(t, "Close's bound", func() bool { return r.clock.armed(bound) })
	r.clock.fire(bound)
	waitDone(t, closed)
	// The cancelled attempt handed the message back for another task.
	if r.queued(t, bob) != 1 {
		t.Fatal("the cancelled attempt left the message claimed")
	}
}

// Two tasks sweeping at once: each expired message is given up on once.
func TestTwoEnginesSweepingTogetherAnswerEachMessageOnce(t *testing.T) {
	st, clock := store.NewMemory(), newFakeClock()
	r1 := newRigWith(t, Config{InstanceID: "task-1", StoreTTL: time.Hour, Batch: 7}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", StoreTTL: time.Hour, Batch: 7, Rand: seeded(2)}, st, clock)
	offline := func(d Delivery) error {
		if d.Recipient == bob {
			return ErrOffline
		}
		return ErrOffline // alice too: the notifications stay queued, to be counted
	}
	r1.d.onPager(offline)
	r2.d.onPager(offline)
	const n = 30
	for i := range n {
		if err := r1.e.Submit(t.Context(), standalone(alice, bob, chat(t, fmt.Sprint("m", i), "hi", imdn.NegativeDelivery))); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "idle", func() bool { return r1.idle() && r2.idle() })
	clock.Advance(time.Hour)
	var wg sync.WaitGroup
	for _, r := range []*rig{r1, r2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, err := r.e.Sweep(t.Context()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if got := st.Len(bob); got != 0 {
		t.Fatalf("%d expired messages left", got)
	}
	if got := st.Len(alice); got != n {
		t.Fatalf("%d notifications for %d expired messages", got, n)
	}
	if got := r1.m.get("message.expired") + r2.m.get("message.expired"); got != n {
		t.Fatalf("%d messages given up on", got)
	}
}

// A failure between queueing the notification and removing the message
// repeats the give-up; the notification is still queued once.
func TestARepeatedGiveUpQueuesItsNotificationOnce(t *testing.T) {
	mem := store.NewMemory()
	st := &flakyStore{Store: mem}
	r := newRigWith(t, Config{StoreTTL: time.Hour}, st, newFakeClock())
	r.d.onPager(func(Delivery) error { return ErrOffline })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", imdn.NegativeDelivery))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	r.clock.Advance(time.Hour)
	st.set("remove")
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	st.set()
	r.clock.Advance(3*DefaultDeliveryTimeout + time.Second) // the claim lapses
	for range 2 {
		if _, err := r.e.Sweep(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if mem.Len(bob) != 0 || mem.Len(alice) != 1 {
		t.Fatalf("bob %d, alice %d", mem.Len(bob), mem.Len(alice))
	}
}

func TestPartialSuccessReportsAddUpToADelivery(t *testing.T) {
	for name, c := range map[string]struct {
		reports []msrp.ByteRange
		code    int
		done    bool
	}{
		"whole":          {[]msrp.ByteRange{{Start: 1, End: 2000, Total: 2000}}, 200, true},
		"two parts":      {[]msrp.ByteRange{{Start: 1, End: 1000, Total: 2000}, {Start: 1001, End: 2000, Total: 2000}}, 200, true},
		"overlapping":    {[]msrp.ByteRange{{Start: 1, End: 1200, Total: 2000}, {Start: 1001, End: 2000, Total: 2000}}, 200, true},
		"a gap":          {[]msrp.ByteRange{{Start: 1, End: 500, Total: 2000}, {Start: 1001, End: 2000, Total: 2000}}, 0, false},
		"the first half": {[]msrp.ByteRange{{Start: 1, End: 1000, Total: 2000}}, 0, false},
	} {
		l := &Leg{waiting: map[string]*delivery{}}
		d := &delivery{size: 2000, done: make(chan int, 1)}
		l.waiting["id"] = d
		for _, r := range c.reports {
			l.HandleReport(nil, msrp.Report{MessageID: "id", Range: r, Code: 200})
		}
		select {
		case code := <-d.done:
			if !c.done || code != c.code {
				t.Errorf("%s: delivered with %d", name, code)
			}
		default:
			if c.done {
				t.Errorf("%s: not delivered", name)
			}
		}
	}
	l := &Leg{waiting: map[string]*delivery{}}
	d := &delivery{size: 2000, done: make(chan int, 1)}
	l.waiting["id"] = d
	l.HandleReport(nil, msrp.Report{MessageID: "id", Range: msrp.ByteRange{Start: 1, End: 1000, Total: 2000}, Code: 200})
	l.HandleReport(nil, msrp.Report{MessageID: "id", Range: msrp.ByteRange{Start: 1001, End: 2000, Total: 2000}, Code: 413})
	l.HandleReport(nil, msrp.Report{MessageID: "other", Code: 200})
	if code := <-d.done; code != 413 {
		t.Fatalf("a failure after a part: %d", code)
	}
}

func TestAFullQueueRefusesTheMessageAndTellsTheSender(t *testing.T) {
	r := newRig(t, Config{MaxQueueMessages: 2, QueueSenderShare: 1})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == bob {
			return ErrOffline
		}
		return nil
	})
	for i := range 2 {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, fmt.Sprint("m", i), "hi", 0))); err != nil {
			t.Fatal(err)
		}
	}
	err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m2", "one too many", imdn.NegativeDelivery)))
	var rej *Rejection
	if !errors.As(err, &rej) || rej.Reason != ReasonQueueFull || rej.MSRPStatus() != msrp.StatusForbidden {
		t.Fatalf("Submit = %v", err)
	}
	var d Delivery
	for d = r.d.nextPager(t); d.Recipient != alice; d = r.d.nextPager(t) {
	}
	if n := readNotification(t, d.CPIM); n.MessageID != "m2" || n.Status != imdn.Failed {
		t.Fatalf("notification %+v", n)
	}
	if r.m.get("message.rejected.queue_full") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestALargeModeSessionCarriesItsOneMessage(t *testing.T) {
	r := newRig(t, Config{PagerLimit: 600})
	l := r.listen(t)
	large := func(id string) []byte { return chat(t, id, strings.Repeat(id, 400), 0) }
	for _, id := range []string{"L1", "L2"} {
		if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: large(id)}); err != nil {
			t.Fatal(err)
		}
	}
	// Each message gets a session of its own.
	inv1, inv2 := r.d.nextInvite(t), r.d.nextInvite(t)
	if inv1.QueueID == "" || inv2.QueueID == "" || inv1.QueueID == inv2.QueueID {
		t.Fatalf("invitations %+v, %+v", inv1, inv2)
	}
	b, leg := r.largeMode(t, l, inv1)
	got := b.next(t)
	waitDone(t, leg.Finished())
	select {
	case m := <-b.got:
		t.Fatalf("a second message on one session: %d bytes", len(m.Body))
	case <-time.After(50 * time.Millisecond):
	}
	b2, leg2 := r.largeMode(t, l, inv2)
	if got2 := b2.next(t); bytes.Equal(got2.Body, got.Body) {
		t.Fatal("both sessions carried the same message")
	}
	waitDone(t, leg2.Finished())

	// A session for a message that is gone finishes at once.
	_, leg3 := r.largeMode(t, l, inv1)
	waitDone(t, leg3.Finished())
}

// alice's own large-mode session to bob only carries what she sends: a
// message from bob to her waits for a session of its own.
func TestALargeModeSessionNeverCarriesTheOtherDirection(t *testing.T) {
	r := newRig(t, Config{PagerLimit: 600})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Standalone, Direction: Originating})
	reply := chat(t, "R1", strings.Repeat("r", 800), 0)
	if err := r.e.Submit(t.Context(), Origin{Sender: bob, Recipient: alice, Conversation: conv, Mode: store.Standalone, CPIM: reply}); err != nil {
		t.Fatal(err)
	}
	if inv := r.d.nextInvite(t); inv.Recipient != alice || inv.QueueID == "" {
		t.Fatalf("invitation %+v", inv)
	}
	select {
	case m := <-a.got:
		t.Fatalf("delivered on alice's own session: %d bytes", len(m.Body))
	case <-time.After(50 * time.Millisecond):
	}
	// Nor does a standalone message go into a chat session.
	_, chatLeg := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	short := chat(t, "R2", "short", 0)
	if err := r.e.Submit(t.Context(), standalone(bob, alice, short)); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); !bytes.Equal(d.CPIM, short) {
		t.Fatalf("pager delivery %q", d.CPIM)
	}
	select {
	case m := <-chatLeg.got:
		t.Fatalf("a standalone message in a chat session: %q", m.Body)
	case <-time.After(50 * time.Millisecond):
	}
}

// flakyListener fails Accept once with a passing error.
type flakyListener struct {
	net.Listener
	failed  atomic.Bool
	accepts atomic.Int32
}

type tempErr struct{}

func (tempErr) Error() string   { return "accept: too many open files" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

func (l *flakyListener) Accept() (net.Conn, error) {
	l.accepts.Add(1)
	if l.failed.CompareAndSwap(false, true) {
		return nil, tempErr{}
	}
	return l.Listener.Accept()
}

func TestServeWaitsOutAFailedAccept(t *testing.T) {
	r := newRig(t, Config{})
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: inner}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- r.e.Serve(ctx, fl) }()
	// Serve counts the failure before it sets its retry timer (the first
	// pause, 5 ms), so the count alone does not say the timer is there yet.
	waitFor(t, "the retry timer", func() bool { return r.clock.armed(5 * time.Millisecond) })
	if n := r.m.get("msrp.accept_failed"); n != 1 {
		t.Fatalf("msrp.accept_failed = %d, want 1", n)
	}
	// Serve waits for the timer before it accepts again: a Serve that set
	// the timer and went straight on would have called Accept again by now.
	time.Sleep(50 * time.Millisecond)
	if n := fl.accepts.Load(); n != 1 {
		t.Fatalf("Accept called %d times before the pause was over, want 1", n)
	}
	r.clock.Advance(time.Second)
	leg, c := r.connect(t, fl, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_ = leg
	c.send(t, chat(t, "m1", "hi", 0))
	cancel()
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v", err)
	}
	// A closed listener ends it.
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	l2.Close()
	if err := r.e.Serve(t.Context(), l2); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve on a closed listener = %v", err)
	}
}

// One sender cannot fill a recipient's queue: past its share it is refused,
// and others still get through.
func TestOneSenderCannotLockOthersOutOfAQueue(t *testing.T) {
	r := newRig(t, Config{MaxQueueMessages: 8, QueueSenderShare: 4, SenderRate: Rate{PerMinute: -1}})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == bob {
			return ErrOffline
		}
		return nil
	})
	for i := range 2 {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, fmt.Sprint("a", i), "hi", 0))); err != nil {
			t.Fatal(err)
		}
	}
	err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "a2", "flood", imdn.NegativeDelivery)))
	if got := rejected(err); got != ReasonQueueShareFull {
		t.Fatalf("alice beyond her share: %v", err)
	}
	var d Delivery
	for d = r.d.nextPager(t); d.Recipient != alice; d = r.d.nextPager(t) {
	}
	if n := readNotification(t, d.CPIM); n.MessageID != "a2" || n.Status != imdn.Failed {
		t.Fatalf("notification %+v", n)
	}
	for i := range 2 {
		if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, fmt.Sprint("c", i), "hi", 0))); err != nil {
			t.Fatalf("carol: %v", err)
		}
	}
	if r.m.get("message.rejected.queue_share_full") != 1 || r.m.get("message.rejected.queue_full") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
	if got := queueLimit(r.e.cfg); got != (store.Limit{Count: 8, Bytes: DefaultMaxQueueBytes, SenderCount: 2, SenderBytes: DefaultMaxQueueBytes / 4,
		GroupCount: 2, GroupBytes: DefaultMaxQueueBytes / 4}) {
		t.Fatalf("limit %+v", got)
	}
}

// While a queue is held, new messages to try on their own are kept up to a
// batch; the rest wait for the next read of the queue.
func TestTheMessagesKeptForAHeldQueueAreBounded(t *testing.T) {
	r := newRig(t, Config{Batch: 3, SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour})
	release, blocked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.d.onInvite(func(Invitation) error { return nil })
	drainInvites(t, r.d)
	// The first message leaves the queue waiting for a session; the next
	// attempt is held up so that new messages pile up meanwhile.
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m0", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	r.d.onInvite(func(Invitation) error { once.Do(func() { close(blocked); <-release }); return nil })
	r.e.mu.Lock()
	delete(r.e.invites, inviteKey{bob, alice, store.Chat, ""})
	r.e.mu.Unlock()
	// One message starts a pass whose invitation is held up...
	if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "m1", "hi", 0)}); err != nil {
		t.Fatal(err)
	}
	<-blocked
	// ...and the rest arrive while it is.
	for i := 1; i < 10; i++ {
		if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, fmt.Sprint("m", i+1), "hi", 0)}); err != nil {
			t.Fatal(err)
		}
	}
	r.e.mu.Lock()
	kept := len(r.e.recipients[bob].single)
	r.e.mu.Unlock()
	close(release)
	if kept > 3 {
		t.Fatalf("%d messages kept for a held queue", kept)
	}
}

// The outcome of an attempt that ends after Close has cancelled it is
// still recorded, so another task does not repeat it.
func TestAnOutcomeAfterTheCloseBoundIsStillRecorded(t *testing.T) {
	st, clock := cancelStore{store.NewMemory()}, newFakeClock()
	r := newRigWith(t, Config{InstanceID: "task-1"}, st, clock)
	entered, answered := make(chan struct{}), make(chan struct{})
	r.d.onPager(func(Delivery) error { close(entered); <-answered; return nil })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	<-entered
	closed := make(chan struct{})
	go func() { r.e.Close(); close(closed) }()
	// Close sets its bound after it marks the engine closed: advancing
	// before then would pass a bound not yet set (#149).
	waitFor(t, "Close's bound", func() bool { return clock.armed(DefaultDeliveryTimeout + 2*DefaultStoreTimeout) })
	clock.Advance(DefaultDeliveryTimeout + 2*DefaultStoreTimeout) // the bound cancels
	close(answered)                                               // the 200 OK comes after
	<-closed
	<-r.d.pagers
	clock.Advance(3*DefaultDeliveryTimeout + time.Second)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2)}, st, clock)
	r2.e.UserRegistered(bob, true)
	select {
	case d := <-r2.d.pagers:
		t.Fatalf("delivered again by task-2: %q", d.CPIM)
	case <-time.After(200 * time.Millisecond):
	}
}

// A recipient catching up on many messages answers each with up to two
// notifications; those are bounded by the messages, not by the share.
func TestReceiptsForManyMessagesAreNotHeldToTheSenderShare(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == alice {
			return ErrOffline // alice is away while bob reads
		}
		return nil
	})
	const n = 70
	for i := range n {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, fmt.Sprint("m", i), "hi", imdn.PositiveDelivery|imdn.Display))); err != nil {
			t.Fatal(err)
		}
	}
	for i := range n {
		id := fmt.Sprint("m", i)
		for _, k := range []struct {
			kind   imdn.Kind
			status imdn.Status
		}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
			if err := r.e.Submit(t.Context(), standalone(bob, alice, receipt(t, id, k.kind, k.status))); err != nil {
				t.Fatalf("receipt %s %s: %v", id, k.kind, err)
			}
		}
	}
	waitFor(t, "idle", r.idle)
	if got := r.store.(*store.Memory).Len(alice); got != 2*n {
		t.Fatalf("%d receipts queued for alice, want %d", got, 2*n)
	}
	if r.m.get("message.rejected.queue_share_full") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

// Messages from one sender that wait for a session do not slow another
// sender's live chat: only a sender with waiting messages takes the slow
// path that reads the queue again.
func TestALiveChatDoesNotReReadAQueueHeldByAnotherSender(t *testing.T) {
	st := &readCounter{Store: store.NewMemory()}
	r := newRigWith(t, Config{SenderRate: Rate{PerMinute: -1}}, st, newFakeClock())
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	drainInvites(t, r.d)
	l := r.listen(t)
	for i := range 100 {
		if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, fmt.Sprint("c", i), "from carol", 0)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "idle", r.idle)
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	waitFor(t, "idle", r.idle)
	before := st.items.Load()
	for i := range 100 {
		if err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, fmt.Sprint("a", i), "live", 0)}); err != nil {
			t.Fatal(err)
		}
		b.next(t)
	}
	if got := st.items.Load() - before; got > 100 {
		t.Fatalf("100 live messages read %d queue items", got)
	}
}

// A held queue gets more new messages than it can try on their own while
// one attempt runs: those beyond are neither lost nor sent out of order.
func TestMessagesBeyondTheHeldQueueSingleListAreNotLost(t *testing.T) {
	const n = 120
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	l := r.listen(t)
	drainInvites(t, r.d)
	var b *client
	for i := range n {
		if i == n/3 {
			_, b = r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
		}
		o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, fmt.Sprint("m", i), fmt.Sprintf("#%04d", i), 0)}
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	for i := range n {
		if got := b.next(t); !bytes.HasSuffix(got.Body, []byte(fmt.Sprintf("#%04d", i))) {
			t.Fatalf("delivery %d: %q", i, got.Body)
		}
	}
}

func TestADroppedSingleDoesNotLetALaterMessageOvertake(t *testing.T) {
	r := newRig(t, Config{Batch: 2, SenderRate: Rate{PerMinute: -1}})
	l := r.listen(t)
	var mu sync.Mutex
	gates := map[string]chan struct{}{}
	entered := make(chan string, 16)
	gate := func(peer string) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		g := make(chan struct{})
		gates[peer] = g
		return g
	}
	r.d.onInvite(func(inv Invitation) error {
		mu.Lock()
		g := gates[inv.Peer]
		mu.Unlock()
		if g != nil {
			entered <- inv.Peer
			<-g
		}
		return ErrOffline
	})
	drainInvites(t, r.d)
	submit := func(from, id string) {
		t.Helper()
		if err := r.e.Submit(t.Context(), Origin{Sender: from, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, id, id, 0)}); err != nil {
			t.Fatal(err)
		}
	}
	x1, x2, x3 := "sip:x1@example.net", "sip:x2@example.net", "sip:x3@example.net"
	submit(carol, "c0") // the queue is held; waiting = {carol}
	waitFor(t, "idle", r.idle)
	g1 := gate(x1)
	submit(x1, "x1") // the worker blocks in Invite(x1)
	<-entered
	g2 := gate(x2)
	submit(x2, "x2")
	submit(carol, "c3") // the single list is full (Batch 2)
	submit(alice, "a1") // dropped: not tried, not in waiting
	close(g1)           // the worker takes [x2, c3] and blocks in Invite(x2)
	<-entered
	g3 := gate(x3)
	submit(x3, "x3")
	submit(alice, "a2") // single list [x3, a2]
	close(g2)           // the worker takes [x3, a2] and blocks in Invite(x3)
	<-entered
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	close(g3)
	if first := b.next(t); !bytes.HasSuffix(first.Body, []byte("a1")) {
		t.Fatalf("bob's first message from alice is %q, want a1", first.Body[len(first.Body)-2:])
	}
}
