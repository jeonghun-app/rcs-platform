package messaging

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// scripted is a client whose answer to each message is answer's.
type scripted struct {
	answer func(*msrp.Message) error
	got    atomic.Int32
}

func (c *scripted) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	c.got.Add(1)
	return c.answer(m)
}

func (c *scripted) HandleReport(*msrp.Session, msrp.Report) {}

// connectScripted opens a leg for p and connects a scripted client to it.
func (r *rig) connectScripted(t *testing.T, l net.Listener, p LegParams, answer func(*msrp.Message) error) (*Leg, *scripted) {
	t.Helper()
	local := clientURI()
	p.Remote = []msrp.URI{local}
	if p.Direction == 0 {
		p.Direction = Originating
	}
	leg, err := r.e.OpenLeg(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	c := &scripted{answer: answer}
	session, err := msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{leg.Local()}, Handler: c})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), hangGuard)
	defer cancel()
	if err := conn.Open(ctx, session); err != nil {
		t.Fatal(err)
	}
	return leg, c
}

// QA's case (#214): a pass that starts with alice's queue blocked, after a
// session that failed her receipt, delivers it; bob's 1-to-1 message,
// queued while that pass waits for the receipt's report, goes too, with
// no other event.
func TestAMessageQueuedWhileABlockedPassGoesThroughIsDelivered(t *testing.T) {
	r := newRigWith(t, Config{}, store.NewMemory(), newFakeClock())
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	var delivered atomic.Int32
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == alice && !d.Notification {
			delivered.Add(1)
		}
		return nil
	})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the receipt's passes", r.idle)
	l := r.listen(t)
	// The first session fails the receipt: the queue is blocked.
	first, c1 := r.connectScripted(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		return &msrp.StatusError{Code: msrp.StatusRequestTimeout}
	})
	waitFor(t, "the failed attempt", func() bool { return c1.got.Load() == 1 && r.idle() })
	_ = first.Close()
	waitFor(t, "idle", r.idle)
	// The second takes it, and bob writes before it answers.
	_, _ = r.connectScripted(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if err := r.e.Submit(context.Background(), standalone(bob, alice, chat(t, "d1", "are you there?", 0))); err != nil {
			t.Errorf("bob: %v", err)
		}
		return nil
	})
	waitFor(t, "bob's message delivered", func() bool { return delivered.Load() == 1 })
	waitFor(t, "alice's queue empty", func() bool { return r.store.(*store.Memory).Len(alice) == 0 && r.idle() })
}

// A pass that ends blocked again leaves what came in meanwhile to wait, as
// a blocked queue does: messages to a recipient that cannot be reached do
// not each start a pass (#214).
func TestMessagesQueuedWhileABlockedPassStaysBlockedWait(t *testing.T) {
	r := newRigWith(t, Config{SenderRate: Rate{PerMinute: -1}}, store.NewMemory(), newFakeClock())
	attempts := make(chan struct{}, 16)
	release := make(chan struct{})
	var held atomic.Bool
	r.d.onPager(func(Delivery) error {
		attempts <- struct{}{}
		if held.Load() {
			<-release
		}
		return errors.New("480 Temporarily Unavailable")
	})
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	<-attempts
	waitFor(t, "the queue blocked", r.idle)
	// A registration starts a pass, blocked still; three messages come
	// in while it tries m1.
	held.Store(true)
	r.e.UserRegistered(bob, true)
	<-attempts
	for _, id := range []string{"m2", "m3", "m4"} {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, id, "hi", 0))); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	waitFor(t, "idle", r.idle)
	select {
	case <-attempts:
		t.Fatal("a message to a recipient that stayed unreachable started another pass")
	default:
	}
}

// The code review's case: the pass that gets through ends with messages
// waiting for a session (holdWaiting, carol's chat message), not with an
// empty queue. bob's message still goes.
func TestAMessageQueuedWhileABlockedPassEndsWaitingIsDelivered(t *testing.T) {
	r := newRigWith(t, Config{}, store.NewMemory(), newFakeClock())
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	var delivered atomic.Int32
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == alice && !d.Notification {
			delivered.Add(1)
		}
		return nil
	})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: alice, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "c1", "chat", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first passes", r.idle)
	l := r.listen(t)
	first, c1 := r.connectScripted(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		return &msrp.StatusError{Code: msrp.StatusRequestTimeout}
	})
	waitFor(t, "the failed attempt", func() bool { return c1.got.Load() == 1 && r.idle() })
	_ = first.Close()
	waitFor(t, "idle", r.idle)
	_, _ = r.connectScripted(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group}, func(*msrp.Message) error {
		if err := r.e.Submit(context.Background(), standalone(bob, alice, chat(t, "d1", "are you there?", 0))); err != nil {
			t.Errorf("bob: %v", err)
		}
		return nil
	})
	waitFor(t, "bob's message delivered", func() bool { return delivered.Load() == 1 })
	waitFor(t, "idle", r.idle)
	r.e.mu.Lock()
	h := r.e.recipients[alice].hold
	r.e.mu.Unlock()
	if h != holdWaiting {
		t.Fatalf("hold %d, want waiting: carol's chat message waits for a session", h)
	}
}

type gate struct{ entered, release chan struct{} }

func newGate() gate { return gate{make(chan struct{}, 1), make(chan struct{})} }

// QA's case: a pass of single messages that starts with the queue blocked
// (by the previous pass of the same run) and gets through. A message that
// came in during it goes too, not at the retry timer.
func TestASinglesPassThatStartsBlockedAndGetsThroughReadsTheQueueAgain(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour, MaxRetryInterval: time.Hour})
	drainInvites(t, r.d)
	g1, g2 := newGate(), newGate()
	var third, firstTries atomic.Int32
	r.d.onPager(func(d Delivery) error {
		switch {
		case bytes.Contains(d.CPIM, []byte("text-first")):
			if firstTries.Add(1) > 1 {
				return nil
			}
			g1.entered <- struct{}{}
			<-g1.release
			return errors.New("480 Temporarily Unavailable")
		case bytes.Contains(d.CPIM, []byte("text-second")):
			g2.entered <- struct{}{}
			<-g2.release
			return nil
		case bytes.Contains(d.CPIM, []byte("text-third")):
			third.Add(1)
		}
		return nil
	})
	// carol's chat message waits for a session: holdWaiting.
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "c1", "text-chat", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	// s1 is tried on its own and blocks in the pager.
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s1", "text-first", 0))); err != nil {
		t.Fatal(err)
	}
	<-g1.entered
	// s2 comes in while the queue is still holdWaiting: a single too.
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s2", "text-second", 0))); err != nil {
		t.Fatal(err)
	}
	close(g1.release) // s1 fails: stop, holdBlocked; the run goes on with s2
	<-g2.entered
	// s3 comes in while a pass runs with the queue blocked.
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s3", "text-third", 0))); err != nil {
		t.Fatal(err)
	}
	close(g2.release) // s2 goes: bob is reachable
	waitFor(t, "s3 delivered", func() bool { return third.Load() == 1 })
	waitFor(t, "s1 delivered on the same read", func() bool { return firstTries.Load() == 2 && r.idle() })
}

// The code review's case: the same singles pass gets through, and s3 comes
// in only once the engine is idle. The queue must not be left blocked, or s3
// and s1 wait for the retry timer, up to an hour.
func TestASinglesPassThatGetsThroughUnblocksTheQueue(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour, MaxRetryInterval: time.Hour})
	drainInvites(t, r.d)
	g1, g2 := newGate(), newGate()
	var third, firstTries atomic.Int32
	r.d.onPager(func(d Delivery) error {
		switch {
		case bytes.Contains(d.CPIM, []byte("text-first")):
			if firstTries.Add(1) > 1 {
				return nil
			}
			g1.entered <- struct{}{}
			<-g1.release
			return errors.New("480 Temporarily Unavailable")
		case bytes.Contains(d.CPIM, []byte("text-second")):
			g2.entered <- struct{}{}
			<-g2.release
			return nil
		case bytes.Contains(d.CPIM, []byte("text-third")):
			third.Add(1)
		}
		return nil
	})
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "c1", "text-chat", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s1", "text-first", 0))); err != nil {
		t.Fatal(err)
	}
	<-g1.entered
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s2", "text-second", 0))); err != nil {
		t.Fatal(err)
	}
	close(g1.release) // s1 fails: stop, holdBlocked; the run goes on with s2
	<-g2.entered
	close(g2.release) // s2 goes: bob is reachable
	waitFor(t, "s1 delivered on the read that follows", func() bool { return firstTries.Load() == 2 && r.idle() })
	r.e.mu.Lock()
	h := r.e.recipients[bob].hold
	r.e.mu.Unlock()
	if h == holdBlocked {
		t.Fatal("the queue is left blocked after a pass that got through")
	}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s3", "text-third", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "s3 delivered", func() bool { return third.Load() == 1 })
}

// A pass of singles that stops reads nothing more: the recipient could not
// be reached, so the queue waits for an event or the retry timer.
func TestASinglesPassThatStopsReadsNothingMore(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour, MaxRetryInterval: time.Hour})
	drainInvites(t, r.d)
	var tries atomic.Int32
	r.d.onPager(func(d Delivery) error {
		if bytes.Contains(d.CPIM, []byte("text-first")) {
			tries.Add(1)
			return errors.New("480 Temporarily Unavailable")
		}
		return nil
	})
	// carol's chat message waits for a session: holdWaiting, so s1 is
	// tried on its own.
	if err := r.e.Submit(t.Context(), Origin{Sender: carol, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: chat(t, "c1", "text-chat", 0)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "s1", "text-first", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the attempt", func() bool { return tries.Load() >= 1 && r.idle() })
	if got := tries.Load(); got != 1 {
		t.Fatalf("s1 tried %d times: a pass that stopped read the queue again", got)
	}
}
