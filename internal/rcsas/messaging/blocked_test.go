package messaging

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

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
