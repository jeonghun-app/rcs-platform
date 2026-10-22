package messaging

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

func TestAStandaloneMessageWaitsForTheRecipientToRegister(t *testing.T) {
	r := newRig(t, Config{})
	r.d.onPager(func(Delivery) error { return ErrOffline })
	msg := chat(t, "m1", "are you there?", 0)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, msg)); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); d.Recipient != bob || d.Sender != alice || !bytes.Equal(d.CPIM.Bytes(), msg) || d.Conversation != conv {
		t.Fatalf("delivery %+v", d)
	}
	waitFor(t, "the message to be released", func() bool { return r.queued(t, bob) == 1 })

	r.d.onPager(nil)
	r.e.UserRegistered(bob, false)
	if d := r.d.nextPager(t); !bytes.Equal(d.CPIM.Bytes(), msg) {
		t.Fatalf("redelivery %+v", d)
	}
	waitFor(t, "the delivery to be counted", func() bool { return r.m.get("delivery.pager") == 1 })
	if r.queued(t, bob) != 0 || r.m.get("delivery.pager_failed") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestAnExpiredMessageSendsTheNegativeNotificationItsSenderAskedFor(t *testing.T) {
	r := newRig(t, Config{StoreTTL: time.Hour})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == bob {
			return ErrOffline
		}
		return nil
	})
	asked := chat(t, "m1", "asked", imdn.NegativeDelivery)
	silent := chat(t, "m2", "not asked", imdn.PositiveDelivery)
	for _, m := range [][]byte{asked, silent} {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, m)); err != nil {
			t.Fatal(err)
		}
	}
	// The first attempt finds bob unreachable; what follows waits for a
	// registration or the retry timer.
	r.d.nextPager(t)
	waitFor(t, "idle", r.idle)
	for len(r.d.pagers) > 0 {
		if d := <-r.d.pagers; d.Recipient != bob {
			t.Fatalf("delivery %+v", d)
		}
	}
	waitFor(t, "both messages to be released", func() bool { return r.queued(t, bob) == 2 })

	if n, err := r.e.Sweep(t.Context()); err != nil || n != 0 {
		t.Fatalf("Sweep before expiry = %d, %v", n, err)
	}
	r.clock.Advance(time.Hour)
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 2 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	d := r.d.nextPager(t)
	if d.Recipient != alice || d.Sender != bob || !d.Notification {
		t.Fatalf("notification delivery %+v", d)
	}
	n := readNotification(t, d.CPIM.Bytes())
	if n.MessageID != "m1" || n.Kind != imdn.DeliveryNotification || n.Status != imdn.Failed || n.RecipientURI != bob ||
		n.DateTime != "2026-03-04T05:06:07.000Z" {
		t.Fatalf("notification %+v", n)
	}
	select {
	case d := <-r.d.pagers:
		t.Fatalf("a second notification: %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if r.queued(t, bob) != 0 || r.m.get("message.expired") != 2 || r.m.get("imdn.generated.failed") != 1 {
		t.Fatalf("queued %d, metrics %v", r.queued(t, bob), r.m)
	}
}

func TestAnUndeliverableMessageIsAnsweredAtOnce(t *testing.T) {
	r := newRig(t, Config{})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == bob {
			return ErrUndeliverable
		}
		return nil
	})
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", imdn.NegativeDelivery))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	d := r.d.nextPager(t)
	if n := readNotification(t, d.CPIM.Bytes()); d.Recipient != alice || n.Status != imdn.Failed {
		t.Fatalf("delivery %+v", d)
	}
	waitFor(t, "the failure to be counted", func() bool { return r.m.get("delivery.undeliverable") == 1 })
	if r.queued(t, bob) != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestANotificationIsNeverAnsweredWithAnother(t *testing.T) {
	r := newRig(t, Config{StoreTTL: time.Hour})
	r.d.onPager(func(d Delivery) error { return ErrOffline })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", imdn.PositiveDelivery|imdn.NegativeDelivery))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	if err := r.e.Submit(t.Context(), standalone(bob, alice, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	waitFor(t, "both released", func() bool { return r.queued(t, alice) == 1 && r.queued(t, bob) == 1 })
	r.clock.Advance(time.Hour)
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 2 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	// Only the message gets a notification; the notification gets none.
	if r.m.get("imdn.generated.failed") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestRunSweepsEveryIntervalUntilCancelled(t *testing.T) {
	r := newRig(t, Config{StoreTTL: time.Minute, SweepInterval: time.Minute})
	r.d.onPager(func(Delivery) error { return ErrOffline })
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	waitFor(t, "release", func() bool { return r.queued(t, bob) == 1 })
	ctx, cancel := context.WithCancel(t.Context())
	ran := make(chan error, 1)
	go func() { ran <- r.e.Run(ctx) }()
	waitFor(t, "the expiry to be swept", func() bool {
		r.clock.Advance(time.Minute)
		return r.m.get("message.expired") == 1
	})
	cancel()
	select {
	case err := <-ran:
		if err != context.Canceled {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(hangGuard):
		t.Fatal("Run did not stop")
	}
}

func TestTwoEnginesSharingAStoreDeliverEachMessageOnce(t *testing.T) {
	st := store.NewMemory()
	clock := newFakeClock()
	r1 := newRigWith(t, Config{InstanceID: "task-1"}, st, clock)
	r2 := newRigWith(t, Config{InstanceID: "task-2", Rand: seeded(2)}, st, clock)

	// Both tasks see bob offline while the messages arrive...
	var online atomic.Bool
	var mu sync.Mutex
	delivered := map[string]int{}
	pager := func(d Delivery) error {
		if !online.Load() {
			return ErrOffline
		}
		mu.Lock()
		delivered[string(d.CPIM.Bytes())]++
		mu.Unlock()
		return nil
	}
	r1.d.onPager(pager)
	r2.d.onPager(pager)
	const n = 40
	for i := range n {
		r := r1
		if i%2 == 1 {
			r = r2
		}
		if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m", string(rune('A'+i)), 0))); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "every message stored", func() bool { return r1.queued(t, bob) == n })

	// ...then both hear of his registration at once.
	online.Store(true)
	var wg sync.WaitGroup
	for _, r := range []*rig{r1, r2} {
		wg.Add(1)
		go func() { defer wg.Done(); r.e.UserRegistered(bob, false) }()
	}
	wg.Wait()
	waitFor(t, "bob's queue to empty", func() bool { return r1.queued(t, bob) == 0 })
	waitFor(t, "every delivery to be counted", func() bool {
		return r1.m.get("delivery.pager")+r2.m.get("delivery.pager") >= n
	})
	if got := r1.m.get("delivery.pager") + r2.m.get("delivery.pager"); got != n {
		t.Fatalf("%d deliveries of %d messages", got, n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(delivered) != n {
		t.Fatalf("%d distinct messages delivered, want %d", len(delivered), n)
	}
	for body, c := range delivered {
		if c != 1 {
			t.Fatalf("%q delivered %d times", body, c)
		}
	}
}

func TestAClientThatTakesNoSessionsGetsWhatFitsByPager(t *testing.T) {
	r := newRig(t, Config{PagerLimit: 500})
	r.d.onInvite(func(Invitation) error { return ErrNoSessions })
	small := chat(t, "m1", "short", 0)
	large := chat(t, "m2", string(bytes.Repeat([]byte("x"), 600)), 0)
	chatFrom := func(body []byte) Origin {
		return Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(body)}
	}
	if err := r.e.Submit(t.Context(), chatFrom(large)); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	waitFor(t, "the pager-only marker", func() bool { return r.m.get("invite.no_sessions") == 1 })
	if err := r.e.Submit(t.Context(), chatFrom(small)); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); !bytes.Equal(d.CPIM.Bytes(), small) {
		t.Fatalf("pager delivery %q", d.CPIM)
	}
	// The large message waits; no further invitation goes out until bob
	// registers again.
	waitFor(t, "the small message to go", func() bool { return r.queued(t, bob) == 1 })
	select {
	case inv := <-r.d.invites:
		t.Fatalf("invited again: %+v", inv)
	default:
	}
	// A refresh on the same flow keeps the marker (ADR 0004).
	r.e.UserRegistered(bob, false)
	waitFor(t, "the refresh to be handled", r.idle)
	select {
	case inv := <-r.d.invites:
		t.Fatalf("invited after a refresh: %+v", inv)
	case <-time.After(20 * time.Millisecond):
	}
	r.d.onInvite(nil)
	r.e.UserRegistered(bob, true)
	if inv := r.d.nextInvite(t); inv.Recipient != bob {
		t.Fatalf("invitation %+v", inv)
	}
}

func TestAFailedInvitationIsRetriedOnlyAfterTheInviteTimeout(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Minute, RetryInterval: time.Hour})
	o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(chat(t, "m1", "hi", 0))}
	if err := r.e.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	r.e.InviteFailed(inv, ErrOffline)
	o.CPIM = content.BodyOf(chat(t, "m2", "again", 0))
	if err := r.e.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both stored", func() bool { return r.queued(t, bob) == 2 })
	select {
	case inv := <-r.d.invites:
		t.Fatalf("invited within the timeout: %+v", inv)
	case <-time.After(20 * time.Millisecond):
	}
	r.clock.Advance(time.Minute)
	o.CPIM = content.BodyOf(chat(t, "m3", "once more", 0))
	if err := r.e.Submit(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	waitFor(t, "the second invitation to be counted", func() bool { return r.m.get("invite.sent") == 2 })
	if r.m.get("invite.failed") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestNetworkReportedDispositionsBecomeNotifications(t *testing.T) {
	r := newRig(t, Config{})
	var got []Delivery
	r.d.onPager(func(d Delivery) error { return nil })
	msg := chat(t, "m1", "hi", imdn.PositiveDelivery)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, msg)); err != nil {
		t.Fatal(err)
	}
	d := r.d.nextPager(t)
	if err := r.e.Report(t.Context(), d, imdn.DeliveryNotification, imdn.Delivered); err != nil {
		t.Fatal(err)
	}
	got = append(got, r.d.nextPager(t))
	if n := readNotification(t, got[0].CPIM.Bytes()); got[0].Recipient != alice || n.Status != imdn.Delivered || n.MessageID != "m1" {
		t.Fatalf("notification %+v", got[0])
	}
	if err := r.e.Report(t.Context(), d, imdn.DisplayNotification, imdn.Displayed); err == nil {
		t.Fatal("a display notification nobody asked for was generated")
	}
	if err := r.e.Report(t.Context(), got[0], imdn.DeliveryNotification, imdn.Delivered); err == nil {
		t.Fatal("a notification about a notification was generated")
	}
}
