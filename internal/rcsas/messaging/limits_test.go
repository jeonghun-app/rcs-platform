package messaging

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

func TestMessagesBeyondTheSizeLimitsAreRefused(t *testing.T) {
	r := newRig(t, Config{MaxMessageSize: 4096, PagerLimit: 1300})
	big := chat(t, "m1", strings.Repeat("x", 1300), 0)
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, big))); got != ReasonTooLarge {
		t.Fatalf("a pager-mode message over the pager limit: %q", got)
	}
	large := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: store.Standalone, CPIM: big}
	if err := r.e.Submit(t.Context(), large); err != nil {
		t.Fatalf("the same content in large mode: %v", err)
	}
	large.CPIM = chat(t, "m2", strings.Repeat("x", 4096), 0)
	if got := rejected(r.e.Submit(t.Context(), large)); got != ReasonTooLarge {
		t.Fatalf("a message over the size limit: %q", got)
	}
	if r.m.get("message.rejected.too_large") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestEachSenderIsHeldToItsRate(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: 60, Burst: 3}, NotificationRate: Rate{PerMinute: 60, Burst: 1}})
	send := func(from string) error {
		return r.e.Submit(t.Context(), standalone(from, bob, chat(t, "m", "hi", 0)))
	}
	for i := range 3 {
		if err := send(alice); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if got := rejected(send(alice)); got != ReasonRateLimited {
		t.Fatalf("beyond the burst: %q", got)
	}
	if err := send(carol); err != nil {
		t.Fatalf("another sender: %v", err)
	}
	r.clock.Advance(time.Second)
	if err := send(alice); err != nil {
		t.Fatalf("after a token refilled: %v", err)
	}
	if got := rejected(send(alice)); got != ReasonRateLimited {
		t.Fatalf("beyond the refill: %q", got)
	}
	// Notifications draw on an allowance of their own.
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, receipt(t, "m", imdn.DeliveryNotification, imdn.Delivered)))); got != ReasonIMDNUnknown {
		t.Fatalf("a notification from a sender out of message tokens: %q", got)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, receipt(t, "m", imdn.DeliveryNotification, imdn.Delivered)))); got != ReasonRateLimited {
		t.Fatalf("beyond the notification burst: %q", got)
	}
}

func TestPagerAndLargeModeShareThePipeline(t *testing.T) {
	r := newRig(t, Config{PagerLimit: 600})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Standalone})
	small := chat(t, "m1", "pager", imdn.PositiveDelivery)
	large := chat(t, "m2", strings.Repeat("large ", 200), imdn.PositiveDelivery)

	// The same checks apply to both: a CPIM From naming someone else is
	// refused whichever way it arrived.
	forged := cpimMessage(t, cpim.Address{URI: carol}, "m3", "x", 0)
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, forged))); got != ReasonFromMismatch {
		t.Fatalf("pager mode: %q", got)
	}
	if code := a.outcome(t, cpim.ContentType, forged); code != 403 {
		t.Fatalf("large mode: %d", code)
	}

	if err := r.e.Submit(t.Context(), standalone(alice, bob, small)); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); !bytes.Equal(d.CPIM, small) {
		t.Fatalf("pager delivery %q", d.CPIM)
	}
	a.send(t, large)
	inv := r.d.nextInvite(t)
	if inv.Mode != store.Standalone || inv.Recipient != bob || inv.QueueID == "" {
		t.Fatalf("invitation %+v", inv)
	}
	b, leg := r.largeMode(t, l, inv)
	if got := b.next(t); !bytes.Equal(got.Body, large) {
		t.Fatalf("large-mode delivery of %d bytes", len(got.Body))
	}
	waitDone(t, leg.Finished())
	// Both were recorded as sent, so both can be answered.
	for _, id := range []string{"m1", "m2"} {
		if err := r.e.Submit(t.Context(), standalone(bob, alice, receipt(t, id, imdn.DeliveryNotification, imdn.Delivered))); err != nil {
			t.Fatalf("notification about %s: %v", id, err)
		}
	}
	if r.m.get("message.rejected.from_mismatch") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestAcceptedCPIMDeviationsAndRejectionReasonsAreCounted(t *testing.T) {
	r := newRig(t, Config{})
	lf := bytes.ReplaceAll(chat(t, "m1", "hi", 0), []byte("\r\n"), []byte("\n"))
	if err := r.e.Submit(t.Context(), standalone(alice, bob, lf)); err != nil {
		t.Fatal(err)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, []byte("From: <tel:+15550100001>\r\n\r\n")))); got != ReasonMalformed {
		t.Fatalf("no content headers: %q", got)
	}
	if r.m.get("cpim.deviation.bare-lf") != 1 || r.m.get("message.rejected.malformed") != 1 || r.m.get("cpim.rejected.framing") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestTheSenderDisplayNameIsEscapedForSIP(t *testing.T) {
	r := newRig(t, Config{})
	from := cpim.Address{Name: "Alice\r\nP-Asserted-Identity: <tel:+15550100005>", URI: alice}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, cpimMessage(t, from, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	d := r.d.nextPager(t)
	if strings.ContainsAny(d.SenderName, "\r\n") || d.SenderName != `Alice\u000d\u000aP-Asserted-Identity: <tel:+15550100005>` {
		t.Fatalf("SenderName = %q", d.SenderName)
	}
}

func TestSubmitNeedsAMode(t *testing.T) {
	r := newRig(t, Config{})
	err := r.e.Submit(t.Context(), Origin{Sender: alice, Recipient: bob, CPIM: chat(t, "m1", "hi", 0)})
	if err == nil || rejected(err) != "" {
		t.Fatalf("Submit without a mode = %v", err)
	}
}

func TestAFailingStoreIsReportedAsAFailureNotARejection(t *testing.T) {
	r := newRigWith(t, Config{}, failingStore{store.NewMemory()}, newFakeClock())
	err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", imdn.PositiveDelivery)))
	if err == nil || rejected(err) != "" || !errors.Is(err, errStore) {
		t.Fatalf("Submit = %v", err)
	}
	if r.m.get("store.failed") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestNewChecksItsConfiguration(t *testing.T) {
	for name, c := range map[string]struct {
		cfg Config
		ok  bool
	}{
		"no host":  {Config{MSRPPort: 2855}, false},
		"no port":  {Config{MSRPHost: "10.0.0.7"}, false},
		"complete": {Config{MSRPHost: "10.0.0.7", MSRPPort: 2855}, true},
	} {
		e, err := New(c.cfg, store.NewMemory(), newFakeDeliverer(), newCounter())
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if e != nil {
			if e.cfg.InstanceID == "" || e.cfg.StoreTTL != DefaultStoreTTL || e.cfg.PagerLimit != DefaultPagerLimit {
				t.Errorf("%s: defaults %+v", name, e.cfg)
			}
			e.Close()
		}
	}
	if _, err := New(Config{MSRPHost: "h", MSRPPort: 1}, nil, newFakeDeliverer(), newCounter()); err == nil {
		t.Error("New without a store succeeded")
	}
	if _, err := New(Config{MSRPHost: "h", MSRPPort: 1, Rand: bytes.NewReader(nil)}, store.NewMemory(), newFakeDeliverer(), newCounter()); err == nil {
		t.Error("New with an empty random source succeeded")
	}
}

// flakyStore fails the operations named in fail.
type flakyStore struct {
	store.Store
	mu   sync.Mutex
	fail map[string]bool
}

func (f *flakyStore) failing(op string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fail[op]
}

func (f *flakyStore) set(ops ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = map[string]bool{}
	for _, op := range ops {
		f.fail[op] = true
	}
}

func (f *flakyStore) Pending(ctx context.Context, r, after string, now time.Time, n int) ([]store.Message, error) {
	if f.failing("pending") {
		return nil, errStore
	}
	return f.Store.Pending(ctx, r, after, now, n)
}

func (f *flakyStore) Claim(ctx context.Context, r, id, owner string, now, until time.Time) (store.Message, error) {
	if f.failing("claim") {
		return store.Message{}, errStore
	}
	return f.Store.Claim(ctx, r, id, owner, now, until)
}

func (f *flakyStore) Remove(ctx context.Context, m store.Message, owner string) error {
	if f.failing("remove") {
		return errStore
	}
	return f.Store.Remove(ctx, m, owner)
}

func (f *flakyStore) Enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	if f.failing("enqueue") && m.Notification {
		return errStore
	}
	return f.Store.Enqueue(ctx, m, l)
}

func (f *flakyStore) Expired(ctx context.Context, now time.Time, cursor string, n int) ([]store.Message, string, error) {
	if f.failing("expired") {
		return nil, cursor, errStore
	}
	return f.Store.Expired(ctx, now, cursor, n)
}

func TestStoreFailuresDuringDeliveryKeepTheMessageAndLogNoContent(t *testing.T) {
	var logs syncBuffer
	st := &flakyStore{Store: store.NewMemory()}
	r := newRigWith(t, Config{StoreTTL: time.Hour, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}, st, newFakeClock())
	r.d.onPager(func(Delivery) error { return ErrOffline })
	msg := chat(t, "m1", "secret words", imdn.NegativeDelivery)

	st.set("pending")
	if err := r.e.Submit(t.Context(), standalone(alice, bob, msg)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed read", func() bool { return r.m.get("store.failed") == 1 })
	st.set("claim")
	r.e.UserRegistered(bob, false)
	waitFor(t, "the failed claim", func() bool { return r.m.get("store.failed") == 2 })

	// At expiry the negative notification cannot be stored: the message
	// stays for the next sweep rather than vanish unanswered.
	st.set("enqueue")
	r.clock.Advance(time.Hour)
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 0 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	st.set("expired")
	if _, err := r.e.Sweep(t.Context()); !errors.Is(err, errStore) {
		t.Fatalf("Sweep = %v", err)
	}
	st.set()
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	if d := r.d.nextPager(t); d.Recipient != alice || !d.Notification {
		t.Fatalf("delivery %+v", d)
	}
	if strings.Contains(logs.String(), "secret") || strings.Contains(logs.String(), "+15550100002") || !strings.Contains(logs.String(), "message store operation failed") {
		t.Fatalf("logs:\n%s", logs.String())
	}
}

func TestALostClaimIsCountedAndLeftToItsHolder(t *testing.T) {
	st := &flakyStore{Store: store.NewMemory()}
	r := newRigWith(t, Config{}, st, newFakeClock())
	st.set("remove")
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	waitFor(t, "the failed removal", func() bool { return r.m.get("store.failed") == 1 })
	// Another task finds it claimed until the lease ends.
	if _, err := st.Store.Claim(t.Context(), bob, firstID(t, st.Store, r), "task-2", r.clock.Now(), r.clock.Now().Add(time.Minute)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Claim = %v", err)
	}
}

// firstID returns the ID of the one message queued for bob, claimed or not.
func firstID(t *testing.T, st store.Store, r *rig) string {
	t.Helper()
	ms, err := st.Pending(t.Context(), bob, "", r.clock.Now().Add(time.Hour), 1)
	if err != nil || len(ms) != 1 {
		t.Fatalf("Pending = %v, %v", ms, err)
	}
	return ms[0].ID
}

func TestTheSystemClockIsTheDefault(t *testing.T) {
	d := newFakeDeliverer()
	e, err := New(Config{MSRPHost: "127.0.0.1", MSRPPort: 2855, Logger: slog.New(slog.DiscardHandler)}, store.NewMemory(), d, newCounter())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	d.onPager(func(Delivery) error { return ErrOffline })
	if err := e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	ms, err := store.Store(e.store).Pending(t.Context(), bob, "", time.Now().Add(time.Hour), 1)
	if err != nil || len(ms) != 1 || time.Since(ms[0].Enqueued) > time.Minute {
		t.Fatalf("Pending = %+v, %v", ms, err)
	}
}

// syncBuffer is a log sink the engine's goroutines and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
