package regevent

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// onceFailing fails the first NOTIFY with err (or answers code), then 200s.
type onceFailing struct {
	mu     sync.Mutex
	failed bool
	err    error
	code   int
	ok     []*sip.Request
}

func (o *onceFailing) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.failed {
		o.failed = true
		if o.err != nil {
			return nil, o.err
		}
		return sip.NewResponse(req, o.code, "", "s")
	}
	o.ok = append(o.ok, req)
	return sip.NewResponse(req, 200, "", "s")
}

// TestAFinalThatFailsOnceIsSentAgain: the set ends; its terminated NOTIFY
// meets a full transport queue, or a 503 from a busy P-CSCF. Over the next
// minutes of sweeps, the subscriber gets a terminated NOTIFY (QA's F1 on
// #256).
func TestAFinalThatFailsOnceIsSentAgain(t *testing.T) {
	for name, o := range map[string]*onceFailing{
		"queue full": {err: transport.ErrQueueFull},
		"503":        {code: 503},
		"500":        {code: 500},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			n := newNotifierWith(t, e, e.store, o)
			if err := n.Ended(bg, before, Rejected); err != nil {
				t.Fatal(err)
			}
			n.Wait()
			for range 30 {
				e.clock.advance(10 * time.Second)
				_, _ = n.Sweep(bg, 10)
				n.Wait()
			}
			got := 0
			for _, r := range o.ok {
				if ss, _ := r.Header.SubscriptionState(); ss.State == "terminated" {
					got++
				}
			}
			if got != 1 || len(e.subscriptions(impu1)) != 0 {
				t.Errorf("%s: terminated NOTIFYs delivered after the failure %d, subscriptions left %d; want 1 and 0", name, got, len(e.subscriptions(impu1)))
			}
		})
	}
}

// TestAFinalNobodyAnswersIsGivenUpAfterFiveSends: sent again later each
// time, then deleted and counted; one answered with a §4.2.2 code is not
// sent again.
func TestAFinalNobodyAnswersIsGivenUpAfterFiveSends(t *testing.T) {
	for name, c := range map[string]struct {
		s     Sender
		sends int
	}{
		"no answer":  {silent{}, maxFinalSends},
		"481":        {&sender{status: 481}, 1},
		"queue full": {&sender{err: transport.ErrQueueFull}, maxFinalSends},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			m := &counts{}
			rec := &countingSender{Sender: c.s}
			n := newNotifierWith(t, e, e.store, rec, func(cfg *Config) { cfg.NotifyTimeout, cfg.Metrics = 10*time.Millisecond, m })
			if err := n.Ended(bg, before, Rejected); err != nil {
				t.Fatal(err)
			}
			n.Wait()
			for range 60 {
				e.clock.advance(10 * time.Second)
				_, _ = n.Sweep(bg, 10)
				n.Wait()
			}
			if got := rec.count(); got != c.sends {
				t.Errorf("%d sends, want %d", got, c.sends)
			}
			if len(e.subscriptions(impu1)) != 0 {
				t.Error("the subscription is left")
			}
			abandoned := int64(0)
			if c.sends == maxFinalSends {
				abandoned = 1
			}
			if m.get("regevent.final_abandoned") != abandoned {
				t.Errorf("final_abandoned %d", m.get("regevent.final_abandoned"))
			}
		})
	}
}

// countingSender counts the NOTIFYs passed to Sender.
type countingSender struct {
	Sender
	mu sync.Mutex
	n  int
}

func (c *countingSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.Sender.Send(ctx, req)
}

func (c *countingSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestALapsedSubscriptionsFinalIsSavedBeforeItIsSent: the end is found
// while notifying (the binding moved to another P-CSCF), so nothing saved
// it before; it is saved Terminated, with its reason, before it is numbered,
// and a send without an answer is made again with that reason.
func TestALapsedSubscriptionsFinalIsSavedBeforeItIsSent(t *testing.T) {
	e := newEnv(t)
	s := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	moved := s.Clone()
	moved.Contacts[0].Path = []string{"<sip:orig@pcscf2." + realm + ";lr>"}
	moved = e.saved(moved)
	o := &onceFailing{code: 503}
	n := newNotifierWith(t, e, e.store, o)
	n.Changed(bg, s, moved, Registered)
	n.Wait()
	for range 3 {
		e.clock.advance(10 * time.Second)
		_, _ = n.Sweep(bg, 10)
		n.Wait()
	}
	if len(o.ok) != 1 {
		t.Fatalf("%d NOTIFYs after the failed one", len(o.ok))
	}
	if ss, _ := o.ok[0].Header.SubscriptionState(); ss.State != "terminated" || ss.Reason() != "deactivated" {
		t.Errorf("sent again as %+v, want terminated;reason=deactivated", ss)
	}
	if len(e.subscriptions(impu1)) != 0 {
		t.Error("the subscription is left")
	}
}

// TestAnEndOfASetRegisteredAgainHasNoBody: the set ended, and a device
// registered it again, a new record, before the end's NOTIFY went; the
// NOTIFY says terminated, deactivated, and lists no identity, which the new
// registration owns (#256 code review).
func TestAnEndOfASetRegisteredAgainHasNoBody(t *testing.T) {
	e := newEnv(t)
	old := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	k := len(e.send.notifies())
	if err := e.store.DeleteRegistration(bg, old); err != nil {
		t.Fatal(err)
	}
	e.saved(&state.Registration{Key: set1, Incarnation: 8, Contacts: []state.Contact{binding(2, time.Hour)}, Identities: old.Identities})
	if err := n.Ended(bg, old, Deactivated); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs", len(got))
	}
	if ss, _ := got[0].Header.SubscriptionState(); ss.State != "terminated" || ss.Reason() != "deactivated" || len(got[0].Body) != 0 {
		t.Errorf("the end: %+v with %d bytes of body", ss, len(got[0].Body))
	}
}

// timedSender answers every NOTIFY 500 at once and records when, by the
// test's clock, each was sent.
type timedSender struct {
	mu  sync.Mutex
	now func() time.Time
	at  []time.Time
}

func (s *timedSender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.at = append(s.at, s.now())
	s.mu.Unlock()
	return sip.NewResponse(req, 500, "", "s")
}

// TestAnUnansweredFinalIsSentAgainLaterEachTime (#336): at 0, 10 s, 30 s,
// 1 min 10 s and 2 min 30 s after the first send, when each fails at once.
func TestAnUnansweredFinalIsSentAgainLaterEachTime(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	s := &timedSender{now: e.clock.Now}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, s, func(c *Config) { c.Metrics = m })
	start := e.clock.Now()
	if err := n.Ended(bg, before, Rejected); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	// Long past the last send: a sixth would come by 5 min 10 s.
	for range 600 {
		e.clock.advance(time.Second)
		_, _ = n.Sweep(bg, 10)
		n.Wait()
	}
	var got []time.Duration
	for _, at := range s.at {
		got = append(got, at.Sub(start))
	}
	want := []time.Duration{0, 10 * time.Second, 30 * time.Second, 70 * time.Second, 150 * time.Second}
	if !slices.Equal(got, want) {
		t.Errorf("sent at %v, want %v", got, want)
	}
	if m.get("regevent.final_abandoned") != 1 || len(e.subscriptions(impu1)) != 0 {
		t.Errorf("abandoned %d, subscriptions left %d; want 1 and 0", m.get("regevent.final_abandoned"), len(e.subscriptions(impu1)))
	}
}

// heldSender holds every NOTIFY until release is closed, then fails it,
// and counts the sends in flight at once.
type heldSender struct {
	mu      sync.Mutex
	release chan struct{}
	sent    chan struct{}
	busy    int
	most    int
	n       int
}

func (s *heldSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.n++
	s.busy++
	s.most = max(s.most, s.busy)
	s.mu.Unlock()
	s.sent <- struct{}{}
	defer func() { s.mu.Lock(); s.busy--; s.mu.Unlock() }()
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return nil, transport.ErrQueueFull
}

// TestAFinalIsNotSentAgainWhileItsFirstSendWaits (#336): another instance's
// sweep leaves alone the final whose send may still be waiting for its
// answer, for pendingEnd from the send, and takes it over after.
func TestAFinalIsNotSentAgainWhileItsFirstSendWaits(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	s := &heldSender{release: make(chan struct{}), sent: make(chan struct{}, 4)}
	a := newNotifierWith(t, e, e.store, s)
	b := newNotifierWith(t, e, e.store, s)
	if err := a.Ended(bg, before, Rejected); err != nil {
		t.Fatal(err)
	}
	<-s.sent
	// Within the hold: B leaves it alone.
	e.clock.advance(a.pendingEnd() - time.Second)
	if _, err := b.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	b.Wait()
	s.mu.Lock()
	n := s.n
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d sends while the first could still be answered", n)
	}
	// Past it, A's send has given up by NotifyTimeout: B takes it over.
	e.clock.advance(2 * time.Second)
	if _, err := b.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.sent:
	case <-time.After(10 * time.Second):
		t.Fatal("B did not take the final over")
	}
	close(s.release)
	b.Wait()
	a.Wait()
}

// watchingSender holds every NOTIFY until release is closed, then fails it;
// at each final it notes how far past the test's clock the subscription's
// expiry is, and it counts the sends of each subscription (by Call-ID) in
// flight at once.
type watchingSender struct {
	e       *env
	mu      sync.Mutex
	release chan struct{}
	sent    chan struct{}
	busy    map[string]int
	most    int
	finals  map[string]int
	ahead   []time.Duration
}

func (s *watchingSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	id := req.Header.Get("Call-ID")
	final := false
	if ss, err := req.Header.SubscriptionState(); err == nil && ss.State == "terminated" {
		final = true
	}
	now := s.e.clock.Now()
	ahead := time.Duration(-1)
	if final {
		for _, impu := range []string{impu1, tel1} {
			subs, _ := s.e.store.SubscriptionsOf(bg, impu)
			for _, sub := range subs {
				if sub.Terminated && sub.NotifiedOf == state.FinalNotify {
					ahead = sub.Expires.Sub(now)
				}
			}
		}
	}
	s.mu.Lock()
	if s.busy == nil {
		s.busy, s.finals = map[string]int{}, map[string]int{}
	}
	s.busy[id]++
	s.most = max(s.most, s.busy[id])
	if final {
		s.finals[id]++
		s.ahead = append(s.ahead, ahead)
	}
	s.mu.Unlock()
	if final {
		s.sent <- struct{}{}
	}
	defer func() { s.mu.Lock(); s.busy[id]--; s.mu.Unlock() }()
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return nil, transport.ErrQueueFull
}

// TestEveryWayAFinalStartsHoldsItForItsSend (#336): a set's end, a
// subscription that lapsed while notifying, one a P-CSCF's pushed out, and
// an unsubscribe each send their final with the subscription held for
// NotifyTimeout and the margin from the send, and another instance's
// sweep a NotifyTimeout later leaves it alone.
func TestEveryWayAFinalStartsHoldsItForItsSend(t *testing.T) {
	const timeout = 30 * time.Second
	// Each start calls checked once its final is queued, before any send of
	// it; a start may block until the send is let go.
	for name, start := range map[string]func(t *testing.T, e *env, a *Notifier, checked func()){
		"the set's end": func(t *testing.T, e *env, a *Notifier, checked func()) {
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			if err := a.Ended(bg, before, Rejected); err != nil {
				t.Error(err)
			}
			checked()
		},
		"the set's end, waiting its turn": func(t *testing.T, e *env, a *Notifier, checked func()) {
			// The second final waits behind the first (SetConcurrency 1):
			// its expiry is the end's until it is numbered.
			before := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			r := subscribe(t, tel1, pcscfPath, 3600)
			_ = r.Header.Set("Call-ID", "sub-tel")
			res, after := e.notifier(1).Subscribe(bg, r)
			wantStatus(t, res, 200)
			after(bg)
			if err := a.Ended(bg, before, Rejected); err != nil {
				t.Error(err)
			}
			wantHeld(t, e, timeout+pendingMargin)
			checked()
		},
		"lapsed while notifying": func(t *testing.T, e *env, a *Notifier, checked func()) {
			set := e.registered(binding(1, time.Hour))
			e.subscribed(e.notifier(1))
			moved := set.Clone()
			moved.Contacts[0].Path = []string{"<sip:orig@pcscf2." + realm + ";lr>"}
			checked()
			a.Changed(bg, set, e.saved(moved), Registered)
		},
		"pushed out": func(t *testing.T, e *env, a *Notifier, checked func()) {
			e.registered(binding(1, time.Hour))
			ue := subscribe(t, impu1, impu1, 3600)
			_ = ue.Header.Set("Contact", "<"+binding(1, 0).URI+">")
			first := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.MaxPerSet = 2 })
			for i, req := range []*sip.Request{ue, subscribe(t, impu1, pcscfPath, 3600)} {
				_ = req.Header.Set("Call-ID", "sub-"+string(rune('a'+i)))
				res, after := first.Subscribe(bg, req)
				wantStatus(t, res, 200)
				after(bg)
			}
			first.Wait()
			req := subscribe(t, tel1, pcscfPath, 3600)
			_ = req.Header.Set("Call-ID", "sub-c")
			res, after := a.Subscribe(bg, req)
			wantStatus(t, res, 200)
			wantHeld(t, e, timeout+pendingMargin)
			checked()
			after(bg)
		},
		"unsubscribed": func(t *testing.T, e *env, a *Notifier, checked func()) {
			e.registered(binding(1, time.Hour))
			res, _ := e.subscribed(e.notifier(1))
			r, after := a.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 0))
			wantStatus(t, r, 200)
			wantHeld(t, e, timeout+pendingMargin)
			checked()
			after(bg)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			s := &watchingSender{e: e, release: make(chan struct{}), sent: make(chan struct{}, 8)}
			cfg := func(c *Config) { c.NotifyTimeout, c.MaxPerSet, c.SetConcurrency = timeout, 2, 1 }
			a := newNotifierWith(t, e, e.store, s, cfg)
			b := newNotifierWith(t, e, e.store, s, cfg)
			checked := make(chan struct{})
			started := make(chan struct{})
			go func() {
				defer close(started)
				start(t, e, a, func() { close(checked) })
			}()
			<-checked
			select {
			case <-s.sent:
			case <-time.After(10 * time.Second):
				t.Fatal("no final was sent")
			}
			e.clock.advance(timeout)
			if _, err := b.Sweep(bg, 10); err != nil {
				t.Fatal(err)
			}
			close(s.release)
			<-started
			b.Wait()
			a.Wait()
			s.mu.Lock()
			defer s.mu.Unlock()
			for id, n := range s.finals {
				if n != 1 {
					t.Errorf("%s: %d finals sent", id, n)
				}
			}
			if s.most != 1 || s.ahead[0] != timeout+pendingMargin {
				t.Errorf("%d of one at once, the first held %v ahead; want one at a time, held %v", s.most, s.ahead[0], timeout+pendingMargin)
			}
		})
	}
}

// wantHeld fails unless a terminated subscription of impu1 or tel1 has its
// expiry ahead of the test's clock by ahead, before any send held it again.
func wantHeld(t *testing.T, e *env, ahead time.Duration) {
	t.Helper()
	now := e.clock.Now()
	for _, impu := range []string{impu1, tel1} {
		for _, sub := range e.subscriptions(impu) {
			if sub.Terminated && sub.NotifiedOf != state.FinalNotify && sub.Expires.Sub(now) != ahead {
				t.Errorf("a final not yet numbered is held %v ahead, want %v", sub.Expires.Sub(now), ahead)
			}
		}
	}
}

// holdFailing fails, while failing, every save of a subscription already
// saved Terminated: the hold of a final, not the save that ended it.
type holdFailing struct {
	*state.Memory
	mu      sync.Mutex
	failing bool
}

func (h *holdFailing) SaveSubscription(ctx context.Context, s *state.Subscription) (*state.Subscription, error) {
	h.mu.Lock()
	failing := h.failing
	h.mu.Unlock()
	if cur, err := h.Memory.Subscription(ctx, s.ID); failing && err == nil && cur.Terminated {
		return nil, errThrottled
	}
	return h.Memory.SaveSubscription(ctx, s)
}

// TestAFinalWhoseHoldCannotBeSavedIsLeftToTheSweep (#346 QA): a store
// failure while the final is held again sends nothing, as the hold is what
// keeps a sweep from sending it at the same time; the end saved before it
// stays, and the sweep after its expiry sends the final.
func TestAFinalWhoseHoldCannotBeSavedIsLeftToTheSweep(t *testing.T) {
	e := newEnv(t)
	set := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	h := &holdFailing{Memory: e.store, failing: true}
	s := &sender{}
	m := &counts{}
	n := newNotifierWith(t, e, h, s, func(c *Config) { c.Metrics = m })
	if err := n.Ended(bg, set, Rejected); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	if len(s.notifies()) != 0 || m.get("regevent.internal_errors") != 1 {
		t.Fatalf("%d NOTIFYs, %d internal errors; want none and 1", len(s.notifies()), m.get("regevent.internal_errors"))
	}
	h.mu.Lock()
	h.failing = false
	h.mu.Unlock()
	e.clock.advance(time.Minute)
	if _, err := n.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	got := s.notifies()
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs from the sweep", len(got))
	}
	if ss, _ := got[0].Header.SubscriptionState(); ss.State != "terminated" || ss.Reason() != "rejected" {
		t.Errorf("sent as %+v, want terminated;reason=rejected", ss)
	}
}
