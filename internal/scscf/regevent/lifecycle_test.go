package regevent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
)

func newNotifierWith(t *testing.T, e *env, st state.Store, s Sender, tweak ...func(*Config)) *Notifier {
	t.Helper()
	u, _ := sip.ParseURI("sip:scscf." + realm)
	cfg := Config{Store: st, Sender: s, Contact: u, Now: e.clock.Now}
	for _, f := range tweak {
		f(&cfg)
	}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func activeURIs(doc *reginfo.Info, aor string) []string {
	var out []string
	for _, r := range doc.Registrations {
		if r.AOR != aor {
			continue
		}
		for _, c := range r.Contacts {
			if c.Active() {
				out = append(out, c.URI)
			}
		}
	}
	return out
}

func (e *env) subscriptions(impu string) []*state.Subscription {
	e.t.Helper()
	subs, err := e.store.SubscriptionsOf(bg, impu)
	if err != nil {
		e.t.Fatal(err)
	}
	return subs
}

// counts records the notifier's counters.
type counts struct {
	mu sync.Mutex
	m  map[string]int64
}

func (c *counts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int64{}
	}
	c.m[name] += n
}

func (c *counts) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[name]
}

// gateStore holds the first NextNotify until released: the slow instance.
type gateStore struct {
	*state.Memory
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (g *gateStore) NextNotify(ctx context.Context, id string, of int64) (uint32, uint32, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		<-g.release
	}
	return g.Memory.NextNotify(ctx, id, of)
}

// TestTheHighestVersionNeverEndsALiveBinding: C1 deregisters binding 2 on
// instance a, whose NextNotify is slow, and C2 registers it again on
// instance b. The NOTIFY with the highest version, which the subscriber
// keeps, must not say binding 2 ended (QA's M1 on #256).
func TestTheHighestVersionNeverEndsALiveBinding(t *testing.T) {
	e := newEnv(t)
	s0 := e.registered(binding(1, time.Hour), binding(2, time.Hour))
	gs := &gateStore{Memory: e.store, entered: make(chan struct{}), release: make(chan struct{})}
	e.subscribed(e.notifier(1))
	a := newNotifierWith(t, e, gs, e.send)
	b := e.notifier(2)
	s1 := s0.Clone()
	s1.Contacts = s1.Contacts[:1]
	s1 = e.saved(s1)
	a.Changed(bg, s0, s1, Registered)
	<-gs.entered
	s2 := s1.Clone()
	s2.Contacts = append(s2.Contacts, binding(2, 2*time.Hour))
	s2 = e.saved(s2)
	b.Changed(bg, s1, s2, Registered)
	b.Wait()
	close(gs.release)
	a.Wait()
	var best *reginfo.Info
	for _, req := range e.send.notifies() {
		doc, _, _ := info(t, req)
		if best == nil || doc.Version > best.Version {
			best = doc
		}
	}
	reg, _ := best.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
	if got := activeURIs(best, impu1); len(got) != 2 {
		t.Errorf("the highest version (%d) lists %v active, want both bindings", best.Version, got)
	}
	for _, c := range reg.Contacts {
		if c.URI == binding(2, 0).URI && !c.Active() {
			t.Errorf("the highest version (%d) says live binding 2 is %s/%s", best.Version, c.State, c.Event)
		}
	}
}

// hookStore runs hook once, before the first SaveSubscription lands.
type hookStore struct {
	*state.Memory
	once sync.Once
	hook func()
}

func (h *hookStore) SaveSubscription(ctx context.Context, s *state.Subscription) (*state.Subscription, error) {
	h.once.Do(h.hook)
	return h.Memory.SaveSubscription(ctx, s)
}

// TestAChangeDuringASubscribeReachesTheSubscriber: the set changes, and is
// notified, between Subscribe reading it and saving the subscription (QA's
// M1 on #256).
func TestAChangeDuringASubscribeReachesTheSubscriber(t *testing.T) {
	e := newEnv(t)
	s0 := e.registered(binding(1, time.Hour))
	other := e.notifier(2)
	hs := &hookStore{Memory: e.store}
	hs.hook = func() {
		s1 := s0.Clone()
		s1.Contacts = append(s1.Contacts, binding(2, time.Hour))
		other.Changed(bg, s0, e.saved(s1), Registered)
		other.Wait()
	}
	n := newNotifierWith(t, e, hs, e.send)
	res, after := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	wantStatus(t, res, 200)
	after(bg)
	got := e.send.notifies()
	doc, _, _ := info(t, got[len(got)-1])
	if len(activeURIs(doc, impu1)) != 2 {
		t.Errorf("%d NOTIFYs, last version %d lists %v: binding 2 never reached the subscriber", len(got), doc.Version, activeURIs(doc, impu1))
	}
}

// ctxStore fails like the AWS SDK does once ctx is done.
type ctxStore struct{ *state.Memory }

func (c ctxStore) Subscription(ctx context.Context, id string) (*state.Subscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Memory.Subscription(ctx, id)
}

func (c ctxStore) DeleteSubscription(ctx context.Context, s *state.Subscription) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Memory.DeleteSubscription(ctx, s)
}

// silent never answers; Send returns when ctx ends.
type silent struct{}

func (silent) Send(ctx context.Context, _ *sip.Request) (*sip.Response, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestASubscriberThatDoesNotAnswerLosesItsSubscription: the NOTIFY's
// timeout must not also end the delete (QA's M2 on #256).
func TestASubscriberThatDoesNotAnswerLosesItsSubscription(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribed(e.notifier(1))
	n := newNotifierWith(t, e, ctxStore{e.store}, silent{}, func(c *Config) { c.NotifyTimeout = 50 * time.Millisecond })
	after := before.Clone()
	after.Contacts[0].Expires = t0.Add(2 * time.Hour)
	n.Changed(bg, before, e.saved(after), Registered)
	n.Wait()
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left after a NOTIFY nobody answered", len(subs))
	}
}

func pathOf(flow string) string { return "sip:" + flow + "@pcscf." + realm + ";lr" }

func bindingVia(n int, flow string, exp time.Duration) state.Contact {
	c := binding(n, exp)
	c.Path = []string{"<" + pathOf(flow) + ">"}
	c.FlowToken = flow
	return c
}

// TestARefreshIsAuthorisedAgainstTheLivePath: a P-CSCF's in-dialog
// SUBSCRIBE must assert the Path of a live binding, which a reconnection
// changes, and not the one it first subscribed with (QA's M3 and code
// review's finding 1 on #256; the lead's contract on #14).
func TestARefreshIsAuthorisedAgainstTheLivePath(t *testing.T) {
	t.Run("another live Path of the set", func(t *testing.T) {
		e := newEnv(t)
		e.registered(bindingVia(1, "f1", time.Hour), bindingVia(2, "f2", 2*time.Hour))
		n := e.notifier(1)
		res, after := n.Subscribe(bg, subscribe(t, impu1, pathOf("f1"), 3600))
		wantStatus(t, res, 200)
		after(bg)
		r2, _ := n.Subscribe(bg, inDialog(t, res, impu1, pathOf("f2"), 2, 3600))
		if r2.StatusCode != 200 {
			t.Fatalf("refresh asserting the other live binding's Path: %d, want 200", r2.StatusCode)
		}
		if subs := e.subscriptions(impu1); len(subs) != 1 || subs[0].Subscriber != pathOf("f2") {
			t.Errorf("subscriber after the refresh: %+v", subs)
		}
	})
	t.Run("Path no longer on any binding", func(t *testing.T) {
		e := newEnv(t)
		s := e.registered(bindingVia(1, "f1", time.Hour), bindingVia(2, "f2", 2*time.Hour))
		n := e.notifier(1)
		res, after := n.Subscribe(bg, subscribe(t, impu1, pathOf("f1"), 3600))
		wantStatus(t, res, 200)
		after(bg)
		next := s.Clone()
		next.Contacts = next.Contacts[1:]
		e.saved(next)
		r2, _ := n.Subscribe(bg, inDialog(t, res, impu1, pathOf("f1"), 2, 3600))
		wantStatus(t, r2, 481)
	})
}

// TestABindingThatMovedToAnotherPCSCFEndsTheOldPCSCFsSubscription: the
// next change ends the old P-CSCF's subscription with a NOTIFY that carries
// nothing of the binding it is not on, and its refresh is 481 and ends it
// too (#256 security review).
func TestABindingThatMovedToAnotherPCSCFEndsTheOldPCSCFsSubscription(t *testing.T) {
	for _, first := range []string{"change", "refresh"} {
		t.Run(first, func(t *testing.T) {
			e := newEnv(t)
			s := e.registered(binding(1, time.Hour))
			n := e.notifier(1)
			res, _ := e.subscribed(n)
			k := len(e.send.notifies())
			moved := s.Clone()
			moved.Contacts[0].Path = []string{"<sip:orig@pcscf2." + realm + ";lr>"}
			moved = e.saved(moved)
			if first == "change" {
				n.Changed(bg, s, moved, Registered)
				n.Wait()
				got := e.send.notifies()[k:]
				if len(got) != 1 {
					t.Fatalf("%d NOTIFYs after the binding moved", len(got))
				}
				ss, _ := got[0].Header.SubscriptionState()
				if r, _ := ss.Params.Get("reason"); ss.State != "terminated" || r != "deactivated" || len(got[0].Body) != 0 {
					t.Errorf("NOTIFY to the old P-CSCF: %+v with %d bytes of body", ss, len(got[0].Body))
				}
			}
			r, _ := n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
			wantStatus(t, r, 481)
			if subs := e.subscriptions(impu1); len(subs) != 0 {
				t.Errorf("%d subscriptions left", len(subs))
			}
			if first == "refresh" && len(e.send.notifies()) != k {
				t.Error("a NOTIFY to the old P-CSCF after its refresh")
			}
		})
	}
}

// TestAPCSCFsNewFlowKeepsItsSubscription: a UE that reconnects at the
// same P-CSCF gets a binding over a new flow; the P-CSCF's subscription
// carries on until its next refresh asserts the new Path.
func TestAPCSCFsNewFlowKeepsItsSubscription(t *testing.T) {
	e := newEnv(t)
	s := e.registered(bindingVia(1, "f1", time.Hour))
	n := e.notifier(1)
	res, after := n.Subscribe(bg, subscribe(t, impu1, pathOf("f1"), 3600))
	wantStatus(t, res, 200)
	after(bg)
	next := s.Clone()
	next.Contacts = []state.Contact{bindingVia(1, "f2", time.Hour)}
	n.Changed(bg, s, e.saved(next), Registered)
	n.Wait()
	got := e.send.notifies()
	if _, _, ss := info(t, got[len(got)-1]); ss.State != "active" {
		t.Errorf("NOTIFY after the new flow: %+v", ss)
	}
	r, _ := n.Subscribe(bg, inDialog(t, res, impu1, pathOf("f2"), 2, 3600))
	wantStatus(t, r, 200)
}

// TestARefreshWithTheSameCSeqIsRefused: the lead's contract on #14 asks
// for a higher CSeq (QA's m1 on #256).
func TestARefreshWithTheSameCSeqIsRefused(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	r, _ := n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 5, 3600))
	wantStatus(t, r, 200)
	r, _ = e.notifier(2).Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 5, 3600))
	wantStatus(t, r, 500)
}

// TestAUERefreshesWithoutAnAssertedIdentity: the P-CSCF asserts none on a
// target refresh (TS 24.229 §5.2.6.3.5), so the dialog alone authorises the
// UE's refresh and its unsubscribe (code review's finding 1 on #256).
func TestAUERefreshesWithoutAnAssertedIdentity(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, after := n.Subscribe(bg, subscribe(t, impu1, tel1, 3600))
	wantStatus(t, res, 200)
	after(bg)
	for i, exp := range []int{3600, 0} {
		req := inDialog(t, res, impu1, impu1, 2+i, exp)
		req.Header.Del("P-Asserted-Identity")
		r, after := n.Subscribe(bg, req)
		wantStatus(t, r, 200)
		after(bg)
	}
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left after the UE's unsubscribe", len(subs))
	}
}

// TestAPPRThatTakesTheWatchedIdentityOutEndsItsSubscription (QA's m3 on
// #256).
func TestAPPRThatTakesTheWatchedIdentityOutEndsItsSubscription(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, after := n.Subscribe(bg, subscribe(t, tel1, impu1, 3600))
	wantStatus(t, res, 200)
	after(bg)
	k := len(e.send.notifies())
	next := before.Clone()
	next.Identities = []state.SetIdentity{{IMPU: impu1}}
	n.Changed(bg, before, e.saved(next), Changed)
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs for the removed tel1", len(got))
	}
	doc, _, ss := info(t, got[0])
	if ss.State != "terminated" {
		t.Errorf("Subscription-State %+v", ss)
	}
	// tel1 is listed once more, terminated with the binding it had.
	reg, ok := doc.ByAOR(sip.URI{Scheme: "tel", User: "+15550100001"})
	if !ok || reg.State != reginfo.Terminated || len(reg.Contacts) != 1 || reg.Contacts[0].Active() {
		t.Errorf("tel1 in the last NOTIFY: %+v, %v", reg, ok)
	}
	if subs := e.subscriptions(tel1); len(subs) != 0 {
		t.Errorf("%d subscriptions to tel1 left", len(subs))
	}
}

// Another user's set, which tel1 moves to.
var (
	impi2   = "001010000000002@" + realm
	setB    = state.SetKey{IMPI: impi2, IMPU: tel1}
	contact = "sip:other-user@192.0.2.99:5060;transport=tcp"
	device  = "<urn:uuid:00000000-0000-0000-0000-0000000000b0>"
)

// moveTel1 has a PPR move tel1 out of impi1's set, before, into another
// user's, and returns impi1's set after and the other user's.
func (e *env) moveTel1(before *state.Registration) (*state.Registration, *state.Registration) {
	e.t.Helper()
	next := before.Clone()
	next.Identities = []state.SetIdentity{{IMPU: impu1}, {IMPU: impu2, Barred: true}}
	next = e.saved(next)
	c := binding(9, 2*time.Hour)
	c.URI, c.InstanceID = contact, device
	other := e.saved(&state.Registration{Key: setB, Incarnation: 9, Contacts: []state.Contact{c}, Identities: []state.SetIdentity{{IMPU: tel1}}})
	id, err := e.store.Identity(bg, tel1, t0)
	if err != nil {
		e.t.Fatal(err)
	}
	id.Set, id.Incarnation = setB, 9
	if _, err := e.store.SaveIdentity(bg, id, t0); err != nil {
		e.t.Fatal(err)
	}
	return next, other
}

// TestAnIdentityMovedToAnotherUserIsNeverReportedToItsOldWatcher: a UE
// watches tel1, which a PPR moves to another user's set. Whether or not the
// change reached the notifier, no NOTIFY to it, for a refresh, for the other
// user's changes or for its expiry, tells of the other user's bindings
// (#256 security review).
func TestAnIdentityMovedToAnotherUserIsNeverReportedToItsOldWatcher(t *testing.T) {
	for _, told := range []bool{true, false} {
		t.Run(fmt.Sprintf("told %v", told), func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			n := e.notifier(1)
			res, after := n.Subscribe(bg, subscribe(t, tel1, impu1, 600000))
			wantStatus(t, res, 200)
			after(bg)
			next, other := e.moveTel1(before)
			if told {
				n.Changed(bg, before, next, Changed)
				n.Wait()
			}
			later := other.Clone()
			later.Contacts[0].Expires = t0.Add(3 * time.Hour)
			n.Changed(bg, other, e.saved(later), Registered)
			n.Wait()
			r, after := n.Subscribe(bg, inDialog(t, res, tel1, impu1, 2, 600000))
			if r.StatusCode == 200 {
				t.Error("the old watcher refreshed its subscription to the moved identity")
				after(bg)
			}
			e.clock.advance(600001 * time.Second)
			if _, err := n.Sweep(bg, 10); err != nil {
				t.Fatal(err)
			}
			for _, req := range e.send.notifies() {
				if b := string(req.Body); strings.Contains(b, "other-user") || strings.Contains(b, "0000000000b0") {
					t.Errorf("a NOTIFY to the old watcher lists the other user's binding:\n%s", b)
				}
			}
			if subs := e.subscriptions(tel1); len(subs) != 0 {
				t.Errorf("%d subscriptions to tel1 left", len(subs))
			}
		})
	}
}

// TestOneSubscriberKeepsAtMostTwoSubscriptionsToAnIdentity: a UE that
// subscribes 500 times replaces its oldest each time, and a change then
// costs two NOTIFYs (#256 security review).
func TestOneSubscriberKeepsAtMostTwoSubscriptionsToAnIdentity(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	for i := range 500 {
		req := subscribe(t, impu1, tel1, 3600+i)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("sub-%d", i))
		res, after := n.Subscribe(bg, req)
		wantStatus(t, res, 200)
		after(bg)
	}
	n.Wait()
	if subs := e.subscriptions(impu1); len(subs) != DefaultMaxPerSubscriber {
		t.Fatalf("%d subscriptions stored, want %d", len(subs), DefaultMaxPerSubscriber)
	}
	if got := m.get("regevent.replaced"); got != 500-DefaultMaxPerSubscriber {
		t.Errorf("%d replaced", got)
	}
	k := len(e.send.notifies())
	after := before.Clone()
	after.Contacts[0].Expires = t0.Add(2 * time.Hour)
	n.Changed(bg, before, e.saved(after), Registered)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != DefaultMaxPerSubscriber {
		t.Errorf("%d NOTIFYs for one change", got)
	}
}

// TestASetKeepsAtMostMaxPerSetSubscriptions: one more is refused with 403.
func TestASetKeepsAtMostMaxPerSetSubscriptions(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.MaxPerSet = 3 })
	for i, s := range [][2]string{{impu1, pcscfPath}, {impu1, tel1}, {tel1, impu1}, {tel1, tel1}} {
		req := subscribe(t, s[0], s[1], 3600)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("sub-%d", i))
		res, _ := n.Subscribe(bg, req)
		want := 200
		if i == 3 {
			want = 403
		}
		wantStatus(t, res, want)
	}
}

// gatedSender holds every NOTIFY until released, and records how many were
// in flight at once.
type gatedSender struct {
	mu       sync.Mutex
	inFlight int
	most     int
	sent     int
	entered  chan struct{}
	release  chan struct{}
}

func (g *gatedSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	g.mu.Lock()
	g.inFlight++
	g.most = max(g.most, g.inFlight)
	g.mu.Unlock()
	g.entered <- struct{}{}
	<-g.release
	g.mu.Lock()
	g.inFlight--
	g.sent++
	g.mu.Unlock()
	return sip.NewResponse(req, 200, "", "subscriber")
}

// subscribedMany has k P-CSCF subscriptions to impu1, made on a notifier of
// their own.
func (e *env) subscribedMany(k int) {
	e.t.Helper()
	n := newNotifierWith(e.t, e, e.store, e.send, func(c *Config) { c.MaxPerSubscriber, c.MaxPerSet = k, k })
	for i := range k {
		req := subscribe(e.t, impu1, pcscfPath, 3600)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("sub-%d", i))
		res, _ := n.Subscribe(bg, req)
		wantStatus(e.t, res, 200)
	}
}

// TestAChangeSendsAtMostWorkersNotifiesAtOnce (#256 security review): once
// the change has queued all its NOTIFYs, Workers are in flight, holding the
// workers' slots, and the others wait for one.
func TestAChangeSendsAtMostWorkersNotifiesAtOnce(t *testing.T) {
	const subs, workers = 12, 3
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(subs)
	g := &gatedSender{entered: make(chan struct{}, subs), release: make(chan struct{}, subs)}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.Workers = workers })
	n.Changed(bg, before, before, Registered)
	for range workers {
		<-g.entered
	}
	// The job that lists the subscriptions is done once only theirs are
	// pending.
	for n.pending.Load() != subs {
		runtime.Gosched()
	}
	g.mu.Lock()
	inFlight := g.inFlight
	g.mu.Unlock()
	if inFlight != workers || len(n.slots) != workers {
		t.Errorf("%d NOTIFYs in flight, %d slots taken; want %d", inFlight, len(n.slots), workers)
	}
	for range subs {
		g.release <- struct{}{}
	}
	n.Wait()
	if g.most != workers || g.sent != subs {
		t.Errorf("%d NOTIFYs in flight at most, %d sent; want %d and %d", g.most, g.sent, workers, subs)
	}
}

// TestNotifiesBeyondTheQueueAreDroppedAndCounted: with one worker busy and
// the queue full, the rest of a change's NOTIFYs are dropped, not queued
// as goroutines.
func TestNotifiesBeyondTheQueueAreDroppedAndCounted(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(10)
	g := &gatedSender{entered: make(chan struct{}, 10), release: make(chan struct{}, 10)}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.Workers, c.Queue, c.Metrics = 1, 2, m })
	// The listing job holds the worker while it queues the NOTIFYs, so two
	// fit and eight do not.
	n.Changed(bg, before, before, Registered)
	for range 10 {
		g.release <- struct{}{}
	}
	n.Wait()
	if got := m.get("regevent.notify_dropped"); got != 8 || g.sent != 2 {
		t.Errorf("%d dropped, %d sent; want 8 and 2", got, g.sent)
	}
}

// flakyStore fails the next reads of a registration or an identity.
type flakyStore struct {
	*state.Memory
	mu                     sync.Mutex
	registration, identity int
}

var errThrottled = errors.New("throttled")

func (f *flakyStore) failing(n *int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if *n > 0 {
		*n--
		return true
	}
	return false
}

func (f *flakyStore) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	if f.failing(&f.registration) {
		return nil, errThrottled
	}
	return f.Memory.Registration(ctx, k)
}

func (f *flakyStore) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	if f.failing(&f.identity) {
		return nil, errThrottled
	}
	return f.Memory.Identity(ctx, impu, now)
}

// TestAStoreFailureSendsNoDocumentWithoutTheSet: a read of the set that
// fails is 500 with Retry-After to a SUBSCRIBE, and no NOTIFY to a change,
// rather than a full document without the set, which the P-CSCF takes for
// the user's deregistration (code review's finding 2 on #256).
func TestAStoreFailureSendsNoDocumentWithoutTheSet(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	fs := &flakyStore{Memory: e.store}
	n := newNotifierWith(t, e, fs, e.send)
	fs.identity = 1
	r, after := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	if r.StatusCode != 500 || r.Header.Get("Retry-After") == "" || after != nil {
		t.Errorf("SUBSCRIBE while the store fails: %d, Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	res, _ := e.subscribed(n)
	k := len(e.send.notifies())
	fs.registration = 1
	r, after = n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
	if r.StatusCode != 500 || r.Header.Get("Retry-After") == "" || after != nil {
		t.Errorf("refresh while the store fails: %d, Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	fs.registration = 1
	n.Changed(bg, before, before, Registered)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != 0 {
		t.Errorf("%d NOTIFYs sent without the set", got)
	}
	if subs := e.subscriptions(impu1); len(subs) != 1 {
		t.Errorf("%d subscriptions left", len(subs))
	}
	n.Changed(bg, before, before, Registered)
	n.Wait()
	got := e.send.notifies()
	if doc, _, _ := info(t, got[len(got)-1]); len(got) != k+1 || len(activeURIs(doc, impu1)) != 1 {
		t.Errorf("once the store is back: %d NOTIFYs", len(got)-k)
	}
}

// TestAReconnectedUELeavesNoDeadSubscription: the UE's old subscription is
// routed over its old flow, which the edge answers 430, and is removed
// (code review's finding 3 on #256).
func TestAReconnectedUELeavesNoDeadSubscription(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	for _, call := range []string{"old-flow", "new-flow"} {
		req := subscribe(t, impu1, impu1, 3600)
		_ = req.Header.Set("Call-ID", call)
		res, after := n.Subscribe(bg, req)
		wantStatus(t, res, 200)
		after(bg)
	}
	byCall := &byCallSender{status: map[string]int{"old-flow": 430}}
	n2 := newNotifierWith(t, e, e.store, byCall)
	n2.Changed(bg, before, before, Registered)
	n2.Wait()
	subs := e.subscriptions(impu1)
	if len(subs) != 1 || subs[0].Dialog.CallID != "new-flow" {
		t.Errorf("subscriptions left: %d", len(subs))
	}
}

// byCallSender answers each NOTIFY with its Call-ID's status, 200 if none.
type byCallSender struct{ status map[string]int }

func (s *byCallSender) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	code := s.status[req.Header.Get("Call-ID")]
	if code == 0 {
		code = 200
	}
	return sip.NewResponse(req, code, "", "subscriber")
}

// TestAUEsSubscriptionEndsWithItsLastBinding: §5.4.2.1.2 treats a UE's
// subscription as cancelled once none of its contacts is active; the other
// device's binding keeps the set registered. The UE's binding is the one
// its SUBSCRIBE's Contact names, by URI or by +sip.instance.
func TestAUEsSubscriptionEndsWithItsLastBinding(t *testing.T) {
	for name, contact := range map[string]string{
		"by URI":      "<" + binding(2, 0).URI + ">",
		"by instance": "<sip:ue2@198.51.100.7:5060>;+sip.instance=\"" + binding(2, 0).InstanceID + "\"",
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour), binding(2, time.Hour))
			n := e.notifier(1)
			req := subscribe(t, impu1, impu1, 3600)
			_ = req.Header.Set("Contact", contact)
			res, after := n.Subscribe(bg, req)
			wantStatus(t, res, 200)
			after(bg)
			next := before.Clone()
			next.Contacts = next.Contacts[:1]
			n.Changed(bg, before, e.saved(next), Unregistered)
			n.Wait()
			got := e.send.notifies()
			doc, _, ss := info(t, got[len(got)-1])
			if ss.State != "terminated" || len(activeURIs(doc, impu1)) != 1 {
				t.Errorf("last NOTIFY: %+v listing %v", ss, activeURIs(doc, impu1))
			}
			if subs := e.subscriptions(impu1); len(subs) != 0 {
				t.Errorf("%d subscriptions left", len(subs))
			}
		})
	}
}

// TestARefreshOnceEveryBindingHasExpiredIs481: the record still lists the
// bindings until the sweep, but none is live: a UE whose Contact named none
// of them has its subscription end with the registration.
func TestARefreshOnceEveryBindingHasExpiredIs481(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, after := n.Subscribe(bg, subscribe(t, impu1, impu1, 7200))
	wantStatus(t, res, 200)
	after(bg)
	e.clock.advance(time.Hour + time.Second)
	r, _ := n.Subscribe(bg, inDialog(t, res, impu1, impu1, 2, 7200))
	wantStatus(t, r, 481)
}

// TestTheEndOfAnotherSetThatListsTheIdentityLeavesTheSubscription: while a
// PPR moves tel1, both sets may list it; the end of the other one does not
// end the subscription to tel1 in impi1's set.
func TestTheEndOfAnotherSetThatListsTheIdentityLeavesTheSubscription(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, after := n.Subscribe(bg, subscribe(t, tel1, impu1, 3600))
	wantStatus(t, res, 200)
	after(bg)
	c := binding(9, time.Hour)
	c.URI, c.InstanceID = contact, device
	other := &state.Registration{Key: setB, Incarnation: 9, Contacts: []state.Contact{c}, Identities: []state.SetIdentity{{IMPU: tel1}}}
	n.Changed(bg, other, nil, Deactivated)
	n.Wait()
	if subs := e.subscriptions(tel1); len(subs) != 1 {
		t.Errorf("%d subscriptions to tel1 left", len(subs))
	}
}

// TestTheNotifyCarriesTheSubscribesEventID (RFC 6665 §4.5.2), and a
// refresh with another id is for a subscription that does not exist.
func TestTheNotifyCarriesTheSubscribesEventID(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	req := subscribe(t, impu1, pcscfPath, 3600)
	_ = req.Header.Set("Event", "reg;id=7")
	res, after := n.Subscribe(bg, req)
	wantStatus(t, res, 200)
	after(bg)
	if got := e.send.notifies()[0].Header.Get("Event"); got != "reg;id=7" {
		t.Errorf("NOTIFY Event %q", got)
	}
	r, _ := n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
	wantStatus(t, r, 481)
}

// TestABarredIdentityMayNotSubscribe: §5.4.2.1.1 lets the UE subscribe as
// an identity not barred.
func TestABarredIdentityMayNotSubscribe(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	res, _ := e.notifier(1).Subscribe(bg, subscribe(t, impu1, impu2, 3600))
	wantStatus(t, res, 403)
}

// TestAnUnchangedBindingIsNotRefreshed: another device registering leaves
// the first one's event as it was (code review's finding 8 on #256).
func TestAnUnchangedBindingIsNotRefreshed(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	next := before.Clone()
	next.Contacts = append(next.Contacts, binding(2, time.Hour))
	n.Changed(bg, before, e.saved(next), Registered)
	n.Wait()
	got := e.send.notifies()
	doc, _, _ := info(t, got[len(got)-1])
	reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
	for _, c := range reg.Contacts {
		if c.Event != reginfo.Registered {
			t.Errorf("%s: %s", c.URI, c.Event)
		}
	}
}

// TestARefreshOfAnEndingSubscriptionIs481: one a sweep or an unsubscribe
// has terminated, about to be deleted.
func TestARefreshOfAnEndingSubscriptionIs481(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	sub := e.subscriptions(impu1)[0]
	sub.Terminated = true
	if _, err := e.store.SaveSubscription(bg, sub); err != nil {
		t.Fatal(err)
	}
	r, _ := n.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
	wantStatus(t, r, 481)
	k := len(e.send.notifies())
	reg, _ := e.store.Registration(bg, set1)
	n.Changed(bg, reg, reg, Registered)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != 0 {
		t.Errorf("%d NOTIFYs to a terminated subscription", got)
	}
}

// TestASubscriptionWhoseCountersRanOutEndsWithoutANotify.
func TestASubscriptionWhoseCountersRanOutEndsWithoutANotify(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	sub := e.subscriptions(impu1)[0]
	sub.CSeq = state.MaxCounter
	if _, err := e.store.SaveSubscription(bg, sub); err != nil {
		t.Fatal(err)
	}
	k := len(e.send.notifies())
	n.Changed(bg, before, before, Registered)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != 0 {
		t.Errorf("%d NOTIFYs", got)
	}
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}

// TestVersionsContinueAcrossARestart: a new Notifier over the same store
// carries on the numbering (QA on #256).
func TestVersionsContinueAcrossARestart(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	after := before.Clone()
	after.Contacts[0].Expires = t0.Add(2 * time.Hour)
	after = e.saved(after)
	n.Changed(bg, before, after, Registered)
	n.Wait()
	restarted := e.notifier(1)
	restarted.Changed(bg, after, after, Registered)
	restarted.Wait()
	r, f := restarted.Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
	wantStatus(t, r, 200)
	f(bg)
	for i, req := range e.send.notifies() {
		doc, cseq, _ := info(t, req)
		if cseq != uint32(i+1) || doc.Version != uint32(i) {
			t.Errorf("NOTIFY %d: CSeq %d version %d", i, cseq, doc.Version)
		}
	}
	if got := len(e.send.notifies()); got != 4 {
		t.Errorf("%d NOTIFYs", got)
	}
}

// bigSet is a set at the store's limits, 32 identities of 32 contacts with
// long URIs, whose full document is beyond reginfo.MaxDocumentSize.
func (e *env) bigSet() *state.Registration {
	e.t.Helper()
	key := state.SetKey{IMPI: impi1, IMPU: "sip:user00@" + realm}
	r := &state.Registration{Key: key, Incarnation: 3}
	for i := range state.MaxIdentities {
		r.Identities = append(r.Identities, state.SetIdentity{IMPU: fmt.Sprintf("sip:user%02d@%s", i, realm)})
	}
	for i := range state.MaxContacts - 1 {
		r.Contacts = append(r.Contacts, bigContact(i))
	}
	saved := e.saved(r)
	if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: key.IMPU, Set: key, Incarnation: 3, KeepUntil: t0.Add(48 * time.Hour)}, t0); err != nil {
		e.t.Fatal(err)
	}
	return saved
}

func bigContact(i int) state.Contact {
	c := binding(1, time.Hour)
	c.URI = fmt.Sprintf("sip:%s%02d@[2001:db8::%x]:5060;transport=tcp;ob", strings.Repeat("u", 120), i, i+1)
	c.InstanceID = fmt.Sprintf("<urn:uuid:00000000-0000-0000-0000-0000000001%02d>", i)
	c.CallID = strings.Repeat("c", 60) + fmt.Sprint(i)
	return c
}

// TestATooLargeDocumentIsSentPartialAndTheEndAlways: over
// reginfo.MaxDocumentSize, a change goes out as what changed, and the end of
// the set with its identities alone; a first NOTIFY that does not fit is
// counted (code review's finding 7 on #256).
func TestATooLargeDocumentIsSentPartialAndTheEndAlways(t *testing.T) {
	e := newEnv(t)
	before := e.bigSet()
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	res, after := n.Subscribe(bg, subscribe(t, before.Key.IMPU, pcscfPath, 3600))
	wantStatus(t, res, 200)
	after(bg)
	if len(e.send.notifies()) != 0 || m.get("regevent.too_large") != 1 {
		t.Fatalf("first NOTIFY: %d sent, %d too large", len(e.send.notifies()), m.get("regevent.too_large"))
	}
	next := before.Clone()
	next.Contacts = append(next.Contacts, bigContact(99))
	next = e.saved(next)
	n.Changed(bg, before, next, Registered)
	n.Wait()
	got := e.send.notifies()
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs for the change", len(got))
	}
	doc, _, _ := info(t, got[0])
	if doc.State != reginfo.Partial || len(doc.Registrations) != state.MaxIdentities || len(doc.Registrations[0].Contacts) != 1 {
		t.Errorf("change: %s with %d registrations", doc.State, len(doc.Registrations))
	}
	n.Changed(bg, next, nil, Deactivated)
	n.Wait()
	got = e.send.notifies()
	doc, _, ss := info(t, got[len(got)-1])
	if ss.State != "terminated" || doc.State != reginfo.Full || len(doc.Registrations) != state.MaxIdentities || doc.Registrations[0].State != reginfo.Terminated {
		t.Errorf("end: %+v, %s with %d registrations", ss, doc.State, len(doc.Registrations))
	}
}

// TestManySubscriptionsUnderRace: two instances, 200 subscriptions over 4
// sets, changes, refreshes and sweeps at once. Every subscription's
// NOTIFYs are numbered once each, with CSeq one above the version, no
// refresh fails, and every subscription ends with at most one terminated
// NOTIFY (QA on #256).
func TestManySubscriptionsUnderRace(t *testing.T) {
	e := newEnv(t)
	sets := make([]*state.Registration, 4)
	for i := range sets {
		key := state.SetKey{IMPI: fmt.Sprintf("race%d@%s", i, realm), IMPU: fmt.Sprintf("sip:race%d@%s", i, realm)}
		sets[i] = e.saved(&state.Registration{Key: key, Incarnation: 1, Contacts: []state.Contact{binding(1, 72*time.Hour)},
			Identities: []state.SetIdentity{{IMPU: key.IMPU}}})
		if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: key.IMPU, Set: key, Incarnation: 1, KeepUntil: t0.Add(96 * time.Hour)}, t0); err != nil {
			t.Fatal(err)
		}
	}
	roomy := func(c *Config) { c.MaxPerSubscriber, c.MaxPerSet = 1000, 1000 }
	ns := []*Notifier{newNotifierWith(t, e, e.store, e.send, roomy), newNotifierWith(t, e, e.store, e.send, roomy)}
	type made struct {
		res  *sip.Response
		impu string
		cid  string
	}
	var mu sync.Mutex
	var subs []made
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			impu := sets[i%4].Key.IMPU
			req := subscribe(t, impu, pcscfPath, 3600+i)
			cid := fmt.Sprintf("race-%d", i)
			_ = req.Header.Set("Call-ID", cid)
			res, after := ns[i%2].Subscribe(bg, req)
			if res.StatusCode != 200 {
				t.Errorf("subscribe %d: %d", i, res.StatusCode)
				return
			}
			after(bg)
			mu.Lock()
			subs = append(subs, made{res, impu, cid})
			mu.Unlock()
		}()
	}
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := sets[i%4]
			ns[i%2].Changed(bg, s, s, Registered)
		}()
	}
	wg.Wait()
	for i, s := range subs {
		if i%3 != 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := inDialog(t, s.res, s.impu, pcscfPath, 2, (i%2)*60)
			_ = req.Header.Set("Call-ID", s.cid)
			res, f := ns[i%2].Subscribe(bg, req)
			if res.StatusCode != 200 {
				t.Errorf("refresh %d: %d", i, res.StatusCode)
			}
			if f != nil {
				f(bg)
			}
		}()
	}
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := sets[i%4]
			ns[i%2].Changed(bg, s, s, Registered)
			if i%5 == 0 {
				_, _ = ns[i%2].Sweep(bg, 50)
			}
		}()
	}
	wg.Wait()
	ns[0].Wait()
	ns[1].Wait()
	e.clock.advance(5000 * time.Second)
	for range 10 {
		wg.Add(2)
		for _, n := range ns {
			go func() {
				defer wg.Done()
				if _, err := n.Sweep(bg, 30); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	}
	byCall := map[string]map[uint32]bool{}
	ended := map[string]int{}
	for _, req := range e.send.notifies() {
		doc, cseq, ss := info(t, req)
		cid := req.Header.Get("Call-ID")
		if byCall[cid] == nil {
			byCall[cid] = map[uint32]bool{}
		}
		if byCall[cid][cseq] {
			t.Errorf("%s: CSeq %d twice", cid, cseq)
		}
		byCall[cid][cseq] = true
		if cseq != doc.Version+1 {
			t.Errorf("%s: CSeq %d with version %d", cid, cseq, doc.Version)
		}
		if ss.State == "terminated" {
			ended[cid]++
		}
	}
	for cid, k := range ended {
		if k > 1 {
			t.Errorf("%s: %d terminated NOTIFYs", cid, k)
		}
	}
	for _, s := range sets {
		if left := e.subscriptions(s.Key.IMPU); len(left) != 0 {
			t.Errorf("%d subscriptions to %s left after every one expired and sweeps ran", len(left), s.Key.IMPU)
		}
	}
}

// TestASubscriptionEndsWithTheRecordItWatched: the set registered again is
// a new record, a new incarnation, which the old subscription was not
// allowed to watch; it ends with a NOTIFY that tells nothing of the new one.
func TestASubscriptionEndsWithTheRecordItWatched(t *testing.T) {
	e := newEnv(t)
	old := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	k := len(e.send.notifies())
	if err := e.store.DeleteRegistration(bg, old); err != nil {
		t.Fatal(err)
	}
	again := e.saved(&state.Registration{Key: set1, Incarnation: 8, Contacts: []state.Contact{binding(2, time.Hour)}, Identities: old.Identities})
	n.Changed(bg, nil, again, Registered)
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs", len(got))
	}
	if ss, _ := got[0].Header.SubscriptionState(); ss.State != "terminated" || len(got[0].Body) != 0 {
		t.Errorf("NOTIFY to the old record's subscriber: %+v with %d bytes of body", ss, len(got[0].Body))
	}
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}

// TestAnIdentityThatPointsAheadOfItsRecordIsNotRegistered: a REGISTER
// points the identities before it saves the record (state.Identity), so
// until then the record is another incarnation and nobody may subscribe.
func TestAnIdentityThatPointsAheadOfItsRecordIsNotRegistered(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	id, err := e.store.Identity(bg, impu1, t0)
	if err != nil {
		t.Fatal(err)
	}
	id.Incarnation = 8
	if _, err := e.store.SaveIdentity(bg, id, t0); err != nil {
		t.Fatal(err)
	}
	res, _ := e.notifier(1).Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	wantStatus(t, res, 403)
}

// TestAnIdentityItsRecordNoLongerListsIsNotRegistered: a PPR took tel1 out
// of the set and its pointer is not cleaned up yet.
func TestAnIdentityItsRecordNoLongerListsIsNotRegistered(t *testing.T) {
	e := newEnv(t)
	s := e.registered(binding(1, time.Hour))
	next := s.Clone()
	next.Identities = []state.SetIdentity{{IMPU: impu1}}
	e.saved(next)
	res, _ := e.notifier(1).Subscribe(bg, subscribe(t, tel1, pcscfPath, 3600))
	wantStatus(t, res, 403)
}

// TestASubscriptionWhoseLastNotifyWentIsDeletedWithoutAnother: its final
// NOTIFY was numbered, and its delete failed; the next end deletes it and
// sends nothing more.
func TestASubscriptionWhoseLastNotifyWentIsDeletedWithoutAnother(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	sub := e.subscriptions(impu1)[0]
	if _, _, err := e.store.NextNotify(bg, sub.ID, state.FinalNotify); err != nil {
		t.Fatal(err)
	}
	k := len(e.send.notifies())
	n.Changed(bg, before, nil, Deactivated)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != 0 {
		t.Errorf("%d NOTIFYs after the last", got)
	}
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}
