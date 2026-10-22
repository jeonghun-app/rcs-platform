package regevent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
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

// TestAPCSCFIsNeverRefusedForTheUEsSubscriptions: the UE's subscriptions
// take MaxUEPerSet at most, and a P-CSCF's pushes out the oldest of them
// when the set is full; the set refuses only once it is all the P-CSCF's
// (#256 security and code reviews).
func TestAPCSCFIsNeverRefusedForTheUEsSubscriptions(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.MaxPerSet, c.Metrics = 6, m })
	calls := 0
	try := func(target, pai, contact string) int {
		t.Helper()
		calls++
		req := subscribe(t, target, pai, 3600+calls)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("sub-%d", calls))
		if contact != "" {
			_ = req.Header.Set("Contact", "<"+contact+">")
		}
		res, _ := n.Subscribe(bg, req)
		return res.StatusCode
	}
	kinds := func() (ue, pcscf int) {
		for _, impu := range []string{impu1, tel1} {
			for _, s := range e.subscriptions(impu) {
				switch {
				case s.Terminated:
				case s.Kind == state.SubscriberUE:
					ue++
				default:
					pcscf++
				}
			}
		}
		return ue, pcscf
	}
	// Five devices' worth of the UE's: three devices, two identities.
	for _, s := range [][2]string{{impu1, binding(1, 0).URI}, {tel1, binding(1, 0).URI}, {impu1, binding(2, 0).URI}, {tel1, binding(2, 0).URI}, {impu1, binding(3, 0).URI}} {
		if code := try(s[0], impu1, s[1]); code != 200 {
			t.Fatalf("UE SUBSCRIBE: %d", code)
		}
	}
	if ue, _ := kinds(); ue != 4 || m.get("regevent.replaced") != 1 {
		t.Fatalf("%d UE subscriptions, %d replaced; want MaxUEPerSet 4 and 1", ue, m.get("regevent.replaced"))
	}
	// The P-CSCF's four (two to each identity) all get in.
	for _, target := range []string{impu1, impu1, tel1, tel1} {
		if code := try(target, pcscfPath, ""); code != 200 {
			t.Fatalf("P-CSCF SUBSCRIBE: %d", code)
		}
	}
	if ue, pcscf := kinds(); ue != 2 || pcscf != 4 {
		t.Errorf("%d UE and %d P-CSCF subscriptions, want 2 and 4", ue, pcscf)
	}
	// The set is full and the UE's are within MaxUEPerSet: the UE is refused.
	if code := try(tel1, impu1, binding(3, 0).URI); code != 403 {
		t.Errorf("UE SUBSCRIBE to a full set: %d, want 403", code)
	}
}

// TestThreeDevicesOfOneUserKeepTheirSubscriptions: every device of a user
// asserts the same identity, so MaxPerSubscriber counts a UE's per device;
// each answers a terminated;reason=deactivated by subscribing again at once
// (RFC 6665 §4.1.3), which must not push out another device (QA's N1 on
// #256).
func TestThreeDevicesOfOneUserKeepTheirSubscriptions(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	device := map[string]int{}
	next := 0
	sub := func(k int) {
		next++
		cid := fmt.Sprintf("dev%d-%d", k, next)
		device[cid] = k
		req := subscribe(t, impu1, impu1, 600000)
		_ = req.Header.Set("Call-ID", cid)
		c := binding(k, 0)
		_ = req.Header.Set("Contact", fmt.Sprintf(`<%s>;+sip.instance="%s"`, c.URI, c.InstanceID))
		res, after := n.Subscribe(bg, req)
		wantStatus(t, res, 200)
		after(bg)
	}
	for k := 1; k <= 3; k++ {
		sub(k)
	}
	n.Wait()
	seen := 0
	for range 10 {
		got := e.send.notifies()
		progressed := false
		for _, req := range got[seen:] {
			ss, _ := req.Header.SubscriptionState()
			if r, _ := ss.Params.Get("reason"); ss.State == "terminated" && r == "deactivated" {
				sub(device[req.Header.Get("Call-ID")])
				progressed = true
			}
		}
		seen = len(got)
		n.Wait()
		if !progressed {
			break
		}
	}
	live := map[int]bool{}
	for _, s := range e.subscriptions(impu1) {
		if !s.Terminated {
			live[device[s.Dialog.CallID]] = true
		}
	}
	if m.get("regevent.replaced") != 0 || len(live) != 3 {
		t.Errorf("a device's SUBSCRIBE ended another device's subscription %d times; devices with one %v", m.get("regevent.replaced"), live)
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

func (g *gatedSender) inFlightNow() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inFlight
}

func newGate(k int) *gatedSender {
	return &gatedSender{entered: make(chan struct{}, k), release: make(chan struct{}, k)}
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

// otherSets stores k sets of other users, each with a binding and a
// P-CSCF subscription with the Call-ID prefix and its index, made on a
// notifier of their own.
func (e *env) otherSets(k int, prefix string) []*state.Registration {
	e.t.Helper()
	n := newNotifierWith(e.t, e, e.store, e.send)
	var out []*state.Registration
	for i := range k {
		key := state.SetKey{IMPI: fmt.Sprintf("%s%04d@%s", prefix, i, realm), IMPU: fmt.Sprintf("sip:%s%04d@%s", prefix, i, realm)}
		out = append(out, e.saved(&state.Registration{Key: key, Incarnation: 1, Contacts: []state.Contact{binding(1, time.Hour)},
			Identities: []state.SetIdentity{{IMPU: key.IMPU}}}))
		if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: key.IMPU, Set: key, Incarnation: 1, KeepUntil: t0.Add(48 * time.Hour)}, t0); err != nil {
			e.t.Fatal(err)
		}
		req := subscribe(e.t, key.IMPU, pcscfPath, 3600)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("%s-%d", prefix, i))
		res, _ := n.Subscribe(bg, req)
		wantStatus(e.t, res, 200)
	}
	return out
}

// settled waits until n is quiet (waitQuiet) and fails unless waiting
// tasks are left waiting.
func settled(t *testing.T, n *Notifier, waiting int) {
	t.Helper()
	waitQuiet(t, n)
	n.sc.mu.Lock()
	got := len(n.sc.waiting)
	n.sc.mu.Unlock()
	if got != waiting {
		t.Fatalf("%d tasks waiting, want %d", got, waiting)
	}
}

// waitQuiet waits until no task of n is on a worker and every task waiting
// waits for room in its set or next hop.
func waitQuiet(t *testing.T, n *Notifier) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		sc := &n.sc
		sc.mu.Lock()
		quiet := sc.working == 0
		for _, w := range sc.waiting {
			if w.sub == "" || sc.inSet[w.set] < n.cfg.SetConcurrency && sc.inHop[w.hop] < n.cfg.HopConcurrency {
				quiet = false
			}
		}
		sc.mu.Unlock()
		if quiet {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the scheduler never settled")
		}
		runtime.Gosched()
	}
}

// TestASetHasAtMostSetConcurrencyNotifiesUnderWay (#256 security review):
// once the change has queued all its NOTIFYs, SetConcurrency are under way
// and the others wait, whatever the workers.
func TestASetHasAtMostSetConcurrencyNotifiesUnderWay(t *testing.T) {
	const subs = 12
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(subs)
	g := newGate(subs)
	n := newNotifierWith(t, e, e.store, g)
	n.Changed(bg, before, e.touched(before), Registered)
	for range DefaultSetConcurrency {
		<-g.entered
	}
	settled(t, n, subs-DefaultSetConcurrency)
	if got := g.inFlightNow(); got != DefaultSetConcurrency {
		t.Errorf("%d NOTIFYs of one set in flight, want %d", got, DefaultSetConcurrency)
	}
	for range subs {
		g.release <- struct{}{}
	}
	n.Wait()
	if g.most != DefaultSetConcurrency || g.sent != subs {
		t.Errorf("%d in flight at most, %d sent", g.most, g.sent)
	}
}

// TestANextHopHasAtMostHopConcurrencyNotifiesUnderWay (#256 code review):
// a P-CSCF task that does not answer holds back only what goes to it.
func TestANextHopHasAtMostHopConcurrencyNotifiesUnderWay(t *testing.T) {
	const sets, hop = 6, 3
	e := newEnv(t)
	others := e.otherSets(sets, "other")
	g := newGate(sets)
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.HopConcurrency = hop })
	for _, r := range others {
		n.Changed(bg, r, e.touched(r), Registered)
	}
	for range hop {
		<-g.entered
	}
	settled(t, n, sets-hop)
	if got := g.inFlightNow(); got != hop {
		t.Errorf("%d NOTIFYs to one next hop in flight, want %d", got, hop)
	}
	for range sets {
		g.release <- struct{}{}
	}
	n.Wait()
	if g.most != hop || g.sent != sets {
		t.Errorf("%d in flight at most, %d sent", g.most, g.sent)
	}
}

// slowSender holds NOTIFYs whose Call-ID starts "slow" until release is
// closed, and those starting "held" until held is, and answers the others
// at once, telling of each on fast.
type slowSender struct {
	release, held chan struct{}
	mu            sync.Mutex
	sent          []*sip.Request
	fast          chan *sip.Request
}

func (s *slowSender) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	s.mu.Lock()
	s.sent = append(s.sent, req)
	s.mu.Unlock()
	var wait chan struct{}
	switch cid := req.Header.Get("Call-ID"); {
	case strings.HasPrefix(cid, "slow"):
		wait = s.release
	case strings.HasPrefix(cid, "held"):
		wait = s.held
	case s.fast != nil:
		s.fast <- req
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return sip.NewResponse(req, 200, "", "subscriber")
}

func (s *slowSender) notifies() []*sip.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sent)
}

// TestASlowSubscriberHoldsNoWorker: the wait for an answer is not a
// worker's, so with one worker and one set's NOTIFYs waiting for a slow
// subscriber, another set's still go out (#256 security review).
func TestASlowSubscriberHoldsNoWorker(t *testing.T) {
	e := newEnv(t)
	slowSet := e.otherSets(1, "slow")[0]
	other := e.otherSets(1, "fast")
	s := &slowSender{release: make(chan struct{}), fast: make(chan *sip.Request, 1)}
	n := newNotifierWith(t, e, e.store, s, func(c *Config) { c.Workers, c.NotifyTimeout = 1, time.Minute })
	n.Changed(bg, slowSet, e.touched(slowSet), Registered)
	n.Changed(bg, other[0], e.touched(other[0]), Registered)
	select {
	case <-s.fast:
	case <-time.After(10 * time.Second):
		t.Fatal("another set's NOTIFY waited for a slow subscriber")
	}
	close(s.release)
	n.Wait()
}

// TestNotifiesBeyondTheQueueAreDroppedAndCounted: beyond what a next hop may
// have waiting (a quarter of Queue), a change's NOTIFYs are dropped, not
// held.
func TestNotifiesBeyondTheQueueAreDroppedAndCounted(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(10)
	g := newGate(10)
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.Queue, c.Metrics = 8, m })
	// Two are under way, two wait (8/4 for the hop), six are dropped.
	n.Changed(bg, before, e.touched(before), Registered)
	settled(t, n, 2)
	for range 10 {
		g.release <- struct{}{}
	}
	n.Wait()
	if got := m.get("regevent.notify_dropped"); got != 6 || g.sent != 4 {
		t.Errorf("%d dropped, %d sent; want 6 and 4", got, g.sent)
	}
}

// TestANotifyWaitingIsNotQueuedTwice: it reads the state when it runs, so a
// second change merges into it.
func TestANotifyWaitingIsNotQueuedTwice(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(3)
	g := newGate(10)
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.Workers, c.SetConcurrency, c.Metrics = 1, 1, m })
	// Each change has a NOTIFY for each of the three subscriptions. With one
	// NOTIFY of the set under way at a time, the second change's for a
	// subscription whose first is still waiting merges into it: all three,
	// if the second change is listed before the first NOTIFY starts, or the
	// two others if it is listed after.
	n.Changed(bg, before, e.touched(before), Registered)
	n.Changed(bg, before, e.touched(before), Registered)
	waitQuiet(t, n)
	for range 10 {
		g.release <- struct{}{}
	}
	n.Wait()
	merged := int(m.get("regevent.notify_merged"))
	if merged < 2 || merged+g.sent != 6 {
		t.Errorf("%d merged, %d sent; want 2 or 3 merged and the rest sent, 6 in all", merged, g.sent)
	}
}

// TestTheEndsOfOtherSetsAreDeliveredWhileOneSubscriberIsSlow: one set's
// subscriber is slow to answer, and 1100 other sets behind the same P-CSCF
// end at once (an RTR each), their NOTIFYs held until all are queued. The
// slow set holds two of the hop's NOTIFYs under way; beyond the hop's share
// of the queue the ends are deferred, and every subscriber gets its
// terminated NOTIFY, at once or from the next sweep (#256 security review).
func TestTheEndsOfOtherSetsAreDeliveredWhileOneSubscriberIsSlow(t *testing.T) {
	const ended, slow = 1100, 8
	e := newEnv(t)
	slowSet := e.registered(binding(1, time.Hour))
	n0 := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.MaxPerSubscriber = slow })
	for i := range slow {
		req := subscribe(t, impu1, pcscfPath, 3600)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("slow-%d", i))
		res, _ := n0.Subscribe(bg, req)
		wantStatus(t, res, 200)
	}
	others := e.otherSets(ended, "held")
	s := &slowSender{release: make(chan struct{}), held: make(chan struct{})}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, s, func(c *Config) { c.NotifyTimeout, c.Metrics = time.Minute, m })
	n.Changed(bg, slowSet, e.touched(slowSet), Registered)
	for _, r := range others {
		if err := e.store.DeleteRegistration(bg, r); err != nil {
			t.Fatal(err)
		}
		n.Changed(bg, r, nil, Rejected)
	}
	// Under way: the slow set's two and the rest of the hop's. Waiting: the
	// slow set's six and the ends, up to the hop's quarter of the queue;
	// how many reach it depends on how soon the workers take them.
	waitQuiet(t, n)
	if m.get("regevent.notify_deferred") == 0 {
		t.Fatal("no end was deferred: the test does not fill the hop's share of the queue")
	}
	close(s.held)
	finals := func() map[string]int {
		got := map[string]int{}
		for _, req := range s.notifies() {
			ss, _ := req.Header.SubscriptionState()
			if r, _ := ss.Params.Get("reason"); strings.HasPrefix(req.Header.Get("Call-ID"), "held") && ss.State == "terminated" && r == "rejected" {
				// Sent at once or by the sweep, it ends the identity.
				doc, err := reginfo.Parse(req.Body)
				if err != nil || len(doc.Registrations) != 1 || doc.Registrations[0].State != reginfo.Terminated {
					t.Errorf("%s: terminated NOTIFY without the identity's end: %v", req.Header.Get("Call-ID"), err)
				}
				got[req.Header.Get("Call-ID")]++
			}
		}
		return got
	}
	// Only the slow set's are left: two under way, six waiting.
	deadline := time.Now().Add(10 * time.Second)
	for {
		n.sc.mu.Lock()
		done := n.sc.working == 0 && n.sc.queued == slow-DefaultSetConcurrency && len(n.sc.inHop) == 1 && len(n.sc.inSet) == 1
		n.sc.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ends were never all sent")
		}
		time.Sleep(time.Millisecond)
	}
	e.clock.advance(n.pendingEnd() + time.Second)
	if _, err := n.Sweep(bg, 2*ended); err != nil {
		t.Fatal(err)
	}
	got := finals()
	for i := range ended {
		if k := got[fmt.Sprintf("held-%d", i)]; k != 1 {
			t.Errorf("held-%d: %d terminated NOTIFYs", i, k)
		}
	}
	for _, r := range others {
		if left := e.subscriptions(r.Key.IMPU); len(left) != 0 {
			t.Errorf("%s: %d subscriptions left", r.Key.IMPU, len(left))
		}
	}
	close(s.release)
	n.Wait()
}

// TestAnRTRsNotifyIsNotLostBehindADeadPCSCF: users of a P-CSCF task that
// died register again elsewhere, and each change sends a NOTIFY to the dead
// task, which takes NotifyTimeout. Meanwhile an RTR ends another user's
// set, and its subscriber gets the terminated NOTIFY, at once or from the
// sweep (QA's N2 on #256, with the next hop bounded to two so that the end
// waits).
func TestAnRTRsNotifyIsNotLostBehindADeadPCSCF(t *testing.T) {
	e := newEnv(t)
	live := e.registered(binding(1, time.Hour))
	s := &slowSender{release: make(chan struct{})}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, s, func(c *Config) {
		c.Workers, c.Queue, c.HopConcurrency, c.NotifyTimeout, c.Metrics = 2, 8, 2, 200*time.Millisecond, m
	})
	res, after := n.Subscribe(bg, subscribe(t, impu1, pcscfPath, 3600))
	wantStatus(t, res, 200)
	after(bg)
	for _, r := range e.otherSets(20, "slow") {
		next := r.Clone()
		next.Contacts[0].Expires = t0.Add(2 * time.Hour)
		n.Changed(bg, r, e.saved(next), Registered)
	}
	if err := e.store.DeleteRegistration(bg, mustReg(t, e, set1)); err != nil {
		t.Fatal(err)
	}
	n.Changed(bg, live, nil, Rejected)
	n.Wait()
	e.clock.advance(n.pendingEnd() + time.Second)
	if _, err := n.Sweep(bg, 100); err != nil {
		t.Fatal(err)
	}
	finals := 0
	for _, req := range s.notifies() {
		if ss, _ := req.Header.SubscriptionState(); req.Header.Get("Call-ID") == "sub-call-1" && ss.State == "terminated" {
			finals++
		}
	}
	if left := e.subscriptions(impu1); finals != 1 || len(left) != 0 {
		t.Errorf("%d terminated NOTIFYs for the RTR, %d subscriptions left (%d deferred)", finals, len(left), m.get("regevent.notify_deferred"))
	}
}

func mustReg(t *testing.T, e *env, k state.SetKey) *state.Registration {
	t.Helper()
	r, err := e.store.Registration(bg, k)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// flakyStore fails the next reads of a registration, an identity or a
// listing of subscriptions.
type flakyStore struct {
	*state.Memory
	mu                              sync.Mutex
	registration, identity, listing int
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

func (f *flakyStore) SubscriptionsOf(ctx context.Context, impu string) ([]*state.Subscription, error) {
	if f.failing(&f.listing) {
		return nil, errThrottled
	}
	return f.Memory.SubscriptionsOf(ctx, impu)
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
	n.Changed(bg, before, e.touched(before), Registered)
	n.Wait()
	if got := len(e.send.notifies()) - k; got != 0 {
		t.Errorf("%d NOTIFYs sent without the set", got)
	}
	if subs := e.subscriptions(impu1); len(subs) != 1 {
		t.Errorf("%d subscriptions left", len(subs))
	}
	n.Changed(bg, before, e.touched(before), Registered)
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
	n2.Changed(bg, before, e.touched(before), Registered)
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
	n.Changed(bg, reg, e.touched(reg), Registered)
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
	n.Changed(bg, before, e.touched(before), Registered)
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
	restarted.Changed(bg, after, e.touched(after), Registered)
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
			ns[i%2].Changed(bg, s, e.touched(s), Registered)
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
			ns[i%2].Changed(bg, s, e.touched(s), Registered)
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

// TestAFinalNotifyNumberedElsewhereIsSentAgainWithItsNumbers: a final
// NOTIFY was numbered, and nothing says it was answered; the next end sends
// it again with the CSeq and version it was numbered with, so that the
// subscriber takes the two for one, and then deletes the subscription.
func TestAFinalNotifyNumberedElsewhereIsSentAgainWithItsNumbers(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	sub := e.subscriptions(impu1)[0]
	cseq, version, err := e.store.NextNotify(bg, sub.ID, state.FinalNotify)
	if err != nil {
		t.Fatal(err)
	}
	k := len(e.send.notifies())
	n.Changed(bg, before, nil, Deactivated)
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 {
		t.Fatalf("%d NOTIFYs after the last was numbered", len(got))
	}
	doc, c, ss := info(t, got[0])
	if c != cseq || doc.Version != version || ss.State != "terminated" {
		t.Errorf("sent again as CSeq %d version %d %s, want %d and %d, terminated", c, doc.Version, ss.State, cseq, version)
	}
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left", len(subs))
	}
}

// TestTheEndOfANewerRecordEndsAnOlderSubscriptionWithoutABody: a
// subscription to an earlier incarnation of the set hears nothing of the
// later one's end but that its own has gone.
func TestTheEndOfANewerRecordEndsAnOlderSubscriptionWithoutABody(t *testing.T) {
	e := newEnv(t)
	old := e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	e.subscribed(n)
	k := len(e.send.notifies())
	if err := e.store.DeleteRegistration(bg, old); err != nil {
		t.Fatal(err)
	}
	newer := old.Clone()
	newer.Incarnation, newer.Version = 8, 0
	n.Changed(bg, newer, nil, Deactivated)
	n.Wait()
	got := e.send.notifies()[k:]
	if len(got) != 1 || len(got[0].Body) != 0 {
		t.Fatalf("%d NOTIFYs, the last with %d bytes of body", len(got), len(got[len(got)-1].Body))
	}
}

// TestARefreshAfterTheLastNotifyIs481: the final NOTIFY of a subscription
// that lapsed is numbered, and the delete has not landed yet.
func TestARefreshAfterTheLastNotifyIs481(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	n := e.notifier(1)
	res, _ := e.subscribed(n)
	sub := e.subscriptions(impu1)[0]
	if _, _, err := e.store.NextNotify(bg, sub.ID, state.FinalNotify); err != nil {
		t.Fatal(err)
	}
	r, _ := e.notifier(2).Subscribe(bg, inDialog(t, res, impu1, pcscfPath, 2, 3600))
	wantStatus(t, r, 481)
}

// TestABarredIdentityMayNotBeWatched: no NOTIFY would list it.
func TestABarredIdentityMayNotBeWatched(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour))
	for _, pai := range []string{impu1, pcscfPath} {
		res, _ := e.notifier(1).Subscribe(bg, subscribe(t, impu2, pai, 3600))
		wantStatus(t, res, 403)
	}
}

// hopSets stores, for each of hops next hops, one set of another user with
// perHop P-CSCF subscriptions whose NOTIFYs go to that hop, made on a
// notifier of their own.
func (e *env) hopSets(hops, perHop int) []*state.Registration {
	e.t.Helper()
	n := newNotifierWith(e.t, e, e.store, e.send, func(c *Config) { c.MaxPerSubscriber = perHop })
	var out []*state.Registration
	for h := range hops {
		key := state.SetKey{IMPI: fmt.Sprintf("hop%d@%s", h, realm), IMPU: fmt.Sprintf("sip:hop%d@%s", h, realm)}
		// Each set's binding came over a P-CSCF of its own, the next hop
		// of its NOTIFYs.
		path := fmt.Sprintf("sip:term@pcscf-%d.%s;lr", h, realm)
		b := binding(1, time.Hour)
		b.Path = []string{"<" + path + ">"}
		out = append(out, e.saved(&state.Registration{Key: key, Incarnation: 1, Contacts: []state.Contact{b},
			Identities: []state.SetIdentity{{IMPU: key.IMPU}}}))
		if _, err := e.store.SaveIdentity(bg, &state.Identity{IMPU: key.IMPU, Set: key, Incarnation: 1, KeepUntil: t0.Add(48 * time.Hour)}, t0); err != nil {
			e.t.Fatal(err)
		}
		for i := range perHop {
			req := subscribe(e.t, key.IMPU, path, 3600)
			_ = req.Header.Set("Call-ID", fmt.Sprintf("hop%d-%d", h, i))
			_ = req.Header.Set("Contact", fmt.Sprintf("<sip:pcscf-%d.%s:5060;transport=tcp>", h, realm))
			_ = req.Header.Set("Record-Route", fmt.Sprintf("<sip:pcscf-%d.%s;lr>", h, realm))
			res, _ := n.Subscribe(bg, req)
			wantStatus(e.t, res, 200)
		}
	}
	return out
}

// TestNextHopsAreBoundedApart: each next hop has its own HopConcurrency.
func TestNextHopsAreBoundedApart(t *testing.T) {
	e := newEnv(t)
	sets := e.hopSets(2, 2)
	g := newGate(4)
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.HopConcurrency = 1 })
	for _, r := range sets {
		n.Changed(bg, r, e.touched(r), Registered)
	}
	for range 2 {
		select {
		case <-g.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("one hop's NOTIFY waited for the other's")
		}
	}
	settled(t, n, 2)
	if got := g.inFlightNow(); got != 2 {
		t.Errorf("%d NOTIFYs in flight, want one to each of the two hops", got)
	}
	for range 4 {
		g.release <- struct{}{}
	}
	n.Wait()
}

// TestTheQueueBoundsWhatWaitsForEveryHop: each hop takes its quarter of the
// queue, and all of them no more than the queue.
func TestTheQueueBoundsWhatWaitsForEveryHop(t *testing.T) {
	const hops, perHop, queue = 6, 3, 8
	e := newEnv(t)
	sets := e.hopSets(hops, perHop)
	g := newGate(hops * perHop)
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.HopConcurrency, c.Queue, c.Metrics = 1, queue, m })
	for _, r := range sets {
		n.Changed(bg, r, e.touched(r), Registered)
	}
	waitQuiet(t, n)
	n.sc.mu.Lock()
	waiting := len(n.sc.waiting)
	n.sc.mu.Unlock()
	if waiting > queue || m.get("regevent.notify_dropped") == 0 {
		t.Errorf("%d waiting, %d dropped; want at most %d waiting", waiting, m.get("regevent.notify_dropped"), queue)
	}
	for range hops * perHop {
		g.release <- struct{}{}
	}
	n.Wait()
}

// TestAnEndTakesTheWaitingNotifysPlace: a set ends while a NOTIFY of the
// change before is waiting for one of its subscriptions; the end must not
// merge into it, or that subscription is never ended.
func TestAnEndTakesTheWaitingNotifysPlace(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(2)
	g := newGate(4)
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.SetConcurrency = 1 })
	n.Changed(bg, before, e.touched(before), Registered)
	settled(t, n, 1)
	n.Changed(bg, before, nil, Rejected)
	settled(t, n, 2)
	for range 4 {
		g.release <- struct{}{}
	}
	n.Wait()
	if subs := e.subscriptions(impu1); len(subs) != 0 {
		t.Errorf("%d subscriptions left after the set ended", len(subs))
	}
	if g.sent != 3 {
		t.Errorf("%d NOTIFYs, want the first change's one under way and two ends", g.sent)
	}
}

// TestAnEndListsTheSubscriptionsAgainAfterAFailure: a listing that fails
// once is tried again, and every subscriber gets its end (#256 code
// review); one that keeps failing is an error, which the registrar keeps
// the record for, and is counted.
func TestAnEndListsTheSubscriptionsAgainAfterAFailure(t *testing.T) {
	for _, fails := range []int{1, listAttempts} {
		t.Run(fmt.Sprintf("%d failures", fails), func(t *testing.T) {
			e := newEnv(t)
			before := e.registered(binding(1, time.Hour))
			e.subscribedMany(2)
			fs := &flakyStore{Memory: e.store, listing: fails}
			m := &counts{}
			n := newNotifierWith(t, e, fs, e.send, func(c *Config) { c.Metrics = m })
			err := n.Ended(bg, before, Rejected)
			n.Wait()
			ends := 0
			for _, req := range e.send.notifies() {
				if ss, _ := req.Header.SubscriptionState(); ss.State == "terminated" {
					ends++
				}
			}
			if fails < listAttempts {
				if err != nil || ends != 2 {
					t.Errorf("Ended = %v, %d ends sent; want nil and 2", err, ends)
				}
				return
			}
			if err == nil || m.get("regevent.end_failed") != 1 || ends != 0 {
				t.Errorf("Ended = %v, end_failed %d, %d ends sent; want an error, 1, 0", err, m.get("regevent.end_failed"), ends)
			}
		})
	}
}

// TestDevicesWhoseContactMatchesNoBindingKeepTheirShares: the SUBSCRIBE
// Contact of each of three devices is written unlike its REGISTER's
// (without ;transport=tcp, RFC 3261 §19.1.4), so it matches no binding;
// the Contact itself tells the devices apart (QA's R1 on #256).
func TestDevicesWhoseContactMatchesNoBindingKeepTheirShares(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	for k := 1; k <= 3; k++ {
		req := subscribe(t, impu1, impu1, 600000)
		_ = req.Header.Set("Call-ID", fmt.Sprintf("nb-%d", k))
		_ = req.Header.Set("Contact", "<"+strings.TrimSuffix(binding(k, 0).URI, ";transport=tcp")+">")
		res, after := n.Subscribe(bg, req)
		wantStatus(t, res, 200)
		after(bg)
	}
	n.Wait()
	if r := m.get("regevent.replaced"); r != 0 {
		t.Errorf("replaced %d", r)
	}
	// Each ends with the set, not with a binding it was never matched to.
	if subs := e.subscriptions(impu1); len(subs) != 3 || subs[0].Binding == "" {
		t.Errorf("%d subscriptions, the first with Binding %q", len(subs), subs[0].Binding)
	}
}

// recGate holds each NOTIFY until released and records it.
type recGate struct {
	mu      sync.Mutex
	sent    []*sip.Request
	release chan struct{}
}

func (g *recGate) Send(_ context.Context, req *sip.Request) (*sip.Response, error) {
	g.mu.Lock()
	g.sent = append(g.sent, req)
	g.mu.Unlock()
	<-g.release
	return sip.NewResponse(req, 200, "", "s")
}

// TestAMergedNotifyTellsOfEachContactByTheChangeThatEndedIt: a REGISTER
// removes binding 2 and its NOTIFY waits for the set's one slot; a sweep
// then expires binding 3, and its NOTIFY merges into the waiting one. Every
// NOTIFY tells of binding 2 as unregistered and of binding 3 as expired
// (QA's R2 on #256).
func TestAMergedNotifyTellsOfEachContactByTheChangeThatEndedIt(t *testing.T) {
	e := newEnv(t)
	s0 := e.registered(binding(1, time.Hour), binding(2, time.Hour), binding(3, time.Hour))
	e.subscribedMany(2)
	g := &recGate{release: make(chan struct{})}
	m := &counts{}
	n := newNotifierWith(t, e, e.store, g, func(c *Config) { c.SetConcurrency, c.Metrics = 1, m })
	s1 := s0.Clone()
	s1.Contacts = []state.Contact{s0.Contacts[0], s0.Contacts[2]}
	s1 = e.saved(s1)
	n.Changed(bg, s0, s1, Registered)
	settled(t, n, 1)
	s2 := s1.Clone()
	s2.Contacts = s2.Contacts[:1]
	s2 = e.saved(s2)
	n.Changed(bg, s1, s2, Expired)
	settled(t, n, 2)
	close(g.release)
	n.Wait()
	if m.get("regevent.notify_merged") != 1 {
		t.Fatalf("%d merged, want 1", m.get("regevent.notify_merged"))
	}
	want := map[string]reginfo.Event{binding(2, 0).URI: reginfo.Unregistered, binding(3, 0).URI: reginfo.Expired}
	told := map[string]bool{}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.sent {
		doc, _, _ := info(t, r)
		reg, _ := doc.ByAOR(sip.URI{Scheme: "sip", User: "+15550100001", Host: realm})
		for _, c := range reg.Contacts {
			if ev, ok := want[c.URI]; ok && !c.Active() {
				told[r.Header.Get("Call-ID")+c.URI] = true
				if c.Event != ev {
					t.Errorf("%s: %s ended as %s, want %s", r.Header.Get("Call-ID"), c.URI, c.Event, ev)
				}
			}
		}
	}
	if len(told) != 4 {
		t.Errorf("each subscriber told of the two ends %d times in all, want 4", len(told))
	}
}

// TestWaitForGivesUpAtItsDeadline: a NOTIFY whose answer does not come
// holds WaitFor only until its context ends; once answered, WaitFor
// returns at once, everything done.
func TestWaitForGivesUpAtItsDeadline(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	e.subscribedMany(1)
	g := newGate(1)
	n := newNotifierWith(t, e, e.store, g)
	n.Changed(bg, before, e.touched(before), Registered)
	<-g.entered
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if n.WaitFor(ctx) {
		t.Error("WaitFor reported everything done with a NOTIFY unanswered")
	}
	g.release <- struct{}{}
	if !n.WaitFor(bg) {
		t.Error("WaitFor gave up without a deadline")
	}
}

// #277: a re-registration that only refreshes the set's bindings still
// sends every subscription a full NOTIFY (TS 24.229 §5.4.2.1.2), counted in
// regevent.notify_refresh so that their rate can be measured. A change of
// the bindings, the subscription's first NOTIFY and a set's end are not
// counted there.
func TestARefreshOnlyReRegistrationsNotifiesAreCounted(t *testing.T) {
	e := newEnv(t)
	before := e.registered(binding(1, time.Hour))
	m := &counts{}
	n := newNotifierWith(t, e, e.store, e.send, func(c *Config) { c.Metrics = m })
	e.subscribed(n)
	if got := m.get("regevent.notify_refresh"); got != 0 {
		t.Fatalf("the first NOTIFY counted %d", got)
	}
	sent := len(e.send.notifies())
	refreshed := before.Clone()
	refreshed.Contacts[0].Expires = refreshed.Contacts[0].Expires.Add(time.Hour)
	refreshed.Contacts[0].CSeq++
	refreshed = e.saved(refreshed)
	n.Changed(bg, before, refreshed, Registered)
	n.Wait()
	if got := len(e.send.notifies()) - sent; got != 1 || m.get("regevent.notify_refresh") != 1 {
		t.Fatalf("%d NOTIFYs for the refresh, %d counted", got, m.get("regevent.notify_refresh"))
	}
	doc, _, _ := info(t, e.send.notifies()[len(e.send.notifies())-1])
	if doc.State != reginfo.Full {
		t.Errorf("the refresh's NOTIFY is %s, want full", doc.State)
	}
	added := refreshed.Clone()
	added.Contacts = append(added.Contacts, binding(2, time.Hour))
	added = e.saved(added)
	n.Changed(bg, refreshed, added, Registered)
	n.Wait()
	moved := added.Clone()
	moved.Contacts[1].Path = []string{"<sip:other@pcscf." + realm + ";lr>"}
	n.Changed(bg, added, e.saved(moved), Registered)
	n.Wait()
	if got := m.get("regevent.notify_refresh"); got != 1 {
		t.Errorf("changes of the bindings counted: %d", got)
	}
}

func TestRefreshOnlyTellsARefreshFromAChange(t *testing.T) {
	before := &state.Registration{Key: set1, Incarnation: 7, Contacts: []state.Contact{binding(1, time.Hour)},
		Identities: []state.SetIdentity{{IMPU: impu1}, {IMPU: tel1}}}
	with := func(f func(r *state.Registration)) *state.Registration {
		r := before.Clone()
		f(r)
		return r
	}
	for name, c := range map[string]struct {
		after *state.Registration
		cause Cause
		want  bool
	}{
		"expiry and CSeq": {with(func(r *state.Registration) {
			r.Contacts[0].Expires = r.Contacts[0].Expires.Add(time.Minute)
			r.Contacts[0].CSeq++
		}), Registered, true},
		"nothing":          {with(func(*state.Registration) {}), Registered, true},
		"a shorter expiry": {with(func(r *state.Registration) { r.Contacts[0].Expires = r.Contacts[0].Expires.Add(-time.Minute) }), Registered, true},
		"another cause":    {with(func(*state.Registration) {}), Unregistered, false},
		"a binding added":  {with(func(r *state.Registration) { r.Contacts = append(r.Contacts, binding(2, time.Hour)) }), Registered, false},
		"another binding":  {with(func(r *state.Registration) { r.Contacts[0] = binding(2, time.Hour) }), Registered, false},
		"its Path":         {with(func(r *state.Registration) { r.Contacts[0].Path = []string{"<sip:x@pcscf." + realm + ";lr>"} }), Registered, false},
		"a barring":        {with(func(r *state.Registration) { r.Identities[1].Barred = true }), Registered, false},
		"another record":   {with(func(r *state.Registration) { r.Incarnation++ }), Registered, false},
	} {
		if got := refreshOnly(before, c.after, c.cause); got != c.want {
			t.Errorf("%s: refreshOnly = %v, want %v", name, got, c.want)
		}
	}
}
