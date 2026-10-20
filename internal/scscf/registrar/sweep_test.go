package registrar

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// counts records the registrar's metrics.
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

func registered(t *testing.T, e *env, g *Registrar, expires int, set ...string) *ue {
	t.Helper()
	u := e.akaUser(impi1, set...)
	u.instance = "<urn:uuid:00000000-0000-0000-0000-0000000000aa>"
	wantStatus(t, u.registerWith(g, expires), 200)
	return u
}

func TestAnExpiredSetIsDeregisteredOnceWithTheHSSAndEverythingOfItGoes(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	registered(t, e, g, 600, impu1, tel1)
	sars := len(e.hss.sarsOf())
	e.clock.advance(601 * time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v: one set, one record", n, err)
	}
	// One SAR for the whole set (TS 29.228 §6.5.2.2), not one per identity.
	if got := e.hss.sarsOf()[sars:]; !slices.Equal(got, []cx.ServerAssignmentType{cx.TimeoutDeregistration}) {
		t.Errorf("SARs %v", got)
	}
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu1, tel1} {
		if _, err := e.store.Identity(bg, impu, e.clock.Now()); err == nil {
			t.Errorf("%s still names the set", impu)
		}
	}
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the profile is still stored")
	}
	if m.get("registrar.expired") != 1 {
		t.Errorf("expired = %d", m.get("registrar.expired"))
	}
}

func TestAnExpiredBindingAmongOthersGoesWithoutAnSAR(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := registered(t, e, g, 600, impu1)
	wantStatus(t, device(u, 2).registerWith(g, 1200), 200)
	sars := len(e.hss.sarsOf())
	e.clock.advance(601 * time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	if len(e.hss.sarsOf()) != sars {
		t.Error("a sweep that left a binding sent SAR")
	}
	if r := must(regOf(e, impu1))(t); len(r.Contacts) != 1 || r.Contacts[0].CallID != "device-2" {
		t.Errorf("left %+v", r.Contacts)
	}
}

func TestADeregistrationTheHSSCouldNotTakeIsRetriedAfterTheLease(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	registered(t, e, g, 600, impu1)
	e.clock.advance(601 * time.Second)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	if _, err := g.Sweep(bg, 10); err == nil {
		t.Fatal("a failed SAR was not reported")
	}
	if r := must(regOf(e, impu1))(t); r.Deregistering.IsZero() {
		t.Errorf("not held for a retry: %+v", r)
	}
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
	if m.get("registrar.expire_failed") != 1 {
		t.Errorf("expire_failed = %d", m.get("registrar.expire_failed"))
	}
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	e.clock.advance(state.SweepLease + time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("retry swept %d, %v", n, err)
	}
	gone(t, e, impu1)
}

func TestPermanentSARRefusalsStillEndTheSet(t *testing.T) {
	for name, res := range map[string]cx.Result{
		"user unknown (5001)":                cx.ExperimentalResult(cx.ErrorUserUnknown),
		"identities do not match (5002)":     cx.ExperimentalResult(cx.ErrorIdentitiesDontMatch),
		"not registered (5003)":              cx.ExperimentalResult(cx.ErrorIdentityNotRegistered),
		"served by another S-CSCF (5005)":    cx.ExperimentalResult(cx.ErrorIdentityAlreadyRegistered),
		"rejected (another 3GPP 5xxx, 5007)": cx.ExperimentalResult(cx.ErrorInAssignmentType),
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := &counts{}
			g := e.instance(1, func(c *Config) { c.Metrics = m })
			registered(t, e, g, 600, impu1)
			e.hss.sarHook = func(s *cx.SAR) (*cx.SAA, error) {
				if s.AssignmentType == cx.TimeoutDeregistration {
					return &cx.SAA{Answer: cx.Answer{Result: res}}, nil
				}
				return nil, nil
			}
			e.clock.advance(601 * time.Second)
			if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
				t.Fatalf("swept %d, %v: a refusal that will not change must not be retried", n, err)
			}
			gone(t, e, impu1)
			if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
				t.Error("the profile is still stored")
			}
			if m.get("registrar.expired_refused") != 1 {
				t.Errorf("expired_refused = %d", m.get("registrar.expired_refused"))
			}
		})
	}
}

func TestAnUnregisteredUsersRecordIsDeregisteredWhenItsStateEnds(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	end := t0.Add(time.Hour)
	seed(t, e, impi1, []string{impu1}, func(r *state.Registration) { r.Unregistered = end })
	if err := e.store.SaveProfile(bg, &state.Profile{Key: set1, UserData: userDataOf(impi1, nil, impu1), Received: t0, KeepUntil: end.Add(state.ProfileGrace)}); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(59 * time.Minute)
	if n, _ := g.Sweep(bg, 10); n != 0 {
		t.Fatal("swept before the unregistered state ended")
	}
	e.clock.advance(time.Minute)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	if got := e.hss.sarsOf(); !slices.Equal(got, []cx.ServerAssignmentType{cx.TimeoutDeregistration}) {
		t.Errorf("SARs %v", got)
	}
	gone(t, e, impu1)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the profile is still stored")
	}
}

func TestARegistrationBetweenTheSweepsClaimAndItsSARGetsTheSetBack(t *testing.T) {
	e := newEnv(t)
	a := registered(t, e, e.instance(1), 600, impu1, tel1)
	e.clock.advance(601 * time.Second)
	b := device(a, 2)
	ch := &crossingHSS{HSS: e.hss, kind: cx.TimeoutDeregistration}
	plain := func(seed byte) *Registrar { return e.instance(seed, func(c *Config) { c.HSS = ch }) }
	// The sweep has claimed the set; before its SAR reaches the HSS, B
	// registers completely, its SAR REGISTRATION first.
	ch.hook = func() { wantStatus(t, b.registerWith(plain(2), 600), 200) }
	if n, err := plain(3).Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	wantSameBindings(t, e, 1, impu1, tel1)
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if ch.last != cx.Registration {
		t.Errorf("the HSS was last told %v, with B registered here", ch.last)
	}
}

func TestADeviceRegisteringAfterTheSweepsSARKeepsItsProfile(t *testing.T) {
	e := newEnv(t)
	a := registered(t, e, e.instance(1), 600, impu1)
	e.clock.advance(601 * time.Second)
	b := device(a, 2)
	// The sweep has sent its SAR and reads the set again when B registers.
	ss := &stepStore{Store: e.store, method: "Registration", n: 1, hook: func() {
		wantStatus(t, b.registerWith(e.instance(2), 600), 200)
	}}
	g := e.instance(3, func(c *Config) { c.Store = ss })
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	r := must(regOf(e, impu1))(t)
	if len(r.Contacts) != 1 || r.Contacts[0].CallID != "device-2" {
		t.Errorf("impu1 holds %+v, want B's binding", r.Contacts)
	}
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
}

func TestAMassExpiryDrainsInOneRun(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	for i, impi := range []string{impi1, impi2, "001010000000003@" + realm} {
		u := e.akaUser(impi, []string{impu1, impu2, impu3}[i])
		wantStatus(t, u.registerWith(g, 600), 200)
	}
	e.clock.advance(601 * time.Second)
	if n := g.sweepAll(bg, 1); n != 3 {
		t.Errorf("one run swept %d of 3 with a limit of 1", n)
	}
	gone(t, e, impu1, impu2, impu3)
}

func TestASweepThatFailsLogsNoIdentity(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	e.clock.advance(601 * time.Second)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	g.sweepAll(bg, 10)
	logs := e.logs.String()
	if !strings.Contains(logs, "registrar: sweep") {
		t.Fatal("the failure was not logged; the check below would prove nothing")
	}
	for _, s := range []string{impi1, "+15550100001"} {
		if strings.Contains(logs, s) {
			t.Errorf("the log has %q", s)
		}
	}
}

func TestRunSweepsSweepsUntilItsContextEnds(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	e.clock.advance(601 * time.Second)
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { g.RunSweeps(ctx, time.Millisecond, 1); close(done) }()
	deadline := time.After(10 * time.Second)
	for {
		if _, err := regOf(e, impu1); err != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("RunSweeps never swept")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunSweeps did not return once cancelled")
	}
}

// reassertDue registers impu1 and marks its set as a failed reassign does,
// due now.
func reassertDue(t *testing.T, e *env, g *Registrar) *ue {
	t.Helper()
	u := registered(t, e, g, 3600, impu1, tel1)
	r := must(e.store.Registration(bg, set1))(t)
	r.Reassert, r.ReassertAttempts = e.clock.Now().Add(reassertBackoff), 1
	must(e.store.SaveRegistration(bg, r))(t)
	e.clock.advance(reassertBackoff)
	return u
}

// TestASweepTellsTheHSSAgainThatItServesASetWhoseReassertIsDue: the
// registrar's own SAR after a crossed deregistration failed; the sweep's
// succeeds, and the mark goes.
func TestASweepTellsTheHSSAgainThatItServesASetWhoseReassertIsDue(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	reassertDue(t, e, g)
	sars := len(e.hss.sarsOf())
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	if got := e.hss.sarsOf()[sars:]; !slices.Equal(got, []cx.ServerAssignmentType{cx.Registration}) {
		t.Errorf("SARs %v", got)
	}
	r := must(e.store.Registration(bg, set1))(t)
	if !r.Reassert.IsZero() || r.ReassertAttempts != 0 || len(r.Contacts) != 1 {
		t.Errorf("after the reassert: Reassert %v, %d attempts, %d contacts", r.Reassert, r.ReassertAttempts, len(r.Contacts))
	}
	if got := m.get("registrar.reasserted"); got != 1 {
		t.Errorf("reasserted = %d", got)
	}
	if n, _ := g.Sweep(bg, 10); n != 0 {
		t.Errorf("a second sweep handled %d", n)
	}
}

// TestAReassertTheHSSKeepsRefusingBacksOffAndGivesUp: an HSS out of reach
// is tried again after 2, 4, 8 and 16 minutes, five sweep attempts in all,
// and then left to the set's next re-registration; the bindings stay.
func TestAReassertTheHSSKeepsRefusingBacksOffAndGivesUp(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	reassertDue(t, e, g)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	sars := len(e.hss.sarsOf())
	for try, wait := range []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute} {
		if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
			t.Fatalf("try %d: swept %d, %v", try+1, n, err)
		}
		r := must(e.store.Registration(bg, set1))(t)
		if !r.Reassert.Equal(e.clock.Now().Add(wait)) || r.ReassertAttempts != try+2 {
			t.Fatalf("after try %d: Reassert in %v, %d attempts; want %v", try+1, r.Reassert.Sub(e.clock.Now()), r.ReassertAttempts, wait)
		}
		e.clock.advance(wait - time.Second)
		if n, _ := g.Sweep(bg, 10); n != 0 {
			t.Fatalf("after try %d: swept a second early", try+1)
		}
		e.clock.advance(time.Second)
	}
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("the last try: swept %d, %v", n, err)
	}
	r := must(e.store.Registration(bg, set1))(t)
	if !r.Reassert.IsZero() || r.ReassertAttempts != 0 || len(r.Contacts) != 1 {
		t.Errorf("after giving up: Reassert %v, %d attempts, %d contacts", r.Reassert, r.ReassertAttempts, len(r.Contacts))
	}
	if got := len(e.hss.sarsOf()) - sars; got != maxReassertTries {
		t.Errorf("%d SARs, want %d", got, maxReassertTries)
	}
	if m.get("registrar.reassert_failed") != maxReassertTries-1 || m.get("registrar.reassert_abandoned") != 1 {
		t.Errorf("reassert_failed = %d, reassert_abandoned = %d", m.get("registrar.reassert_failed"), m.get("registrar.reassert_abandoned"))
	}
}

// TestAReassertTheHSSRefusesForGoodIsNotRetried: 5001 and the like will not
// change, so the mark goes at once.
func TestAReassertTheHSSRefusesForGoodIsNotRetried(t *testing.T) {
	e := newEnv(t)
	m := &counts{}
	g := e.instance(1, func(c *Config) { c.Metrics = m })
	reassertDue(t, e, g)
	unknown := cx.ExperimentalResult(cx.ErrorUserUnknown)
	e.hss.mu.Lock()
	e.hss.sarResult = &unknown
	e.hss.mu.Unlock()
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	r := must(e.store.Registration(bg, set1))(t)
	if !r.Reassert.IsZero() || m.get("registrar.reassert_abandoned") != 1 {
		t.Errorf("after 5001: Reassert %v, abandoned %d", r.Reassert, m.get("registrar.reassert_abandoned"))
	}
}

// TestAReassertSweepLosingToARegisterLeavesTheRegistersSave: the REGISTER
// told the HSS itself, and its save carries no Reassert.
func TestAReassertSweepLosingToARegisterLeavesTheRegistersSave(t *testing.T) {
	e := newEnv(t)
	u := reassertDue(t, e, e.instance(1))
	// The re-REGISTER lands while the sweep's SAR is on its way.
	ch := &crossingHSS{HSS: e.hss, kind: cx.Registration}
	ch.hook = func() { wantStatus(t, u.registerWith(e.instance(2), 3600), 200) }
	g := e.instance(3, func(c *Config) { c.HSS = ch })
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	r := must(e.store.Registration(bg, set1))(t)
	if !r.Reassert.IsZero() || len(r.Contacts) != 1 || !r.Contacts[0].Expires.Equal(e.clock.Now().Add(time.Hour)) {
		t.Errorf("after the race: Reassert %v, %+v", r.Reassert, r.Contacts)
	}
}

// TestADeregistrationLeftAsALeaseIsFinishedByTheNextSweep: the HSS cannot be
// told of a deregistration and the bindings cannot be put back either, so the
// lease stands. The first sweep after the lease tells the HSS and leaves
// nothing of the set (QA's minor 2 on #196).
func TestADeregistrationLeftAsALeaseIsFinishedByTheNextSweep(t *testing.T) {
	e := newEnv(t)
	u := e.akaUser(impi1, impu1, tel1)
	wantStatus(t, u.registerWith(e.instance(1), 600), 200)
	e.hss.mu.Lock()
	e.hss.sarHook = func(r *cx.SAR) (*cx.SAA, error) {
		if r.AssignmentType == cx.UserDeregistration {
			return nil, errUnreachable
		}
		return nil, nil
	}
	e.hss.mu.Unlock()
	// The writes are the lease, then the record put back, which fails.
	fs := &faultStore{Store: e.store, at: 1, kind: "error"}
	wantStatus(t, u.registerWith(e.instance(2, func(c *Config) { c.Store = fs }), 0), 480)
	if r := must(e.store.Registration(bg, set1))(t); len(r.Contacts) != 0 || r.Deregistering.IsZero() {
		t.Fatalf("not left as a lease: %+v", r)
	}
	e.hss.mu.Lock()
	e.hss.sarHook = nil
	e.hss.mu.Unlock()
	sars := len(e.hss.sarsOf())
	e.clock.advance(state.SweepLease + time.Second)
	if n, err := e.instance(3).Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	if got := e.hss.sarsOf()[sars:]; !slices.Equal(got, []cx.ServerAssignmentType{cx.TimeoutDeregistration}) {
		t.Errorf("SARs %v", got)
	}
	gone(t, e, impu1, tel1)
	for _, impu := range []string{impu1, tel1} {
		if _, err := e.store.Identity(bg, impu, e.clock.Now()); err == nil {
			t.Errorf("%s still names the set", impu)
		}
	}
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the profile is still stored")
	}
}
