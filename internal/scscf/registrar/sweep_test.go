package registrar

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

var set1 = state.ProfileKey{IMPI: impi1, IMPU: impu1}

func registered(t *testing.T, e *env, g *Registrar, expires int, set ...string) *ue {
	t.Helper()
	u := e.akaUser(impi1, set...)
	wantStatus(t, u.registerWith(g, expires), 200)
	return u
}

func gone(t *testing.T, e *env, impus ...string) {
	t.Helper()
	for _, impu := range impus {
		if r, err := e.store.Registration(bg, impu); err == nil {
			t.Errorf("%s is still stored: %+v", impu, r)
		}
	}
}

func TestAnExpiredRegistrationIsDeregisteredWithTheHSSAndItsProfileGoes(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1, tel1)
	e.clock.advance(601 * time.Second)
	n, err := g.Sweep(bg, 10)
	if n != 2 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	sars := e.hss.sarsOf()
	if got := sars[len(sars)-2:]; got[0] != cx.TimeoutDeregistration || got[1] != cx.TimeoutDeregistration {
		t.Errorf("SARs %v", sars)
	}
	gone(t, e, impu1, tel1)
	if _, err := e.store.Profile(bg, set1, e.clock.Now()); err == nil {
		t.Error("the profile is still stored")
	}
}

func TestAnExpiredBindingAmongOthersGoesWithoutAnSAR(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	u := registered(t, e, g, 600, impu1)
	other := *u
	other.callID, other.contact = "device-2", "sip:ue2@192.0.2.20:5060;transport=tcp"
	wantStatus(t, other.registerWith(g, 1200), 200)
	sars := len(e.hss.sarsOf())
	e.clock.advance(601 * time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	if len(e.hss.sarsOf()) != sars {
		t.Error("a sweep that left a binding sent SAR")
	}
	if r := must(e.store.Registration(bg, impu1))(t); len(r.Contacts) != 1 || r.Contacts[0].CallID != "device-2" {
		t.Errorf("left %+v", r.Contacts)
	}
}

func TestADeregistrationTheHSSCouldNotTakeIsRetriedAfterTheLease(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	e.clock.advance(601 * time.Second)
	e.hss.mu.Lock()
	e.hss.unavailable = true
	e.hss.mu.Unlock()
	if _, err := g.Sweep(bg, 10); err == nil {
		t.Fatal("a failed SAR was not reported")
	}
	if r := must(e.store.Registration(bg, impu1))(t); r.Deregistering.IsZero() {
		t.Errorf("not held for a retry: %+v", r)
	}
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
	e.hss.mu.Lock()
	e.hss.unavailable = false
	e.hss.mu.Unlock()
	e.clock.advance(state.SweepLease + time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("retry swept %d, %v", n, err)
	}
	gone(t, e, impu1)
}

func TestAPermanentSARRefusalStillEndsTheRegistration(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	e.hss.sarHook = func(s *cx.SAR) (*cx.SAA, error) {
		if s.AssignmentType == cx.TimeoutDeregistration {
			return &cx.SAA{Answer: cx.Answer{Result: cx.ExperimentalResult(cx.ErrorUserUnknown)}}, nil
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
}

func TestAnUnregisteredUsersRecordIsDeregisteredWhenItsStateEnds(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	end := t0.Add(time.Hour)
	if _, err := e.store.SaveRegistration(bg, &state.Registration{IMPU: impu1, IMPI: impi1, DefaultIMPU: impu1, Unregistered: end}); err != nil {
		t.Fatal(err)
	}
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

func TestTheProfileStaysWhileAnotherIdentityOfTheSetHasBindings(t *testing.T) {
	e := newEnv(t)
	g := e.instance(1)
	registered(t, e, g, 600, impu1, tel1)
	// tel1's save of a later REGISTER succeeded, impu1's did not.
	r := must(e.store.Registration(bg, tel1))(t)
	r.Contacts[0].Expires = t0.Add(time.Hour)
	must(e.store.SaveRegistration(bg, r))(t)
	e.clock.advance(601 * time.Second)
	if n, err := g.Sweep(bg, 10); n != 1 || err != nil {
		t.Fatalf("swept %d, %v", n, err)
	}
	must(e.store.Profile(bg, set1, e.clock.Now()))(t)
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
		if _, err := e.store.Registration(bg, impu1); err != nil {
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
