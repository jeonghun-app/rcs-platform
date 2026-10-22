package registrar

import (
	"fmt"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// wantHSSAgreesWithTheStore checks live-here <=> the HSS's last word assigns the set.
func wantHSSAgreesWithTheStore(t *testing.T, e *env, v *qaView, m *counts, err error) {
	t.Helper()
	r, rerr := e.store.Registration(bg, set1)
	liveHere := rerr == nil && live(r, e.clock.Now())
	last := v.last()
	assigned := last == "REG" || last == "UNREG"
	v.mu.Lock()
	evs := append([]string(nil), v.events...)
	v.mu.Unlock()
	info := fmt.Sprintf("live here %v, HSS view %v, undone %d, sweep err %v", liveHere, evs, m.get("registrar.reassert_undone"), err)
	if liveHere != assigned {
		t.Errorf("MISMATCH %s", info)
	} else {
		t.Logf("ok %s", info)
	}
}

// deregistrationUnderWay turns the set into a deregistration under way (its lease,
// its SAR applied at the HSS) and returns the lease as claimed.
func deregistrationUnderWay(t *testing.T, e *env, v *qaView) *state.Registration {
	r := must(e.store.Registration(bg, set1))(t)
	r.Contacts, r.Deregistering = nil, e.clock.Now().Add(state.SweepLease)
	lease := must(e.store.SaveRegistration(bg, r))(t)
	must(v.SAR(bg, &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.UserDeregistration}))(t)
	return lease
}

func reassertingSet(t *testing.T) (*env, *qaView, func(byte, ...func(*Config)) *Registrar, *ue) {
	e := newEnv(t)
	v := &qaView{HSS: e.hss}
	inst := func(seed byte, tw ...func(*Config)) *Registrar {
		return e.instance(seed, append([]func(*Config){func(c *Config) { c.HSS = v }}, tw...)...)
	}
	u := reassertDue(t, e, inst(1))
	v.mu.Lock()
	v.events = []string{"REG"}
	v.mu.Unlock()
	return e, v, inst, u
}

func sweepForSixMinutes(e *env, inst func(byte, ...func(*Config)) *Registrar) {
	for range 6 {
		e.clock.advance(time.Minute)
		_, _ = inst(6).Sweep(bg, 10)
	}
}

// TestADeregistrationThatFinishesBeforeTheTombstoneIsReadAgain (#410 QA):
// a deregistration under way while the reassert is on its way finishes
// (deletes its lease under the version it claimed) between the undo's read
// and its tombstone's save, which then conflicts and reads the set again.
func TestADeregistrationThatFinishesBeforeTheTombstoneIsReadAgain(t *testing.T) {
	e, v, inst, _ := reassertingSet(t)
	under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
	var lease *state.Registration
	under.before["REG"] = func() { lease = deregistrationUnderWay(t, e, v) }
	store := &qaSaveHook{Store: e.store, at: 3, hook: func() { must(0, e.store.DeleteRegistration(bg, lease))(t) }}
	m := &counts{}
	_, err := e.instance(3, func(c *Config) { c.HSS, c.Store, c.Metrics = under, store, m }).Sweep(bg, 10)
	store.mu.Lock()
	t.Logf("saves by the sweeping instance: %d", store.n)
	store.mu.Unlock()
	sweepForSixMinutes(e, inst)
	wantHSSAgreesWithTheStore(t, e, v, m, err)
}

// TestATombstoneSavedOverALeaseCatchesALaterRegister (#410 QA): the
// deregistration under way finishes, or tries to, while the undo's SAR is
// about to go; a REGISTER then reads the set, sends its SAR before the
// undo's, and saves after it. The tombstone saved over the lease holds the
// set, so the REGISTER takes it over and is marked.
func TestATombstoneSavedOverALeaseCatchesALaterRegister(t *testing.T) {
	e, v, inst, u := reassertingSet(t)
	under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
	var lease *state.Registration
	under.before["REG"] = func() { lease = deregistrationUnderWay(t, e, v) }
	block := &qaBlockFirstSave{Store: e.store, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	under.before["DEREG"] = func() {
		// The deregistration finishes under the version it claimed.
		derr := e.store.DeleteRegistration(bg, lease)
		t.Logf("the deregistration's delete: %v", derr)
		go func() {
			defer close(done)
			wantStatus(t, u.registerWith(inst(4, func(c *Config) { c.Store = block }), 600), 200)
		}()
		<-block.entered
	}
	m := &counts{}
	_, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = under, m }).Sweep(bg, 10)
	close(block.release)
	<-done
	sweepForSixMinutes(e, inst)
	wantHSSAgreesWithTheStore(t, e, v, m, err)
}

// TestATombstoneHoldsTheSetForItsWholeLease (#410 QA): the late-save
// REGISTER, its save released 10 s (fake clock) after the undo, a sweep in
// between: the tombstone lasts a lease, not a moment.
func TestATombstoneHoldsTheSetForItsWholeLease(t *testing.T) {
	e, v, inst, u := reassertingSet(t)
	block := &qaBlockFirstSave{Store: e.store, entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
	under.before["REG"] = func() {
		wantStatus(t, u.registerWith(inst(2), 0), 200)
		go func() {
			defer close(done)
			wantStatus(t, u.registerWith(inst(4, func(c *Config) { c.Store = block }), 600), 200)
		}()
		<-block.entered
	}
	m := &counts{}
	_, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = under, m }).Sweep(bg, 10)
	e.clock.advance(10 * time.Second)
	_, _ = inst(6).Sweep(bg, 10)
	close(block.release)
	<-done
	sweepForSixMinutes(e, inst)
	wantHSSAgreesWithTheStore(t, e, v, m, err)
}
