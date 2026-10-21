package registrar

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// qaView is every instance's HSS: it keeps the HSS's view as the list of
// assignments it took (failed SARs excluded) plus RTRs it issued, and runs
// hooks at points around the SARs of the instance under test.
type qaView struct {
	HSS
	mu     sync.Mutex
	events []string
	// hooks by point; each runs once.
	before, after map[string]func()
	under         bool // true while the instance under test's SAR runs (set by qaUnder)
}

func (v *qaView) note(ev string) { v.mu.Lock(); v.events = append(v.events, ev); v.mu.Unlock() }

func (v *qaView) last() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.events) == 0 {
		return ""
	}
	return v.events[len(v.events)-1]
}

func sarName(t cx.ServerAssignmentType) string {
	switch t {
	case cx.Registration, cx.ReRegistration:
		return "REG"
	case cx.UnregisteredUser:
		return "UNREG"
	case cx.UserDeregistration, cx.TimeoutDeregistration, cx.AdministrativeDeregistration:
		return "DEREG"
	}
	return fmt.Sprint(int(t))
}

func (v *qaView) record(r *cx.SAR, saa *cx.SAA, err error) {
	if err == nil && saa != nil && cxclient.Classify(saa.Result) == cxclient.Success {
		v.note(sarName(r.AssignmentType))
	}
}

// qaUnder is the instance under test's HSS: hooks fire on its SARs only.
type qaUnder struct {
	v             *qaView
	mu            sync.Mutex
	before, after map[string]func()
}

func (u *qaUnder) Authenticate(ctx context.Context, r *cx.MAR, s []string) (*cx.MAA, error) {
	return u.v.Authenticate(ctx, r, s)
}
func (u *qaUnder) MAR(ctx context.Context, r *cx.MAR) (*cx.MAA, error) { return u.v.MAR(ctx, r) }
func (u *qaUnder) take(m map[string]func(), k string) func() {
	u.mu.Lock()
	defer u.mu.Unlock()
	f := m[k]
	delete(m, k)
	return f
}
func (u *qaUnder) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	k := sarName(r.AssignmentType)
	if f := u.take(u.before, k); f != nil {
		f()
	}
	saa, err := u.v.HSS.SAR(ctx, r)
	u.v.record(r, saa, err)
	if f := u.take(u.after, k); f != nil {
		f()
	}
	return saa, err
}

func (v *qaView) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	saa, err := v.HSS.SAR(ctx, r)
	v.record(r, saa, err)
	return saa, err
}

// qaSaveHook runs hook before the n-th SaveRegistration of the instance.
type qaSaveHook struct {
	state.Store
	mu   sync.Mutex
	n    int
	at   int
	hook func()
}

func (s *qaSaveHook) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.mu.Lock()
	s.n++
	run := s.n == s.at && s.hook != nil
	s.mu.Unlock()
	if run {
		s.hook()
	}
	return s.Store.SaveRegistration(ctx, r)
}

// TestEveryInterleavingOfAReassertLeavesTheHSSAgreeingWithTheStore (#410
// QA): the sweep's reassert of impu1's set, with other instances' actions
// at points of it (before / after the HSS applies the reassert's SAR,
// before the reassert's save, before / after the undo's SAR). After the
// sweep and six minutes of further sweeps, the HSS's view must match the
// store: set live here <=> the HSS's last word assigns it.
//
// One interleaving is left out: an RTR the HSS applied before the
// reassert's SAR but that reaches this instance after it ("before-REG/
// rtr-late"). No read here can see it, and the lead accepted it as a
// narrow case (#410).
func TestEveryInterleavingOfAReassertLeavesTheHSSAgreeingWithTheStore(t *testing.T) {
	type step struct{ kind, at, act string }
	cases := map[string][]step{}
	for _, at := range []step{{"before", "REG", ""}, {"after", "REG", ""}, {"save", "", ""}} {
		for _, act := range []string{"dereg", "dereg+register", "rtr-now", "rtr-late"} {
			cases[at.kind+"-"+at.at+"/"+act] = []step{{at.kind, at.at, act}}
		}
	}
	for _, at := range []step{{"before", "DEREG", ""}, {"after", "DEREG", ""}} {
		for _, act := range []string{"register", "rtr-now"} {
			cases["dereg@before-REG,"+at.kind+"-"+at.at+"/"+act] = []step{{"before", "REG", "dereg"}, {at.kind, at.at, act}}
		}
	}
	delete(cases, "before-REG/rtr-late")
	for name, steps := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			v := &qaView{HSS: e.hss}
			inst := func(seed byte) *Registrar { return e.instance(seed, func(c *Config) { c.HSS = v }) }
			u := reassertDue(t, e, inst(1))
			v.mu.Lock()
			v.events = []string{"REG"}
			v.mu.Unlock()
			under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
			store := &qaSaveHook{Store: e.store}
			late := false
			rtr := func(seed byte) {
				wantResult(t, inst(seed).HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.ServerChange}}), resultSuccess)
			}
			for _, st := range steps {
				var act func()
				switch st.act {
				case "dereg":
					act = func() { wantStatus(t, u.registerWith(inst(2), 0), 200) }
				case "register":
					act = func() { wantStatus(t, u.registerWith(inst(4), 600), 200) }
				case "dereg+register":
					act = func() {
						wantStatus(t, u.registerWith(inst(2), 0), 200)
						wantStatus(t, u.registerWith(inst(4), 600), 200)
					}
				case "rtr-now":
					act = func() { v.note("DEREG(rtr)"); rtr(7) }
				case "rtr-late":
					act = func() { v.note("DEREG(rtr)"); late = true }
				}
				switch st.kind {
				case "before":
					under.before[st.at] = act
				case "after":
					under.after[st.at] = act
				case "save":
					store.at, store.hook = 2, act
				}
			}
			m := &counts{}
			g := e.instance(3, func(c *Config) { c.HSS, c.Store, c.Metrics = under, store, m })
			_, err := g.Sweep(bg, 10)
			if late {
				rtr(5)
			}
			for range 6 {
				e.clock.advance(time.Minute)
				_, _ = inst(6).Sweep(bg, 10)
			}
			under.mu.Lock()
			unfired := len(under.before) + len(under.after)
			under.mu.Unlock()
			store.mu.Lock()
			if store.hook != nil && store.n < store.at {
				unfired++
			}
			store.mu.Unlock()
			r, rerr := e.store.Registration(bg, set1)
			liveHere := rerr == nil && live(r, e.clock.Now())
			last := v.last()
			assigned := last == "REG" || last == "UNREG"
			v.mu.Lock()
			evs := append([]string(nil), v.events...)
			v.mu.Unlock()
			info := fmt.Sprintf("live here %v, HSS view %v, undone %d, undo_failed %d, hooks not reached %d, sweep err %v",
				liveHere, evs, m.get("registrar.reassert_undone"), m.get("registrar.reassert_undo_failed"), unfired, err)
			if liveHere != assigned {
				t.Errorf("MISMATCH %s", info)
			} else {
				t.Logf("ok %s", info)
			}
		})
	}
}

// TestAnUndoThatFailsOnceIsSentAgain (#410 QA): the undo's SAR fails once,
// the HSS busy for one request, and the HSS ends with the deregistration.
func TestAnUndoThatFailsOnceIsSentAgain(t *testing.T) {
	e := newEnv(t)
	v := &qaView{HSS: e.hss}
	inst := func(seed byte) *Registrar { return e.instance(seed, func(c *Config) { c.HSS = v }) }
	u := reassertDue(t, e, inst(1))
	v.events = []string{"REG"}
	under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
	under.before["REG"] = func() { wantStatus(t, u.registerWith(inst(2), 0), 200) }
	failOnce := &qaFailOnceDereg{HSS: under}
	m := &counts{}
	_, err := e.instance(3, func(c *Config) { c.HSS, c.Metrics = failOnce, m }).Sweep(bg, 10)
	for range 10 {
		e.clock.advance(time.Minute)
		_, _ = inst(6).Sweep(bg, 10)
	}
	_, rerr := e.store.Registration(bg, set1)
	t.Logf("sweep err %v; undo_failed %d; record gone %v; HSS view %v", err != nil, m.get("registrar.reassert_undo_failed"), rerr != nil, v.events)
	if l := v.last(); l != "DEREG" {
		t.Errorf("HSS last %q with no record here, 10 min after one failed undo", l)
	}
}

type qaFailOnceDereg struct {
	HSS
	mu   sync.Mutex
	done bool
}

func (f *qaFailOnceDereg) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	f.mu.Lock()
	first := r.AssignmentType == cx.UserDeregistration && !f.done
	if first {
		f.done = true
	}
	f.mu.Unlock()
	if first {
		return nil, errUnreachable
	}
	return f.HSS.SAR(ctx, r)
}

// qaBlockFirstSave blocks the first SaveRegistration until release.
type qaBlockFirstSave struct {
	state.Store
	once             sync.Once
	entered, release chan struct{}
}

func (s *qaBlockFirstSave) SaveRegistration(ctx context.Context, r *state.Registration) (*state.Registration, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.Store.SaveRegistration(ctx, r)
}

// qaAfterDelete runs hook once right after the first DeleteRegistration.
type qaAfterDelete struct {
	state.Store
	once sync.Once
	hook func()
}

func (s *qaAfterDelete) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	err := s.Store.DeleteRegistration(ctx, r)
	if s.hook != nil {
		s.once.Do(s.hook)
	}
	return err
}

// TestARegisterSavedAfterTheUndoIsToldToTheHSSAgain (#410 code review and
// QA): the user deregisters while the sweep's reassert is on its way, then
// registers again: that REGISTER reads no record, its SAR reaches the HSS
// before the undo's, and its record save is held until a point of the
// undo. The tombstone, kept for its lease, makes the REGISTER take the set
// over, which marks it for the sweep.
func TestARegisterSavedAfterTheUndoIsToldToTheHSSAgain(t *testing.T) {
	for _, at := range []string{"after the undo SAR", "after the tombstone's delete", "after the sweep returns"} {
		t.Run(at, func(t *testing.T) {
			e := newEnv(t)
			v := &qaView{HSS: e.hss}
			inst := func(seed byte, tw ...func(*Config)) *Registrar {
				return e.instance(seed, append([]func(*Config){func(c *Config) { c.HSS = v }}, tw...)...)
			}
			u := reassertDue(t, e, inst(1))
			v.mu.Lock()
			v.events = []string{"REG"}
			v.mu.Unlock()
			block := &qaBlockFirstSave{Store: e.store, entered: make(chan struct{}), release: make(chan struct{})}
			done := make(chan struct{})
			under := &qaUnder{v: v, before: map[string]func(){}, after: map[string]func(){}}
			released := false
			release := func() {
				if !released {
					released = true
					close(block.release)
					<-done
				}
			}
			under.before["REG"] = func() {
				wantStatus(t, u.registerWith(inst(2), 0), 200)
				go func() {
					defer close(done)
					wantStatus(t, u.registerWith(inst(4, func(c *Config) { c.Store = block }), 600), 200)
				}()
				<-block.entered // its SAR is at the HSS, its record not saved
			}
			del := &qaAfterDelete{Store: e.store}
			switch at {
			case "after the undo SAR":
				under.after["DEREG"] = release
			case "after the tombstone's delete":
				del.hook = release
			}
			m := &counts{}
			_, err := e.instance(3, func(c *Config) { c.HSS, c.Store, c.Metrics = under, del, m }).Sweep(bg, 10)
			release()
			for range 6 {
				e.clock.advance(time.Minute)
				_, _ = inst(6).Sweep(bg, 10)
			}
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
		})
	}
}
