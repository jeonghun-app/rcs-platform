package registrar

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// change is one call of Events.Changed.
type change struct {
	before, after int // contacts, -1 for nil
	cause         regevent.Cause
}

type recordedEvents struct {
	mu   sync.Mutex
	seen []change
}

func (r *recordedEvents) Changed(_ context.Context, before, after *state.Registration, cause regevent.Cause) {
	n := func(reg *state.Registration) int {
		if reg == nil {
			return -1
		}
		return len(reg.Contacts)
	}
	r.mu.Lock()
	r.seen = append(r.seen, change{n(before), n(after), cause})
	r.mu.Unlock()
}

func (r *recordedEvents) got() []change {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

func withEvents(r *recordedEvents) func(*Config) { return func(c *Config) { c.Events = r } }

// TestEveryChangeOfASetIsTold: what the reg event notifier hears of
// (TS 24.229 §5.4.2.1.2): a registration, a refresh, a binding added, the
// user's deregistration.
func TestEveryChangeOfASetIsTold(t *testing.T) {
	e := newEnv(t)
	ev := &recordedEvents{}
	g := e.instance(1, withEvents(ev))
	u := registered(t, e, g, 600, impu1, tel1)
	v := device(u, 2)
	wantStatus(t, u.registerWith(g, 600), 200)
	wantStatus(t, v.registerWith(g, 600), 200)
	wantStatus(t, u.registerWith(g, 0), 200)
	wantStatus(t, v.registerWith(g, 0), 200)
	want := []change{
		{-1, 1, regevent.Registered},
		{1, 1, regevent.Registered},
		{1, 2, regevent.Registered},
		{2, 1, regevent.Registered},
		{1, -1, regevent.Unregistered},
	}
	if got := ev.got(); !slices.Equal(got, want) {
		t.Errorf("changes %+v, want %+v", got, want)
	}
}

func TestASweepTellsOfExpiredBindings(t *testing.T) {
	e := newEnv(t)
	ev := &recordedEvents{}
	g := e.instance(1, withEvents(ev))
	u := registered(t, e, g, 600, impu1)
	wantStatus(t, device(u, 2).registerWith(g, 1200), 200)
	e.clock.advance(601 * time.Second)
	if _, err := g.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(600 * time.Second)
	if _, err := g.Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	got := ev.got()[2:]
	// The record the sweep claimed still lists the binding that expired,
	// which the NOTIFY reports as such.
	want := []change{{2, 1, regevent.Expired}, {1, -1, regevent.Expired}}
	if !slices.Equal(got, want) {
		t.Errorf("changes %+v, want %+v", got, want)
	}
}

func TestAnRTRTellsOfTheSetsItEnds(t *testing.T) {
	for reason, cause := range map[cx.ReasonCode]regevent.Cause{
		cx.PermanentTermination: regevent.Rejected, cx.NewServerAssigned: regevent.Deactivated, cx.ServerChange: regevent.Deactivated,
	} {
		e := newEnv(t)
		ev := &recordedEvents{}
		g := e.instance(1, withEvents(ev))
		registered(t, e, g, 600, impu1)
		wantResult(t, g.HandleRTR(bg, &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: reason}}), resultSuccess)
		if got := ev.got(); len(got) != 2 || got[1] != (change{1, -1, cause}) {
			t.Errorf("reason %d: changes %+v", reason, got)
		}
	}
}

func TestAPPRThatChangesTheIdentitiesTellsOfIt(t *testing.T) {
	e := newEnv(t)
	ev := &recordedEvents{}
	g := e.instance(1, withEvents(ev))
	registered(t, e, g, 600, impu1)
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, tel1)}), resultSuccess)
	if got := ev.got(); len(got) != 2 || got[1] != (change{1, 1, regevent.Changed}) {
		t.Errorf("changes %+v", got)
	}
	// The same identities again change nothing to tell.
	wantResult(t, g.HandlePPR(bg, &cx.PPR{UserName: impi1, UserData: userDataOf(impi1, nil, impu1, tel1)}), resultSuccess)
	if got := ev.got(); len(got) != 2 {
		t.Errorf("changes %+v after a PPR that changed nothing", got)
	}
}
