package state_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/statetest"
)

func TestAReassertIsDueFromItsTimeOn(t *testing.T) {
	r := &state.Registration{Reassert: statetest.T0}
	for _, tc := range []struct {
		now  time.Time
		want bool
	}{
		{statetest.T0.Add(-time.Nanosecond), false},
		{statetest.T0, true},
		{statetest.T0.Add(time.Second), true},
	} {
		if got := r.ReassertDue(tc.now); got != tc.want {
			t.Errorf("ReassertDue(Reassert %+v) = %v", tc.now.Sub(statetest.T0), got)
		}
	}
	if (&state.Registration{}).ReassertDue(statetest.T0) {
		t.Error("due without a Reassert")
	}
}

// actor is one side of the interleaving model below: each step is one store
// call, and step reports whether the actor has finished.
type actor func() bool

// handleModel is a sweep's handle for the set claimed as claimed, as #196 and
// #210 run it: read the record again and stop if it is live or changed, delete
// the identity if it names the claimed incarnation, then the record, reading
// again after a conflict.
func handleModel(ctx context.Context, s state.Store, claimed *state.Registration, now time.Time) actor {
	pc, tries := 0, 0
	var again *state.Registration
	var id *state.Identity
	return func() bool {
		switch pc {
		case 0:
			r, err := s.Registration(ctx, statetest.Set1)
			if err != nil || len(r.Contacts) > 0 || r.Version != claimed.Version {
				return true
			}
			again, pc = r, 1
		case 1:
			i, err := s.Identity(ctx, statetest.IMPU1, now)
			if err != nil || i.Set != claimed.Key || i.Incarnation != claimed.Incarnation {
				pc = 3
				break
			}
			id, pc = i, 2
		case 2:
			if err := s.DeleteIdentity(ctx, id); errors.Is(err, state.ErrConflict) {
				pc = 1
				break
			}
			pc = 3
		case 3:
			err := s.DeleteRegistration(ctx, again)
			if tries++; errors.Is(err, state.ErrConflict) && tries < 3 {
				pc = 0
				break
			}
			return true
		}
		return false
	}
}

// registerModel is a REGISTER as #196 runs it: read the record, save it with
// a binding, under a new incarnation if it was claimed for a deregistration
// (Registration.Incarnation), then point the identity at it.
func registerModel(ctx context.Context, s state.Store, now time.Time, failed *bool) actor {
	pc, inc, tries := 0, int64(100), 0
	var cur, saved *state.Registration
	var id *state.Identity
	return func() bool {
		switch pc {
		case 0:
			r, err := s.Registration(ctx, statetest.Set1)
			cur = nil
			if err == nil {
				cur = r
			}
			pc = 1
		case 1:
			next := statetest.Registration(statetest.IMPI1, statetest.IMPU1, 2*time.Hour)
			switch {
			case cur == nil:
				inc++
				next.Incarnation = inc
			case !cur.Deregistering.IsZero():
				inc++
				next.Incarnation, next.Version = inc, cur.Version
			default:
				next.Incarnation, next.Version = cur.Incarnation, cur.Version
			}
			r, err := s.SaveRegistration(ctx, next)
			if err != nil {
				// Read again and apply to what won, as often as #196 does.
				if tries++; tries == 3 {
					*failed = true
					return true
				}
				pc = 0
				break
			}
			saved, pc = r, 2
		case 2:
			i, err := s.Identity(ctx, statetest.IMPU1, now)
			id = nil
			if err == nil {
				id = i
			}
			pc = 3
		case 3:
			want := &state.Identity{IMPU: statetest.IMPU1, Set: saved.Key, Incarnation: saved.Incarnation, KeepUntil: now.Add(26 * time.Hour)}
			if id != nil {
				want.Version = id.Version
			}
			if _, err := s.SaveIdentity(ctx, want, now); err != nil {
				pc = 2
				break
			}
			return true
		}
		return false
	}
}

// TestADeregistrationAndARegisterInEveryOrderLeaveNoLiveSetUnpointed: a sweep
// has claimed a set whose last binding expired, and the device registers
// again while the sweep's handle runs. In every order of their store calls,
// the set ends registered with its identity pointing at it, or gone with no
// identity left. From QA's model on #184, which failed with the incarnation
// kept across the revival.
func TestADeregistrationAndARegisterInEveryOrderLeaveNoLiveSetUnpointed(t *testing.T) {
	ctx := context.Background()
	now := statetest.T0.Add(time.Minute)
	orders, bad := 0, 0
	var run func(prefix []int)
	run = func(prefix []int) {
		m := state.NewMemory()
		live, err := m.SaveRegistration(ctx, statetest.Registration(statetest.IMPI1, statetest.IMPU1, time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.SaveIdentity(ctx, &state.Identity{IMPU: statetest.IMPU1, Set: statetest.Set1, Incarnation: live.Incarnation, KeepUntil: now.Add(24 * time.Hour)}, now); err != nil {
			t.Fatal(err)
		}
		lease := live.Clone()
		lease.Contacts, lease.Deregistering = nil, now.Add(state.SweepLease)
		claimed, err := m.SaveRegistration(ctx, lease)
		if err != nil {
			t.Fatal(err)
		}
		failed := false
		actors := []actor{handleModel(ctx, m, claimed, now), registerModel(ctx, m, now, &failed)}
		done := []bool{false, false}
		for _, a := range prefix {
			if done[a] {
				return
			}
			done[a] = actors[a]()
		}
		if !done[0] || !done[1] {
			if len(prefix) == 40 {
				t.Fatalf("order %v: still running after 40 store calls", prefix)
			}
			for a := range actors {
				if !done[a] {
					run(append(prefix[:len(prefix):len(prefix)], a))
				}
			}
			return
		}
		orders++
		problem := setState(ctx, m, now)
		if failed {
			problem = "the REGISTER lost every save"
		}
		if problem != "" {
			bad++
			t.Errorf("order %v: %s", prefix, problem)
		}
	}
	run(nil)
	if orders < 20 {
		t.Fatalf("only %d orders explored", orders)
	}
	t.Logf("%d orders, %d broke the invariant", orders, bad)
}

func setState(ctx context.Context, s state.Store, now time.Time) string {
	r, rerr := s.Registration(ctx, statetest.Set1)
	i, ierr := s.Identity(ctx, statetest.IMPU1, now)
	switch {
	case rerr == nil && len(r.Contacts) > 0 && (ierr != nil || i.Incarnation != r.Incarnation):
		return fmt.Sprintf("registered, but the identity names %v (%v)", i, ierr)
	case rerr == nil && len(r.Contacts) == 0:
		return "a record without bindings left"
	case rerr != nil && ierr == nil:
		return "an identity without its set"
	}
	return ""
}
