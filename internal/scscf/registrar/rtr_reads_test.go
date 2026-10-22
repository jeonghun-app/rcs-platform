package registrar

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// failingRead fails the first call of one read method with err, as a
// throttled read whose SDK retries are spent does.
type failingRead struct {
	state.Store
	method string
	err    error
	calls  atomic.Int32
}

func (s *failingRead) fail(method string) error {
	if method == s.method && s.calls.Add(1) == 1 {
		return s.err
	}
	return nil
}

func (s *failingRead) Identity(ctx context.Context, impu string, now time.Time) (*state.Identity, error) {
	if err := s.fail("Identity"); err != nil {
		return nil, err
	}
	return s.Store.Identity(ctx, impu, now)
}

func (s *failingRead) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	if err := s.fail("RegistrationsOf"); err != nil {
		return nil, err
	}
	return s.Store.RegistrationsOf(ctx, impi)
}

func (s *failingRead) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	if err := s.fail("Registration"); err != nil {
		return nil, err
	}
	return s.Store.Registration(ctx, k)
}

func (s *failingRead) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	if err := s.fail("Profile"); err != nil {
		return nil, err
	}
	return s.Store.Profile(ctx, k, now)
}

// A store read before an RTR's claim that fails for a reason that may pass
// is answered DIAMETER_TOO_BUSY, which the HSS sends again to another peer:
// nothing has been written, so the resend ends the set (#422). A read the
// store refuses as invalid, which no resend mends, stays
// DIAMETER_UNABLE_TO_COMPLY.
func TestAnRTRWhoseReadFailsBeforeItsClaimIsAnsweredTooBusy(t *testing.T) {
	byIdentity := &cx.RTR{UserName: impi1, PublicIdentities: []string{impu1}, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	byIMPI := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	for _, read := range []struct {
		method string
		rtr    *cx.RTR
	}{
		{"Identity", byIdentity},
		{"RegistrationsOf", byIMPI},
		{"Registration", byIMPI},
		{"Profile", byIMPI},
	} {
		for name, c := range map[string]struct {
			err  error
			want cx.Result
		}{
			"throttled": {errors.New("store: throttled"), resultTooBusy},
			"invalid":   {fmt.Errorf("store: %w", state.ErrInvalid), resultUnableToComply},
		} {
			t.Run(read.method+"/"+name, func(t *testing.T) {
				e := newEnv(t)
				g, n, s := withNotifier(t, e)
				registered(t, e, g, 600, impu1)
				n.Wait()
				subscribeAsPCSCF(t, n)
				k := s.count()
				before := must(e.store.Registration(bg, set1))(t)
				profile := must(e.store.Profile(bg, set1, e.clock.Now()))(t)
				store := &failingRead{Store: e.store, method: read.method, err: c.err}
				h := e.instance(2, func(cfg *Config) { cfg.Store, cfg.Events = store, n })
				wantResult(t, h.HandleRTR(bg, read.rtr), c.want)
				n.Wait()
				if store.calls.Load() == 0 {
					t.Fatalf("the RTR never called %s", read.method)
				}
				// Nothing written: the record, its identity and its
				// profile are as they were, and no subscriber was told.
				if after := must(regOf(e, impu1))(t); !reflect.DeepEqual(after, before) {
					t.Errorf("record %+v, was %+v", after, before)
				}
				if p := must(e.store.Profile(bg, set1, e.clock.Now()))(t); !reflect.DeepEqual(p, profile) {
					t.Errorf("profile %+v, was %+v", p, profile)
				}
				if got := reasonsSent(s, k); len(got) != 0 {
					t.Errorf("NOTIFYs %v for an RTR that ended nothing", got)
				}
				if c.want != resultTooBusy {
					return
				}
				// The resend, to this peer as well, ends the set.
				wantResult(t, h.HandleRTR(bg, read.rtr), resultSuccess)
				if _, err := e.store.Registration(bg, set1); !errors.Is(err, state.ErrNotFound) {
					t.Errorf("the resend left the set: %v", err)
				}
			})
		}
	}
}

// conflictThenFailingRead has the first DeleteRegistration conflict, as a
// REGISTER landing after the claim does, and the read after it fail.
type conflictThenFailingRead struct {
	failingRead
	conflicted atomic.Bool
}

func (s *conflictThenFailingRead) DeleteRegistration(ctx context.Context, r *state.Registration) error {
	if s.conflicted.CompareAndSwap(false, true) {
		return state.ErrConflict
	}
	return s.Store.DeleteRegistration(ctx, r)
}

func (s *conflictThenFailingRead) Registration(ctx context.Context, k state.SetKey) (*state.Registration, error) {
	if s.conflicted.Load() {
		return s.failingRead.Registration(ctx, k)
	}
	return s.Store.Registration(ctx, k)
}

func (s *conflictThenFailingRead) Profile(ctx context.Context, k state.SetKey, now time.Time) (*state.Profile, error) {
	if s.conflicted.Load() {
		return s.failingRead.Profile(ctx, k, now)
	}
	return s.Store.Profile(ctx, k, now)
}

// A read that fails after the RTR's claim was saved, when a write after it
// conflicted, leaves the lease for the sweep, as every failure after the
// claim does: the RTR has done its part (#422).
func TestAnRTRWhoseReadFailsAfterItsClaimLeavesTheLease(t *testing.T) {
	for _, method := range []string{"Registration", "Profile"} {
		t.Run(method, func(t *testing.T) {
			e := newEnv(t)
			registered(t, e, e.instance(1), 600, impu1)
			m := &counts{}
			st := &conflictThenFailingRead{failingRead: failingRead{Store: e.store, method: method, err: errors.New("store: throttled")}}
			rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
			wantResult(t, e.instance(2, func(c *Config) { c.Store, c.Metrics = st, m }).HandleRTR(bg, rtr), resultSuccess)
			if st.calls.Load() == 0 {
				t.Fatalf("no %s after the conflict", method)
			}
			r := must(e.store.Registration(bg, set1))(t)
			if len(r.Contacts) > 0 || r.Deregistering.IsZero() {
				t.Errorf("record %+v, want the lease", r)
			}
			if m.get("registrar.rtr_left_to_sweep") != 1 {
				t.Errorf("registrar.rtr_left_to_sweep = %d", m.get("registrar.rtr_left_to_sweep"))
			}
		})
	}
}
