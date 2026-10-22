package registrar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// unreadableListing lists a private identity's sets with bad[impi] more
// items that do not decode, an ErrInvalid each, joined once as the DynamoDB
// store joins them (#478 QA); with invalidIMPI, each is the error a
// document with an invalid IMPI gets, which wraps two; with onlyBad[impi],
// it lists no readable set.
type unreadableListing struct {
	state.Store
	bad         map[string]int
	onlyBad     map[string]bool
	invalidIMPI bool
}

func (s unreadableListing) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	var regs []*state.Registration
	if !s.onlyBad[impi] {
		var err error
		if regs, err = s.Store.RegistrationsOf(ctx, impi); err != nil {
			return nil, err
		}
	}
	var errs []error
	for range s.bad[impi] {
		err := fmt.Errorf("%w: registration document does not decode", state.ErrInvalid)
		if s.invalidIMPI {
			r := &state.Registration{Key: state.SetKey{IMPI: "not-an-impi", IMPU: impu1}, Incarnation: 1, Identities: []state.SetIdentity{{IMPU: impu1}}}
			err = r.Validate()
		}
		errs = append(errs, err)
	}
	return regs, errors.Join(errs...)
}

// An RTR whose listing holds items that do not decode still ends every
// readable set, and counts and logs each unreadable item without its
// content: 2001 when they all ended (#451, #478 QA).
func TestAnRTRWithUnreadableItemsEndsTheReadableSets(t *testing.T) {
	for _, tt := range []struct {
		invalidIMPI bool
		bad         []int
	}{
		{false, []int{1, 3, 5}},
		// One item each, though its error wraps two (#478 QA).
		{true, []int{1, 2, 3, 5}},
	} {
		for _, bad := range tt.bad {
			t.Run(fmt.Sprintf("invalid IMPI %v, %d", tt.invalidIMPI, bad), func(t *testing.T) {
				e := newEnv(t)
				twoSets(t, e, e.instance(1))
				m := &counts{}
				var logs bytes.Buffer
				g := e.instance(2, func(c *Config) {
					c.Store, c.Metrics = unreadableListing{Store: e.store, bad: map[string]int{impi1: bad}, invalidIMPI: tt.invalidIMPI}, m
					c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
				})
				rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
				wantResult(t, g.HandleRTR(bg, rtr), resultSuccess)
				for _, k := range []state.SetKey{set1, set2} {
					if _, err := e.store.Registration(bg, k); !errors.Is(err, state.ErrNotFound) {
						t.Errorf("%s is left: %v", k.IMPU, err)
					}
				}
				if n := m.get("registrar.rtr_unreadable"); n != int64(bad) {
					t.Errorf("registrar.rtr_unreadable = %d, want %d", n, bad)
				}
				if n := m.get("registrar.rtr_deregistered"); n != 2 {
					t.Errorf("registrar.rtr_deregistered = %d, want 2", n)
				}
				out := logs.String()
				if !strings.Contains(out, fmt.Sprintf("items=%d", bad)) || strings.Contains(out, "does not decode") || strings.Contains(out, "not-an-impi") || strings.Contains(out, "15550100") {
					t.Errorf("log:\n%s", out)
				}
			})
		}
	}
}

// An associated private identity whose listing has nothing readable is
// answered DIAMETER_UNABLE_TO_COMPLY and counted, but the other identity's
// readable sets still end, whichever comes first (#478 QA).
func TestAnUnreadableAssociatedIdentityLeavesNoOtherSetLive(t *testing.T) {
	for _, order := range [][2]string{{impi1, impi2}, {impi2, impi1}} {
		t.Run(order[0], func(t *testing.T) {
			e := newEnv(t)
			twoSets(t, e, e.instance(1))
			m := &counts{}
			g := e.instance(2, func(c *Config) {
				c.Store, c.Metrics = unreadableListing{Store: e.store, bad: map[string]int{impi2: 1}, onlyBad: map[string]bool{impi2: true}}, m
			})
			rtr := &cx.RTR{UserName: order[0], AssociatedIdentities: []string{order[1]}, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
			wantResult(t, g.HandleRTR(bg, rtr), resultUnableToComply)
			for _, k := range []state.SetKey{set1, set2} {
				if _, err := e.store.Registration(bg, k); !errors.Is(err, state.ErrNotFound) {
					t.Errorf("%s is left: %v", k.IMPU, err)
				}
			}
			if n := m.get("registrar.rtr_unreadable"); n != 1 {
				t.Errorf("registrar.rtr_unreadable = %d, want 1", n)
			}
		})
	}
}

// A readable set whose read fails for a reason that may pass is still
// answered DIAMETER_TOO_BUSY, so that the HSS sends the RTR again.
func TestAnRTRWithAnUnreadableItemAndABusyReadIsAnsweredTooBusy(t *testing.T) {
	e := newEnv(t)
	twoSets(t, e, e.instance(1))
	store := &failingRead{Store: unreadableListing{Store: e.store, bad: map[string]int{impi1: 1}}, method: "Profile", err: errors.New("store: throttled")}
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(c *Config) { c.Store = store }).HandleRTR(bg, rtr), resultTooBusy)
}

// With an unreadable associated identity and a set whose read may pass, the
// answer is DIAMETER_TOO_BUSY, so that the HSS sends the RTR again; the
// resend ends that set and answers DIAMETER_UNABLE_TO_COMPLY for the
// unreadable listing (#478 QA).
func TestABusySetIsAnsweredBeforeAnUnreadableAssociatedIdentity(t *testing.T) {
	e := newEnv(t)
	twoSets(t, e, e.instance(1))
	listing := unreadableListing{Store: e.store, bad: map[string]int{impi2: 1}, onlyBad: map[string]bool{impi2: true}}
	busy := &failingRead{Store: listing, method: "Profile", err: errors.New("store: throttled")}
	rtr := &cx.RTR{UserName: impi1, AssociatedIdentities: []string{impi2}, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(c *Config) { c.Store = busy }).HandleRTR(bg, rtr), resultTooBusy)
	left := 0
	for _, k := range []state.SetKey{set1, set2} {
		if _, err := e.store.Registration(bg, k); err == nil {
			left++
		}
	}
	if left != 1 {
		t.Fatalf("%d sets left after the first RTR, want the busy one", left)
	}
	// The HSS's resend.
	wantResult(t, e.instance(3, func(c *Config) { c.Store = listing }).HandleRTR(bg, rtr), resultUnableToComply)
	for _, k := range []state.SetKey{set1, set2} {
		if _, err := e.store.Registration(bg, k); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("%s is left after the resend: %v", k.IMPU, err)
		}
	}
}
