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
// items that do not decode, an ErrInvalid each, joined one at a time as
// the DynamoDB store joined them before #478, so that the count holds
// however the joins nest; with onlyBad[impi], it lists no readable set.
type unreadableListing struct {
	state.Store
	bad     map[string]int
	onlyBad map[string]bool
}

func (s unreadableListing) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	var regs []*state.Registration
	if !s.onlyBad[impi] {
		var err error
		if regs, err = s.Store.RegistrationsOf(ctx, impi); err != nil {
			return nil, err
		}
	}
	var errs error
	for range s.bad[impi] {
		errs = errors.Join(errs, fmt.Errorf("%w: registration document does not decode", state.ErrInvalid))
	}
	return regs, errs
}

// An RTR whose listing holds items that do not decode still ends every
// readable set, and counts and logs each unreadable item without its
// content: 2001 when they all ended (#451, #478 QA).
func TestAnRTRWithUnreadableItemsEndsTheReadableSets(t *testing.T) {
	for _, bad := range []int{1, 3, 5} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			e := newEnv(t)
			twoSets(t, e, e.instance(1))
			m := &counts{}
			var logs bytes.Buffer
			g := e.instance(2, func(c *Config) {
				c.Store, c.Metrics = unreadableListing{Store: e.store, bad: map[string]int{impi1: bad}}, m
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
			if !strings.Contains(out, fmt.Sprintf("items=%d", bad)) || strings.Contains(out, "does not decode") || strings.Contains(out, "15550100") {
				t.Errorf("log:\n%s", out)
			}
		})
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
