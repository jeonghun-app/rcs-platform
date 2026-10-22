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

// unreadableListing lists a private identity's sets with two more items
// that do not decode, as the DynamoDB store does: the readable sets and an
// ErrInvalid for each item, joined.
type unreadableListing struct{ state.Store }

func (s unreadableListing) RegistrationsOf(ctx context.Context, impi string) ([]*state.Registration, error) {
	regs, err := s.Store.RegistrationsOf(ctx, impi)
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: registration document does not decode", state.ErrInvalid)
	return regs, errors.Join(bad, bad)
}

// An RTR whose listing holds items that do not decode still ends every
// readable set, and counts and logs the unreadable items without their
// content: 2001 when they all ended (#451).
func TestAnRTRWithAnUnreadableItemEndsTheReadableSets(t *testing.T) {
	e := newEnv(t)
	twoSets(t, e, e.instance(1))
	m := &counts{}
	var logs bytes.Buffer
	g := e.instance(2, func(c *Config) {
		c.Store, c.Metrics = unreadableListing{e.store}, m
		c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	})
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, g.HandleRTR(bg, rtr), resultSuccess)
	for _, k := range []state.SetKey{set1, set2} {
		if _, err := e.store.Registration(bg, k); !errors.Is(err, state.ErrNotFound) {
			t.Errorf("%s is left: %v", k.IMPU, err)
		}
	}
	if n := m.get("registrar.rtr_unreadable"); n != 2 {
		t.Errorf("registrar.rtr_unreadable = %d, want 2", n)
	}
	if n := m.get("registrar.rtr_deregistered"); n != 2 {
		t.Errorf("registrar.rtr_deregistered = %d, want 2", n)
	}
	out := logs.String()
	if !strings.Contains(out, "unreadable registration items") || strings.Contains(out, "does not decode") || strings.Contains(out, "15550100") {
		t.Errorf("log:\n%s", out)
	}
}

// A readable set whose read fails for a reason that may pass is still
// answered DIAMETER_TOO_BUSY, so that the HSS sends the RTR again.
func TestAnRTRWithAnUnreadableItemAndABusyReadIsAnsweredTooBusy(t *testing.T) {
	e := newEnv(t)
	twoSets(t, e, e.instance(1))
	store := &failingRead{Store: unreadableListing{e.store}, method: "Profile", err: errors.New("store: throttled")}
	rtr := &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}
	wantResult(t, e.instance(2, func(c *Config) { c.Store = store }).HandleRTR(bg, rtr), resultTooBusy)
}
