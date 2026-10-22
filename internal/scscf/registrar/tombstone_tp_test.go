package registrar

import (
	"context"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// heldEnded holds Ended (a user's deregistration, after its claim and
// SAR, before endSet) until release is closed.
type heldEnded struct {
	entered, release chan struct{}
}

func (h *heldEnded) Changed(context.Context, *state.Registration, *state.Registration, regevent.Cause) {
}
func (h *heldEnded) Ended(context.Context, *state.Registration, regevent.Cause) error {
	close(h.entered)
	<-h.release
	return nil
}

// TestATombstoneOverAUsersDeregistrationTellsTheEndOnce (#410 code
// review): a user's deregistration is under way, its lease claimed and its
// SAR sent, when the undo saves its tombstone over that lease. That
// tombstone is not marked: the deregistration's endSet then stands back
// and tells the servers nothing, and the sweep after the lease tells them
// of the end, once.
func TestATombstoneOverAUsersDeregistrationTellsTheEndOnce(t *testing.T) {
	e := newEnv(t)
	tp := &recordedThirdParty{}
	u := reassertDue(t, e, e.instance(1, withThirdParty(tp)))
	k := len(tp.got())
	held := &heldEnded{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	b := &beforeSAR{HSS: e.hss, match: isReassertion}
	b.hook = func() {
		go func() {
			defer close(done)
			wantStatus(t, u.registerWith(e.instance(2, withThirdParty(tp), func(c *Config) { c.Events = held }), 0), 200)
		}()
		<-held.entered
	}
	if _, err := e.instance(3, func(c *Config) { c.HSS, c.ThirdParty = b, tp }).Sweep(bg, 10); err != nil {
		t.Logf("sweep: %v", err)
	}
	r := must(e.store.Registration(bg, set1))(t)
	t.Logf("after the undo: tombstone=%v leased=%v contacts=%d", r.Tombstone, !r.Deregistering.IsZero(), len(r.Contacts))
	close(held.release)
	<-done
	t.Logf("told before the sweep: %d", len(tp.got())-k)
	e.clock.advance(state.SweepLease)
	if _, err := e.instance(9, withThirdParty(tp)).Sweep(bg, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Registration(bg, set1); err == nil {
		t.Error("the tombstone outlived the sweep")
	}
	ends := 0
	for _, r := range tp.got()[k:] {
		if r.Type == ifc.DeRegistration {
			ends++
		}
	}
	t.Logf("SARs %v, de-REGISTERs told %d", e.hss.sarsOf(), ends)
	if ends != 1 {
		t.Errorf("the servers heard of the end %d times, want once", ends)
	}
}
