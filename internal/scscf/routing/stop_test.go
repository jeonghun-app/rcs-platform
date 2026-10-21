package routing

import (
	"context"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// TestAStopThatRunsOutGivesUpOnTheThirdPartyREGISTERs (#439 QA): with one
// REGISTER at a server that does not answer, one of its set's waiting
// behind it and one of another set's waiting for the server's one slot, a
// stop whose context ends drops all three, counted, sends neither of the
// waiting ones, and applies no default handling: the S-CSCF stopped, the
// server was not silent.
func TestAStopThatRunsOutGivesUpOnTheThirdPartyREGISTERs(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionTerminated))
	s := &sentRegisters{hold: make(chan struct{}), inside: make(chan struct{}, 4)}
	rt := e.router(nil, withSender(s), func(c *Config) { c.MaxThirdParty = 1 })
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	recv(t, s.inside)
	rt.Registered(bg, registration(t, ifc.ReRegistration, time.Hour))
	rt.Registered(bg, otherSet(t, e, 1))
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if rt.StopBy(ctx) {
		t.Error("StopBy says it waited for all, with a REGISTER held at the server")
	}
	if got := len(s.got()); got != 1 {
		t.Errorf("%d REGISTERs sent, want only the one under way at the stop", got)
	}
	if got := e.metrics.get("routing.third_party.dropped_at_stop"); got != 3 {
		t.Errorf("%d dropped at the stop, want 3", got)
	}
	for _, name := range []string{"routing.third_party.unanswered", "routing.third_party.terminated_unanswered"} {
		if got := e.metrics.get(name); got != 0 {
			t.Errorf("%s %d, want 0", name, got)
		}
	}
}

// TestAStopInTimeSaysSo: a stop whose REGISTERs are done before its
// context ends waits for them and says it did.
func TestAStopInTimeSaysSo(t *testing.T) {
	e := newEnv(t)
	e.profile(t0, criterion(40, rcsAS, registerTrigger(), ifc.SessionContinued))
	s := &sentRegisters{}
	rt := e.router(nil, withSender(s))
	rt.Registered(bg, registration(t, ifc.InitialRegistration, time.Hour))
	ctx, cancel := context.WithTimeout(bg, time.Minute)
	defer cancel()
	if !rt.StopBy(ctx) {
		t.Error("StopBy gave up with nothing held")
	}
	if got := e.metrics.get("routing.third_party.registered"); got != 1 {
		t.Errorf("%d registered, want 1", got)
	}
}

// heldIdentities is the memory store, whose SaveIdentity, once inside
// says it was called, waits for its context to end.
type heldIdentities struct {
	*state.Memory
	inside chan struct{}
}

func (h heldIdentities) SaveIdentity(ctx context.Context, _ *state.Identity, _ time.Time) (*state.Identity, error) {
	h.inside <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestAStopThatRunsOutGivesUpOnTheRepairs: an identity repair held by the
// store is cut short when the stop's context ends, rather than holding the
// stop for its RepairTimeout, and is counted as failed: the set's next
// REGISTER points the item.
func TestAStopThatRunsOutGivesUpOnTheRepairs(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	id, err := e.store.Identity(bg, tel1, t0)
	if err != nil {
		t.Fatal(err)
	}
	id.Incarnation = 9
	if _, err := e.store.SaveIdentity(bg, id, t0); err != nil {
		t.Fatal(err)
	}
	st := heldIdentities{Memory: e.store, inside: make(chan struct{}, 1)}
	rt := e.router(st, func(c *Config) { c.RepairTimeout = time.Hour })
	if d := rt.Terminating(bg, request(t, "INVITE", tel1)); len(d.Targets) != 1 {
		t.Fatalf("status %d, %d targets", d.Status, len(d.Targets))
	}
	recv(t, st.inside)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if rt.StopBy(ctx) {
		t.Error("StopBy says it waited for all, with a repair held")
	}
	if got := e.metrics.get("routing.identity_repair_failed"); got != 1 {
		t.Errorf("%d repairs failed, want the held one", got)
	}
}
