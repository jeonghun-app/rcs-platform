package routing

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// guardFor is a Guard counting into e's metrics, logging nowhere.
func guardFor(e *env) *panics.Guard {
	return panics.New(panics.Config{Metric: "background.panics", Message: "test", Log: slog.New(slog.DiscardHandler), Metrics: e.metrics})
}

// TestAPanickingThirdPartySendReleasesItsSlot (#488): with one slot at the
// server, a third-party REGISTER whose send panics is recovered and
// counted; its slot and its place in the queue are released, so the next
// registration is sent, and the queue ends empty.
func TestAPanickingThirdPartySendReleasesItsSlot(t *testing.T) {
	e := newEnv(t)
	var calls atomic.Int64
	s := senderFunc(func(_ context.Context, req *sip.Request) (*sip.Response, error) {
		if calls.Add(1) == 1 {
			panic("routing test panic")
		}
		return sip.NewResponse(req, 200, "", "as")
	})
	rt := e.router(nil, withSender(s), func(c *Config) { c.MaxThirdParty = 1; c.Panics = guardFor(e) })
	rt.Registered(bg, otherSet(t, e, 0))
	rt.Registered(bg, otherSet(t, e, 1))
	rt.Stop()
	if got := e.metrics.get("background.panics"); got != 1 {
		t.Errorf("%d panics counted, want 1", got)
	}
	if got := e.metrics.get("routing.third_party.registered"); got != 1 {
		t.Errorf("%d registered after the panicking send, want the next one", got)
	}
	queueEmpty(t, rt)
}

// panickingIdentities is the memory store, whose SaveIdentity panics.
type panickingIdentities struct{ *state.Memory }

func (panickingIdentities) SaveIdentity(context.Context, *state.Identity, time.Time) (*state.Identity, error) {
	panic("routing test panic")
}

// TestAPanickingRepairIsCountedAsFailed (#488): an identity repair whose
// store write panics is recovered, counted as a panic and as a failed
// repair, and the stop does not wait for it.
func TestAPanickingRepairIsCountedAsFailed(t *testing.T) {
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
	rt := e.router(panickingIdentities{e.store}, func(c *Config) { c.Panics = guardFor(e) })
	if d := rt.Terminating(bg, request(t, "INVITE", tel1)); len(d.Targets) != 1 {
		t.Fatalf("status %d, %d targets", d.Status, len(d.Targets))
	}
	rt.Stop()
	if got, failed := e.metrics.get("background.panics"), e.metrics.get("routing.identity_repair_failed"); got != 1 || failed != 1 {
		t.Errorf("%d panics, %d failed repairs; want 1 and 1", got, failed)
	}
}
