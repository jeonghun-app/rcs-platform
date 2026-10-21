package regevent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// gatedStore holds the non-final NextNotify calls while gate is open.
type gatedStore struct {
	state.Store
	mu      sync.Mutex
	gate    chan struct{}
	entered chan struct{}
}

func (g *gatedStore) NextNotify(ctx context.Context, id string, of int64) (uint32, uint32, error) {
	g.mu.Lock()
	gate := g.gate
	g.mu.Unlock()
	if gate != nil && of != int64(state.FinalNotify) {
		g.entered <- struct{}{}
		<-gate
	}
	return g.Store.NextNotify(ctx, id, of)
}

// TestAFinalQueuedBehindAChangesNOTIFYIsSent (#346 code review): a change's
// NOTIFY that numbers itself after the set's end terminated the
// subscription moves its version, but not its expiry; the final queued
// after it is held and sent, not taken for one another instance has.
func TestAFinalQueuedBehindAChangesNOTIFYIsSent(t *testing.T) {
	e := newEnv(t)
	set := e.registered(binding(1, time.Hour))
	n0 := e.notifier(1)
	for _, id := range []string{"c1", "c2"} {
		r := subscribe(t, impu1, pcscfPath, 3600)
		_ = r.Header.Set("Call-ID", id)
		res, after := n0.Subscribe(bg, r)
		wantStatus(t, res, 200)
		after(bg)
	}
	n0.Wait()
	g := &gatedStore{Store: e.store, gate: make(chan struct{}), entered: make(chan struct{}, 4)}
	s := &sender{}
	m := &counts{}
	n := newNotifierWith(t, e, g, s, func(c *Config) { c.Metrics = m })
	// A REGISTER refresh: its NOTIFYs are under way (default SetConcurrency 2).
	moved := set.Clone()
	moved.Contacts[0].Expires = t0.Add(2 * time.Hour)
	after := e.saved(moved)
	n.Changed(bg, set, after, Registered)
	<-g.entered
	<-g.entered
	// Meanwhile the set ends (an RTR, a deregistration).
	if err := n.Ended(bg, after, Rejected); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	close(g.gate)
	g.gate = nil
	g.mu.Unlock()
	n.Wait()
	finals := 0
	for _, req := range s.notifies() {
		if ss, _ := req.Header.SubscriptionState(); ss.State == "terminated" {
			finals++
		}
	}
	if finals != 2 || m.get("regevent.final_taken_over") != 0 {
		t.Errorf("%d finals sent at the end, %d taken over; want 2 and 0", finals, m.get("regevent.final_taken_over"))
	}
}
