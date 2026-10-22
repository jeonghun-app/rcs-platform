package registrar

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// sweepPanics is the memory store, whose first listing for a sweep panics.
type sweepPanics struct {
	*state.Memory
	calls atomic.Int64
}

func (s *sweepPanics) ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*state.Registration, error) {
	if s.calls.Add(1) == 1 {
		panic("registrar test panic")
	}
	return s.Memory.ExpiringRegistrations(ctx, now, limit)
}

// TestAPanickingSweepEndsThatRoundOnly (#488): a sweep whose store listing
// panics is recovered and counted, and the next round, at the next tick,
// sweeps the expired set.
func TestAPanickingSweepEndsThatRoundOnly(t *testing.T) {
	e := newEnv(t)
	guard := panics.New(panics.Config{Metric: "background.panics", Message: "test", Log: slog.New(slog.DiscardHandler)})
	g := e.instance(1)
	registered(t, e, g, 600, impu1)
	e.clock.advance(601 * time.Second)
	store := &sweepPanics{Memory: e.store}
	swept := e.instance(2, func(c *Config) { c.Store, c.Panics = store, guard })
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { swept.RunSweeps(ctx, time.Millisecond, 1); close(done) }()
	deadline := time.After(10 * time.Second)
	for {
		if _, err := regOf(e, impu1); err != nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("RunSweeps never swept after the panic")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done
	if guard.Panics() != 1 {
		t.Errorf("%d panics recovered, want 1", guard.Panics())
	}
}
