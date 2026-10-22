package pcscf

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/panics"
)

type countingPanics struct {
	mu sync.Mutex
	n  map[string]int64
}

func (c *countingPanics) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int64{}
	}
	c.n[name] += n
}

// A panic in background work, such as a reg-event subscription, ends that
// work only (#445, QA of #436): it is counted and logged under the work's
// name, the work counts as done, so wait and close return, and the next
// work runs.
func TestAPanicInBackgroundWorkEndsThatWorkOnly(t *testing.T) {
	var logs bytes.Buffer
	counts := &countingPanics{}
	b := &background{ctx: context.Background(), name: "regevent",
		panics: panics.New(panics.Config{Metric: metricBackgroundPanics, Log: slog.New(slog.NewTextHandler(&logs, nil)), Metrics: counts})}
	if !b.goRun(func(context.Context) { panic("subscription") }) {
		t.Fatal("the work was not started")
	}
	b.wait()
	ran := make(chan struct{})
	b.goRun(func(context.Context) { close(ran) })
	<-ran
	b.close()
	if n := counts.n[metricBackgroundPanics]; n != 1 {
		t.Errorf("%s = %d, want 1", metricBackgroundPanics, n)
	}
	if !strings.Contains(logs.String(), "name=regevent") {
		t.Errorf("the log does not name the work:\n%s", logs.String())
	}
}
