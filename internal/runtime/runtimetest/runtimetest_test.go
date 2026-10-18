package runtimetest_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

// run stands in for a service's Run function.
func run(ctx context.Context, rt *runtime.Runtime, storeUp, closed *atomic.Bool, ready chan<- struct{}) error {
	rt.Admin.AddReadinessCheck("store", func(context.Context) error {
		if !storeUp.Load() {
			return errors.New("store unreachable")
		}
		return nil
	})
	rt.OnShutdown("store", func(context.Context) error { closed.Store(true); return nil })
	rt.Metrics.Count("sip.requests", 2)
	rt.Metrics.Count("sip.requests", 3)
	rt.Logger.Info("listening", "port", 5060)
	rt.Ready()
	close(ready)
	<-ctx.Done()
	return nil
}

func TestAServiceRunFunctionCanBeDrivenWithoutAProcess(t *testing.T) {
	h := runtimetest.New(t, "pcscf")
	var storeUp, closed atomic.Bool
	storeUp.Store(true)

	if code, body := h.Get("/readyz"); code != 503 || !strings.Contains(body, "starting") {
		t.Fatalf("readyz before Run = %d %s", code, body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done, ready := make(chan error, 1), make(chan struct{})
	go func() { done <- run(ctx, h.Runtime, &storeUp, &closed, ready) }()
	<-ready
	if len(h.Logs("ready")) != 1 {
		t.Fatalf("no ready record:\n%s", h.Output())
	}

	if code, _ := h.Get("/readyz"); code != 200 {
		t.Fatalf("readyz = %d", code)
	}
	storeUp.Store(false)
	if code, _ := h.Get("/readyz"); code != 200 {
		t.Fatalf("the cached result should still answer: %d", code)
	}
	h.Advance(time.Second)
	if code, body := h.Get("/readyz"); code != 503 || !strings.Contains(body, `"store"`) {
		t.Fatalf("readyz after the cache expired = %d %s", code, body)
	}

	if v, ok := h.Metric("sip.requests"); !ok || v != 5 {
		t.Fatalf("sip.requests = %v, %v", v, ok)
	}
	if recs := h.Logs("listening"); len(recs) != 1 || recs[0]["service"] != "pcscf" || recs[0]["port"] != 5060.0 {
		t.Fatalf("listening records = %v", recs)
	}
	if h.Runtime.Environment != runtime.Test {
		t.Fatalf("environment = %q", h.Runtime.Environment)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := h.Shutdown(context.Background()); err != nil || !closed.Load() {
		t.Fatalf("Shutdown = %v, hook ran %v", err, closed.Load())
	}
	if code, body := h.Get("/readyz"); code != 503 || !strings.Contains(body, "stopping") {
		t.Fatalf("readyz after Shutdown = %d %s", code, body)
	}
}

func TestAdvanceFiresTheReadinessDeadline(t *testing.T) {
	h := runtimetest.New(t, "hss")
	entered := make(chan struct{})
	h.Runtime.Admin.AddReadinessCheck("diameter", func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	h.Runtime.Ready()
	go func() {
		<-entered
		h.Advance(2 * time.Second)
	}()
	if code, body := h.Get("/readyz"); code != 503 || !strings.Contains(body, "diameter") {
		t.Fatalf("readyz = %d %s", code, body)
	}
}

func TestWithTimeoutEndsAShutdownThatHangs(t *testing.T) {
	h := runtimetest.New(t, "scscf")
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	h.Runtime.OnShutdown("flows", func(context.Context) error {
		close(entered)
		<-release
		return nil
	})
	ctx, cancel := h.WithTimeout(20 * time.Second)
	defer cancel()
	go func() {
		<-entered
		h.Advance(19 * time.Second)
		h.Advance(time.Second)
	}()
	if err := h.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown returned nil for a hook that never finished")
	}
	if len(h.Logs("shutdown hook did not finish before the deadline")) != 1 {
		t.Fatalf("output:\n%s", h.Output())
	}
}

func TestTheClockStartsAtStartAndOnlyMovesWhenAdvanced(t *testing.T) {
	h := runtimetest.New(t, "rcs-as")
	if !h.Now().Equal(runtimetest.Start) {
		t.Fatalf("Now = %v", h.Now())
	}
	h.Advance(90 * time.Second)
	if got := h.Now().Sub(runtimetest.Start); got != 90*time.Second {
		t.Fatalf("advanced %v", got)
	}
	ctx, cancel := h.WithTimeout(0)
	defer cancel()
	<-ctx.Done()
}

func TestMetricReportsAbsentMetrics(t *testing.T) {
	h := runtimetest.New(t, "ft-server")
	h.Runtime.Logger.Info("not a metric", "uploads", 1)
	if _, ok := h.Metric("uploads"); ok {
		t.Fatal("a log attribute was counted as a metric")
	}
}
