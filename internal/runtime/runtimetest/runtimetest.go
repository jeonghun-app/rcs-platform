// Package runtimetest gives tests of service packages a *runtime.Runtime
// without a process: no signals, no listener, and a clock that moves only when
// the test moves it. A service's Run function can be called with it directly,
// and its log and metric lines, admin endpoints and shutdown hooks inspected,
// instead of every service rebuilding a harness around runtime.Run.
package runtimetest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Start is the time the clock of every Harness starts at.
var Start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Harness holds a Runtime for one test and everything it wrote.
type Harness struct {
	// Runtime is what the service's Run function receives. Its Environment is
	// runtime.Test and it logs at debug level.
	Runtime *runtime.Runtime

	t     testing.TB
	out   *buffer
	clock *clock
}

// New returns a Harness for service.
func New(t testing.TB, service string) *Harness {
	t.Helper()
	h := &Harness{t: t, out: &buffer{}, clock: &clock{now: Start}}
	h.Runtime = runtime.NewRuntime(runtime.RuntimeOptions{
		Service:     service,
		Environment: runtime.Test,
		Out:         h.out,
		Level:       slog.LevelDebug,
		Now:         h.clock.Now,
		After:       h.clock.After,
	})
	return h
}

// Now is the Harness clock's current time.
func (h *Harness) Now() time.Time { return h.clock.Now() }

// Advance moves the clock forward and fires every timer that is due: the
// readiness check deadline (2 s), the readiness cache (1 s), and the shutdown
// deadline of a context passed to Shutdown from WithTimeout.
func (h *Harness) Advance(d time.Duration) { h.clock.Advance(d) }

// WithTimeout returns a context that ends when the Harness clock has advanced
// by d, for passing to Shutdown.
func (h *Harness) WithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(context.Background())
	timer := h.clock.After(d)
	go func() {
		select {
		case <-timer:
			cancel(context.DeadlineExceeded)
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(context.Canceled) }
}

// Get serves a GET for path on the admin handler and returns the status code
// and body.
func (h *Harness) Get(path string) (int, string) {
	rec := httptest.NewRecorder()
	h.Runtime.Admin.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Body.String()
}

// Shutdown runs the shutdown hooks as runtime.Run would after the service's
// Run function returns.
func (h *Harness) Shutdown(ctx context.Context) error {
	return h.Runtime.Shutdown(ctx)
}

// Output is every log and metric line written so far.
func (h *Harness) Output() string { return h.out.String() }

// Records parses Output into one map per line, failing the test on a line that
// is not a JSON object.
func (h *Harness) Records() []map[string]any {
	h.t.Helper()
	var recs []map[string]any
	sc := bufio.NewScanner(strings.NewReader(h.Output()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			h.t.Fatalf("runtimetest: line is not a JSON object: %q: %v", sc.Text(), err)
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		h.t.Fatalf("runtimetest: reading output: %v", err)
	}
	return recs
}

// Logs returns the log records with message msg.
func (h *Harness) Logs(msg string) []map[string]any {
	h.t.Helper()
	var out []map[string]any
	for _, rec := range h.Records() {
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// Metric flushes the runtime's metrics and returns the sum of every value
// written for the metric name, and whether any was written. For a timing the
// sum is of the values written, which are the recorded durations themselves
// while there are 100 or fewer per flush.
func (h *Harness) Metric(name string) (float64, bool) {
	h.t.Helper()
	h.Runtime.Metrics.Flush()
	sum, found := 0.0, false
	for _, rec := range h.Records() {
		if _, isMetric := rec["_aws"]; !isMetric {
			continue
		}
		switch v := rec[name].(type) {
		case float64:
			sum, found = sum+v, true
		case []any:
			for _, x := range v {
				if f, ok := x.(float64); ok {
					sum, found = sum+f, true
				}
			}
		}
	}
	return sum, found
}

type buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type timer struct {
	at time.Time
	ch chan time.Time
}

// clock is a manual clock: After fires only when Advance reaches it.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []timer
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.now
		return ch
	}
	c.timers = append(c.timers, timer{at: c.now.Add(d), ch: ch})
	return ch
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	c.timers = slices.DeleteFunc(c.timers, func(t timer) bool {
		if t.at.After(c.now) {
			return false
		}
		t.ch <- c.now
		return true
	})
}
