package rcsas

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

type countRecorder struct {
	mu sync.Mutex
	n  map[string]int64
}

func (r *countRecorder) Count(name string, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n[name] += n
}

// A connection ended as stalled is counted every time and logged at most
// once a minute, without an identifier; other ends are neither (#517 code
// review).
func TestStalledConnectionsAreCountedAndLoggedAtMostOnceAMinute(t *testing.T) {
	var logs bytes.Buffer
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	rec := &countRecorder{n: map[string]int64{}}
	p := &pathStalls{metrics: rec, log: slog.New(slog.NewJSONHandler(&logs, nil)), now: func() time.Time { return now }}
	stalled := msrp.Event{Kind: msrp.EventClosed, Err: msrp.ErrPathStalled}
	p.onEvent(stalled)
	p.onEvent(stalled)
	p.onEvent(msrp.Event{Kind: msrp.EventClosed, Err: msrp.ErrPeerGone})
	p.onEvent(msrp.Event{Kind: msrp.EventDropped, Err: errors.New("x")})
	now = now.Add(pathStallLogEvery)
	p.onEvent(stalled)
	if n := rec.n[metricPathStalled]; n != 3 {
		t.Errorf("%s = %d, want 3", metricPathStalled, n)
	}
	if lines := strings.Count(logs.String(), "\n"); lines != 2 {
		t.Errorf("%d log lines, want 2 (one a minute):\n%s", lines, logs.String())
	}
}
