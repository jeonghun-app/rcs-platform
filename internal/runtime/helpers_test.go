package runtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// envMap is a fake environment for Process.LookupEnv and NewEnv.
type envMap map[string]string

func (m envMap) lookup(name string) (string, bool) {
	v, ok := m[name]
	return v, ok
}

// lockedBuffer is a bytes.Buffer that a test can read while Run writes to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// records parses JSON lines; every line written to stdout must be one object.
func records(t *testing.T, out string) []map[string]any {
	t.Helper()
	var recs []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line is not a JSON object: %q: %v", sc.Text(), err)
		}
		recs = append(recs, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading log lines: %v", err)
	}
	return recs
}

// record returns the first log record with message msg.
func record(t *testing.T, out, msg string) map[string]any {
	t.Helper()
	for _, rec := range records(t, out) {
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no log record %q in:\n%s", msg, out)
	return nil
}

func hasRecord(t *testing.T, out, msg string) bool {
	t.Helper()
	for _, rec := range records(t, out) {
		if rec["msg"] == msg {
			return true
		}
	}
	return false
}

// fakeTimers stands in for time.After: a timer fires only when the test says so.
type fakeTimers struct {
	mu      sync.Mutex
	pending map[time.Duration][]chan time.Time
	made    []time.Duration
	// changed is closed and replaced whenever a timer is made.
	changed chan struct{}
}

func newFakeTimers() *fakeTimers {
	return &fakeTimers{pending: map[time.Duration][]chan time.Time{}, changed: make(chan struct{})}
}

func (f *fakeTimers) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	f.pending[d] = append(f.pending[d], ch)
	f.made = append(f.made, d)
	close(f.changed)
	f.changed = make(chan struct{})
	return ch
}

// WaitFor blocks until a timer of duration d has been made.
func (f *fakeTimers) WaitFor(d time.Duration) { f.WaitForN(d, 1) }

// WaitForN blocks until n timers of duration d have been made, such as the
// next timer of a loop that makes one after doing its work.
func (f *fakeTimers) WaitForN(d time.Duration, n int) {
	for {
		f.mu.Lock()
		made, changed := countOf(f.made, d), f.changed
		f.mu.Unlock()
		if made >= n {
			return
		}
		<-changed
	}
}

func countOf[T comparable](s []T, v T) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

// Fire fires every timer of duration d created so far.
func (f *fakeTimers) Fire(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.pending[d] {
		ch <- time.Time{}
	}
	f.pending[d] = nil
}

func (f *fakeTimers) Made() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.made...)
}

// restoreDefaults undoes the process-wide defaults Run sets.
func restoreDefaults(t *testing.T) {
	t.Helper()
	old, oldOut, oldFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(old)
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
		pii.SetDefault(nil)
	})
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
