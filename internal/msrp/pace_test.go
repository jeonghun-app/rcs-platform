package msrp

import (
	"sync/atomic"
	"testing"
	"time"
)

// The tests that use real time never check how fast something happens,
// only that it happens and that a bound holds. Their waits therefore fail
// on a lack of progress, not on a deadline, so a slow or shared machine
// (CI under the race detector) makes them slower rather than failing.

// hangGuard is how long a test waits for something that is not making
// progress before it calls it hung. It only ever ends a broken test.
var hangGuard = map[bool]time.Duration{false: 30 * time.Second, true: 2 * time.Minute}[raceEnabled]

// prompt bounds how long a message may take when nothing should hold it
// up. The failures these bounds catch were stalls of tens of seconds (a
// write deadline), so a looser bound under the race detector still tells
// them apart.
var prompt = map[bool]time.Duration{false: time.Second, true: 5 * time.Second}[raceEnabled]

// scaled is n under normal runs and a quarter of it, at least 1, under the
// race detector: the same behaviour on less data.
func scaled(n int) int {
	if raceEnabled {
		return max(1, n/4)
	}
	return n
}

// waitProgress waits until done reports true, failing once progress,
// whatever value marks advancing work, has stood still for hangGuard, or
// when check fails.
func waitProgress(t *testing.T, what string, done func() bool, progress func() int64, check func() error) {
	t.Helper()
	last, since := progress(), time.Now()
	for !done() {
		if check != nil {
			if err := check(); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		}
		if p := progress(); p != last {
			last, since = p, time.Now()
		} else if time.Since(since) > hangGuard {
			t.Fatalf("%s: no progress for %v (at %d)", what, hangGuard, p)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// counter adapts an atomic counter for waitProgress.
func counter(c *atomic.Int64) func() int64 { return c.Load }
