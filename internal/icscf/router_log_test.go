package icscf

import (
	"testing"
	"time"
)

// Review of #274: the warning about an unknown S-CSCF name, which a
// configuration fault repeats for every request, is logged at most once a
// minute.
func TestTheUnknownNameWarningIsLoggedOnceAMinute(t *testing.T) {
	var e everyMinute
	t0 := time.Unix(1_000_000, 0)
	for _, tc := range []struct {
		at   time.Duration
		want bool
	}{{0, true}, {time.Second, false}, {59 * time.Second, false}, {time.Minute, true}, {time.Minute + time.Second, false}} {
		if got := e.allow(t0.Add(tc.at)); got != tc.want {
			t.Errorf("at %v: allowed %t, want %t", tc.at, got, tc.want)
		}
	}
}
