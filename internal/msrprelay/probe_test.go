package msrprelay

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// The connections toward rcs-as are probed when a request on them times
// out, with RELAY_CORE_PROBE_TIMEOUT as the probe's wait (#517).
func TestTheCoreSideIsProbed(t *testing.T) {
	c, err := configure(with(devEnv, "RELAY_CORE_PROBE_TIMEOUT", "4s"))
	if err != nil {
		t.Fatal(err)
	}
	core := coreConfig(c)
	if !core.ProbeOnTimeout || core.ProbeTimeout != 4*time.Second || core.KeepAliveInterval != c.KeepAlive {
		t.Fatalf("core config %+v", core)
	}
}

// A core connection ended as stalled counts as Core.Closed.PathStalled, not
// as a peer gone (#517 code review).
func TestAStalledCoreConnectionIsCountedAsSuch(t *testing.T) {
	m := newCounters()
	m.onEvent(mCorePrefix)(msrp.Event{Kind: msrp.EventClosed, Err: msrp.ErrPathStalled})
	if n := m.count(mCorePrefix + "Closed.PathStalled"); n != 1 {
		t.Fatalf("Core.Closed.PathStalled = %d, want 1", n)
	}
}
