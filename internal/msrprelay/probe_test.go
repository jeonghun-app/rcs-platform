package msrprelay

import (
	"testing"
	"time"
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
