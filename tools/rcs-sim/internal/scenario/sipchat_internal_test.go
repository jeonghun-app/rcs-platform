package scenario

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// atRelay holds a path to msrp-relay's host, port and TCP, each of them
// (code review on #553): a path at the relay's port on another host, as
// rcs-as's would be if it listened on the same port, is not the relay's.
func TestAtRelayTakesOnlyTheRelaysHostPortAndTCP(t *testing.T) {
	r := &run{cfg: Config{RelayPublic: "msrp-relay:2855"}}
	for name, c := range map[string]struct {
		u    msrp.URI
		want bool
	}{
		"the relay's":             {msrp.URI{Host: "msrp-relay", Port: 2855, SessionID: "s1", Transport: "tcp"}, true},
		"the host in upper case":  {msrp.URI{Host: "MSRP-Relay", Port: 2855, SessionID: "s1", Transport: "tcp"}, true},
		"another host, same port": {msrp.URI{Host: "rcs-as-a.rcs.local", Port: 2855, SessionID: "s1", Transport: "tcp"}, false},
		"another port":            {msrp.URI{Host: "msrp-relay", Port: 2856, SessionID: "s1", Transport: "tcp"}, false},
		"another transport":       {msrp.URI{Host: "msrp-relay", Port: 2855, SessionID: "s1", Transport: "udp"}, false},
	} {
		if got := r.atRelay(c.u); got != c.want {
			t.Errorf("%s: atRelay(%s) = %v, want %v", name, c.u, got, c.want)
		}
	}
	// Without the relay's address, no path is the relay's.
	if (&run{}).atRelay(msrp.URI{Host: "msrp-relay", Port: 2855, SessionID: "s1", Transport: "tcp"}) {
		t.Error("atRelay holds a path without a relay address configured")
	}
}
