package routing

import (
	"slices"
	"testing"
	"time"

	hssprofile "github.com/jeonghun-app/rcs-platform/internal/hss"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// TestARosterSubscribeGoesToRCSASByTheDefaultProfile (#557): with hss's
// default profile, a group chat's roster SUBSCRIBE goes to rcs-as, though
// its conference URI's host is outside the home domain, where the end of
// the chain finds no route (404). In the compact form too, which the view
// presents by its full name. A reg event SUBSCRIBE goes on as before.
func TestARosterSubscribeGoesToRCSASByTheDefaultProfile(t *testing.T) {
	const conf = "sip:chat-0123456789abcdef0123456789abcdef@conf.rcs.local;transport=tcp"
	criteria := hssprofile.DefaultRCSProfile(hssprofile.DefaultProfileID, rcsAS).Criteria
	without := slices.DeleteFunc(slices.Clone(criteria), func(fc ifc.FilterCriteria) bool { return fc.Priority == 25 })
	if len(without) != len(criteria)-1 {
		t.Fatalf("the default profile has no criterion 25: %d criteria", len(criteria))
	}
	for name, c := range map[string]struct {
		criteria []ifc.FilterCriteria
		target   string
		extra    []string
		// server is the host the request goes to first, "" for none.
		server string
		status int
	}{
		"roster":             {criteria, conf, []string{"Event: conference", "Accept: application/conference-info+xml"}, "rcs-as.rcs.local", 0},
		"compact roster":     {criteria, conf, []string{"o: conference"}, "rcs-as.rcs.local", 0},
		"reg event":          {criteria, impu1, []string{"Event: reg", "Accept: application/reginfo+xml"}, "icscf.rcs.local", 0},
		"roster, no trigger": {without, conf, []string{"Event: conference"}, "", 404},
		"reg, no trigger":    {without, impu1, []string{"Event: reg"}, "icscf.rcs.local", 0},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, c.criteria...)
			d := e.router(nil).Originating(bg, fromUser(t, "SUBSCRIBE", c.target, c.extra...))
			if c.server == "" {
				if d.Status != c.status || len(d.Targets) != 0 {
					t.Fatalf("status %d, targets %v; want %d", d.Status, uris(d.Targets), c.status)
				}
				return
			}
			if host := serverOf(t, d); host != c.server {
				t.Fatalf("sent to %s, want %s", host, c.server)
			}
		})
	}
}
