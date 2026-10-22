package scenario_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestOptionsReachThePeerByItsTelURIAndWithTheClientsTags(t *testing.T) {
	cfg, core := sipStack(t)
	ok, results := runAll(t, cfg, "options")
	if !ok {
		t.Fatalf("results %+v", results)
	}
	steps := byStep(results)
	for _, s := range []string{"register", "tel-uri", "capabilities"} {
		if !steps[s].OK || (s != "register" && steps[s].Detail["status"] != 200) {
			t.Fatalf("%s: %+v", s, steps[s])
		}
	}
	if core.Registered(self.URI) || core.Registered(peer.URI) {
		t.Fatal("a binding outlived the scenario")
	}
}

// TestAnOptionsScenarioFailsWhenTheNetworkLosesSomething: a network that
// drops the client's feature tags, or the peer's from its answer, fails the
// capabilities step, and one that hands the peer another query than the
// one sent fails the tel-uri step.
func TestAnOptionsScenarioFailsWhenTheNetworkLosesSomething(t *testing.T) {
	for _, tt := range []struct {
		name, step string
		rewrite    func(*sip.Request)
		response   func(*sip.Request, *sip.Response)
	}{
		{"tags dropped on the way", "capabilities", func(req *sip.Request) {
			if req.Method == "OPTIONS" {
				req.Header.Del("Contact")
			}
		}, nil},
		// The peer answers a query that is not the one sent: the step
		// must see its own reach the peer, not only a 200 come back.
		{"another query at the peer", "tel-uri", func(req *sip.Request) {
			if req.Method == "OPTIONS" {
				_ = req.Header.Set("Call-ID", "another-query")
			}
		}, nil},
		// The peer's 200 loses its Contact on the way back: the client
		// cannot tell the peer's services (#473 QA).
		{"the answer's tags dropped", "capabilities", nil, func(req *sip.Request, res *sip.Response) {
			if req.Method == "OPTIONS" {
				res.Header.Del("Contact")
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, core := sipStack(t)
			cfg.StepTimeout = 3 * time.Second
			core.Rewrite, core.RewriteResponse = tt.rewrite, tt.response
			ok, results := runAll(t, cfg, "options")
			if ok {
				t.Fatalf("passed: %+v", results)
			}
			if r := byStep(results)[tt.step]; r.OK || r.Error == "" || strings.Contains(r.Error, "+1555") {
				t.Fatalf("%s: %+v", tt.step, r)
			}
		})
	}
}
