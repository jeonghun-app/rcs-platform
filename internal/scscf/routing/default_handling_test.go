package routing

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

func qaTimeout(tg proxy.Target) proxy.BranchFailure {
	return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
}

func qaHosts(ts []proxy.Target) []string {
	var out []string
	for _, t := range ts {
		if len(t.Routes) > 0 {
			out = append(out, t.Routes[0].URI.Host)
		} else {
			out = append(out, t.URI.String())
		}
	}
	return out
}

// TestAServerThatSentTheRequestOnIsNotBypassedOnEitherSide (QA on #359):
// a SESSION_CONTINUED server that proxies a non-INVITE on (as rcs-as
// does for OPTIONS) and whose downstream takes longer than ASTimeout: the
// copy it sent back is resumed toward the I-CSCF, and the original
// branch's Target.Timeout makes the S-CSCF send the same request to the
// I-CSCF a second time.
func TestAServerThatSentTheRequestOnIsNotBypassedOnEitherSide(t *testing.T) {
	for _, side := range []string{"originating", "terminating"} {
		t.Run(side, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), ifc.SessionContinued))
			var r *proxy.Request
			if side == "originating" {
				r = fromUser(t, "OPTIONS", impu2)
			} else {
				r = request(t, "OPTIONS", impu1)
			}
			a := e.router(nil) // instance A
			d := a.Initial(bg, r)
			if serverOf(t, d) != "rcs-as.rcs.local" || d.Targets[0].Timeout != DefaultASTimeout {
				t.Fatalf("first hop %v timeout %v", qaHosts(d.Targets), d.Targets[0].Timeout)
			}
			// t+0.1 s: rcs-as forwarded the request along the Route; any
			// instance resumes it and sends it on.
			resumed := e.router(nil).Initial(bg, backFrom(t, r, d, 0))
			// t+5 s: the downstream has not answered yet; A's branch toward
			// rcs-as times out (the proxy terminates that transaction).
			again := d.OnBranchFailure(bg, qaTimeout(d.Targets[0]))
			t.Logf("copy via rcs-as -> %v; after ASTimeout A also sends -> %v", qaHosts(resumed.Targets), qaHosts(again))
			if len(resumed.Targets) > 0 && len(again) > 0 {
				t.Errorf("the request leaves twice toward %v and %v: a server that forwarded it is taken for a silent one", qaHosts(resumed.Targets), qaHosts(again))
			}
		})
	}
}

// A server hop the request's Max-Breadth left no share for was never sent:
// its default handling does not apply, and no hop replaces it, which would
// fail the same way and use up the proxy's MaxBranches (QA of #454).
func TestNoHopReplacesOneWithoutMaxBreadth(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	d := e.router(nil).Initial(bg, fromUser(t, "OPTIONS", impu2))
	f := proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 440}, Err: proxy.ErrMaxBreadth}
	if more := d.OnBranchFailure(bg, f); len(more) != 0 {
		t.Errorf("a branch without Max-Breadth was replaced by %v", qaHosts(more))
	}
}
