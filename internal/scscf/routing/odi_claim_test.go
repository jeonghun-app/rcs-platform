package routing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// asTimeout is a branch toward a server that ended at ASTimeout.
func asTimeout(tg proxy.Target) proxy.BranchFailure {
	return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
}

// TestEveryCopyAServerSendsBackGoesOn (TS 24.229 §5.4.3.2 NOTE 8, §5.4.3.3
// NOTE 2; #359 code review and QA): a server that forks the request, or
// sends it to another target after a busy callee, sends it back more than
// once with one position, and each copy goes on; the default handling does
// not go on after them.
func TestEveryCopyAServerSendsBackGoesOn(t *testing.T) {
	other := "sip:+15550100004@" + realm
	for name, c := range map[string]struct {
		method string
		start  func(t *testing.T) *proxy.Request
		hosts  [2]string
	}{
		"an originating fork": {"MESSAGE", func(t *testing.T) *proxy.Request { return fromUser(t, "MESSAGE", impu2) }, [2]string{"third-as.rcs.local", "third-as.rcs.local"}},
		// The callee's 486, and the server's call forwarding on busy.
		"a terminating forward": {"INVITE", func(t *testing.T) *proxy.Request { return request(t, "INVITE", impu1) }, [2]string{"third-as.rcs.local", "icscf.rcs.local"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, operatorAS, method(c.method), ifc.SessionContinued), criterion(20, thirdAS, method(c.method), ifc.SessionTerminated))
			r := c.start(t)
			d := e.router(nil).Initial(bg, r)
			for i, host := range c.hosts {
				back := backFrom(t, r, d, 0)
				if i == 1 {
					back.Message.URI = mustURI(other)
				}
				if got := serverOf(t, e.router(nil).Initial(bg, back)); got != host {
					t.Errorf("copy %d went to %s, want %s", i+1, got, host)
				}
			}
			if more := d.OnBranchFailure(bg, asTimeout(d.Targets[0])); len(more) != 0 {
				t.Errorf("the default handling went on too, to %v", uris(more))
			}
			if n := e.metrics.get("routing.odi.late"); n != 0 {
				t.Errorf("%d copies refused", n)
			}
		})
	}
}

// claimsTwice applies each claim of an iFC position twice, as DynamoDB
// does with a put the SDK resends after its answer was lost.
type claimsTwice struct{ *state.Memory }

func (s claimsTwice) ClaimODI(ctx context.Context, scope, side string, now, expires time.Time) (string, error) {
	if _, err := s.Memory.ClaimODI(ctx, scope, side, now, expires); err != nil {
		return "", err
	}
	return s.Memory.ClaimODI(ctx, scope, side, now, expires)
}

// TestAClaimAppliedTwiceStillGoesOn (#359 QA): neither the only copy back
// nor the default handling is taken for a second because the store applied
// its claim twice.
func TestAClaimAppliedTwiceStillGoesOn(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
	twice := claimsTwice{e.store}
	r := fromUser(t, "MESSAGE", impu2)
	d := e.router(twice).Initial(bg, r)
	if host := serverOf(t, e.router(twice).Initial(bg, backFrom(t, r, d, 0))); host != "third-as.rcs.local" {
		t.Errorf("the copy back went to %s", host)
	}
	e.profile(t0, criterion(10, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	r = fromUser(t, "OPTIONS", impu2)
	d = e.router(twice).Initial(bg, r)
	if more := d.OnBranchFailure(bg, asTimeout(d.Targets[0])); len(more) != 1 {
		t.Errorf("the default handling went on to %v", uris(more))
	}
}

// TestAUserWhoDeregisteredMeanwhileStillGetsOneCopy (#359 code review and
// QA): the copy back, which finds the set ending, claims the position too,
// so the default handling, from the set the first step had, does not send
// a second.
func TestAUserWhoDeregisteredMeanwhileStillGetsOneCopy(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	r := fromUser(t, "OPTIONS", impu2)
	d := e.router(nil).Initial(bg, r)
	e.change(deregister)
	if host := serverOf(t, e.router(nil).Initial(bg, backFrom(t, r, d, 0))); host != "icscf.rcs.local" {
		t.Fatalf("the copy back went to %s", host)
	}
	if more := d.OnBranchFailure(bg, asTimeout(d.Targets[0])); len(more) != 0 {
		t.Errorf("a second copy went to %v", uris(more))
	}
}

// TestTheChainsAnswerDropsTheServersRetryAfter (#359 QA): a server passed
// over after its 500 with Retry-After does not lend it to the answer the
// chain makes, which is about the user, not the server.
func TestTheChainsAnswerDropsTheServersRetryAfter(t *testing.T) {
	e := newEnv(t)
	e.unregistered()
	e.profile(t0, criterion(10, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	d := e.router(nil).Initial(bg, request(t, "OPTIONS", impu1))
	busy := &sip.Response{StatusCode: 500, Reason: "Server Internal Error"}
	_ = busy.Header.Set("Retry-After", "120")
	if more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: d.Targets[0], Response: busy}); len(more) != 0 {
		t.Fatalf("then %v", uris(more))
	}
	d.OnFinal(bg, busy)
	if busy.StatusCode != 480 || busy.Header.Get("Retry-After") != "" {
		t.Errorf("answered %d with Retry-After %q", busy.StatusCode, busy.Header.Get("Retry-After"))
	}
}

// TestASTimeoutBoundsOnlyTheWaitForTheServer (#386): once the server has
// sent a non-INVITE back, its branch is no longer cut at ASTimeout, as the
// far end answers along it; a server that has not keeps the timeout, and a
// copy it sends back after that is late. Either way, as for the default
// handling, the first of the two to take up the position decides.
func TestASTimeoutBoundsOnlyTheWaitForTheServer(t *testing.T) {
	for _, handling := range []ifc.DefaultHandling{ifc.SessionContinued, ifc.SessionTerminated} {
		for _, returned := range []bool{true, false} {
			name := map[ifc.DefaultHandling]string{ifc.SessionContinued: "SESSION_CONTINUED", ifc.SessionTerminated: "SESSION_TERMINATED"}[handling]
			t.Run(fmt.Sprintf("%s, sent back %v", name, returned), func(t *testing.T) {
				e := newEnv(t)
				e.registered(binding(1, 0, time.Hour))
				e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), handling))
				r := fromUser(t, "OPTIONS", impu2)
				d := e.router(nil).Initial(bg, r)
				tg := d.Targets[0]
				if tg.Timeout != DefaultASTimeout || tg.OnTimeout == nil {
					t.Fatalf("timeout %v, OnTimeout set %v", tg.Timeout, tg.OnTimeout != nil)
				}
				if returned {
					if got := serverOf(t, e.router(nil).Initial(bg, backFrom(t, r, d, 0))); got != "icscf.rcs.local" {
						t.Fatalf("the copy sent back went to %s", got)
					}
				}
				if applies := tg.OnTimeout(bg); applies == returned {
					t.Fatalf("the timeout applies %v with the request sent back %v", applies, returned)
				}
				if returned {
					if n := e.metrics.get("routing.ifc.returned_before_timeout"); n != 1 {
						t.Errorf("returned_before_timeout %d", n)
					}
					return
				}
				// Sent back after the timeout took the position: late.
				if got := e.router(nil).Initial(bg, backFrom(t, r, d, 0)); got.Status != 403 {
					t.Errorf("a copy sent back after the timeout got %+v, want 403", got)
				}
			})
		}
	}
	// An INVITE keeps no Timeout, and so no OnTimeout either.
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(30, rcsAS, method("INVITE"), ifc.SessionContinued))
	if tg := e.router(nil).Initial(bg, fromUser(t, "INVITE", impu2)).Targets[0]; tg.Timeout != 0 || tg.OnTimeout != nil {
		t.Errorf("an INVITE's branch has timeout %v, OnTimeout set %v", tg.Timeout, tg.OnTimeout != nil)
	}
}
