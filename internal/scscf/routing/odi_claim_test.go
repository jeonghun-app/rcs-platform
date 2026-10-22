package routing

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
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

// heldClaim applies the first default-handling claim of an iFC position to
// the store and then holds its answer until release closes, as a slow
// store or a retried put whose answer was lost.
type heldClaim struct {
	*state.Memory
	held             atomic.Bool
	applied, release chan struct{}
}

func (s *heldClaim) ClaimODI(ctx context.Context, scope, side string, now, expires time.Time) (string, error) {
	recorded, err := s.Memory.ClaimODI(ctx, scope, side, now, expires)
	// Not a sync.Once, whose other callers would wait for the held one.
	if side == state.ODIDefault && s.held.CompareAndSwap(false, true) {
		close(s.applied)
		<-s.release
	}
	return recorded, err
}

// A copy the server sends back after the timeout took the position is
// refused 403, and the server may relay that 403 on the branch while
// OnTimeout still waits for the store's answer, the branch alive meanwhile:
// the default handling still applies, as the timeout's (code review of
// #443). SESSION_CONTINUED goes on to the next hop, SESSION_TERMINATED
// answers 504, not the 403.
func TestTheTimeoutsPositionStandsAgainstTheRelayedLateRefusal(t *testing.T) {
	for _, handling := range []ifc.DefaultHandling{ifc.SessionContinued, ifc.SessionTerminated} {
		name := map[ifc.DefaultHandling]string{ifc.SessionContinued: "SESSION_CONTINUED", ifc.SessionTerminated: "SESSION_TERMINATED"}[handling]
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), handling))
			held := &heldClaim{Memory: e.store, applied: make(chan struct{}), release: make(chan struct{})}
			r := fromUser(t, "OPTIONS", impu2)
			d := e.router(held).Initial(bg, r)
			tg := d.Targets[0]
			applies := make(chan bool, 1)
			go func() { applies <- tg.OnTimeout(bg) }()
			<-held.applied
			defer func() {
				close(held.release)
				if !<-applies {
					t.Error("the timeout did not apply to a server that had not sent the request back")
				}
			}()
			late := e.router(nil).Initial(bg, backFrom(t, r, d, 0))
			if late.Status != 403 {
				t.Fatalf("the copy sent back after the timeout got %+v, want 403", late)
			}
			// The server relays that 403 on its branch before OnTimeout
			// has its answer.
			relayed := &sip.Response{StatusCode: 403, Reason: "Forbidden"}
			more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: tg, Response: relayed})
			if handling == ifc.SessionContinued {
				if len(more) != 1 || more[0].Routes[0].URI.Host != "icscf.rcs.local" {
					t.Fatalf("after the relayed 403 the request went to %v, want on to the I-CSCF", uris(more))
				}
				return
			}
			if len(more) != 0 {
				t.Fatalf("SESSION_TERMINATED went on to %v", uris(more))
			}
			d.OnFinal(bg, relayed)
			if relayed.StatusCode != 504 {
				t.Errorf("the caller gets %d, want the timeout's 504", relayed.StatusCode)
			}
		})
	}
}

// When the server sent the request back before the timeout, the far end's
// answer comes along the branch even after OnTimeout ran: failed asks the
// store again and finds the return's claim, so a 403 from the far end is
// passed on, not taken for the timeout's (code review of #443).
func TestTheFarEndsAnswerStandsWhenTheReturnCameFirst(t *testing.T) {
	for _, handling := range []ifc.DefaultHandling{ifc.SessionContinued, ifc.SessionTerminated} {
		e := newEnv(t)
		e.registered(binding(1, 0, time.Hour))
		e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), handling))
		r := fromUser(t, "OPTIONS", impu2)
		d := e.router(nil).Initial(bg, r)
		tg := d.Targets[0]
		if got := serverOf(t, e.router(nil).Initial(bg, backFrom(t, r, d, 0))); got != "icscf.rcs.local" {
			t.Fatalf("the copy sent back went to %s", got)
		}
		if tg.OnTimeout(bg) {
			t.Fatal("the timeout applies to a request the server sent back")
		}
		refused := &sip.Response{StatusCode: 403, Reason: "Forbidden"}
		if more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: tg, Response: refused}); len(more) != 0 {
			t.Errorf("handling %v: the far end's 403 sent the request on to %v", handling, uris(more))
		}
		d.OnFinal(bg, refused)
		if refused.StatusCode != 403 {
			t.Errorf("handling %v: the caller gets %d, want the far end's 403", handling, refused.StatusCode)
		}
	}
}

// switchedClaims fails every claim of an iFC position once fail is set.
type switchedClaims struct {
	*state.Memory
	fail atomic.Bool
}

func (s *switchedClaims) ClaimODI(ctx context.Context, scope, side string, now, expires time.Time) (string, error) {
	if s.fail.Load() {
		return "", errors.New("throttled")
	}
	return s.Memory.ClaimODI(ctx, scope, side, now, expires)
}

// A store that fails failed's own claim, after the server sent the request
// back first, does not make the far end's 403 the timeout's: the request
// is not sent on a second time (code review of #443).
func TestAStoreErrorOnTheReclaimIsNotTheTimeouts(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	st := &switchedClaims{Memory: e.store}
	r := fromUser(t, "OPTIONS", impu2)
	d := e.router(st).Initial(bg, r)
	tg := d.Targets[0]
	if got := serverOf(t, e.router(nil).Initial(bg, backFrom(t, r, d, 0))); got != "icscf.rcs.local" {
		t.Fatalf("the copy sent back went to %s", got)
	}
	if tg.OnTimeout(bg) {
		t.Fatal("the timeout applies to a request the server sent back")
	}
	st.fail.Store(true)
	refused := &sip.Response{StatusCode: 403, Reason: "Forbidden"}
	if more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: tg, Response: refused}); len(more) != 0 {
		t.Errorf("a second copy went to %v", uris(more))
	}
	d.OnFinal(bg, refused)
	if refused.StatusCode != 403 {
		t.Errorf("the caller gets %d, want the far end's 403", refused.StatusCode)
	}
}

// failingClaims fails every claim of an iFC position, as a throttled store.
type failingClaims struct{ *state.Memory }

func (failingClaims) ClaimODI(context.Context, string, string, time.Time, time.Time) (string, error) {
	return "", errors.New("throttled")
}

// A store that cannot say whether the server sent the request back leaves
// the timeout to apply, as before #386 (QA of #443).
func TestTheTimeoutAppliesWhenTheStoreCannotSay(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(30, rcsAS, method("OPTIONS"), ifc.SessionContinued))
	d := e.router(failingClaims{e.store}).Initial(bg, fromUser(t, "OPTIONS", impu2))
	if !d.Targets[0].OnTimeout(bg) {
		t.Error("a store failure kept the branch")
	}
}
