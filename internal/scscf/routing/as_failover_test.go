package routing

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Two tasks of rcs-as, the first of which stopped (#574).
var (
	deadAS = netip.MustParseAddrPort("10.0.3.7:5060")
	liveAS = netip.MustParseAddrPort("10.0.3.6:5060")
)

// fixedAddresses resolves every server to addrs, in that order, as a DNS
// answer that still names a stopped task does.
type fixedAddresses []netip.AddrPort

func (f fixedAddresses) ResolveAll(_ context.Context, _ sip.URI) ([]transport.Destination, error) {
	out := make([]transport.Destination, 0, len(f))
	for _, a := range f {
		out = append(out, transport.Destination{Network: transport.TCP, Addr: a})
	}
	return out, nil
}

// unreachable is the proxy's failure of a branch whose connection was not
// made (§16.9).
func unreachable(tg proxy.Target) proxy.BranchFailure {
	return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}, Err: errors.New("dial tcp 10.0.3.7:5060: i/o timeout")}
}

func addrOf(t *testing.T, tg proxy.Target) netip.AddrPort {
	t.Helper()
	if tg.Destination == nil {
		t.Fatalf("a target without an address: %+v", tg)
	}
	return tg.Destination.Addr
}

func withResolver(r ASResolver) func(*Config) { return func(c *Config) { c.Resolver = r } }

// TestARequestGoesOnToTheNextAddressOfAServerThatCannotBeReached (#574):
// the server's name resolves to a stopped task and a live one; the branch
// to the stopped one fails for want of a connection, and the request goes
// to the live one, with the same route back and served user, before any
// default handling. The stopped task is tried last while the DNS answer
// may still name it, and first again after.
func TestARequestGoesOnToTheNextAddressOfAServerThatCannotBeReached(t *testing.T) {
	for name, handling := range map[string]ifc.DefaultHandling{"terminated": ifc.SessionTerminated, "continued": ifc.SessionContinued} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), handling), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
			rt := e.router(nil, withResolver(fixedAddresses{deadAS, liveAS}))
			r := fromUser(t, "MESSAGE", impu2)
			d := rt.Initial(bg, r)
			if serverOf(t, d) != "rcs-as.rcs.local" || addrOf(t, d.Targets[0]) != deadAS {
				t.Fatalf("first target %+v", d.Targets[0])
			}
			more := d.OnBranchFailure(bg, unreachable(d.Targets[0]))
			if len(more) != 1 || more[0].Routes[0].URI.Host != "rcs-as.rcs.local" || addrOf(t, more[0]) != liveAS {
				t.Fatalf("then %+v", more)
			}
			if more[0].Routes[1].URI.String() != d.Targets[0].Routes[1].URI.String() {
				t.Errorf("the route back changed: %v, then %v", d.Targets[0].Routes[1], more[0].Routes[1])
			}
			if got := branchOf(t, r, d, more[0]).Header.Get("P-Served-User"); got == "" {
				t.Error("the next address's branch has no P-Served-User")
			}
			if e.metrics.get("routing.as_failover") != 1 || e.metrics.get("routing.ifc.default_handling_continued") != 0 {
				t.Errorf("failovers %d, default handlings %d", e.metrics.get("routing.as_failover"), e.metrics.get("routing.ifc.default_handling_continued"))
			}
			// While the answer may still name it, the stopped task is last.
			if d2 := rt.Initial(bg, fromUser(t, "MESSAGE", impu2)); addrOf(t, d2.Targets[0]) != liveAS {
				t.Errorf("the next request went first to %v", d2.Targets[0].Destination.Addr)
			}
			e.clock.advance(proxy.DefaultDNSTTL)
			if d3 := rt.Initial(bg, fromUser(t, "MESSAGE", impu2)); addrOf(t, d3.Targets[0]) != deadAS {
				t.Errorf("after the DNS TTL the first went to %v", d3.Targets[0].Destination.Addr)
			}
		})
	}
}

// TestADefaultHandlingAppliesOnceEveryAddressFailed (#574): with both
// tasks gone, the criterion's default handling applies once, after the
// second address: SESSION_CONTINUED goes on to the next criterion,
// SESSION_TERMINATED answers 500 with Retry-After, which the client may
// act on, where the proxy's 500 had none.
func TestADefaultHandlingAppliesOnceEveryAddressFailed(t *testing.T) {
	for name, handling := range map[string]ifc.DefaultHandling{"terminated": ifc.SessionTerminated, "continued": ifc.SessionContinued} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), handling), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
			d := e.router(nil, withResolver(fixedAddresses{deadAS, liveAS})).Initial(bg, fromUser(t, "MESSAGE", impu2))
			more := d.OnBranchFailure(bg, unreachable(d.Targets[0]))
			if len(more) != 1 {
				t.Fatalf("after the first address: %+v", more)
			}
			last := d.OnBranchFailure(bg, unreachable(more[0]))
			if handling == ifc.SessionContinued {
				if len(last) != 1 || last[0].Routes[0].URI.Host != "third-as.rcs.local" || e.metrics.get("routing.ifc.default_handling_continued") != 1 {
					t.Fatalf("after the last address: %+v, %d default handlings", last, e.metrics.get("routing.ifc.default_handling_continued"))
				}
				return
			}
			if len(last) != 0 {
				t.Fatalf("after the last address: %+v", last)
			}
			res := &sip.Response{StatusCode: 500, Reason: "Server Internal Error"}
			d.OnFinal(bg, res)
			if res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
				t.Errorf("answered %d with Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
			}
			if e.metrics.get("routing.as_failover") != 1 {
				t.Errorf("failovers %d, want 1", e.metrics.get("routing.as_failover"))
			}
		})
	}
}

// TestAServerThatHadTheRequestIsNotFailedOver (#574): an answer of the
// server's own, a provisional response first, or the server's timeout,
// which the default handling settles with the server's return (takeUp),
// does not send the request to another address.
func TestAServerThatHadTheRequestIsNotFailedOver(t *testing.T) {
	for name, failure := range map[string]func(proxy.Target) proxy.BranchFailure{
		"its own 503": func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}}
		},
		"closed after a 100": func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}, Err: errors.New("connection reset"), Provisional: true}
		},
		"its timeout": func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 408}, Err: proxy.ErrTargetTimeout}
		},
		"queue full": func(tg proxy.Target) proxy.BranchFailure {
			return proxy.BranchFailure{Target: tg, Response: &sip.Response{StatusCode: 503}, Err: transport.ErrQueueFull}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), ifc.SessionTerminated))
			d := e.router(nil, withResolver(fixedAddresses{deadAS, liveAS})).Initial(bg, fromUser(t, "MESSAGE", impu2))
			if more := d.OnBranchFailure(bg, failure(d.Targets[0])); len(more) != 0 {
				t.Errorf("went on to %+v", more)
			}
			if e.metrics.get("routing.as_failover") != 0 {
				t.Errorf("%d failovers", e.metrics.get("routing.as_failover"))
			}
		})
	}
}

// otherLiveAS is a second live task of rcs-as.
var otherLiveAS = netip.MustParseAddrPort("10.0.3.8:5060")

// TestARequestTheServerSentBackIsNotFailedOverOnTimerF (#578 code review):
// the server sent a MESSAGE back, so OnTimeout keeps its branch, which
// later ends on Timer F with nothing received, as a proxying server sends
// no 100 for a non-INVITE (RFC 4320). The server had the request: it does
// not go to another address, which would send a second copy on.
func TestARequestTheServerSentBackIsNotFailedOverOnTimerF(t *testing.T) {
	for name, handling := range map[string]ifc.DefaultHandling{"terminated": ifc.SessionTerminated, "continued": ifc.SessionContinued} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.registered(binding(1, 0, time.Hour))
			e.profile(t0, criterion(10, rcsAS, method("MESSAGE"), handling), criterion(20, thirdAS, method("MESSAGE"), ifc.SessionTerminated))
			rt := e.router(nil, withResolver(fixedAddresses{liveAS, otherLiveAS}))
			r := fromUser(t, "MESSAGE", impu2)
			d := rt.Initial(bg, r)
			rt.Initial(bg, backFrom(t, r, d, 0))
			if d.Targets[0].OnTimeout(bg) {
				t.Fatal("the timeout took the branch of a request sent back")
			}
			more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Err: transaction.ErrTimeout})
			for _, tg := range more {
				if tg.Destination != nil && tg.Destination.Addr == otherLiveAS {
					t.Errorf("went on to %v after the server had sent the request back", otherLiveAS)
				}
			}
			if e.metrics.get("routing.as_failover") != 0 {
				t.Errorf("%d failovers", e.metrics.get("routing.as_failover"))
			}
		})
	}
}

// TestAnINVITEWithNoAnswerAtAllGoesOnToTheNextAddress (#578 code review):
// an INVITE's Timer B with not even a 100 Trying, which every element sends
// within 200 ms (RFC 3261 §16.2), means the server never had it: the next
// address is tried.
func TestAnINVITEWithNoAnswerAtAllGoesOnToTheNextAddress(t *testing.T) {
	e := newEnv(t)
	e.registered(binding(1, 0, time.Hour))
	e.profile(t0, criterion(10, rcsAS, method("INVITE"), ifc.SessionTerminated))
	d := e.router(nil, withResolver(fixedAddresses{deadAS, liveAS})).Initial(bg, fromUser(t, "INVITE", impu2))
	more := d.OnBranchFailure(bg, proxy.BranchFailure{Target: d.Targets[0], Response: &sip.Response{StatusCode: 408}, Err: transaction.ErrTimeout})
	if len(more) != 1 || addrOf(t, more[0]) != liveAS || e.metrics.get("routing.as_failover") != 1 {
		t.Fatalf("then %+v, %d failovers", more, e.metrics.get("routing.as_failover"))
	}
}
