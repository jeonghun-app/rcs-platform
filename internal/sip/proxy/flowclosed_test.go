package proxy

import (
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// keep430 is the edge proxy's OnFinal: it passes 430 on (RFC 5626 §11.5).
func keep430(contextT, *sip.Response) {}

// #234: a branch sent over a flow that then closes, before any final
// response, is answered 430 at once, not after Timer B or F: an INVITE
// before or after a provisional, and a MESSAGE.
func TestABranchWhoseFlowClosesIsAnswered430AtOnce(t *testing.T) {
	for _, tc := range []struct {
		name        string
		req         func(*testing.T) *sip.Request
		provisional bool
	}{
		{"INVITE", func(t *testing.T) *sip.Request { return invite(t) }, false},
		{"ringing INVITE", func(t *testing.T) *sip.Request { return invite(t) }, true},
		{"MESSAGE", func(t *testing.T) *sip.Request { return request(t, "MESSAGE", "sip:bob@example.com") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			var failures []BranchFailure
			h.decide(Decision{
				Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "client"}}},
				OnFinal: keep430,
				OnBranchFailure: func(_ contextT, f BranchFailure) []Target {
					failures = append(failures, f)
					return nil
				},
			})
			h.receive(tc.req(t))
			fwd := h.one()
			if tc.provisional {
				h.reply(fwd, 180)
			}
			h.upstream()
			h.p.FlowClosed("client")
			h.settle()
			if got := h.upstream(); len(got) != 1 || got[0] != 430 {
				t.Fatalf("upstream got %v, want 430 at once", got)
			}
			if len(failures) != 1 || !errors.Is(failures[0].Err, transport.ErrNoFlow) || !errors.Is(failures[0].Err, transaction.ErrFlowClosed) {
				t.Fatalf("failures = %+v, want one with ErrFlowClosed", failures)
			}
		})
	}
}

// The authoritative proxy of RFC 5626 §7 can try the user's other flow when
// one closes with the request on it, as when the send itself fails.
func TestABranchWhoseFlowClosesCanBeRetriedOnAnotherFlow(t *testing.T) {
	h := newHarness(t, Config{})
	other := Target{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "flow-2"}}
	h.decide(Decision{
		Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "flow-1"}}},
		OnBranchFailure: func(_ contextT, f BranchFailure) []Target {
			if f.Target.Destination.Flow == "flow-1" && f.Response.StatusCode == 430 {
				return []Target{other}
			}
			return nil
		},
	})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.one()
	h.p.FlowClosed("flow-1")
	h.settle()
	sent := h.sent()
	if len(sent) != 1 || sent[0].dst.Flow != "flow-2" {
		t.Fatalf("sent %v, want the MESSAGE again over flow-2", methodsOf(sent))
	}
	h.reply(sent[0].req, 200)
	check(t, "upstream", h.upstream(), codes(200))
}

// A flow that closes after the final response changes nothing.
func TestAFlowThatClosesAfterTheAnswerChangesNothing(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "client"}}}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	h.reply(h.one(), 200)
	check(t, "upstream", h.upstream(), codes(200))
	h.p.FlowClosed("client")
	h.settle()
	check(t, "upstream after the close", h.upstream(), nil)
}

// Review of #293: a branch already being cancelled whose flow then closes
// counts as the 487 its CANCEL asked for, whether or not the CANCEL could be
// sent yet; a flow that closes before the CANCEL leaves the 430.
func TestACancelledBranchWhoseFlowClosesIs487(t *testing.T) {
	for _, tc := range []struct {
		name        string
		provisional bool
		closeFirst  bool
		want        []int
	}{
		{"CANCEL sent, then the flow closes", true, false, codes(200, 487)},
		{"CANCEL waiting for a provisional, then the flow closes", false, false, codes(200, 487)},
		{"the flow closes, then the CANCEL", true, true, codes(200, 430)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			h.decide(Decision{
				Targets: []Target{{URI: mustURI("sip:alice@192.0.2.10"), Destination: &transport.Destination{Flow: "client"}}},
				OnFinal: keep430,
			})
			req := invite(t)
			h.receive(req)
			fwd := h.one()
			if tc.provisional {
				h.reply(fwd, 180)
			}
			h.upstream()
			closeFlow := func() {
				h.p.FlowClosed("client")
				h.settle()
			}
			if tc.closeFirst {
				closeFlow()
			}
			h.receive(uacCancel(t, req))
			if !tc.closeFirst {
				closeFlow()
			}
			got := h.upstream()
			slices.Sort(got)
			check(t, "upstream", got, tc.want)
		})
	}
}

// BranchFailure.Provisional tells a service whether the target had the
// request (noted on #14 for scscf), and Progress whether the target, not
// only the next hop with its 100, answered (#322).
func TestABranchFailureSaysWhetherAProvisionalCame(t *testing.T) {
	for _, code := range []int{0, 100, 180} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			h := newHarness(t, Config{})
			var failures []BranchFailure
			h.decide(Decision{
				Targets: []Target{target("sip:alice@192.0.2.10")},
				OnBranchFailure: func(_ contextT, f BranchFailure) []Target {
					failures = append(failures, f)
					return nil
				},
			})
			h.receive(invite(t))
			fwd := h.one()
			if code != 0 {
				h.reply(fwd, code)
			}
			h.reply(fwd, 486)
			if len(failures) != 1 || failures[0].Provisional != (code != 0) || failures[0].Progress != (code > 100) {
				t.Fatalf("failures = %+v, want one with Provisional %v, Progress %v", failures, code != 0, code > 100)
			}
		})
	}
}
