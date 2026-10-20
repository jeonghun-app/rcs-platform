package proxy

import (
	"errors"
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
