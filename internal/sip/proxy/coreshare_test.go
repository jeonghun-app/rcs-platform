package proxy

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// clientSource is a client-facing listener's flow, as pcscf's client side.
var clientSource = transport.Source{Flow: "client", Network: transport.TCP, Listener: "client", ClientFacing: true}

// numbered is a MESSAGE with body, a transaction and dialog of its own.
func numbered(t *testing.T, n int, body string) *sip.Request {
	t.Helper()
	return withBody(t, "MESSAGE", "sip:bob@example.com", body,
		fmt.Sprintf("Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKshare-%d", n),
		fmt.Sprintf("Call-ID: share-%d@192.0.2.10", n))
}

// held is what a request held with one branch takes of MaxContextBytes: the
// request and the Router's copy of its header, and the branch's header and
// its CANCEL.
func held(req *sip.Request) int64 { return int64(len(req.Body)) + 4*headerSize(&req.Header) }

// Requests from client-facing listeners may take the proxy's context bytes
// only to the transaction layer's ClientShare of them, so that a flood of
// clients leaves the rest to the core's terminating requests (#489).
func TestClientsLeaveTheCoreItsShareOfTheContextBytes(t *testing.T) {
	first, second := numbered(t, 1, strings.Repeat("x", 2000)), numbered(t, 2, strings.Repeat("x", 2000))
	core := numbered(t, 3, "")
	c, k := held(first), held(core)
	// Room for both client requests and not the core's; with the default
	// share, room for one client request beside the core's, not two.
	budget := 2*c + k - 1
	if share := float64(2*c) / float64(budget); share <= transaction.DefaultClientShare || c+k > budget {
		t.Fatalf("the sizes do not test the share: two client requests are %.2f of the budget", share)
	}
	h := newHarness(t, Config{MaxContextBytes: budget})
	h.p.Receive(transport.Inbound{Message: first, Source: clientSource})
	h.settle()
	h.one()
	h.p.Receive(transport.Inbound{Message: second, Source: clientSource})
	h.settle()
	check(t, "the second client request", h.upstream(), codes(503))
	h.receive(core)
	h.one()
	check(t, "the core's request", h.upstream(), nil)
	if n := h.p.Stats().Overloaded; n != 1 {
		t.Errorf("Overloaded = %d, want the second client request only", n)
	}
}

// A client request's branches count against the client share too: one whose
// branch would take the context bytes past it fails as 503, where the same
// request from the core is forwarded.
func TestAClientRequestsBranchKeepsToTheClientShare(t *testing.T) {
	req := request(t, "MESSAGE", "sip:bob@example.com")
	// The request fits within the share; its branch, the header twice
	// more, only within the whole.
	budget := held(req)
	if ctx := held(req) - 2*headerSize(&req.Header); float64(ctx) > transaction.DefaultClientShare*float64(budget) {
		t.Fatal("the request alone is past the client share")
	}
	for name, tt := range map[string]struct {
		src  transport.Source
		want []int
	}{
		"from a client": {clientSource, codes(503)},
		"from the core": {upstreamSource, nil},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, Config{MaxContextBytes: budget})
			h.p.Receive(transport.Inbound{Message: request(t, "MESSAGE", "sip:bob@example.com"), Source: tt.src})
			h.settle()
			check(t, "upstream", h.upstream(), tt.want)
			if sent := len(h.sent()); (sent == 1) != (tt.want == nil) {
				t.Errorf("sent %d requests", sent)
			}
		})
	}
}

// A ClientShare set for the layer sets the proxy's too. A client request
// past it is refused before it is routed, as one past MaxContextBytes is.
func TestTheProxyTakesTheLayersClientShare(t *testing.T) {
	req := numbered(t, 1, strings.Repeat("x", 2000))
	h := newHarness(t, Config{MaxContextBytes: 2 * held(req), Transaction: transaction.Config{ClientShare: 0.4}})
	h.p.Receive(transport.Inbound{Message: req, Source: clientSource})
	h.settle()
	check(t, "a client request past 0.4 of the bytes", h.upstream(), codes(503))
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.seen) != 0 {
		t.Error("the Router saw a request refused at the client share")
	}
}

// ofSize is a MESSAGE that, held with one branch, takes exactly n bytes.
func ofSize(t *testing.T, n int64) *sip.Request {
	t.Helper()
	req := numbered(t, 1, "")
	req.Body = []byte(strings.Repeat("x", int(n-held(req))))
	if held(req) != n {
		t.Fatalf("a request of %d bytes takes %d", n, held(req))
	}
	return req
}

// The client share is rounded up and reached, not passed: at 1843 bytes it
// is ceil(0.8 * 1843) = 1475, and a client request that takes exactly that
// is forwarded, where one byte more is refused (#511 code review).
func TestAClientRequestMayTakeTheClientShareExactly(t *testing.T) {
	for n, want := range map[int64][]int{1475: nil, 1476: codes(503)} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			h := newHarness(t, Config{MaxContextBytes: 1843})
			h.p.Receive(transport.Inbound{Message: ofSize(t, n), Source: clientSource})
			h.settle()
			check(t, "upstream", h.upstream(), want)
		})
	}
}

// A share of 1 with the largest byte bound lets clients use all of it: the
// client bound does not leave the int64 range (#511 code review).
func TestAWholeClientShareOfTheLargestBoundAdmitsClients(t *testing.T) {
	h := newHarness(t, Config{MaxContextBytes: math.MaxInt64, Transaction: transaction.Config{ClientShare: 1}})
	h.p.Receive(transport.Inbound{Message: numbered(t, 1, ""), Source: clientSource})
	h.settle()
	h.one()
	check(t, "upstream", h.upstream(), nil)
}
