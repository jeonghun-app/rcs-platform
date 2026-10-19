package proxy

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ackFor2xx is the ACK a UAC sends for a 2xx through a proxy that
// record-routed: its own branch, the To tag of the 2xx, the route set.
func ackFor2xx(t *testing.T, extra ...string) *sip.Request {
	t.Helper()
	fields := append(override([]string{
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKack-1",
		"To: <sip:bob@example.com>;tag=b1",
		"CSeq: 1 ACK",
		"Route: <sip:proxy.example.net;lr>",
		"Route: <sip:next.example.net;lr>",
	}, extra), extra...)
	return request(t, "ACK", "sip:bob@192.0.2.30", fields...)
}

func TestAnACKForA2xxIsForwardedStatelesslyFollowingItsRoute(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(ackFor2xx(t))
	sent := h.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want the ACK", len(sent))
	}
	ack := sent[0].req
	if ack.Method != "ACK" || ack.URI.String() != "sip:bob@192.0.2.30" || sent[0].dst.ServerName != "next.example.net" {
		t.Errorf("sent %s %s to %s", ack.Method, ack.URI.String(), sent[0].dst.ServerName)
	}
	check(t, "Route", ack.Header.Values("Route"), []string{"<sip:next.example.net;lr>"})
	if mf, _ := ack.Header.MaxForwards(); mf != 69 {
		t.Errorf("Max-Forwards = %d, want 69", mf)
	}
	if !ack.Header.Has("Via") || len(ack.Header.Values("Via")) != 2 {
		t.Errorf("Via = %v, want the proxy's on top of the UAC's", ack.Header.Values("Via"))
	}
	if h.p.Stats().ACKsForwarded != 1 {
		t.Errorf("ACKsForwarded = %d", h.p.Stats().ACKsForwarded)
	}
	if n, _ := h.p.Layer().Len(); n != 0 {
		t.Errorf("%d client transactions for an ACK, want none", n)
	}
}

func TestAnACKIsNotRecordRouted(t *testing.T) {
	h := newHarness(t, Config{})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.30")}, RecordRoute: []sip.Address{mustAddr("<sip:proxy.example.net;lr>")}})
	h.receive(ackFor2xx(t))
	if h.one().Header.Has("Record-Route") {
		t.Error("the ACK was record-routed")
	}
}

// TestAnACKRetransmissionCarriesTheSameBranch is §16.11: the branch of a request
// forwarded statelessly is a function of what its retransmissions share, and
// differs between ACKs.
func TestAnACKRetransmissionCarriesTheSameBranch(t *testing.T) {
	h := newHarness(t, Config{})
	h.receive(ackFor2xx(t))
	h.receive(ackFor2xx(t))
	h.receive(ackFor2xx(t, "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKack-2"))
	sent := h.sent()
	if len(sent) != 3 {
		t.Fatalf("sent %d, want 3", len(sent))
	}
	b0, b1, b2 := topBranch(t, sent[0].req), topBranch(t, sent[1].req), topBranch(t, sent[2].req)
	if b0 != b1 {
		t.Errorf("a retransmitted ACK got branch %s, then %s", b0, b1)
	}
	if b0 == b2 {
		t.Error("two ACKs share a branch")
	}
}

func TestAnACKWithoutAnRFC3261BranchStillGetsAStableBranch(t *testing.T) {
	h := newHarness(t, Config{})
	old := "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=1"
	h.receive(ackFor2xx(t, old))
	h.receive(ackFor2xx(t, old))
	sent := h.sent()
	if len(sent) != 2 || topBranch(t, sent[0].req) != topBranch(t, sent[1].req) {
		t.Fatal("an RFC 2543 ACK's retransmission got another branch")
	}
	if b := topBranch(t, sent[0].req); b[:len(sip.MagicCookie)] != sip.MagicCookie {
		t.Errorf("branch %s lacks the magic cookie", b)
	}
}

func TestACKsThatCannotBeForwardedAreDropped(t *testing.T) {
	tests := []struct {
		name  string
		extra []string
		route func(*Request) Decision
		fail  error
	}{
		{name: "Max-Forwards 0", extra: []string{"Max-Forwards: 0"}},
		{name: "a malformed Route", extra: []string{"Route: sip:bare.example.net"}},
		{name: "no target", route: func(*Request) Decision { return Decision{} }},
		{name: "an answer instead of targets", route: func(*Request) Decision { return Decision{Status: 404} }},
		{name: "a failed send", fail: transport.ErrNoFlow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t, Config{})
			if tt.route != nil {
				h.route(func(_ contextT, r *Request) Decision { return tt.route(r) })
			}
			if tt.fail != nil {
				h.net.setFail(func(*sip.Request, transport.Destination) error { return tt.fail })
			}
			h.receive(ackFor2xx(t, tt.extra...))
			check(t, "sent", h.sentMethods(), nil)
			check(t, "upstream", h.upstream(), nil)
			if n := h.p.Stats().ACKsDropped; n != 1 {
				t.Errorf("ACKsDropped = %d, want 1", n)
			}
		})
	}
}

func TestAResponseMatchingNoTransactionIsDropped(t *testing.T) {
	h := newHarness(t, Config{})
	stray := responseTo(t, request(t, "INVITE", "sip:bob@example.com",
		"Via: SIP/2.0/TCP invalid;branch=z9hG4bKnot-ours", "Via: SIP/2.0/TCP 192.0.2.10"), 200)
	h.p.Receive(inboundFrom(stray, "down"))
	h.settle()
	check(t, "upstream", h.upstream(), nil)
	check(t, "sent", h.sentMethods(), nil)
	if n := h.p.Stats().StrayResponses; n != 1 {
		t.Errorf("StrayResponses = %d, want 1", n)
	}
}

func TestAnACKForANon2xxIsAbsorbedByTheTransaction(t *testing.T) {
	h := newHarness(t, Config{})
	inv := invite(t)
	h.receive(inv)
	h.reply(h.one(), 486)
	h.sent()
	res := h.upstreamResponses()[0]
	ack := request(t, "ACK", inv.URI.String(), "Via: "+inv.Header.Get("Via"), "To: "+res.Header.Get("To"), "CSeq: 1 ACK")
	h.receive(ack)
	check(t, "sent", h.sentMethods(), nil)
	if h.p.Stats().ACKsForwarded != 0 {
		t.Error("an ACK for a non-2xx was forwarded")
	}
}
