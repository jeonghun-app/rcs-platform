package proxy

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestNumericResolver(t *testing.T) {
	tests := []struct {
		uri     string
		network transport.Network
		addr    string
	}{
		{"sip:bob@192.0.2.1", transport.UDP, "192.0.2.1:5060"},
		{"sip:192.0.2.1:5070;transport=TCP", transport.TCP, "192.0.2.1:5070"},
		{"sip:192.0.2.1;transport=tls", transport.TLS, "192.0.2.1:5061"},
		{"sip:192.0.2.1;transport=udp", transport.UDP, "192.0.2.1:5060"},
		{"sips:[2001:db8::1]", transport.TLS, "[2001:db8::1]:5061"},
		// RFC 3261 §26.2.2: SIPS means TLS whatever the transport parameter.
		{"sips:192.0.2.1;transport=tcp", transport.TLS, "192.0.2.1:5061"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			dst, err := NumericResolver{}.Resolve(context.Background(), mustURI(tt.uri))
			if err != nil {
				t.Fatal(err)
			}
			if dst.Network != tt.network || dst.Addr != netip.MustParseAddrPort(tt.addr) {
				t.Errorf("Resolve = %s %s, want %s %s", dst.Network, dst.Addr, tt.network, tt.addr)
			}
		})
	}
}

func TestNumericResolverRefusesWhatNeedsDNSOrIsNotSIP(t *testing.T) {
	for _, uri := range []string{"sip:bob@example.com", "tel:+15550100001", "sip:192.0.2.1;transport=sctp"} {
		if _, err := (NumericResolver{}).Resolve(context.Background(), mustURI(uri)); !errors.Is(err, ErrUnresolvable) {
			t.Errorf("Resolve(%s) = %v, want ErrUnresolvable", uri, err)
		}
	}
}

func TestAnUnresolvableTargetFailsOnlyItsBranch(t *testing.T) {
	h := newHarness(t, Config{Resolver: NumericResolver{}})
	h.decide(Decision{Targets: []Target{target("sip:bob@192.0.2.1;transport=tcp"), target("sip:bob@example.com")}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	sent := h.sent()
	if len(sent) != 1 || sent[0].dst.Addr != netip.MustParseAddrPort("192.0.2.1:5060") || sent[0].dst.Network != transport.TCP {
		t.Fatalf("sent %v, want the numeric target only", methodsOf(sent))
	}
	// The unresolvable branch counts as a 503 from its next hop.
	h.reply(sent[0].req, 404)
	check(t, "upstream", h.upstream(), codes(404))
}
