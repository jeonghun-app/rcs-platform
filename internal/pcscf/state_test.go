package pcscf

import (
	"net/netip"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// A flow that ended is forgotten: the drain sees only the flows still open,
// and an address with none left holds no entry (QA of #188).
func TestAnEndedFlowIsForgotten(t *testing.T) {
	fl := newFlows(10, 4)
	info := transport.FlowInfo{Listener: clientListener, Addr: netip.MustParseAddrPort("198.51.100.7:40000")}
	for _, id := range []transport.FlowID{"a", "b", "c"} {
		if !fl.admit(id, info) {
			t.Fatalf("flow %s refused", id)
		}
	}
	fl.closed("a", info)
	if ids := fl.ids(); len(ids) != 2 {
		t.Fatalf("ids after a close = %v, want b and c", ids)
	}
	fl.closed("b", info)
	fl.closed("c", info)
	fl.closed("c", info)
	if len(fl.ids()) != 0 || len(fl.perIP) != 0 {
		t.Fatalf("open %v, perIP %v after every flow ended", fl.ids(), fl.perIP)
	}
}

// One client is an IPv4 address, written plain or mapped, or an IPv6 /64.
func TestTheLimitCountsAClientByItsAddressOrItsSlash64(t *testing.T) {
	fl := newFlows(100, 1)
	admit := func(id, addr string) bool {
		return fl.admit(transport.FlowID(id), transport.FlowInfo{Listener: clientListener, Addr: netip.MustParseAddrPort(addr)})
	}
	for _, tt := range []struct {
		id, addr string
		want     bool
	}{
		{"1", "198.51.100.7:1", true},
		{"2", "[::ffff:198.51.100.7]:2", false},
		{"3", "[2001:db8:1:2::1]:1", true},
		{"4", "[2001:db8:1:2::5]:1", false},
		{"5", "[2001:db8:1:3::1]:1", true},
	} {
		if got := admit(tt.id, tt.addr); got != tt.want {
			t.Errorf("flow from %s admitted %v, want %v", tt.addr, got, tt.want)
		}
	}
	if !fl.admit("core", transport.FlowInfo{Listener: coreListener, Addr: netip.MustParseAddrPort("198.51.100.7:3")}) {
		t.Error("a core flow was counted against a client")
	}
}
