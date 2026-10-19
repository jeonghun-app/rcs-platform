package pcscf

import (
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func TestTheLimiterRefillsAtItsRateUpToItsBurst(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := newLimiter(2, 3, clock.now)
	a, b := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	for i := range 3 {
		if !l.allow(a) {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	if l.allow(a) {
		t.Fatal("a request past the burst allowed")
	}
	if !l.allow(b) {
		t.Fatal("another address shares the bucket")
	}
	clock.t = clock.t.Add(500 * time.Millisecond)
	if !l.allow(a) || l.allow(a) {
		t.Fatal("half a second at 2/s is one request")
	}
	clock.t = clock.t.Add(time.Hour)
	for i := range 3 {
		if !l.allow(a) {
			t.Fatalf("after an hour, request %d refused", i)
		}
	}
	if l.allow(a) {
		t.Fatal("the bucket refilled past its burst")
	}
}

func TestTheLimiterDropsRefilledBucketsWhenFull(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := newLimiter(1, 1, clock.now)
	for i := range maxLimitedAddrs {
		l.buckets[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = &bucket{tokens: 0, at: clock.t}
	}
	if l.allow(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("a new address was let in while every bucket holds state")
	}
	clock.t = clock.t.Add(time.Second)
	if !l.allow(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("refilled buckets were not dropped")
	}
	if len(l.buckets) != 1 {
		t.Fatalf("%d buckets kept", len(l.buckets))
	}
}

func TestTheRegistryCountsExpiresAndForgetsFlows(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRegistry(3, clock.now)
	save := func(flow transport.FlowID, aor string, ttl time.Duration) error {
		return r.save(&registration{flow: flow, aor: aor, expires: clock.t.Add(ttl)})
	}
	for _, s := range []struct {
		flow transport.FlowID
		aor  string
		ttl  time.Duration
	}{{"A", "sip:1@h", time.Minute}, {"A", "sip:2@h", time.Hour}, {"B", "sip:1@h", time.Hour}} {
		if err := save(s.flow, s.aor, s.ttl); err != nil {
			t.Fatal(err)
		}
	}
	if err := save("C", "sip:1@h", time.Hour); err != errRegistryFull {
		t.Fatalf("save past the size = %v", err)
	}
	if err := save("A", "sip:1@h", 2*time.Minute); err != nil || r.size() != 3 {
		t.Fatalf("a refresh = %v, size %d", err, r.size())
	}
	if r.tryReserve("C", "sip:1@h", clock.t.Add(time.Minute)) || !r.tryReserve("A", "sip:2@h", clock.t.Add(time.Minute)) {
		t.Fatal("a full registry reserved a new slot, or refused a registered one")
	}
	r.release("A", "sip:2@h")
	clock.t = clock.t.Add(5 * time.Minute)
	r.sweep()
	if r.size() != 2 {
		t.Fatalf("after the sweep %d registrations", r.size())
	}
	r.removeFlow("A")
	if _, ok := r.lookup("A", "sip:2@h"); ok || r.size() != 1 {
		t.Fatalf("flow A not forgotten: size %d", r.size())
	}
	r.remove("B", "sip:1@h")
	r.remove("B", "sip:1@h")
	if r.size() != 0 || len(r.byFlow) != 0 {
		t.Fatalf("size %d, flows %d", r.size(), len(r.byFlow))
	}
}

func TestAoRKeysIgnoreTheHostsCaseOnly(t *testing.T) {
	a := aorKey(mustURI(t, "sip:+15550100001@IMS.mnc001.mcc001.3gppnetwork.org"))
	b := aorKey(mustURI(t, "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org;user=phone"))
	c := aorKey(mustURI(t, "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"))
	if a != b || a == c {
		t.Fatalf("keys %q %q %q", a, b, c)
	}
}

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

// A REGISTER reserves its identity's slot before it is forwarded, so a full
// registry refuses the next one then rather than after its 200; the slot is
// freed when the REGISTER ends unregistered, or when its reservation lapses
// (QA of #198).
func TestRegistrySlotsAreReservedUntilReleasedOrLapsed(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	r := newRegistry(2, clock.now)
	until := clock.t.Add(time.Minute)
	if !r.tryReserve("F1", "sip:1@h", until) || !r.tryReserve("F1", "sip:1@h", until) || !r.tryReserve("F2", "sip:1@h", until) {
		t.Fatal("refused with room")
	}
	if r.tryReserve("F3", "sip:1@h", until) || r.size() != 2 {
		t.Fatalf("a third slot was taken: size %d", r.size())
	}
	// The second REGISTER of F1 still holds the slot after the first ends.
	r.release("F1", "sip:1@h")
	if r.tryReserve("F3", "sip:1@h", until) {
		t.Fatal("a slot still reserved was given away")
	}
	r.release("F1", "sip:1@h")
	r.release("F1", "sip:1@h")
	if r.size() != 1 || !r.tryReserve("F3", "sip:1@h", until) {
		t.Fatalf("a released slot was not freed: size %d", r.size())
	}
	// A reservation that becomes a registration keeps its slot.
	if err := r.save(&registration{flow: "F2", aor: "sip:1@h", expires: clock.t.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r.release("F2", "sip:1@h")
	if r.size() != 2 {
		t.Fatalf("size %d after saving and releasing", r.size())
	}
	// One no response released lapses at the sweep.
	clock.t = until
	r.sweep()
	if r.size() != 1 || len(r.pending) != 0 {
		t.Fatalf("size %d, %d reservations after they lapsed", r.size(), len(r.pending))
	}
	// A flow that closes keeps a REGISTER's slot until it ends.
	if !r.tryReserve("F2", "sip:2@h", clock.t.Add(time.Minute)) {
		t.Fatal("refused")
	}
	r.removeFlow("F2")
	if r.size() != 1 {
		t.Fatalf("size %d after the flow closed", r.size())
	}
	r.release("F2", "sip:2@h")
	if r.size() != 0 {
		t.Fatalf("size %d at the end", r.size())
	}
}

// tryReserve is reserve that reports only whether it took the slot.
func (r *registry) tryReserve(flow transport.FlowID, aor string, until time.Time) bool {
	return r.reserve(flow, aor, until) == nil
}
