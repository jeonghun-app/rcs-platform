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
	if r.room("C", "sip:1@h") || !r.room("A", "sip:2@h") {
		t.Fatal("room is wrong")
	}
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
