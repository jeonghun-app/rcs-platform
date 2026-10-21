package transport

import (
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeNow is a clock that moves only when told.
type fakeNow struct{ t time.Time }

func (c *fakeNow) now() time.Time          { return c.t }
func (c *fakeNow) advance(d time.Duration) { c.t = c.t.Add(d) }

// testTable returns a table with a UDP flow lifetime of a minute that records
// the flows it reports closed.
func testTable(key byte, clock *fakeNow, maxUDP int) *flowTable {
	tab, _ := recordingTable(key, clock, maxUDP, maxUDP)
	return tab
}

func recordingTable(key byte, clock *fakeNow, maxUDP, perIP int) (*flowTable, *[]FlowID) {
	var k [sha256.Size]byte
	k[0] = key
	var closed []FlowID
	tab := newFlowTable(k, clock.now, tableConfig{
		udpTimeout: time.Minute, maxUDP: maxUDP, maxUDPPerIP: perIP,
		onClosed: func(f *flow) { closed = append(closed, f.id) },
	})
	return tab, &closed
}

// seen is what the UDP read loop does with a datagram: find the source's flow, or
// enter a new one.
func seen(tab *flowTable, lis *listener, remote string) *flow {
	ap := netip.MustParseAddrPort(remote)
	if f := tab.udpFlow(lis, ap); f != nil {
		return f
	}
	f, _ := tab.addUDP(tab.newFlow(UDP, lis, ap))
	return f
}

func TestFlowIDsDifferForEveryConnectionFromTheSameAddress(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	remote := netip.MustParseAddrPort("192.0.2.10:40000")
	lis := &listener{name: "public"}
	a := tab.newFlow(TCP, lis, remote)
	b := tab.newFlow(TCP, lis, remote)
	if a.id == b.id {
		t.Fatal("two connections from one address share a FlowID")
	}
}

func TestFlowIDDependsOnEveryPartOfTheIdentity(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	remote := netip.MustParseAddrPort("192.0.2.10:40000")
	base := tab.token(TCP, "public", remote, 7)
	for name, id := range map[string]FlowID{
		"network":  tab.token(TLS, "public", remote, 7),
		"listener": tab.token(TCP, "core", remote, 7),
		"address":  tab.token(TCP, "public", netip.MustParseAddrPort("192.0.2.11:40000"), 7),
		"port":     tab.token(TCP, "public", netip.MustParseAddrPort("192.0.2.10:40001"), 7),
		"counter":  tab.token(TCP, "public", remote, 8),
		"key":      testTable(2, &fakeNow{}, 10).token(TCP, "public", remote, 7),
	} {
		if id == base {
			t.Errorf("changing the %s does not change the FlowID", name)
		}
	}
	if tab.token(TCP, "public", remote, 7) != base {
		t.Error("the FlowID is not a function of the identity")
	}
}

func TestFlowIDsAreSafeInASIPURI(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	for i := range uint64(64) {
		id := tab.token(UDP, "l", netip.MustParseAddrPort("192.0.2.10:1"), i)
		if len(id) != 22 || strings.Trim(string(id), "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
			t.Fatalf("FlowID %q is not 22 URL-safe base64 characters", id)
		}
	}
}

func TestUDPFlowLivesWhileDatagramsArriveAndExpiresAfterTheUDPFlowTimeout(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab, closed := recordingTable(1, clock, 10, 10)
	lis := &listener{name: "udp"}

	f := seen(tab, lis, "192.0.2.10:5060")
	clock.advance(50 * time.Second)
	if seen(tab, lis, "192.0.2.10:5060") != f {
		t.Fatal("second datagram from the same source made a new flow")
	}
	clock.advance(50 * time.Second)
	if tab.lookup(f.id) != f {
		t.Fatal("flow expired although a datagram arrived within the timeout")
	}
	clock.advance(11 * time.Second)
	if tab.lookup(f.id) != nil {
		t.Fatal("flow outlived the UDP flow timeout")
	}
	if g := seen(tab, lis, "192.0.2.10:5060"); g == nil || g.id == f.id {
		t.Fatal("a datagram after expiry did not start a new flow")
	}
	if len(*closed) != 1 || (*closed)[0] != f.id {
		t.Fatalf("closed = %v, want the expired flow once", *closed)
	}
}

func TestFullUDPFlowTableDisplacesTheLeastRecentlySeenFlow(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab, closed := recordingTable(1, clock, 2, 2)
	lis := &listener{name: "udp"}
	a := seen(tab, lis, "192.0.2.1:5060")
	clock.advance(time.Second)
	b := seen(tab, lis, "192.0.2.2:5060")
	clock.advance(time.Second)
	seen(tab, lis, "192.0.2.1:5060") // a is now the more recent of the two

	c := seen(tab, lis, "192.0.2.3:5060")
	if c == nil {
		t.Fatal("a full table refused a new source")
	}
	if tab.lookup(b.id) != nil || tab.lookup(a.id) != a {
		t.Fatal("the wrong flow was displaced")
	}
	if s := tab.stats(); s.udp != 2 || s.evicted != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if len(*closed) != 1 || (*closed)[0] != b.id {
		t.Fatalf("closed = %v, want the displaced flow", *closed)
	}
}

func TestOneHostCanOnlyDisplaceItsOwnUDPFlows(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab, _ := recordingTable(1, clock, 100, 2)
	lis := &listener{name: "udp"}
	victim := seen(tab, lis, "192.0.2.50:5060")
	var flood []*flow
	for port := 1; port <= 10; port++ {
		clock.advance(time.Millisecond)
		flood = append(flood, seen(tab, lis, netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), uint16(port)).String()))
	}
	if tab.lookup(victim.id) != victim {
		t.Fatal("a flood from one host displaced another host's flow")
	}
	if tab.lookup(flood[9].id) == nil || tab.lookup(flood[8].id) == nil || tab.lookup(flood[7].id) != nil {
		t.Fatal("the flooding host kept more than its two most recent flows")
	}
	if s := tab.stats(); s.udp != 3 || s.evicted != 8 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestExpiredUDPFlowsAreDroppedBeforeAnyLiveOneIsDisplaced(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab, _ := recordingTable(1, clock, 2, 2)
	lis := &listener{name: "udp"}
	old := seen(tab, lis, "192.0.2.1:5060")
	clock.advance(2 * time.Minute)
	live := seen(tab, lis, "192.0.2.2:5060")
	seen(tab, lis, "192.0.2.3:5060")
	if tab.lookup(live.id) != live || tab.lookup(old.id) != nil {
		t.Fatal("a live flow was displaced while an expired one remained")
	}
	if s := tab.stats(); s.evicted != 0 {
		t.Fatalf("dropping an expired flow counted as a displacement: %+v", s)
	}
}

func TestClosingTheTableReportsItsUDPFlows(t *testing.T) {
	tab, closed := recordingTable(1, &fakeNow{t: time.Unix(1000, 0)}, 10, 10)
	lis := &listener{name: "udp"}
	f := seen(tab, lis, "192.0.2.1:5060")
	tab.close()
	if len(*closed) != 1 || (*closed)[0] != f.id || tab.stats().udp != 0 {
		t.Fatalf("closed = %v", *closed)
	}
}

func TestRemovedFlowIsUnknownAndRemovingTwiceIsHarmless(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	f := tab.newFlow(TCP, &listener{name: "l"}, netip.MustParseAddrPort("192.0.2.1:1"))
	if !tab.addStream(f) || tab.stats().inbound != 1 {
		t.Fatal("flow not added")
	}
	tab.remove(f)
	tab.remove(f)
	if tab.lookup(f.id) != nil || tab.stats().inbound != 0 {
		t.Fatal("removed flow still counted or resolvable")
	}
}

func TestClosedTableAcceptsNoFlows(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	tab.close()
	lis := &listener{name: "l"}
	if tab.addStream(tab.newFlow(TCP, lis, netip.MustParseAddrPort("192.0.2.1:1"))) {
		t.Fatal("closed table accepted a stream")
	}
	if _, ok := tab.addUDP(tab.newFlow(UDP, lis, netip.MustParseAddrPort("192.0.2.1:1"))); ok {
		t.Fatal("closed table accepted a UDP flow")
	}
}

func TestFlowBeingClosedIsAlreadyUnknown(t *testing.T) {
	// closeFlow marks the flow closed before it takes it out of the table; a
	// lookup in between must not hand out a connection that is shutting down.
	tab := testTable(1, &fakeNow{}, 10)
	f := tab.newFlow(TCP, &listener{name: "l"}, netip.MustParseAddrPort("192.0.2.1:1"))
	tab.addStream(f)
	f.closed.Store(true)
	if tab.lookup(f.id) != nil {
		t.Fatal("a closing flow resolved")
	}
}
