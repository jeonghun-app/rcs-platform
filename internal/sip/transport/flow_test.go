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

func testTable(key byte, clock *fakeNow, maxUDP int) *flowTable {
	var k [sha256.Size]byte
	k[0] = key
	return newFlowTable(k, clock.now, time.Minute, maxUDP)
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

func TestUDPFlowLivesWhileDatagramsArriveAndExpiresAfterTheIdleTimeout(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab := testTable(1, clock, 10)
	lis := &listener{name: "udp"}
	remote := netip.MustParseAddrPort("192.0.2.10:5060")

	f, created := tab.udp(lis, remote)
	if f == nil || !created {
		t.Fatal("first datagram did not create a flow")
	}
	clock.advance(50 * time.Second)
	if again, created := tab.udp(lis, remote); again != f || created {
		t.Fatal("second datagram from the same source made a new flow")
	}
	clock.advance(50 * time.Second)
	if tab.lookup(f.id) != f {
		t.Fatal("flow expired although a datagram arrived within the idle timeout")
	}
	clock.advance(11 * time.Second)
	if tab.lookup(f.id) != nil {
		t.Fatal("flow outlived the idle timeout")
	}
	if g, created := tab.udp(lis, remote); g == nil || !created || g.id == f.id {
		t.Fatal("a datagram after expiry did not start a new flow")
	}
}

func TestFullUDPFlowTableMakesRoomOnlyFromExpiredFlows(t *testing.T) {
	clock := &fakeNow{t: time.Unix(1000, 0)}
	tab := testTable(1, clock, 2)
	lis := &listener{name: "udp"}
	a, _ := tab.udp(lis, netip.MustParseAddrPort("192.0.2.1:5060"))
	clock.advance(30 * time.Second)
	tab.udp(lis, netip.MustParseAddrPort("192.0.2.2:5060"))
	if f, _ := tab.udp(lis, netip.MustParseAddrPort("192.0.2.3:5060")); f != nil {
		t.Fatal("a full table accepted a new source")
	}
	clock.advance(31 * time.Second) // the first flow is now past the idle timeout
	if f, _ := tab.udp(lis, netip.MustParseAddrPort("192.0.2.3:5060")); f == nil {
		t.Fatal("an expired flow was not swept to make room")
	}
	if tab.lookup(a.id) != nil {
		t.Fatal("the swept flow still resolves")
	}
}

func TestRemovedFlowIsUnknownAndRemovingTwiceIsHarmless(t *testing.T) {
	tab := testTable(1, &fakeNow{}, 10)
	f := tab.newFlow(TCP, &listener{name: "l"}, netip.MustParseAddrPort("192.0.2.1:1"))
	if !tab.addStream(f) || tab.openStreams() != 1 {
		t.Fatal("flow not added")
	}
	tab.remove(f)
	tab.remove(f)
	if tab.lookup(f.id) != nil || tab.openStreams() != 0 {
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
	if f, _ := tab.udp(lis, netip.MustParseAddrPort("192.0.2.1:1")); f != nil {
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
