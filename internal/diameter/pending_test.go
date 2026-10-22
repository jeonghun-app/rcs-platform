package diameter

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// warnings records the messages of the records it is given.
type warnings struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, r.Message)
	return nil
}
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

func (w *warnings) count(msg string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, m := range w.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

// pendingOf is how many connections from src are still in the
// capabilities exchange, and in all.
func pendingOf(n *Node, src string) (int, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.pendingFrom[netip.MustParseAddr(src)], n.exchanging
}

// TestAFloodingSourceDoesNotKeepAConfiguredPeerOut (#32): a host in the
// accepted network opens connection after connection and sends nothing.
// It fills its own share of the pending exchanges, not everyone's: a
// configured peer from another address still completes its exchange.
func TestAFloodingSourceDoesNotKeepAConfiguredPeerOut(t *testing.T) {
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxPendingConnections, c.MaxPendingPerSource = 8, 2 })
	for i := range 20 {
		newScript(t, ln.connect(t, fmt.Sprintf("10.0.9.9:%d", 41000+i)), scscfHost)
	}
	waitFor(t, "the flood's share taken", func() bool {
		from, _ := pendingOf(hss, "10.0.9.9")
		return from == 2
	})
	openScript(t, ln, scscfHost)
	if from, _ := pendingOf(hss, "10.0.9.9"); from > 2 {
		t.Errorf("%d of the flood's connections pending, want at most its share of 2", from)
	}
}

// TestAConnectionBeyondItsSourcesShareIsClosedAtOnce (#32): one address
// holds at most MaxPendingPerSource connections in the exchange; the next
// is closed as it is accepted, and its place comes back once one finishes.
func TestAConnectionBeyondItsSourcesShareIsClosedAtOnce(t *testing.T) {
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxPendingPerSource = 1 })
	first := newScript(t, ln.connect(t, "10.0.1.7:40000"), scscfHost)
	waitFor(t, "the first pending", func() bool {
		from, _ := pendingOf(hss, "10.0.1.7")
		return from == 1
	})
	newScript(t, ln.connect(t, "10.0.1.7:40001"), scscfHost).expectClosed()
	first.write(testCER(scscfHost, testRealm, cxVSA()))
	if rc, _ := first.read().ResultCode(); rc != ResultSuccess {
		t.Fatalf("CEA result %d", rc)
	}
	waitFor(t, "the source's place given back", func() bool {
		from, _ := pendingOf(hss, "10.0.1.7")
		return from == 0
	})
	s := newScript(t, ln.connect(t, "10.0.1.7:40002"), "scscf-2.rcs.test")
	s.write(testCER("scscf-2.rcs.test", testRealm, cxVSA()))
	if rc, _ := s.read().ResultCode(); rc != ResultSuccess {
		t.Fatalf("the source's next connection: CEA result %d", rc)
	}
}

// TestASourceNoRuleAllowsIsClosedBeforeItCounts (#32): every rule limits
// the source networks, and the connection comes from none of them: it is
// closed as it is accepted, with no exchange and no place counted.
func TestASourceNoRuleAllowsIsClosedBeforeItCounts(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	newScript(t, ln.connect(t, "192.0.2.50:5000"), scscfHost).expectClosed()
	if from, all := pendingOf(hss, "192.0.2.50"); from != 0 || all != 0 {
		t.Errorf("%d pending from the source, %d in all; want none", from, all)
	}
}

// TestClosedOutsidersAreLoggedOnceAMinute (#32): a peer outside the
// configured networks is no longer answered DIAMETER_UNKNOWN_PEER, so the
// close itself is logged, but a scan of many connections logs one line a
// minute, not one each.
func TestClosedOutsidersAreLoggedOnceAMinute(t *testing.T) {
	const msg = "diameter connection closed: source outside every accept rule's networks"
	w := &warnings{}
	_, ln, clock := startResponder(t, func(c *Config) { c.Logger = slog.New(w) })
	for i := range 5 {
		newScript(t, ln.connect(t, fmt.Sprintf("192.0.2.50:%d", 5000+i)), scscfHost).expectClosed()
	}
	if got := w.count(msg); got != 1 {
		t.Fatalf("%d warnings for five closed connections in the same minute, want 1", got)
	}
	clock.Advance(59 * time.Second)
	newScript(t, ln.connect(t, "192.0.2.50:5100"), scscfHost).expectClosed()
	if got := w.count(msg); got != 1 {
		t.Fatalf("%d warnings 59 s after the first, want still 1", got)
	}
	clock.Advance(time.Second)
	newScript(t, ln.connect(t, "192.0.2.50:5101"), scscfHost).expectClosed()
	if got := w.count(msg); got != 2 {
		t.Errorf("%d warnings a minute after the first, want 2", got)
	}
}
