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

// warnings records the records it is given: each message, with its
// remote and suppressed attributes.
type warnings struct {
	mu   sync.Mutex
	recs []warning
}

type warning struct {
	msg, remote string
	suppressed  int64
}

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	rec := warning{msg: r.Message}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "remote":
			rec.remote = a.Value.String()
		case "suppressed":
			rec.suppressed = a.Value.Int64()
		}
		return true
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recs = append(w.recs, rec)
	return nil
}
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

// of returns the records with message msg.
func (w *warnings) of(msg string) []warning {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []warning
	for _, r := range w.recs {
		if r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

func (w *warnings) count(msg string) int { return len(w.of(msg)) }

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
	// The second line counts the five closes the minute left out, so that
	// a misconfigured peer behind a scanner still shows (#615).
	if got := w.of(msg); len(got) != 2 || got[0].suppressed != 0 || got[1].suppressed != 5 {
		t.Errorf("warnings a minute after the first: %+v, want 2, the second with 5 suppressed", got)
	}
}

const (
	sourceRefused = "diameter connections refused: too many from one source have not completed CER"
	limitRefused  = "diameter connections refused: too many have not completed CER"
)

// fillAndRefuse has src take its one place among those exchanging, has a
// second connection from refused refused, and gives the place back by
// closing the first, as a host cycling its share does (#615).
func fillAndRefuse(t *testing.T, hss *Node, ln *pipeListener, src, refused string, port int) {
	t.Helper()
	first := ln.connect(t, fmt.Sprintf("%s:%d", src, port))
	waitFor(t, "the place taken", func() bool { _, all := pendingOf(hss, src); return all == 1 })
	newScript(t, ln.connect(t, fmt.Sprintf("%s:%d", refused, port+1)), scscfHost).expectClosed()
	_ = first.Close()
	waitFor(t, "the place given back", func() bool { _, all := pendingOf(hss, src); return all == 0 })
}

// TestEachSourceBeyondItsShareIsLoggedOnItsOwn (#615): two hosts each
// fill their share; each is named in a line of its own. A third that
// completes CER meanwhile does not have the first logged again.
func TestEachSourceBeyondItsShareIsLoggedOnItsOwn(t *testing.T) {
	w := &warnings{}
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxPendingPerSource, c.Logger = 1, slog.New(w) })
	a := ln.connect(t, "10.0.4.1:40000")
	b := ln.connect(t, "10.0.4.2:40000")
	waitFor(t, "both pending", func() bool { _, all := pendingOf(hss, "10.0.4.1"); return all == 2 })
	newScript(t, ln.connect(t, "10.0.4.1:40001"), scscfHost).expectClosed()
	newScript(t, ln.connect(t, "10.0.4.2:40001"), scscfHost).expectClosed()
	openScript(t, ln, scscfHost) // 10.0.1.5 completes its exchange
	newScript(t, ln.connect(t, "10.0.4.1:40002"), scscfHost).expectClosed()
	got := w.of(sourceRefused)
	if len(got) != 2 || got[0].remote != "10.0.4.1:40001" || got[1].remote != "10.0.4.2:40001" {
		t.Fatalf("warnings %+v, want one naming each source", got)
	}
	_, _ = a.Close(), b.Close()
}

// TestASourceCyclingItsShareLogsALineAMinute (#615): a host that fills
// its share, has one more refused and empties it again, fifty times in a
// minute, logs one line; the next refusal a minute on logs the second,
// with the 49 left out.
func TestASourceCyclingItsShareLogsALineAMinute(t *testing.T) {
	w := &warnings{}
	hss, ln, clock := startResponder(t, func(c *Config) { c.MaxPendingPerSource, c.Logger = 1, slog.New(w) })
	for i := range 50 {
		fillAndRefuse(t, hss, ln, "10.0.9.9", "10.0.9.9", 41000+2*i)
	}
	if got := w.count(sourceRefused); got != 1 {
		t.Fatalf("%d warnings for 50 refusals within a minute, want 1", got)
	}
	clock.Advance(refusalLogEvery)
	fillAndRefuse(t, hss, ln, "10.0.9.9", "10.0.9.9", 42000)
	if got := w.of(sourceRefused); len(got) != 2 || got[1].suppressed != 49 {
		t.Fatalf("warnings a minute on: %+v, want 2, the second with 49 suppressed", got)
	}
}

// TestRefusalsAtTheGlobalCapLogALineAMinute (#615): the same for the cap
// on all pending connections, which another host's connection fills and
// empties.
func TestRefusalsAtTheGlobalCapLogALineAMinute(t *testing.T) {
	w := &warnings{}
	hss, ln, clock := startResponder(t, func(c *Config) { c.MaxPendingConnections, c.Logger = 1, slog.New(w) })
	for i := range 20 {
		fillAndRefuse(t, hss, ln, "10.0.9.9", "10.0.9.8", 41000+2*i)
	}
	if got := w.count(limitRefused); got != 1 {
		t.Fatalf("%d warnings for 20 refusals within a minute, want 1", got)
	}
	clock.Advance(refusalLogEvery)
	fillAndRefuse(t, hss, ln, "10.0.9.9", "10.0.9.8", 42000)
	if got := w.of(limitRefused); len(got) != 2 || got[1].suppressed != 19 {
		t.Fatalf("warnings a minute on: %+v, want 2, the second with 19 suppressed", got)
	}
}

// TestSourceLogsStayBounded (#615): past maxSourceLogs sources refused
// within a minute, a new one shares one log with the others; once the
// minute has passed, the old logs make room for it.
func TestSourceLogsStayBounded(t *testing.T) {
	hss, _, clock := startResponder(t, nil)
	hss.mu.Lock()
	defer hss.mu.Unlock()
	for i := range maxSourceLogs {
		hss.sourceLogs.of(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), clock.Now()).note(clock.Now())
	}
	extra := netip.MustParseAddr("10.0.200.1")
	if l := hss.sourceLogs.of(extra, clock.Now()); l != &hss.sourceLogs.shared || len(hss.sourceLogs.by) != maxSourceLogs {
		t.Fatalf("source %d had a log of its own; %d kept", maxSourceLogs+1, len(hss.sourceLogs.by))
	}
	clock.Advance(refusalLogEvery)
	if l := hss.sourceLogs.of(extra, clock.Now()); l == &hss.sourceLogs.shared || len(hss.sourceLogs.by) != 1 {
		t.Fatalf("a minute on: shared %v, %d kept; want a log of its own, the old ones gone", l == &hss.sourceLogs.shared, len(hss.sourceLogs.by))
	}
}
