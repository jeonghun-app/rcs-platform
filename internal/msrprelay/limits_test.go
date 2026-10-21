package msrprelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// guess is a session id in the form the relay issues, naming no binding.
func guess(i int) string {
	return strings.Repeat("b", issuedSessionIDLen-1) + string(rune('a'+i))
}

func guessPath(i int) string {
	return "msrps://" + publicHost + ":2856/" + guess(i) + ";tcp"
}

func TestSessionIDsTheRelayCannotHaveIssuedCostNoLookup(t *testing.T) {
	f := &flakyStore{}
	r := newRig(t, 1, wrapStore(f))
	for _, sid := range []string{
		"short",
		strings.Repeat("A", issuedSessionIDLen), // upper case
		strings.Repeat("1", issuedSessionIDLen), // outside base32
		strings.Repeat("b", issuedSessionIDLen+1),
	} {
		if _, err := r.dial(0, nil).open(t, "msrps://"+publicHost+":2856/"+sid+";tcp", newRecorder()); statusOf(err) != msrp.StatusNoSession {
			t.Fatalf("Open %s = %v, want 481", sid, err)
		}
	}
	if n := f.gets.Load(); n != 0 {
		t.Fatalf("%d store reads for session ids nobody issued", n)
	}
	if _, err := r.dial(0, nil).open(t, guessPath(0), newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
	if n := f.gets.Load(); n != 1 {
		t.Fatalf("%d store reads for a well-formed unknown id, want 1", n)
	}
}

func TestFloodingSourceDoesNotBlockAnotherSourcesBind(t *testing.T) {
	// One source guesses session ids, reconnecting whenever internal/msrp
	// closes its connection for too many unknown sessions. The budget
	// outlives the connections, so after three failed lookups it costs no
	// further store reads, while another source binds as usual.
	f := &flakyStore{}
	r := newRig(t, 1, withProxyProtocol, wrapStore(f), func(o *relayOptions) {
		o.FailedLookupsPerSource = 3
		o.Edge.MaxFailedBinds = 1
	})
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asflood")}})
	r.as.session(t, "asflood", b.coreLocal, newRecorder())

	for i := range 3 {
		c := r.dial(0, proxyFrom("192.0.2.66:4000"+string(rune('0'+i))))
		if _, err := c.open(t, guessPath(i), newRecorder()); statusOf(err) != msrp.StatusNoSession {
			t.Fatalf("guess %d = %v, want 481", i, err)
		}
	}
	if n := f.gets.Load(); n != 3 {
		t.Fatalf("%d store reads, want 3", n)
	}
	flood := r.dial(0, proxyFrom("192.0.2.66:40009"))
	if _, err := flood.open(t, guessPath(9), newRecorder()); !closedNotRefused(err) {
		t.Fatalf("guess over the budget = %v, want the connection closed", err)
	}
	if n := f.gets.Load(); n != 3 {
		t.Fatalf("a guess over the budget reached the store (%d reads)", n)
	}
	if got := r.metrics.count(mRefusedPrefix + reasonSourceBudget); got != 1 {
		t.Fatalf("Refused.SourceLookupBudget = %d", got)
	}

	if _, err := r.dial(0, proxyFrom("192.0.2.77:40000")).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatalf("another source's bind = %v", err)
	}
	// The flooding source earns a lookup back at the budget's rate.
	r.clock.Advance(20 * time.Second)
	if _, err := r.dial(0, proxyFrom("192.0.2.66:40010")).open(t, guessPath(10), newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("guess after a refill = %v, want 481", err)
	}
}

func TestLookupBudgetRefillsAndForgetsFullSources(t *testing.T) {
	clock := newFakeClock()
	l := newLookupBudget(clock, 2)
	a := sourceKey(netip.MustParseAddr("192.0.2.1"))
	for i := range 2 {
		if ok, tracked := l.take(a); !ok || !tracked {
			t.Fatalf("take %d = %v, %v", i, ok, tracked)
		}
	}
	if ok, _ := l.take(a); ok {
		t.Fatal("took a third token from a bucket of two")
	}
	// A refund is for a lookup that found its binding; it never overfills.
	l.refund(a)
	if ok, _ := l.take(a); !ok {
		t.Fatal("the refunded token was not there")
	}
	clock.Advance(30 * time.Second)
	if ok, _ := l.take(a); !ok {
		t.Fatal("no token after half a minute at two a minute")
	}
	// Refunds of lookups that found their binding leave nothing behind.
	b := sourceKey(netip.MustParseAddr("192.0.2.2"))
	l.take(b)
	l.refund(b)
	l.refund(sourceKey(netip.MustParseAddr("192.0.2.3")))
	if l.size() != 1 {
		t.Fatalf("%d sources remembered, want only the one short of tokens", l.size())
	}
}

func TestLookupBudgetTableIsBounded(t *testing.T) {
	clock := newFakeClock()
	l := newLookupBudget(clock, 1)
	for i := range maxBudgetSources {
		l.take(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	extra := sourceKey(netip.MustParseAddr("192.0.2.1"))
	if ok, tracked := l.take(extra); !ok || tracked {
		t.Fatalf("take with a full table = %v, %v; want let through untracked", ok, tracked)
	}
	// Once the buckets have refilled, a sweep makes room.
	clock.Advance(time.Minute)
	if ok, tracked := l.take(extra); !ok || !tracked {
		t.Fatalf("take after the refill = %v, %v", ok, tracked)
	}
	if l.size() != 1 {
		t.Fatalf("%d sources remembered after the sweep", l.size())
	}
}

func TestRebindOnTheConnectionWhoseBridgeEndedIsAQuiet481(t *testing.T) {
	// The bridge ends from the core side (an rcs-as task replaced); the
	// client, which cannot know, sends on the same connection again. That
	// is not a second connection and must not look like one.
	r := newRig(t, 1)
	_, client, clientH, _, _ := r.bridged(0, 600)
	core := <-r.as.conns
	_ = core.Close()
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
	send(t, client, "after the core went")
	select {
	case rep := <-clientH.reports:
		if rep.Code != msrp.StatusNoSession {
			t.Fatalf("report %+v, want 481", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failure report")
	}
	if r.metrics.count(mRefusedPrefix+reasonClaimed) != 0 || r.metrics.count(mRefusedPrefix+reasonEndedSession) != 1 {
		t.Fatalf("AlreadyClaimed %d, EndedSession %d", r.metrics.count(mRefusedPrefix+reasonClaimed), r.metrics.count(mRefusedPrefix+reasonEndedSession))
	}
	if strings.Contains(r.logText(), "refused a second connection") {
		t.Fatal("a rebind on the claiming connection was logged as a second connection")
	}
}

func TestFailedBindOnAConnectionWithBridgesRefusesOnlyTheNewSession(t *testing.T) {
	// A client may reuse one connection for several sessions (RFC 4975
	// §5.4). A store failure binding the second must not end the first.
	f := &flakyStore{}
	r := newRig(t, 1, wrapStore(f))
	first := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asreuse1")}})
	asH := newRecorder()
	r.as.session(t, "asreuse1", first.coreLocal, asH)
	second := r.allocate(map[string]any{"client_endpoint_path": []string{"msrp://client.invalid:7777/sec0ndse55ion;tcp"}, "core_path": []string{r.as.uri("asreuse2")}})
	c := r.dial(0, nil)
	a, err := c.open(t, first.clientPath, newRecorder())
	if err != nil {
		t.Fatal(err)
	}
	f.failGets(1)
	if _, err := c.openAs(t, "msrp://client.invalid:7777/sec0ndse55ion;tcp", second.clientPath, newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("second Open = %v, want 481 on the shared connection", err)
	}
	select {
	case <-c.conn.Done():
		t.Fatal("the connection, and the bridge on it, was closed")
	default:
	}
	send(t, a, "first survives")
	if m := asH.message(t); string(m.Body) != "first survives" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
}

func TestUnreachableCoreDoesNotHoldABindSlot(t *testing.T) {
	// An rcs-as that accepts and never answers keeps a bind connecting for
	// RELAY_CORE_CONNECT_TIMEOUT; with the one slot released before that,
	// other binds go on meanwhile.
	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hang.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		if nc, err := hang.Accept(); err == nil {
			accepted <- nc
		}
	}()
	r := newRig(t, 1, extraCorePorts{netip.MustParseAddrPort(hang.Addr().String()).Port()}, func(o *relayOptions) {
		o.MaxConcurrentBinds = 1
		o.CoreConnectTimeout = time.Minute
	})
	stuck := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{"msrp://" + hang.Addr().String() + "/hung;tcp"}})
	good := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asfine")}})
	r.as.session(t, "asfine", good.coreLocal, newRecorder())
	stuckDone := make(chan error, 1)
	go func() {
		_, err := r.dial(0, nil).open(t, stuck.clientPath, newRecorder())
		stuckDone <- err
	}()
	var nc net.Conn
	select {
	case nc = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not connect to the hanging rcs-as")
	}
	if _, err := r.dial(0, nil).open(t, good.clientPath, newRecorder()); err != nil {
		t.Fatalf("a bind while another waits on its core = %v", err)
	}
	_ = nc.Close()
	if err := <-stuckDone; statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("the stuck bind = %v, want 481", err)
	}
}

func TestTrafficTowardTheClientKeepsItsConnectionOpen(t *testing.T) {
	// rcs-as sends with Failure-Report no or partial, which the client does
	// not answer (RFC 4975 §7.1.2): the client sends nothing at all, and
	// still must not be cut while messages flow to it. The idle timeout is
	// real time, so it is shortened here. "yes" is the control case: the client
	// answers every chunk.
	//
	// The test waits on progress (#124): the test sends the next message
	// only once the last one arrived, and the relay writes one message at a
	// time and resets its idle deadline once each write returns. So a relay
	// that cuts correctly, after the idle timeout without a reset, leaves
	// three consecutive gaps between deliveries that add up to the idle
	// timeout or more: the reset after a delivery may come as late as the
	// next delivery (review of #128, #150). A cut while every gap of the
	// attempt stayed under a third of the idle timeout is the relay's fault;
	// otherwise the host may have stalled (the deadline can even fire after
	// the next message was written), the attempt is inconclusive, and the
	// test starts over on a new connection, up to maxAttempts.
	const maxAttempts = 5
	for _, tt := range []struct {
		name string
		mode msrp.ReportMode
	}{{"no", msrp.ReportNo}, {"partial", msrp.ReportPartial}, {"yes", msrp.ReportYes}} {
		t.Run("Failure-Report "+tt.name, func(t *testing.T) {
			delivered := 0
			for attempt := 1; ; attempt++ {
				ok, n := trafficKeepsTheClientConnected(t, tt.name, tt.mode, -1)
				if ok {
					return
				}
				delivered += n
				if attempt == maxAttempts {
					// A loaded host delays messages; it does not lose
					// every one of them.
					if delivered == 0 {
						t.Fatalf("no message reached the client in %d attempts", maxAttempts)
					}
					t.Skipf("traffic was held up for a third of the idle timeout or longer in all %d attempts: the host is too loaded for real-time deadlines", maxAttempts)
				}
			}
		})
	}
}

// A stall of the test itself, after a message is sent and before it is
// read, lets the relay close the quiet connection correctly; the attempt
// must come out inconclusive, not as a relay fault (review of #128). The
// stall waits for the cut and then reads the message, so the attempt takes
// the same path every time: a delivery after the stall, then the cut seen
// soon after it.
func TestAStallOfTheTestIsNotTakenForARelayFault(t *testing.T) {
	for _, stallAt := range []int{0, 3} {
		if ok, _ := trafficKeepsTheClientConnected(t, "stall", msrp.ReportNo, stallAt); ok {
			t.Fatalf("stall after message %d: the attempt passed, so the stall did not happen", stallAt)
		}
	}
}

// trafficKeepsTheClientConnected runs one attempt of the test above on a new
// relay and connection: messages toward a client that sends nothing keep it
// connected for three idle timeouts, and once nothing flows the idle
// timeout closes it. It fails the test if the client is cut while traffic
// flows, and returns false, inconclusive, if a stall of the host stopped
// the traffic first. With stallAt >= 0, the test stalls for longer than the
// idle timeout after sending message stallAt, as a loaded host can, and
// until the relay has cut the client.
func trafficKeepsTheClientConnected(t *testing.T, name string, mode msrp.ReportMode, stallAt int) (bool, int) {
	t.Helper()
	idle := time.Second
	r := newRig(t, 1, func(o *relayOptions) { o.IdleTimeout = idle })
	sid := "asquiet" + name
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri(sid)}})
	as := r.as.session(t, sid, b.coreLocal, newRecorder())
	clientH := newRecorder()
	// last is the latest delivery (at first, before the bind), worst the
	// longest gap between two deliveries so far.
	last := time.Now()
	var worst time.Duration
	delivered := 0
	gap := func() {
		now := time.Now()
		worst = max(worst, now.Sub(last))
		last = now
	}
	c := r.dial(0, nil)
	if _, err := c.open(t, b.clientPath, clientH); err != nil {
		t.Fatal(err)
	}
	// cut reports a cut seen at this moment: the relay's fault if every gap
	// between deliveries, this last one included, stayed under a third of
	// the idle timeout, a stall of the host otherwise.
	cut := func() (bool, int) {
		gap()
		if worst >= idle/3 {
			t.Logf("traffic was held up for %v, a third of the %v idle timeout or more; starting over", worst, idle)
			return false, delivered
		}
		t.Fatalf("the client was cut although the longest gap between deliveries was %v, under a third of the %v idle timeout", worst, idle)
		return false, delivered
	}
	// Traffic goes out every idle/10.
	deadline := time.Now().Add(3 * idle)
	for i := 0; time.Now().Before(deadline); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := as.Send(ctx, msrp.Outgoing{ContentType: "text/plain", Body: []byte("to a quiet client"), FailureReport: mode})
		cancel()
		if err != nil {
			select {
			case <-c.conn.Done():
				return cut()
			default:
			}
			t.Fatalf("Send = %v", err)
		}
		if i == stallAt {
			time.Sleep(idle + idle/5)
			// The relay wrote the message before it cut the client: read
			// it only once the cut is seen, so that a select choosing
			// between the two does not decide what the attempt checks.
			waitDone(t, c.conn.Done(), "the quiet connection after the stall")
			select {
			case <-clientH.msgs:
			default:
				// It was dropped with the session before the handler ran.
				return cut()
			}
			delivered++
			gap()
			continue
		}
		select {
		case m := <-clientH.msgs:
			if string(m.Body) != "to a quiet client" {
				t.Fatalf("client got %q", m.Body)
			}
		case <-c.conn.Done():
			return cut()
		case <-time.After(5 * time.Second):
			t.Fatal("no message arrived")
		}
		delivered++
		gap()
		time.Sleep(idle / 10)
	}
	select {
	case <-c.conn.Done():
		return cut()
	default:
	}
	// Once nothing flows either way, the idle timeout applies.
	waitDone(t, c.conn.Done(), "the idle connection")
	eventually(t, "the idle close to be counted", func() bool { return r.metrics.count(mIdleClosed) == 1 })
	return true, delivered
}

func TestConnectionWhoseLastBridgeEndedStaysForTheIdleTimeout(t *testing.T) {
	// The bridge ends from the core side; the client may reuse its
	// connection for its next session, so the connection is kept like any
	// quiet one, not cut by the first-bind timeout. The session itself is
	// answered 481.
	r := newRig(t, 1)
	_, client, clientH, _, _ := r.bridged(0, 600)
	_ = (<-r.as.conns).Close()
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
	r.clock.Advance(msrp.DefaultUnboundTimeout + time.Second)
	send(t, client, "still connected")
	select {
	case rep := <-clientH.reports:
		if rep.Code != msrp.StatusNoSession {
			t.Fatalf("report %+v, want 481", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failure report")
	}
	if r.metrics.count(mUnboundClosed) != 0 {
		t.Fatal("a connection that had carried a bridge was closed as never bound")
	}
	// The rig's idle timeout is a minute; internal/msrp's unbound timer
	// follows it.
	r.clock.Advance(time.Minute)
	eventually(t, "the connection to close", func() bool { return r.metrics.conns.Load() == 0 })
}

func TestConnectionThatNeverNamesASessionIsClosed(t *testing.T) {
	// A raw socket, not an msrp.Conn: a test client's own unbound timer
	// runs on the same fake clock and could close the connection first,
	// which is not what is under test.
	r := newRig(t, 1)
	nc, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	eventually(t, "the connection to be admitted", func() bool { return r.metrics.conns.Load() == 1 })
	r.clock.Advance(msrp.DefaultUnboundTimeout)
	_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := nc.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("read %v, want the relay to close the connection", err)
	}
	eventually(t, "the relay-side close to be counted", func() bool {
		return r.metrics.count(mUnboundClosed) == 1 && r.metrics.conns.Load() == 0
	})
}

func TestBindSlotsAreReturnedOnEveryRefusalPath(t *testing.T) {
	// With a single slot, a leak on any path would refuse every later bind.
	failing := &flakyStore{}
	r := newRig(t, 1, wrapStore(failing), func(o *relayOptions) { o.MaxConcurrentBinds = 1; o.PathWait = time.Nanosecond })
	for i := range 5 {
		if _, err := r.dial(0, nil).open(t, guessPath(i), newRecorder()); statusOf(err) != msrp.StatusNoSession {
			t.Fatalf("unknown %d = %v", i, err)
		}
	}
	inc := r.allocate(map[string]any{"core_path": []string{r.as.uri("asinc")}})
	done := make(chan error, 1)
	go func() { _, err := r.dial(0, nil).open(t, inc.clientPath, newRecorder()); done <- err }()
	r.clock.waitTimer(t, time.Nanosecond)
	r.clock.Advance(time.Nanosecond)
	if err := <-done; statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("incomplete = %v", err)
	}
	failing.failGets(1)
	if _, err := r.dial(0, nil).open(t, inc.clientPath, newRecorder()); !closedNotRefused(err) {
		t.Fatalf("store failure = %v", err)
	}
	b, _, _, _, _ := r.bridged(0, 60)
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); statusOf(err) != msrp.StatusForbidden {
		t.Fatalf("second claim = %v", err)
	}
	b2 := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}})
	r.as.session(t, "asafter", b2.coreLocal, newRecorder())
	r.patch(b2.id, map[string]any{"core_path": []string{r.as.uri("asafter")}})
	if _, err := r.dial(0, nil).open(t, b2.clientPath, newRecorder()); err != nil {
		t.Fatalf("bind after refusals = %v (slot leaked?)", err)
	}
}

func TestPerSourceSlotIsReturnedWhenTheConnectionCloses(t *testing.T) {
	r := newRig(t, 1, withProxyProtocol, func(o *relayOptions) { o.MaxConnectionsPerSource = 1 })
	for i := range 5 {
		sid := "asps" + string(rune('a'+i))
		b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri(sid)}})
		r.as.session(t, sid, b.coreLocal, newRecorder())
		c := r.dial(0, proxyFrom("192.0.2.10:40000"))
		if _, err := c.open(t, b.clientPath, newRecorder()); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		_ = c.conn.Close()
		eventually(t, "the source to be released", func() bool {
			r.relays[0].mu.Lock()
			defer r.relays[0].mu.Unlock()
			return len(r.relays[0].sources) == 0
		})
	}
}

func TestStalledProxyHeaderIsClosed(t *testing.T) {
	const timeout = 50 * time.Millisecond
	r := newRig(t, 1, withProxyProtocol, func(o *relayOptions) { o.ProxyHeaderTimeout = timeout })
	// The test is of a connection that sent part of a header and stalled,
	// so the octets must reach the relay before its wait ends. The wait
	// starts after the accept, which comes after the dial starts: a write
	// done within the timeout of the dial's start was in time. On a loaded
	// host one that was not tests a connection that sent nothing; it is
	// tried again, a bounded number of times (code review on #300).
	const attempts = 10
	for i := 1; ; i++ {
		start := time.Now()
		nc, err := net.Dial("tcp", r.addrs[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nc.Write([]byte("\r\n\r\n\x00")); err != nil {
			t.Fatal(err)
		}
		inTime := time.Since(start) < timeout
		// The relay closes the connection either way: with a FIN, read
		// here as EOF, once it has read the five octets; with a RST when
		// its wait ran out before it read them, as on a loaded host, since
		// a socket closed with octets it has not read is reset (RFC 1122
		// §4.2.2.13; #295). A read that times out is the relay not closing.
		_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = nc.Read(make([]byte, 1))
		_ = nc.Close()
		if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("stalled header: read %v, want the relay to close", err)
		}
		// Each attempt is refused, in time or not.
		eventually(t, "the refusal to be counted", func() bool { return r.metrics.count(mRefusedPrefix+reasonProxyHeader) == int64(i) })
		if inTime {
			return
		}
		if i == attempts {
			t.Fatalf("no attempt in %d wrote its octets within %v of the dial", attempts, timeout)
		}
	}
}

func TestDrainClosesRemainingConnectionsOneByOne(t *testing.T) {
	r := newRig(t, 1)
	var clients []*client
	for i, sid := range []string{"asdrain1", "asdrain2"} {
		local := "msrp://client.invalid:7777/dra1nclient" + string(rune('a'+i)) + ";tcp"
		b := r.allocate(map[string]any{"client_endpoint_path": []string{local}, "core_path": []string{r.as.uri(sid)}})
		r.as.session(t, sid, b.coreLocal, newRecorder())
		c := r.dial(0, nil)
		if _, err := c.openAs(t, local, b.clientPath, newRecorder()); err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	closed := func() int {
		n := 0
		for _, c := range clients {
			select {
			case <-c.conn.Done():
				n++
			default:
			}
		}
		return n
	}
	drained := make(chan struct{})
	go func() {
		r.relays[0].Drain(context.Background(), 10*time.Second)
		close(drained)
	}()
	r.clock.waitTimer(t, 5*time.Second)
	if closed() != 0 {
		t.Fatal("a connection was closed in the first half of the drain")
	}
	r.clock.Advance(5 * time.Second)
	// One now, the next one step later: two connections over five seconds.
	r.clock.waitTimer(t, 2500*time.Millisecond)
	eventually(t, "the first close", func() bool { return closed() == 1 })
	r.clock.Advance(2500 * time.Millisecond)
	eventually(t, "the second close", func() bool { return closed() == 2 })
	waitDone(t, drained, "Drain")
}

func TestConnectionAcceptedAsTheDrainBeginsIsCountedApart(t *testing.T) {
	r := newRig(t, 1)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	r.relays[0].mu.Lock()
	r.relays[0].draining = true
	r.relays[0].mu.Unlock()
	if reason := r.relays[0].admit(a); reason != reasonDraining {
		t.Fatalf("admit while draining = %q, want %q", reason, reasonDraining)
	}
}

func TestBindCutShortByShutdownIsNotAStoreError(t *testing.T) {
	r := newRig(t, 1)
	b := r.allocate(map[string]any{"core_path": []string{r.as.uri("ascut")}})
	opened := make(chan error, 1)
	go func() {
		_, err := r.dial(0, nil).open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	r.clock.waitTimer(t, 25*time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); r.relays[0].Close() }()
	if err := <-opened; err == nil {
		t.Fatal("the bind succeeded on a closing relay")
	}
	wg.Wait()
	if r.metrics.count(mRefusedPrefix+reasonDraining) != 1 || r.metrics.count(mStoreErrors) != 0 {
		t.Fatalf("Refused.Draining %d, StoreErrors %d", r.metrics.count(mRefusedPrefix+reasonDraining), r.metrics.count(mStoreErrors))
	}
	if strings.Contains(r.logText(), "binding lookup failed") {
		t.Fatal("a shutdown was logged as a store failure")
	}
}
