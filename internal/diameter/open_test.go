package diameter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// openOf is how many inbound connections from src are open, and in all.
func openOf(n *Node, src string) (int, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.openFrom[netip.MustParseAddr(src)], n.inbound
}

// openFrom completes the capabilities exchange as host from remote.
func openFrom(t *testing.T, ln *pipeListener, remote, host string) *script {
	t.Helper()
	s := newScript(t, ln.connect(t, remote), host)
	s.write(testCER(host, testRealm, cxVSA()))
	if rc, _ := s.read().ResultCode(); rc != ResultSuccess {
		t.Fatalf("CEA result %d for %s from %s", rc, host, remote)
	}
	return s
}

// TestAHostOpeningPeerAfterPeerIsRefusedPastItsShare (#617): one address
// completes the exchange again and again, each time under another
// Origin-Host. Past its share of open connections the next is closed as
// it is accepted, logged once; a configured peer from another address
// still connects, and a closed connection gives its place back.
func TestAHostOpeningPeerAfterPeerIsRefusedPastItsShare(t *testing.T) {
	w := &warnings{}
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxConnectionsPerSource, c.Logger = 3, slog.New(w) })
	var held []*script
	for i := range 3 {
		held = append(held, openFrom(t, ln, fmt.Sprintf("10.0.9.9:%d", 41000+i), fmt.Sprintf("scscf-%d.rcs.test", 10+i)))
	}
	for i := range 2 {
		newScript(t, ln.connect(t, fmt.Sprintf("10.0.9.9:%d", 42000+i)), "scscf-20.rcs.test").expectClosed()
	}
	if from, _ := openOf(hss, "10.0.9.9"); from != 3 {
		t.Fatalf("%d open from the host, want its share of 3", from)
	}
	if got := w.of("diameter connections refused: too many open from one source"); len(got) != 1 || got[0].remote != "10.0.9.9:42000" {
		t.Fatalf("warnings %+v, want one naming the host", got)
	}
	openScript(t, ln, scscfHost)
	_ = held[0].nc.Close()
	waitFor(t, "the host's place given back", func() bool { from, _ := openOf(hss, "10.0.9.9"); return from == 2 })
	openFrom(t, ln, "10.0.9.9:43000", "scscf-30.rcs.test")
}

// TestOpenConnectionsAreBoundedInAll (#617): past MaxConnections open,
// from whatever addresses, the next is closed as it is accepted.
func TestOpenConnectionsAreBoundedInAll(t *testing.T) {
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxConnections = 2 })
	openFrom(t, ln, "10.0.2.1:40000", "scscf-1.rcs.test")
	openFrom(t, ln, "10.0.2.2:40000", "scscf-2.rcs.test")
	newScript(t, ln.connect(t, "10.0.2.3:40000"), "scscf-3.rcs.test").expectClosed()
	if _, all := openOf(hss, "10.0.2.3"); all != 2 {
		t.Fatalf("%d open in all, want 2", all)
	}
}

// flakyListener fails its first Accepts with err, then accepts from inner.
type flakyListener struct {
	*pipeListener
	err   error
	fails atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, l.err
	}
	return l.pipeListener.Accept()
}

// TestServeWaitsOutTemporaryAcceptErrors (#617): out of file descriptors,
// Accept fails for a while; Serve waits, 5 ms and then twice as long each
// time, and goes on accepting, rather than end the node's service.
func TestServeWaitsOutTemporaryAcceptErrors(t *testing.T) {
	clock := newFakeClock()
	cfg := testConfig(clock, hssHost)
	cfg.Accept = []PeerRule{{HostPattern: "scscf-*.rcs.test", Realm: testRealm}}
	n := newTestNode(t, cfg)
	ln := &flakyListener{pipeListener: newPipeListener(), err: &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}}
	ln.fails.Store(3)
	served := make(chan error, 1)
	go func() { served <- n.Serve(ln) }()
	t.Cleanup(func() {
		// Shut down first: a Serve waiting out an error waits on the
		// node's clock, which no one advances once the test has failed.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = n.Shutdown(ctx)
		_ = ln.Close()
		<-served
	})
	for _, d := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		clock.waitForTimer(t, d)
		clock.Advance(d)
	}
	openScript(t, ln.pipeListener, scscfHost)
}

// TestServeEndsOnAnAcceptErrorThatIsNotTemporary: any other error still
// ends Serve, as before.
func TestServeEndsOnAnAcceptErrorThatIsNotTemporary(t *testing.T) {
	cfg := testConfig(newFakeClock(), hssHost)
	n := newTestNode(t, cfg)
	broken := errors.New("listener broken")
	ln := &flakyListener{pipeListener: newPipeListener(), err: broken}
	ln.fails.Store(1)
	if err := n.Serve(ln); !errors.Is(err, broken) {
		t.Fatalf("Serve = %v, want the listener's error", err)
	}
}
