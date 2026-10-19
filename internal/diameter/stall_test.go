package diameter

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWriteStalledPastTheWriteTimeoutClosesTheConnection(t *testing.T) {
	// WriteTimeout is a socket deadline on the wall clock; 1 ms keeps the
	// test fast. The script never reads after the CEA.
	n, peer, dialer, _ := startInitiator(t, func(c *Config) { c.WriteTimeout = time.Millisecond })
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	_, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
	if !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("err = %v, want ErrConnectionClosed", err)
	}
}

func TestPeerThatSendsRequestsButNeverReadsAnswersIsDisconnected(t *testing.T) {
	// A small message limit makes the control queue small enough to fill.
	_, ln, _ := startResponder(t, func(c *Config) { c.Limits.MaxMessageSize = 1024 })
	s := openScript(t, ln, scscfHost)
	// Requests for a command nobody handles are answered by the read loop.
	// The script only writes; the node must close instead of blocking.
	req := &Message{Flags: FlagRequest, Code: cmdTest + 50, ApplicationID: appCx, AVPs: s.origin()}
	b, _ := req.Encode()
	for i := 0; ; i++ {
		_ = s.nc.SetWriteDeadline(time.Now().Add(realWait))
		if _, err := s.nc.Write(b); err != nil {
			break
		}
		if i > 100000 {
			t.Fatal("the node kept reading without ever answering or closing")
		}
	}
}

// countingConn counts the bytes read from a connection, which is the
// progress of the load test: while bytes move, nothing is deadlocked.
type countingConn struct {
	net.Conn
	read *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

type countingListener struct {
	net.Listener
	read *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return countingConn{c, l.read}, nil
}

// loadStall is how long the load test lets the connection carry no bytes
// before it calls the nodes deadlocked: far longer than any pause a loaded
// host or the race detector causes, and far shorter than the test timeout.
const loadStall = 30 * time.Second

// Two healthy nodes over real TCP with default settings send each other
// large requests as fast as they can. Each side's writer depends on the
// other side's read loop, so a read loop that waits for its own writer
// deadlocks both.
//
// The test waits on progress, the bytes either node reads, not on a time
// (#113). Each node admits MaxInFlight of the other's requests to its
// handler and answers the rest DIAMETER_TOO_BUSY at once, and an admitted
// request's answer queues behind the node's own backlog of requests, about
// 64 MB here: the admitted requests are answered only once both backlogs
// have been written. On a loaded CI runner that took over the minute the
// test once gave as RequestTimeout, and the 256 admitted requests of one
// side timed out together (answered 3744, error 256). RequestTimeout is now
// beyond the test's own timeout, so only a stall fails the test.
func TestBidirectionalLoadOverLoopbackTCPCompletes(t *testing.T) {
	const perSide, size = 2000, 32 << 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	var read atomic.Int64
	quiet := slog.New(slog.DiscardHandler)
	apps := []Application{{ID: appCx, VendorID: vendor3GPP}}
	hss, err := NewNode(Config{OriginHost: hssHost, OriginRealm: testRealm, Logger: quiet, Applications: apps,
		RequestTimeout: time.Hour,
		Accept:         []PeerRule{{HostPattern: "scscf-*.rcs.test", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}})
	if err != nil {
		t.Fatal(err)
	}
	scscf, err := NewNode(Config{OriginHost: scscfHost, OriginRealm: testRealm, Logger: quiet, Applications: apps,
		RequestTimeout: time.Hour,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return countingConn{c, &read}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = scscf.Shutdown(ctx)
		_ = hss.Shutdown(ctx)
	})
	for _, n := range []*Node{hss, scscf} {
		n.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
			return n.NewAnswer(req, ResultSuccess), nil
		})
	}
	go func() { _ = hss.Serve(countingListener{ln, &read}) }()
	toHSS, err := scscf.Connect(PeerConfig{Address: ln.Addr().String(), Host: hssHost})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the connection to open", func() bool { return toHSS.Available() && hss.Peer(scscfHost) != nil })
	toSCSCF := hss.Peer(scscfHost)

	payload := NewAVP(9999, 0, 0, make([]byte, size))
	var wg sync.WaitGroup
	var mu sync.Mutex
	outcomes := map[string]int{}
	send := func(from *Node, to *Peer) {
		defer wg.Done()
		ans, err := to.Send(context.Background(), from.NewRequest(cmdTest, appCx, from.NewSessionID(""), payload))
		key := "error"
		if err == nil {
			if rc, _ := ans.ResultCode(); rc == ResultSuccess || rc == ResultTooBusy {
				key = "answered"
			}
		}
		mu.Lock()
		outcomes[key]++
		mu.Unlock()
	}
	for range perSide {
		wg.Add(2)
		go send(scscf, toHSS)
		go send(hss, toSCSCF)
	}
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last, lastMoved := read.Load(), time.Now()
	for done := false; !done; {
		select {
		case <-finished:
			done = true
		case <-tick.C:
			if now := read.Load(); now != last {
				last, lastMoved = now, time.Now()
			} else if time.Since(lastMoved) > loadStall {
				mu.Lock()
				defer mu.Unlock()
				t.Fatalf("no byte moved for %v after %d bytes: outcomes so far %v of %d", loadStall, now, outcomes, 2*perSide)
			}
		}
	}
	if outcomes["answered"] != 2*perSide {
		t.Fatalf("outcomes %v, want all %d answered", outcomes, 2*perSide)
	}
}
