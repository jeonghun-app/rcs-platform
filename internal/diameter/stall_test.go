package diameter

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
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

// Two healthy nodes over real TCP with default settings send each other
// large requests as fast as they can. Each side's writer depends on the
// other side's read loop, so a read loop that waits for its own writer
// deadlocks both.
func TestBidirectionalLoadOverLoopbackTCPCompletes(t *testing.T) {
	const perSide, size = 2000, 32 << 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	quiet := slog.New(slog.DiscardHandler)
	apps := []Application{{ID: appCx, VendorID: vendor3GPP}}
	// Generous timeouts: the test is about progress, and the race detector
	// slows the copying a great deal.
	hss, err := NewNode(Config{OriginHost: hssHost, OriginRealm: testRealm, Logger: quiet, Applications: apps,
		RequestTimeout: time.Minute,
		Accept:         []PeerRule{{HostPattern: "scscf-*.rcs.test", Networks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}})
	if err != nil {
		t.Fatal(err)
	}
	scscf, err := NewNode(Config{OriginHost: scscfHost, OriginRealm: testRealm, Logger: quiet, Applications: apps,
		RequestTimeout: time.Minute})
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
	go func() { _ = hss.Serve(ln) }()
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
	select {
	case <-finished:
	case <-time.After(2 * time.Minute):
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("requests stuck: outcomes so far %v of %d", outcomes, 2*perSide)
	}
	if outcomes["answered"] != 2*perSide {
		t.Fatalf("outcomes %v, want all %d answered", outcomes, 2*perSide)
	}
}
