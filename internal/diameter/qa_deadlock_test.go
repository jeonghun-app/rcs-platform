package diameter

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Regression test contributed by QA on PR #21.

func TestQABidirectionalLoadDoesNotDeadlockTwoHealthyNodes(t *testing.T) {
	const inflight, perSide = 4, 200
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = inflight })
	cfg := testConfig(newFakeClock(), scscfHost)
	cfg.MaxInFlight = inflight
	cfg.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return addrConn{Conn: ln.connect(t, "10.0.7.7:41000"), local: tcpAddr("10.0.7.7:41000"), remote: tcpAddr("10.0.0.1:3868")}, nil
	}
	scscf := newTestNode(t, cfg)
	slow := func(n *Node) HandlerFunc {
		return func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
			time.Sleep(time.Millisecond)
			return n.NewAnswer(req, ResultSuccess), nil
		}
	}
	hss.Handle(appCx, cmdTest, slow(hss))
	scscf.Handle(appCx, cmdTest, slow(scscf))
	toHSS, err := scscf.Connect(PeerConfig{Address: "hss:3868", Host: hssHost})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "open", func() bool { return toHSS.Available() && hss.Peer(scscfHost) != nil })
	toSCSCF := hss.Peer(scscfHost)
	var done atomic.Int32
	for i := 0; i < perSide; i++ {
		go func() {
			_, _ = toHSS.Send(context.Background(), scscf.NewRequest(cmdTest, appCx, scscf.NewSessionID("")))
			done.Add(1)
		}()
		go func() {
			_, _ = toSCSCF.Send(context.Background(), hss.NewRequest(cmdTest, appCx, hss.NewSessionID("")))
			done.Add(1)
		}()
	}
	deadline := time.Now().Add(realWait)
	for int(done.Load()) < 2*perSide {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d requests finished; the rest are stuck", done.Load(), 2*perSide)
		}
		time.Sleep(time.Millisecond)
	}
}
