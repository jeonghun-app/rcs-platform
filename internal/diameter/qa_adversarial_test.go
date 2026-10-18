package diameter

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Regression tests contributed by QA on PR #21.

func pendingCount(p *Peer) int {
	c := p.current()
	if c == nil {
		return -1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func TestQASendEndsAfterTheRequestTimeoutWhenTheWriteQueueIsFull(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, func(c *Config) { c.MaxInFlight = 1 })
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	// The script never reads again.
	const sends = 3
	errc := make(chan error, sends)
	for i := 0; i < sends; i++ {
		go func() {
			_, err := peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID("")))
			errc <- err
		}()
	}
	waitFor(t, "three pending requests", func() bool { return pendingCount(peer) == sends })
	clock.Advance(testRequestWait)
	for i := 0; i < sends; i++ {
		select {
		case err := <-errc:
			if !errors.Is(err, ErrTimeout) {
				t.Errorf("send %d: err = %v, want ErrTimeout", i, err)
			}
		case <-time.After(realWait):
			t.Fatalf("only %d of %d Sends returned after RequestTimeout", i, sends)
		}
	}
}

func TestQAWatchdogClosesAPeerThatStoppedReadingUnderLoad(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, func(c *Config) { c.MaxInFlight = 1 })
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	for i := 0; i < 2; i++ { // one in the blocked writer, one in the queue
		go func() { _, _ = peer.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID(""))) }()
	}
	waitFor(t, "two pending requests", func() bool { return pendingCount(peer) == 2 })
	for i := 0; i < 4; i++ {
		clock.Advance(testWatchdog)
		time.Sleep(50 * time.Millisecond)
	}
	deadline := time.Now().Add(realWait)
	for peer.Available() || n.Peer(hssHost) != nil {
		if time.Now().After(deadline) {
			t.Fatalf("after 4 x Tw of silence the peer is still open (available=%v)", peer.Available())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestQAShutdownDuringReopenClosesOnTheDPA(t *testing.T) {
	n, peer, dialer, clock := startInitiator(t, nil)
	first := dialer.next(t)
	acceptCER(t, first)
	waitFor(t, "the first connection to open", peer.Available)
	_ = first.nc.Close()
	clock.waitForTimer(t, n.backoff(0))
	clock.Advance(n.backoff(0))
	s := dialer.next(t)
	acceptCER(t, s)
	s.expectDWR() // REOPEN, left unanswered
	errc := make(chan error, 1)
	go func() { errc <- n.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected DPR, got %+v", dpr)
	}
	s.write(s.answer(dpr, ResultSuccess))
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	case <-time.After(realWait):
		t.Fatal("Shutdown did not return after the DPA")
	}
}
