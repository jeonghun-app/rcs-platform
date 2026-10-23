package diameter

import (
	"context"
	"sync"
	"testing"
	"time"
)

// blockingHandler holds every request until release is closed.
func blockingHandler(n *Node, started chan<- *Message, release <-chan struct{}) HandlerFunc {
	return func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		started <- req
		<-release
		return n.NewAnswer(req, ResultSuccess), nil
	}
}

func TestShutdownAnswersRequestsInProgressBeforeSendingDPR(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	hss, ln, _ := startResponder(t, nil)
	hss.Handle(appCx, cmdTest, blockingHandler(hss, started, release))
	s := openScript(t, ln, scscfHost)
	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started

	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	waitFor(t, "shutdown to stop taking new work", func() bool {
		p := hss.Peer(scscfHost)
		return p != nil && !p.Available()
	})
	refused := s.roundTrip(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	if rc, _ := refused.ResultCode(); rc != ResultUnableToDeliver {
		t.Fatalf("new request during shutdown answered %d, want DIAMETER_UNABLE_TO_DELIVER", rc)
	}

	close(release)
	ans := s.read()
	if rc, _ := ans.ResultCode(); ans.IsRequest() || ans.HopByHop != first.HopByHop || rc != ResultSuccess {
		t.Fatalf("expected the answer to the request in progress, got %+v", ans)
	}
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected DPR after the answer, got %+v", dpr)
	}
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestShutdownGivesUpOnHandlersWhenItsContextEnds(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	defer close(release)
	hss, ln, _ := startResponder(t, nil)
	hss.Handle(appCx, cmdTest, blockingHandler(hss, started, release))
	s := openScript(t, ln, scscfHost)
	s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(ctx) }()
	waitFor(t, "shutdown to start", func() bool { return !hss.Peer(scscfHost).Available() })
	cancel()
	s.expectClosed()
	if err := <-errc; err == nil {
		t.Fatal("Shutdown reported success although a handler never finished")
	}
}

func TestDPRReceiverAnswersRequestsInProgressBeforeTheDPA(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	scscf, peer, dialer, _ := startInitiator(t, nil)
	scscf.Handle(appCx, cmdTest, blockingHandler(scscf, started, release))
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)

	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	close(release)
	if ans := s.read(); ans.HopByHop != first.HopByHop {
		t.Fatalf("expected the answer to the request in progress first, got command %d", ans.Code)
	}
	if dpa := s.read(); dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
}

// TestAPeerIsAvailableOnlyOnceItsConnectionRuns (#587): between the
// capabilities exchange and the start of run, the connection is not one a
// Shutdown sends a DPR on, so its peer is not reported available either:
// a caller that went by Available and stopped at once would close it
// without a goodbye.
func TestAPeerIsAvailableOnlyOnceItsConnectionRuns(t *testing.T) {
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hook := func(*conn) {
		once.Do(func() {
			close(reached)
			<-release
		})
	}
	testHookRun.Store(&hook)
	t.Cleanup(func() { testHookRun.Store(nil) })
	var released sync.Once
	t.Cleanup(func() { released.Do(func() { close(release) }) })
	_, peer, dialer, _ := startInitiator(t, nil)
	acceptCER(t, dialer.next(t))
	select {
	case <-reached:
	case <-time.After(realWait):
		t.Fatal("the connection never started to run")
	}
	if peer.Available() {
		t.Fatal("the peer is available before its connection runs")
	}
	released.Do(func() { close(release) })
	waitFor(t, "the peer available once its connection runs", peer.Available)
}
