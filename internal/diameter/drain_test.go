package diameter

import (
	"context"
	"testing"
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
