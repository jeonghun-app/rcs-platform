package diameter

import (
	"context"
	"testing"
	"time"
)

// backlog is a node's own requests to a peer, waiting for its writer:
// the script reads nothing, so the writer is held on the first and the rest
// fill the main queue and wait for room in it.
const backlog = 4 * testInFlight

// testInFlight keeps the main queue short, so that a backlog several times
// its size is cheap.
const testInFlight = 4

// sendBacklog starts backlog requests from n to p and waits until every one
// is pending on the connection.
func sendBacklog(t *testing.T, n *Node, p *Peer) *conn {
	t.Helper()
	c := p.current()
	if c == nil {
		t.Fatal("no connection to the peer")
	}
	for range backlog {
		go func() { _, _ = p.Send(context.Background(), n.NewRequest(cmdTest, appCx, n.NewSessionID(""))) }()
	}
	waitFor(t, "the backlog to be pending", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.pending) >= backlog
	})
	return c
}

// waitForAnswersQueued waits until no handler is running on c, each having
// queued its answer, for realWait at most, and reports whether they did. A
// handler held behind the node's own requests never gets there, and the
// count of what is written before its answer then says why.
func waitForAnswersQueued(c *conn) bool {
	deadline := time.Now().Add(realWait)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		active := c.active
		c.mu.Unlock()
		if active == 0 {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// readUntil reads messages until one matches, and returns how many requests
// came before it.
func readUntil(s *script, match func(*Message) bool) (requests int, m *Message) {
	s.t.Helper()
	for {
		m := s.read()
		if match(m) {
			return requests, m
		}
		if !m.IsRequest() || m.Code != cmdTest {
			s.t.Fatalf("expected the node's requests, got %+v", m)
		}
		requests++
	}
}

// checkBehindTheMainQueue checks that what ends the connection came after at
// least the requests that filled the main queue before it: a channel's
// buffer is first in, first out. (Requests still waiting for room in it come
// first too, but the order of blocked senders is the runtime's.)
func checkBehindTheMainQueue(t *testing.T, what string, requests int) {
	t.Helper()
	if requests < testInFlight {
		t.Fatalf("the %s came after %d requests, ahead of the %d in the main queue", what, requests, testInFlight)
	}
}

// An admitted request's answer is written next once its handler finishes,
// not behind the node's own requests to the same peer (#117). Only the
// request the writer is already sending may come first.
func TestAHandlersAnswerIsWrittenAheadOfTheNodesOwnRequests(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = testInFlight })
	hss.Handle(appCx, cmdTest, blockingHandler(hss, started, release))
	s := openScript(t, ln, scscfHost)
	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	c := sendBacklog(t, hss, hss.Peer(scscfHost))

	close(release)
	queued := waitForAnswersQueued(c)
	before, _ := readUntil(s, func(m *Message) bool { return !m.IsRequest() && m.HopByHop == first.HopByHop })
	if before > 1 {
		t.Fatalf("%d of the node's requests were written between the handler finishing and its answer, want at most the one being written", before)
	}
	if !queued {
		t.Fatal("the handler could not queue its answer until the peer read the node's requests")
	}
}

// Answers queued while the node drains for Shutdown still reach the peer
// before the DPR, with the node's own requests queued as well (drain).
func TestShutdownWritesAnswersBeforeTheDPRAheadOfQueuedRequests(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = testInFlight })
	hss.Handle(appCx, cmdTest, blockingHandler(hss, started, release))
	s := openScript(t, ln, scscfHost)
	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	c := sendBacklog(t, hss, hss.Peer(scscfHost))

	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	waitFor(t, "shutdown to drain", func() bool { return !hss.Peer(scscfHost).Available() })
	close(release)
	waitForAnswersQueued(c)
	before, _ := readUntil(s, func(m *Message) bool { return !m.IsRequest() && m.HopByHop == first.HopByHop })
	if before > 1 {
		t.Fatalf("%d requests came before the answer", before)
	}
	after, dpr := readUntil(s, func(m *Message) bool { return m.Code == CodeDisconnectPeer })
	if !dpr.IsRequest() {
		t.Fatalf("expected a DPR, got %+v", dpr)
	}
	checkBehindTheMainQueue(t, "DPR", before+after)
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// A node that receives a DPR answers the requests in progress first and
// sends the DPA last, behind its own requests already queued (RFC 6733
// §5.4: the DPA is the last message the peer gets).
func TestTheDPAFollowsTheAnswersAndTheQueuedRequests(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	scscf, peer, dialer, _ := startInitiator(t, func(c *Config) { c.MaxInFlight = testInFlight })
	scscf.Handle(appCx, cmdTest, blockingHandler(scscf, started, release))
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	first := s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	c := sendBacklog(t, scscf, peer)

	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	waitFor(t, "the DPR to be read", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.gotDPR
	})
	close(release)
	waitForAnswersQueued(c)
	before, _ := readUntil(s, func(m *Message) bool { return !m.IsRequest() && m.HopByHop == first.HopByHop })
	if before > 1 {
		t.Fatalf("%d requests came before the answer", before)
	}
	after, dpa := readUntil(s, func(m *Message) bool { return m.Code == CodeDisconnectPeer })
	if dpa.IsRequest() || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
	checkBehindTheMainQueue(t, "DPA", before+after)
}
