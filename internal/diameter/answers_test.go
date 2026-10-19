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

// A peer that keeps requests outstanding faster than it reads the answers
// cannot hold up the node's own requests: one goes out after at most
// maxAnswersInARow answers, however many are queued (review of #148). The
// script reads nothing until the answers and the request are all queued,
// so the order is the writer's alone.
func TestTheNodesOwnRequestFollowsAtMostABoundedRunOfAnswers(t *testing.T) {
	for _, outstanding := range []int{2, maxAnswersInARow + 1, 64} {
		hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = 64 })
		hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
			return hss.NewAnswer(req, ResultSuccess), nil
		})
		s := openScript(t, ln, scscfHost)
		for range outstanding {
			s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
		}
		peer := hss.Peer(scscfHost)
		c := peer.current()
		// The writer holds one answer, waiting for the script to read it.
		waitFor(t, "the answers to be queued", func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.active == 0 && len(c.answers) == outstanding-1
		})
		go func() { _, _ = peer.Send(context.Background(), hss.NewRequest(cmdTest, appCx, hss.NewSessionID(""))) }()
		waitFor(t, "the node's request to be queued", func() bool { return len(c.writes) == 1 })
		answers, _ := countUntil(s, func(m *Message) bool { return m.IsRequest() })
		if answers > maxAnswersInARow {
			t.Errorf("%d outstanding: the node's request came after %d answers, want at most %d", outstanding, answers, maxAnswersInARow)
		}
	}
}

// countUntil reads messages until one matches and returns how many came
// before it.
func countUntil(s *script, match func(*Message) bool) (before int, m *Message) {
	s.t.Helper()
	for {
		if m := s.read(); match(m) {
			return before, m
		}
		before++
	}
}

// A DPR the writer takes from the main queue while an answer is ready, as
// a select that found both ready may, follows that answer on the wire: the
// hook queues the answer just after the writer took the DPR (review of
// #148).
func TestAnAnswerReadyWhenTheWriterTakesTheDPRGoesFirst(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	late := &Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx, HopByHop: 0x5150, EndToEnd: 0x5150, AVPs: s.origin()}
	b, err := hss.NewAnswer(late, ResultSuccess).Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The DPR exchange needs a running connection; the DWR proves it.
	s.sync()
	testHookTookLast = func(c *conn) { c.answers <- b }
	t.Cleanup(func() { testHookTookLast = nil })
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	if ans := s.read(); ans.IsRequest() || ans.HopByHop != late.HopByHop {
		t.Fatalf("expected the ready answer first, got %+v", ans)
	}
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected the DPR, got %+v", dpr)
	}
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// The same for the DPA a node sends when the peer disconnects.
func TestAnAnswerReadyWhenTheWriterTakesTheDPAGoesFirst(t *testing.T) {
	scscf, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	s.sync()
	late := &Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx, HopByHop: 0x5151, EndToEnd: 0x5151, AVPs: s.origin()}
	b, err := scscf.NewAnswer(late, ResultSuccess).Encode()
	if err != nil {
		t.Fatal(err)
	}
	testHookTookLast = func(c *conn) { c.answers <- b }
	t.Cleanup(func() { testHookTookLast = nil })
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if ans := s.read(); ans.IsRequest() || ans.HopByHop != late.HopByHop {
		t.Fatalf("expected the ready answer first, got %+v", ans)
	}
	if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
}

// The node's own request, once queued, must not wait behind an endless
// stream of answers (QA of #148): here the peer keeps one request in progress at a time,
// and the node never gets to write its own second request.
func TestQA148OwnRequestIsNotStarvedByAStreamOfAnswers(t *testing.T) {
	const rounds = 3 * testInFlight
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = testInFlight })
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		return hss.NewAnswer(req, ResultSuccess), nil
	})
	s := openScript(t, ln, scscfHost)
	p := hss.Peer(scscfHost)
	c := p.current()
	// Two own requests: the writer blocks on the first (the script is not
	// reading), the second waits in the main queue.
	for range 2 {
		go func() { _, _ = p.Send(context.Background(), hss.NewRequest(cmdTest, appCx, hss.NewSessionID(""))) }()
	}
	waitFor(t, "both requests pending", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.pending) == 2
	})
	ownSeen, answers := 0, 0
	for range rounds {
		// While the writer is still on the previous message, one more
		// request from the peer is answered and its answer queued.
		s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
		if !waitForAnswersQueued(c) {
			t.Fatal("answer not queued")
		}
		m := s.read()
		if m.IsRequest() {
			ownSeen++
			if ownSeen == 2 {
				t.Logf("second own request written after %d answers", answers)
				return
			}
		} else {
			answers++
		}
	}
	t.Fatalf("the node's second request was still not written after %d answers (MaxInFlight %d)", answers, testInFlight)
}
