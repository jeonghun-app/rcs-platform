package diameter

import (
	"context"
	"errors"
	"io"
	"sync"
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
	hookFor(t, hss.Peer(scscfHost).current(), func(c *conn) { c.answers <- b }, nil)
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

// A request that reaches the main queue only after the DPR, as one whose
// sender found the connection open and was still waiting for room when
// the DPR went in, is not written after it: nothing follows the DPR on the
// wire (RFC 6733 §5.6, #324). The hook queues the request once the writer
// has taken the DPR; then either the next read gets it or the writer drops
// it. The writer goes on after the drop: the peer's DWR still gets its DWA.
func TestNothingFollowsTheDPROnTheWire(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	late := &Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx, HopByHop: 0x5152, EndToEnd: 0x5152, AVPs: s.origin()}
	b, err := late.Encode()
	if err != nil {
		t.Fatal(err)
	}
	s.sync()
	dropped := make(chan struct{}, 1)
	// The DPR has just left the main queue, so there is room for one.
	hookFor(t, hss.Peer(scscfHost).current(),
		func(c *conn) { c.writes <- queued{b: b, hbh: late.HopByHop} },
		func(*conn) { dropped <- struct{}{} })
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected the DPR, got %+v", dpr)
	}
	reads := expectDropped(t, s, "DPR", dropped)
	expectDWA(t, s, reads)
	s.write(s.answer(dpr, ResultSuccess))
	expectEnd(t, reads)
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// The same for the DPA a node sends when the peer disconnects.
func TestNothingFollowsTheDPAOnTheWire(t *testing.T) {
	_, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	s.sync()
	late := &Message{Flags: FlagRequest, Code: cmdTest, ApplicationID: appCx, HopByHop: 0x5153, EndToEnd: 0x5153, AVPs: s.origin()}
	b, err := late.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dropped := make(chan struct{}, 1)
	hookFor(t, peer.current(),
		func(c *conn) { c.writes <- queued{b: b, hbh: late.HopByHop} },
		func(*conn) { dropped <- struct{}{} })
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
	reads := expectDropped(t, s, "DPA", dropped)
	expectDWA(t, s, reads)
	_ = s.nc.Close() // RFC 6733 §5.4: the DPR's sender closes on the DPA
	expectEnd(t, reads)
}

// A DPR from the peer that crosses ours still gets its DPA: it is the one
// message the main queue still sends after a DPR (code review of #367).
func TestACrossingDPRGetsItsDPA(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync()
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected the DPR, got %+v", dpr)
	}
	mine := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != mine.HopByHop {
		t.Fatalf("expected the DPA to the crossing DPR, got %+v", dpa)
	}
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// A real Send that found the connection open, and reaches the main queue
// only once the writer has taken the DPR, is dropped, and its caller learns
// at once that it was not sent, as for a request refused before the send:
// cxclient then retries it on another HSS task straight away and counts it
// as never sent, rather than waiting for the connection to close, or for
// RequestTimeout if the peer never answers the DPR (QA and code review of
// #367).
func TestARealSendBehindTheDPREndsAtOnceAsNotSent(t *testing.T) {
	for _, answered := range []bool{true, false} {
		t.Run(map[bool]string{true: "the peer answers the DPR", false: "the peer never answers it"}[answered], func(t *testing.T) {
			hss, ln, clock := startResponder(t, nil)
			s := openScript(t, ln, scscfHost)
			s.sync()
			peer := hss.Peer(scscfHost)
			res, dropped := holdASend(t, peer.current(), func() error {
				_, err := peer.Send(context.Background(), hss.NewRequest(cmdTest, appCx, hss.NewSessionID("")))
				return err
			})
			errc := make(chan error, 1)
			go func() { errc <- hss.Shutdown(context.Background()) }()
			dpr := s.read()
			if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
				t.Fatalf("expected the DPR, got %+v", dpr)
			}
			reads := expectDropped(t, s, "DPR", dropped)
			expectNotSent(t, res)
			if answered {
				s.write(s.answer(dpr, ResultSuccess))
			} else {
				clock.waitForTimer(t, testRequestWait)
				clock.Advance(testRequestWait)
			}
			expectEnd(t, reads)
			<-errc
		})
	}
}

// The same behind the DPA a node sends when the peer disconnects.
func TestARealSendBehindTheDPAEndsAtOnceAsNotSent(t *testing.T) {
	for _, closes := range []bool{true, false} {
		t.Run(map[bool]string{true: "the peer closes", false: "the peer keeps the connection"}[closes], func(t *testing.T) {
			scscf, peer, dialer, clock := startInitiator(t, nil)
			s := dialer.next(t)
			acceptCER(t, s)
			waitFor(t, "peer to open", peer.Available)
			s.sync()
			res, dropped := holdASend(t, peer.current(), func() error {
				_, err := peer.Send(context.Background(), scscf.NewRequest(cmdTest, appCx, scscf.NewSessionID("")))
				return err
			})
			dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
			if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
				t.Fatalf("expected the DPA, got %+v", dpa)
			}
			reads := expectDropped(t, s, "DPA", dropped)
			expectNotSent(t, res)
			if closes {
				_ = s.nc.Close()
			} else {
				// The grace timer starts once the DPA is written.
				clock.waitForTimer(t, disconnectWaitForPeerToDrop)
				clock.Advance(disconnectWaitForPeerToDrop)
			}
			expectEnd(t, reads)
		})
	}
}

// holdASend starts send, whose request on c is held after its closing check
// until the writer has taken the DPR or DPA, and returns its outcome and the
// writer's drops.
func holdASend(t *testing.T, c *conn, send func() error) (<-chan error, <-chan struct{}) {
	t.Helper()
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	queuing := func(x *conn, m *Message) {
		if x == c && m.Code == cmdTest {
			once.Do(func() { close(reached); <-release })
		}
	}
	testHookQueuing.Store(&queuing)
	t.Cleanup(func() { testHookQueuing.Store(nil) })
	dropped := make(chan struct{}, 1)
	hookFor(t, c, func(*conn) { close(release) }, func(*conn) { dropped <- struct{}{} })
	res := make(chan error, 1)
	go func() { res <- send() }()
	select {
	case <-reached:
	case <-time.After(realWait):
		t.Fatal("the Send did not reach the queue")
	}
	return res, dropped
}

// expectNotSent checks that the dropped request's caller has its answer
// already: ErrPeerUnavailable, which cxclient counts as never sent.
func expectNotSent(t *testing.T, res <-chan error) {
	t.Helper()
	select {
	case err := <-res:
		if !errors.Is(err, ErrPeerUnavailable) || errors.Is(err, ErrConnectionClosed) || errors.Is(err, ErrTimeout) {
			t.Fatalf("the dropped request ended with %v, want ErrPeerUnavailable", err)
		}
	case <-time.After(realWait):
		t.Fatal("the dropped request has not ended while the connection is still open")
	}
}

// hookFor sets the writer's hooks for c alone until the test ends.
func hookFor(t *testing.T, c *conn, tookLast, dropped func(*conn)) {
	t.Helper()
	took := func(x *conn) {
		if x == c && tookLast != nil {
			tookLast(x)
		}
	}
	drop := func(x *conn) {
		if x == c && dropped != nil {
			dropped(x)
		}
	}
	testHookTookLast.Store(&took)
	testHookDropped.Store(&drop)
	t.Cleanup(func() { testHookTookLast.Store(nil); testHookDropped.Store(nil) })
}

type read struct {
	m   *Message
	err error
}

// expectDropped reads on from s and fails if a message follows the DPR or
// DPA (what) before the writer drops the request queued behind it. It
// returns what is read after that, up to the first error.
func expectDropped(t *testing.T, s *script, what string, dropped <-chan struct{}) <-chan read {
	t.Helper()
	reads := make(chan read, 4)
	go func() {
		for {
			_ = s.nc.SetReadDeadline(time.Now().Add(realWait))
			m, err := ReadMessage(s.br, s.dict, Limits{})
			reads <- read{m, err}
			if err != nil {
				return
			}
		}
	}()
	select {
	case r := <-reads:
		if r.err == nil {
			t.Fatalf("command %d followed the %s", r.m.Code, what)
		}
		t.Fatalf("the writer neither wrote nor dropped the request behind the %s: %v", what, r.err)
	case <-dropped:
	}
	return reads
}

// expectDWA sends a DWR and checks that its answer is what s reads next: the
// writer still writes after the drop.
func expectDWA(t *testing.T, s *script, reads <-chan read) {
	t.Helper()
	dwr := s.request(&Message{Code: CodeDeviceWatchdog, AVPs: s.origin()})
	r := <-reads
	if r.err != nil || r.m.IsRequest() || r.m.Code != CodeDeviceWatchdog || r.m.HopByHop != dwr.HopByHop {
		t.Fatalf("expected the DWA after the drop, got %+v", r)
	}
}

// expectEnd checks that the connection closes next.
func expectEnd(t *testing.T, reads <-chan read) {
	t.Helper()
	r := <-reads
	if r.err == nil {
		t.Fatalf("expected the connection to close, got command %d", r.m.Code)
	}
	if !errors.Is(r.err, io.EOF) && !errors.Is(r.err, io.ErrClosedPipe) {
		t.Fatalf("expected the connection to close, got %v", r.err)
	}
}

// The watchdog sends no DWR while the node disconnects (RFC 6733 §5.6,
// Closing; #376): its interval passing after the DPR brings nothing before
// the DPA to a crossing DPR, nor anything more before the connection
// closes.
func TestTheWatchdogSendsNoDWRAfterTheDPR(t *testing.T) {
	hss, ln, clock := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync()
	c := hss.Peer(scscfHost).current()
	clock.Advance(testWatchdog - 3*time.Second)
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected the DPR, got %+v", dpr)
	}
	// Past the watchdog's interval, short of the DPR's timeout; the
	// watchdog has run once it has set its next timer.
	c.mu.Lock()
	armed := c.wdTimer
	c.mu.Unlock()
	clock.Advance(6 * time.Second)
	waitFor(t, "the watchdog to run", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.wdTimer != armed
	})
	// The writer would drop a DWR now too; the watchdog does not even
	// count one as sent.
	c.mu.Lock()
	pending := c.dwrPending
	c.mu.Unlock()
	if pending {
		t.Fatal("the watchdog sent a DWR while the node disconnects")
	}
	expectNoRequestBeforeTheDPAToACrossingDPR(t, s)
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// The same on the side that answers the peer's DPR: a watchdog interval
// that passes while the node drains its handlers before the DPA sends no
// DWR, which would reach the wire ahead of the DPA (code review of #383).
func TestTheWatchdogSendsNoDWRWhileDrainingBeforeTheDPA(t *testing.T) {
	started, release := make(chan *Message, 1), make(chan struct{})
	scscf, peer, dialer, clock := startInitiator(t, func(c *Config) { c.WatchdogInterval = MinWatchdogInterval })
	scscf.Handle(appCx, cmdTest, blockingHandler(scscf, started, release))
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	c := peer.current()
	s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	<-started
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	waitFor(t, "the DPR to be read", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.closing
	})
	c.mu.Lock()
	armed := c.wdTimer
	c.mu.Unlock()
	clock.Advance(MinWatchdogInterval + 100*time.Millisecond)
	waitFor(t, "the watchdog to run", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.wdTimer != armed
	})
	close(release)
	for {
		m := s.read()
		if m.IsRequest() {
			t.Fatalf("request %d before the DPA", m.Code)
		}
		if m.Code == CodeDisconnectPeer && m.HopByHop == dpr.HopByHop {
			return
		}
	}
}

// A DWR already in the control queue when the writer takes the DPR is not
// written after it either (#376).
func TestADWRQueuedAsTheDPRGoesIsDropped(t *testing.T) {
	hss, ln, _ := startResponder(t, nil)
	s := openScript(t, ln, scscfHost)
	s.sync()
	hookFor(t, hss.Peer(scscfHost).current(), func(c *conn) { c.sendDWR() }, nil)
	errc := make(chan error, 1)
	go func() { errc <- hss.Shutdown(context.Background()) }()
	dpr := s.read()
	if !dpr.IsRequest() || dpr.Code != CodeDisconnectPeer {
		t.Fatalf("expected the DPR, got %+v", dpr)
	}
	expectNoRequestBeforeTheDPAToACrossingDPR(t, s)
	s.write(s.answer(dpr, ResultSuccess))
	s.expectClosed()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// The same for the DPA: a DWR queued as the writer takes it is dropped,
// while the writer goes on answering (QA of #383).
func TestADWRQueuedAsTheDPAGoesIsDropped(t *testing.T) {
	_, peer, dialer, _ := startInitiator(t, nil)
	s := dialer.next(t)
	acceptCER(t, s)
	waitFor(t, "peer to open", peer.Available)
	s.sync()
	hookFor(t, peer.current(), func(c *conn) { c.sendDWR() }, nil)
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
	dwr := s.request(&Message{Code: CodeDeviceWatchdog, AVPs: s.origin()})
	if m := s.read(); m.IsRequest() || m.Code != CodeDeviceWatchdog || m.HopByHop != dwr.HopByHop {
		t.Fatalf("after the DPA expected the DWA, got %+v (request %v)", m, m.IsRequest())
	}
	_ = s.nc.Close() // RFC 6733 §5.4: the DPR's sender closes on the DPA
}

// expectNoRequestBeforeTheDPAToACrossingDPR sends a DPR and checks that its
// DPA is the next thing s reads.
func expectNoRequestBeforeTheDPAToACrossingDPR(t *testing.T, s *script) {
	t.Helper()
	mine := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if m := s.read(); m.IsRequest() || m.Code != CodeDisconnectPeer || m.HopByHop != mine.HopByHop {
		t.Fatalf("expected the DPA to the crossing DPR, got %+v (request %v)", m, m.IsRequest())
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
	hookFor(t, peer.current(), func(c *conn) { c.answers <- b }, nil)
	dpr := s.request(&Message{Code: CodeDisconnectPeer, AVPs: s.origin()})
	if ans := s.read(); ans.IsRequest() || ans.HopByHop != late.HopByHop {
		t.Fatalf("expected the ready answer first, got %+v", ans)
	}
	if dpa := s.read(); dpa.IsRequest() || dpa.Code != CodeDisconnectPeer || dpa.HopByHop != dpr.HopByHop {
		t.Fatalf("expected the DPA, got %+v", dpa)
	}
}

// The node's own requests, once queued, do not wait behind an endless
// stream of answers: the peer keeps one request in progress at a time, so
// an answer is always ready, and the node's second request still goes out
// within a few of them (QA of #148).
func TestOwnRequestsAreNotStarvedByAStreamOfAnswers(t *testing.T) {
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

// With a full answer queue and a full main queue, the last answer is
// written after at most one of the node's requests per maxAnswersInARow
// answers ahead of it: the run bound keeps AC1 of #117 (QA of #148).
func TestAnAnswerBehindAFullAnswerQueueWaitsForFewRequests(t *testing.T) {
	const inFlight = 64
	hss, ln, _ := startResponder(t, func(c *Config) { c.MaxInFlight = inFlight })
	hss.HandleFunc(appCx, cmdTest, func(ctx context.Context, p *Peer, req *Message) (*Message, error) {
		return hss.NewAnswer(req, ResultSuccess), nil
	})
	s := openScript(t, ln, scscfHost)
	var last *Message
	for range inFlight {
		last = s.request(&Message{Code: cmdTest, ApplicationID: appCx, AVPs: s.origin()})
	}
	p := hss.Peer(scscfHost)
	c := p.current()
	waitFor(t, "the answers to be queued", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.active == 0 && len(c.answers) == inFlight-1
	})
	for range inFlight {
		go func() { _, _ = p.Send(context.Background(), hss.NewRequest(cmdTest, appCx, hss.NewSessionID(""))) }()
	}
	waitFor(t, "the main queue to fill", func() bool { return len(c.writes) == inFlight })
	requests := 0
	for {
		m := s.read()
		if m.IsRequest() {
			requests++
			continue
		}
		if m.HopByHop == last.HopByHop {
			break
		}
	}
	if want := (inFlight-1)/maxAnswersInARow + 1; requests > want {
		t.Fatalf("%d of the node's requests came before the last queued answer, want at most %d", requests, want)
	}
}
