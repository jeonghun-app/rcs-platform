package msrp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forwarder is a Handler that passes every message on to other sessions,
// the way a group chat's controlling function fans out.
type forwarder struct {
	to   []*Session
	errs chan error
}

func (f *forwarder) HandleMessage(_ *Session, m *Message) error {
	for _, s := range f.to {
		_, err := s.Send(context.Background(), Outgoing{ContentType: m.ContentType, Body: m.Body})
		f.errs <- err
	}
	return nil
}

func (f *forwarder) HandleReport(*Session, Report) {}

func TestAHandlerMaySendOnASessionThatIsNotBoundYet(t *testing.T) {
	reg := &Registry{}
	two := newTestSession(t, "msrp://as.example.org:9000/as9two;tcp", "msrp://client.example.com:2855/cl1two;tcp", newRecorder())
	fw := &forwarder{to: []*Session{two}, errs: make(chan error, 1)}
	one := newTestSession(t, asURI, clientURI, fw)
	for _, s := range []*Session{one, two} {
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	sentinel(t, p) // binds one
	p.send(t, sendLines("f4n0ut", "Message-ID: msg1", "Content-Type: text/plain", "", "to two", "-------f4n0ut$")...)
	expectResponse(t, p, "f4n0ut", StatusOK)
	// The handler is now waiting for two to be bound; the connection must
	// still read the request that binds it.
	p.send(t, "MSRP b1ndtw0 SEND", "To-Path: msrp://as.example.org:9000/as9two;tcp", "From-Path: msrp://client.example.com:2855/cl1two;tcp",
		"Message-ID: b1ndtw0", "-------b1ndtw0$")
	var gotBind, gotSend bool
	for range 2 {
		m := p.next(t)
		switch {
		case !m.IsRequest() && m.TransactionID == "b1ndtw0":
			gotBind = true
		case m.Method == MethodSend && string(m.Body) == "to two" && m.FromPath[0].SessionID == "as9two":
			gotSend = true
			p.respond(t, m, StatusOK)
		}
	}
	if !gotBind || !gotSend {
		t.Fatalf("bind answered %v, message sent %v", gotBind, gotSend)
	}
	if err := <-fw.errs; err != nil {
		t.Fatal(err)
	}
}

func TestAHandlerFansOutToEverySessionOnTheConnection(t *testing.T) {
	reg := &Registry{}
	var members []*Session
	for _, id := range []string{"m3mbera", "m3mberb"} {
		s := newTestSession(t, "msrp://as.example.org:9000/"+id+";tcp", "msrp://client.example.com:2855/c"+id+";tcp", newRecorder())
		members = append(members, s)
	}
	fw := &forwarder{to: members, errs: make(chan error, 2)}
	focus := newTestSession(t, asURI, clientURI, fw)
	for _, s := range append([]*Session{focus}, members...) {
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	sentinel(t, p)
	for _, s := range members {
		id := s.Local().SessionID
		p.send(t, "MSRP b"+id+" SEND", "To-Path: "+s.Local().String(), "From-Path: "+s.Remote()[0].String(), "Message-ID: b"+id, "-------b"+id+"$")
		expectResponse(t, p, "b"+id, StatusOK)
	}
	p.send(t, sendLines("gr0up", "Message-ID: msg1", "Content-Type: message/cpim", "", "hello all", "-------gr0up$")...)
	expectResponse(t, p, "gr0up", StatusOK)
	seen := map[string]bool{}
	for range 2 {
		m := p.next(t)
		if m.Method != MethodSend || string(m.Body) != "hello all" {
			t.Fatalf("got %+v", m)
		}
		seen[m.FromPath[0].SessionID] = true
		p.respond(t, m, StatusOK)
	}
	if !seen["m3mbera"] || !seen["m3mberb"] {
		t.Fatalf("fanned out to %v", seen)
	}
	for range 2 {
		if err := <-fw.errs; err != nil {
			t.Fatal(err)
		}
	}
}

// blocker holds its handler until released.
type blocker struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blocker) HandleMessage(*Session, *Message) error {
	b.entered <- struct{}{}
	<-b.release
	return nil
}

func (b *blocker) HandleReport(*Session, Report) {}

func TestAFullHandlerQueueRefusesOnlyThatSessionsMessages(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	cfg := Config{Clock: newFakeClock(), MaxHandlerQueue: 2, OnEvent: func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}}
	b := &blocker{entered: make(chan struct{}, 8), release: make(chan struct{})}
	reg := &Registry{}
	slow := newTestSession(t, asURI, clientURI, b)
	other := newTestSession(t, "msrp://as.example.org:9000/as9two;tcp", "msrp://client.example.com:2855/cl1two;tcp", newRecorder())
	for _, s := range []*Session{slow, other} {
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	_, p := passiveWithPeer(t, reg, cfg)
	msg := func(tid string) {
		p.send(t, sendLines(tid, "Message-ID: "+tid, "Content-Type: text/plain", "", "x", "-------"+tid+"$")...)
	}
	msg("busy0001")
	expectResponse(t, p, "busy0001", StatusOK)
	<-b.entered // the handler now holds the first message
	msg("busy0002")
	expectResponse(t, p, "busy0002", StatusOK)
	msg("busy0003")
	expectResponse(t, p, "busy0003", StatusOK)
	msg("busy0004")
	expectResponse(t, p, "busy0004", StatusMessageTooLarge)
	// Another session on the same connection is not held up.
	p.send(t, "MSRP fr33 SEND", "To-Path: msrp://as.example.org:9000/as9two;tcp", "From-Path: msrp://client.example.com:2855/cl1two;tcp",
		"Message-ID: fr33", "Content-Type: text/plain", "", "y", "-------fr33$")
	expectResponse(t, p, "fr33", StatusOK)
	close(b.release)
	mu.Lock()
	defer mu.Unlock()
	var busy bool
	for _, e := range events {
		if e.Kind == EventDropped && errors.Is(e.Err, ErrHandlerBusy) {
			busy = true
		}
	}
	if !busy {
		t.Fatalf("no ErrHandlerBusy event in %+v", events)
	}
}

func TestEventsNameRefusalsDropsAndTheEndWithoutIdentifiers(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, newRecorder())); err != nil {
		t.Fatal(err)
	}
	c, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}})
	p.send(t, "MSRP unkn0wn SEND", "To-Path: msrp://as.example.org:9000/nobody;tcp", "From-Path: "+clientURI, "Message-ID: x1x1", "-------unkn0wn$")
	expectResponse(t, p, "unkn0wn", StatusNoSession)
	p.send(t, sendLines("m4lformed", "Byte-Range: bad", "-------m4lformed$")...)
	expectResponse(t, p, "m4lformed", StatusBadRequest)
	p.send(t, "MSRP str4y 200 OK", "From-Path: "+clientURI, "-------str4y$")
	p.send(t, "garbage")
	waitDone(t, c.Done(), "connection")
	mu.Lock()
	defer mu.Unlock()
	want := []Event{
		{Kind: EventRefused, Method: MethodSend, Code: StatusNoSession},
		{Kind: EventRefused, Method: MethodSend, Code: StatusBadRequest},
		{Kind: EventDropped},
		{Kind: EventClosed},
	}
	if len(events) != len(want) {
		t.Fatalf("events %+v", events)
	}
	for i, w := range want {
		e := events[i]
		if e.Kind != w.Kind || e.Method != w.Method || e.Code != w.Code {
			t.Errorf("event %d = %+v, want %+v", i, e, w)
		}
		if e.Err != nil && strings.Contains(e.Err.Error(), "as.example.org") {
			t.Errorf("event %d names an address: %v", i, e.Err)
		}
	}
	if !errors.Is(events[3].Err, ErrFraming) {
		t.Errorf("closed with %v", events[3].Err)
	}
}

func TestAcceptTypesWithParametersMatchTheBareType(t *testing.T) {
	s := &Session{accept: []string{"text/plain;charset=UTF-8", "image/*;q=1", " Message/CPIM "}}
	for mt, want := range map[string]bool{"text/plain": true, "image/png": true, "message/cpim": true, "text/html": false} {
		if got := s.accepts(mt); got != want {
			t.Errorf("accepts(%q) = %v, want %v", mt, got, want)
		}
	}
}

func TestPathsInTheWrongOrderAreAnsweredWith400(t *testing.T) {
	_, p := boundPassive(t, newRecorder(), Config{})
	p.send(t, "MSRP 0rder SEND", "From-Path: "+clientURI, "To-Path: "+asURI, "Message-ID: msg1", "-------0rder$")
	resp := expectResponse(t, p, "0rder", StatusBadRequest)
	if resp.ToPath[0].String() != clientURI {
		t.Fatalf("answered to %v", resp.ToPath)
	}
}

func TestAnOddlySizedTransactionIDIsAnsweredWith400(t *testing.T) {
	_, p := boundPassive(t, newRecorder(), Config{})
	for _, tid := range []string{"abc", "a", strings.Repeat("t", 40)} {
		p.send(t, sendLines(tid, "Message-ID: msg1", "-------"+tid+"$")...)
		expectResponse(t, p, tid, StatusBadRequest)
	}
	sentinel(t, p)
	// An id that cannot even frame the message ends the connection.
	c, p2 := passiveWithPeer(t, &Registry{}, Config{Clock: newFakeClock()})
	p2.send(t, sendLines("ab!c", "Message-ID: msg1", "-------ab!c$")...)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrFraming) {
		t.Fatalf("Err = %v", c.Err())
	}
}

func TestNicknameStatusesHaveTheirText(t *testing.T) {
	if StatusText(StatusNicknameInvalid) == "" || StatusText(StatusNicknameInUse) == "" {
		t.Fatal("RFC 7701 codes lack a comment")
	}
}

func TestRelayStopsAChunkMidwayOnceTheNextHopRefusesIt(t *testing.T) {
	r := newRelayRig(t, Config{})
	body := bodyOf(5000)
	head := wire(clientSend("m1dway", "Message-ID: msg1", "Byte-Range: 1-5000/5000", "Content-Type: text/plain", "")...)
	if _, err := r.client.nc.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.nc.Write(body[:2049]); err != nil {
		t.Fatal(err)
	}
	first := r.as.next(t)
	r.as.respond(t, first, StatusMessageTooLarge)
	// The refusal has been taken in once its REPORT reaches the client.
	if rep := r.client.next(t); rep.Method != MethodReport || rep.Status.Code != StatusMessageTooLarge {
		t.Fatalf("got %+v", rep)
	}
	if _, err := r.client.nc.Write(append(append([]byte{}, body[2049:]...), "\r\n-------m1dway$\r\n"...)); err != nil {
		t.Fatal(err)
	}
	expectResponse(t, r.client, "m1dway", StatusMessageTooLarge)
	r.asSentinel(t)
}

func TestContextEndsAnOpenThatCannotBeWritten(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	t.Cleanup(func() { _ = c.Close() })
	s := newTestSession(t, clientURI, asURI, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := c.Open(ctx, s); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Open = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Open ignored its context for %v", elapsed)
	}
}

func TestConnectionLayerValuesPrintWithoutSessionIDs(t *testing.T) {
	reg := &Registry{}
	s := newTestSession(t, asURI, clientURI, newRecorder())
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	c, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	sentinel(t, p)
	pool := &Pool{}
	var out bytes.Buffer
	for _, v := range []any{s, c, reg, pool} {
		fmt.Fprintf(&out, "%v %+v %#v %s\n", v, v, v, v)
		slog.New(slog.NewTextHandler(&out, nil)).Info("x", "v", v)
		slog.New(slog.NewJSONHandler(&out, nil)).Info("x", "v", v, "in", []any{v})
	}
	for _, secret := range []string{"as9ses", "cl1ses"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("%q printed:\n%s", secret, out.String())
		}
	}
	for _, want := range []string{"bound=true", "role=passive", "sessions=1", "connections=0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%q missing:\n%s", want, out.String())
		}
	}
}

func TestEventsCarryOnlyFixedValuesWhateverThePeerSends(t *testing.T) {
	var mu sync.Mutex
	var events []Event
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, newRecorder())); err != nil {
		t.Fatal(err)
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}})
	sentinel(t, p)
	for _, method := range []string{"FROBNICATE", "XYZZY", "QQQQQQQQQQQQQQQQQQQQQQQQ"} {
		tid := strings.ToLower(method)[:4] + "1"
		p.send(t, "MSRP "+tid+" "+method, "To-Path: "+asURI, "From-Path: "+clientURI, "-------"+tid+"$")
		expectResponse(t, p, tid, StatusNotImplemented)
	}
	p.send(t, "MSRP str4y 200 OK", "From-Path: 10.0.0.1 \"quoted\"", "-------str4y$")
	sentinel(t, p)
	_ = p.nc.Close()
	closed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(events) > 0 && events[len(events)-1].Kind == EventClosed
	}
	for deadline := time.Now().Add(hangGuard); !closed(); {
		if time.Now().After(deadline) {
			t.Fatal("no EventClosed")
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if last := events[len(events)-1]; last.Err != ErrPeerGone {
		t.Errorf("closed with %v, want ErrPeerGone for a peer that hung up", last.Err)
	}
	allowed := map[string]bool{"": true, MethodSend: true, MethodReport: true, MethodNickname: true, "other": true}
	sentinels := append([]error{nil, ErrPeerGone}, eventErrs...)
	for _, e := range events {
		if !allowed[e.Method] {
			t.Errorf("method %q in %+v", e.Method, e)
		}
		known := false
		for _, s := range sentinels {
			if e.Err == s {
				known = true
			}
		}
		if !known {
			t.Errorf("error %v is not a sentinel", e.Err)
		}
	}
}

func TestAnUnboundConnectionIsClosedAfterAFewUnknownSessions(t *testing.T) {
	c, p := passiveWithPeer(t, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 2})
	for _, tid := range []string{"unkn1", "unkn2"} {
		p.send(t, "MSRP "+tid+" SEND", "To-Path: msrp://as.example.org:9000/guess"+tid+";tcp", "From-Path: "+clientURI, "Message-ID: "+tid, "-------"+tid+"$")
		expectResponse(t, p, tid, StatusNoSession)
	}
	p.send(t, "MSRP unkn3 SEND", "To-Path: msrp://as.example.org:9000/guess3;tcp", "From-Path: "+clientURI, "Message-ID: unkn3", "-------unkn3$")
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrTooManyUnknownSessions) {
		t.Fatalf("Err = %v", c.Err())
	}
}

func TestAnUnboundConnectionQueuesLittleForAPeerThatDoesNotRead(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, &Registry{}, Config{Clock: newFakeClock(), MaxFailedBinds: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	req := []byte(wire("MSRP m4l SEND", "To-Path: "+asURI, "From-Path: "+clientURI, "Byte-Range: bad", "-------m4l$"))
	go func() {
		for {
			if _, err := theirs.Write(req); err != nil {
				return
			}
		}
	}()
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrPeerNotReading) {
		t.Fatalf("Err = %v", c.Err())
	}
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.posted > unboundQueueBytes {
		t.Fatalf("%d octets were queued", c.posted)
	}
}

// slowReporter takes a while over each report, as marking a message failed
// in a database does.
type slowReporter struct {
	reports atomic.Int64
	delay   time.Duration
}

func (h *slowReporter) HandleMessage(*Session, *Message) error { return nil }
func (h *slowReporter) HandleReport(*Session, Report) {
	time.Sleep(h.delay)
	h.reports.Add(1)
}

func TestEveryRefusalOfASentMessageReachesHandleReport(t *testing.T) {
	// Adapted from the tester's reproduction on PR #28: the peer refuses
	// every message, the sender's HandleReport is slow, and no refusal may
	// be lost; Send slows down instead.
	var dropped atomic.Int64
	cfg := Config{SendWindow: 8, MaxHandlerQueue: 4, OnEvent: func(e Event) {
		if e.Kind == EventDropped && e.Method == MethodReport {
			dropped.Add(1)
		}
	}}
	reg := &Registry{}
	bob, err := NewSession(SessionConfig{Local: mustURI(t, asURI), Remote: []URI{mustURI(t, clientURI)},
		Handler: &slowReporter{}, AcceptTypes: []string{"text/plain"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	pc, err := NewPassiveConn(b, reg, Config{})
	if err != nil {
		t.Fatal(err)
	}
	ac, err := NewActiveConn(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ac.Close(); _ = pc.Close() })
	h := &slowReporter{delay: 2 * time.Millisecond}
	alice := newTestSession(t, clientURI, asURI, h)
	if err := ac.Open(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	const n = 200
	for i := range n {
		if _, err := alice.Send(context.Background(), Outgoing{ContentType: "image/png", Body: []byte("x")}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
		if waiting := alice.undeliveredReports(); waiting > cfg.SendWindow {
			t.Fatalf("%d reports waiting with a window of %d", waiting, cfg.SendWindow)
		}
	}
	for deadline := time.Now().Add(hangGuard); h.reports.Load() < n; {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if h.reports.Load() != n || dropped.Load() != 0 {
		t.Fatalf("HandleReport saw %d of %d refusals, %d dropped", h.reports.Load(), n, dropped.Load())
	}
}

func TestUnknownSessionsKeepCountingAfterTheFirstBind(t *testing.T) {
	// One bound session raises the allowance by one; a peer that goes on
	// guessing is closed all the same.
	clock := newFakeClock()
	_, p := boundPassive(t, newRecorder(), Config{Clock: clock, MaxFailedBinds: 2})
	guess := func(i int) {
		tid := fmt.Sprintf("gu3ss%d", i)
		p.send(t, "MSRP "+tid+" SEND", fmt.Sprintf("To-Path: msrp://as.example.org:9000/guess%d;tcp", i),
			"From-Path: "+clientURI, "Message-ID: "+tid, "-------"+tid+"$")
	}
	for i := range 3 {
		guess(i)
		expectResponse(t, p, fmt.Sprintf("gu3ss%d", i), StatusNoSession)
	}
	// A minute later the count starts again.
	clock.Advance(time.Minute)
	for i := 3; i < 6; i++ {
		guess(i)
		expectResponse(t, p, fmt.Sprintf("gu3ss%d", i), StatusNoSession)
	}
	guess(6)
	p.closed(t)
}

func TestAMaximumSizeMessageFitsInASessionsReserveWhenThePoolIsFull(t *testing.T) {
	// A shared pool of one octet is as good as full.
	_, p := boundPassive(t, newRecorder(), Config{MaxMessageSize: 4096, MaxConnBuffer: 1})
	whole := strings.Repeat("w", 4096)
	p.send(t, sendLines("fu11", "Message-ID: whole1", "Byte-Range: 1-4096/4096", "Content-Type: text/plain", "", whole, "-------fu11$")...)
	expectResponse(t, p, "fu11", StatusOK)
}

// stuckReports is a handler whose HandleReport blocks until release closes,
// and counts the reports it took.
type stuckReports struct {
	release chan struct{}
	got     atomic.Int64
}

func (h *stuckReports) HandleMessage(*Session, *Message) error { return nil }
func (h *stuckReports) HandleReport(*Session, Report) {
	h.got.Add(1)
	<-h.release
}

// #258: after a session closes, a handler that blocks holds one goroutine,
// not one per report. 10000 reports later the goroutine count has barely
// moved, every report beyond MaxHandlerQueue was dropped and counted, and
// each one's after ran, so nothing is held for it.
func TestReportsAfterACloseAreBoundedByOneGoroutine(t *testing.T) {
	var dropped atomic.Int64
	c, p := activeWithPeer(t, Config{Clock: newFakeClock(), OnEvent: func(e Event) {
		if e.Kind == EventDropped && e.Err == ErrHandlerBusy {
			dropped.Add(1)
		}
	}})
	h := &stuckReports{release: make(chan struct{})}
	t.Cleanup(func() { close(h.release) })
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s.Done(), "session")
	before := runtime.NumGoroutine()
	const n = 10000
	var afters atomic.Int64
	for i := range n {
		s.reportOwn(Report{MessageID: "m", Range: ByteRange{Start: int64(i) + 1, End: int64(i) + 1, Total: n}, Code: StatusRequestTimeout}, func() { afters.Add(1) })
	}
	if grown := runtime.NumGoroutine() - before; grown > 2 {
		t.Fatalf("%d more goroutines for %d reports after the close", grown, n)
	}
	// The drainer is in HandleReport with the first one; DefaultMaxHandlerQueue
	// more wait behind it, at most.
	if d := dropped.Load(); d < n-DefaultMaxHandlerQueue-1 || d != afters.Load() {
		t.Fatalf("%d dropped, %d afters run, of %d", d, afters.Load(), n)
	}
}

// What is left after the close, within the bound, is still delivered, in
// order, on one goroutine.
func TestReportsAfterACloseAreDeliveredInOrder(t *testing.T) {
	c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	h := newRecorder()
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitDone(t, s.Done(), "session")
	for i := range 10 {
		s.reportOwn(Report{MessageID: "m", Range: ByteRange{Start: int64(i) + 1, End: int64(i) + 1, Total: 10}, Code: StatusRequestTimeout}, nil)
	}
	for i := range 10 {
		if r := h.report(t); r.Range.Start != int64(i)+1 {
			t.Fatalf("report %d is for %v", i, r.Range)
		}
	}
}

// gatedReports blocks HandleReport on report 1 until release closes, and
// records the order reports came in and the goroutines they came on.
type gatedReports struct {
	release chan struct{}
	mu      sync.Mutex
	starts  []int64
	callers map[string]bool
	n       chan struct{}
}

func (h *gatedReports) HandleMessage(*Session, *Message) error { return nil }
func (h *gatedReports) HandleReport(_ *Session, r Report) {
	if r.Range.Start == 1 {
		<-h.release
	}
	buf := make([]byte, 64)
	id := strings.Fields(string(buf[:runtime.Stack(buf, false)]))[1]
	h.mu.Lock()
	h.starts = append(h.starts, r.Range.Start)
	h.callers[id] = true
	h.mu.Unlock()
	h.n <- struct{}{}
}

// Code review on #259: a handler stuck on the first report while the
// session is open, 9 more queued behind it, then the close, then 10 more:
// all 20 still come in order, on one goroutine.
func TestReportsQueuedAcrossTheCloseKeepTheirOrder(t *testing.T) {
	for range 50 {
		c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
		h := &gatedReports{release: make(chan struct{}), callers: map[string]bool{}, n: make(chan struct{}, 32)}
		s := newTestSession(t, clientURI, asURI, h)
		openWithPeer(t, c, p, s)
		report := func(i int) {
			s.reportOwn(Report{MessageID: "m", Range: ByteRange{Start: int64(i), End: int64(i), Total: 20}, Code: StatusRequestTimeout}, nil)
		}
		for i := 1; i <= 10; i++ {
			report(i)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		waitDone(t, s.Done(), "session")
		for i := 11; i <= 20; i++ {
			report(i)
		}
		close(h.release)
		for range 20 {
			select {
			case <-h.n:
			case <-time.After(hangGuard):
				t.Fatal("not every report came")
			}
		}
		h.mu.Lock()
		for i, got := range h.starts {
			if got != int64(i)+1 {
				t.Fatalf("reports came as %v", h.starts)
			}
		}
		if len(h.callers) != 1 {
			t.Fatalf("reports came on %d goroutines", len(h.callers))
		}
		h.mu.Unlock()
	}
}
