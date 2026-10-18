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
	for deadline := time.Now().Add(5 * time.Second); !closed(); {
		if time.Now().After(deadline) {
			t.Fatal("no EventClosed")
		}
		runtime.Gosched()
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
