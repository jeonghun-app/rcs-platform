package msrp

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

const (
	asURI     = "msrp://as.example.org:9000/as9ses;tcp"
	clientURI = "msrp://client.example.com:2855/cl1ses;tcp"
)

func newTestSession(t *testing.T, local, remote string, h Handler) *Session {
	t.Helper()
	s, err := NewSession(SessionConfig{Local: mustURI(t, local), Remote: []URI{mustURI(t, remote)}, Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func passiveWithPeer(t *testing.T, b Binder, cfg Config) (*Conn, *wirePeer) {
	t.Helper()
	ours, theirs := net.Pipe()
	c, err := NewPassiveConn(ours, b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, newWirePeer(t, theirs)
}

func activeWithPeer(t *testing.T, cfg Config) (*Conn, *wirePeer) {
	t.Helper()
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, newWirePeer(t, theirs)
}

// openWithPeer opens s on c and lets the raw peer accept the binding SEND.
func openWithPeer(t *testing.T, c *Conn, p *wirePeer, s *Session) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusOK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// sendLines builds a request from the client to the rcs-as session.
func sendLines(tid string, extra ...string) []string {
	return append([]string{"MSRP " + tid + " SEND", "To-Path: " + asURI, "From-Path: " + clientURI}, extra...)
}

func expectResponse(t *testing.T, p *wirePeer, tid string, code int) *Message {
	t.Helper()
	m := p.next(t)
	if m.IsRequest() || m.TransactionID != tid || m.StatusCode != code {
		t.Fatalf("got %s %s %d, want response %s %d", m.TransactionID, m.Method, m.StatusCode, tid, code)
	}
	return m
}

// sentinel sends a bodiless SEND and expects its 200 as the next message,
// proving that nothing else was sent before it.
func sentinel(t *testing.T, p *wirePeer) {
	t.Helper()
	p.send(t, sendLines("s3ntinel", "Message-ID: s3ntinel", "-------s3ntinel$")...)
	expectResponse(t, p, "s3ntinel", StatusOK)
}

type binderFunc func(c *Conn, to URI) (*Session, error)

func (f binderFunc) Bind(c *Conn, to URI) (*Session, error) { return f(c, to) }

func TestActiveSideBindsWithAnImmediateBodilessSend(t *testing.T) {
	c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()

	m := p.next(t)
	if m.Method != MethodSend || m.HasBody() || m.MessageID == "" || *m.ByteRange != (ByteRange{1, 0, 0}) {
		t.Fatalf("binding request %+v", m)
	}
	if len(m.ToPath) != 1 || m.ToPath[0].String() != asURI || m.FromPath[0].String() != clientURI {
		t.Fatalf("paths %v %v", m.ToPath, m.FromPath)
	}
	p.respond(t, m, StatusOK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.Err() != nil {
		t.Fatalf("session ended: %v", s.Err())
	}
}

func TestOpenEndsTheSessionWhenThePeerRefusesIt(t *testing.T) {
	c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusNoSession)
	if err := <-done; statusCode(err) != StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
	waitDone(t, s.Done(), "session")
}

func TestOpenGivesUpAfterTheTransactionTimeout(t *testing.T) {
	clock := newFakeClock()
	const timeout = 20 * time.Second
	c, p := activeWithPeer(t, Config{Clock: clock, TransactionTimeout: timeout})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	clock.watchTimers()
	go func() { done <- c.Open(context.Background(), s) }()
	p.next(t)
	clock.waitTimer(t, timeout)
	clock.Advance(timeout)
	if err := <-done; statusCode(err) != StatusRequestTimeout {
		t.Fatalf("Open = %v, want 408", err)
	}
}

func TestOpenStopsWhenTheContextEnds(t *testing.T) {
	c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Open(ctx, s) }()
	p.next(t)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Open = %v", err)
	}
	waitDone(t, s.Done(), "session")
}

func TestThePassiveSideNeverOpensASession(t *testing.T) {
	c, _ := passiveWithPeer(t, &Registry{}, Config{Clock: newFakeClock()})
	s := newTestSession(t, asURI, clientURI, newRecorder())
	if err := c.Open(context.Background(), s); !errors.Is(err, ErrPassive) {
		t.Fatalf("Open = %v, want ErrPassive", err)
	}
}

func TestPassiveSideBindsASessionOnItsFirstRequest(t *testing.T) {
	reg := &Registry{}
	h := newRecorder()
	s := newTestSession(t, asURI, clientURI, h)
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})

	p.send(t, sendLines("b1nd", "Message-ID: b1nd", "Byte-Range: 1-0/0", "-------b1nd$")...)
	resp := expectResponse(t, p, "b1nd", StatusOK)
	if resp.ToPath[0].String() != clientURI || resp.FromPath[0].String() != asURI {
		t.Fatalf("response paths %v %v", resp.ToPath, resp.FromPath)
	}

	p.send(t, sendLines("tr2x", "Message-ID: msg2", "Byte-Range: 1-5/5", "Content-Type: text/plain", "", "hello", "-------tr2x$")...)
	expectResponse(t, p, "tr2x", StatusOK)
	if m := h.message(t); string(m.Body) != "hello" || m.MessageID != "msg2" {
		t.Fatalf("delivered %+v", m)
	}
}

func TestRequestsForUnknownSessionsGet481(t *testing.T) {
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, newRecorder())); err != nil {
		t.Fatal(err)
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	for tid, to := range map[string]string{
		"0ther": "To-Path: msrp://as.example.org:9000/unknown;tcp",
		"h0st":  "To-Path: msrp://as2.example.org:9000/as9ses;tcp", // same session-id, other host
		"tw0p":  "To-Path: " + asURI + " " + clientURI,             // §7.3: exactly one URI on arrival
	} {
		p.send(t, "MSRP "+tid+" SEND", to, "From-Path: "+clientURI, "Message-ID: "+tid, "-------"+tid+"$")
		expectResponse(t, p, tid, StatusNoSession)
	}
}

func TestASessionBoundToOneConnectionIsRefusedOnAnotherWith506(t *testing.T) {
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, newRecorder())); err != nil {
		t.Fatal(err)
	}
	_, first := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	_, second := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	first.send(t, sendLines("f1rst", "Message-ID: f1rst", "-------f1rst$")...)
	expectResponse(t, first, "f1rst", StatusOK)
	second.send(t, sendLines("s3cond", "Message-ID: s3cond", "-------s3cond$")...)
	expectResponse(t, second, "s3cond", StatusSessionInUse)
	// The session keeps working where it is bound.
	sentinel(t, first)
}

func TestBinderErrorsChooseTheResponseCode(t *testing.T) {
	tests := []struct {
		err  error
		code int
	}{
		{&StatusError{Code: StatusForbidden}, StatusForbidden},
		{ErrNoSession, StatusNoSession},
		{ErrSessionInUse, StatusSessionInUse},
		{errors.New("lookup failed"), StatusNoSession},
		{nil, StatusNoSession}, // a binder that finds nothing
	}
	for _, tt := range tests {
		b := binderFunc(func(*Conn, URI) (*Session, error) { return nil, tt.err })
		_, p := passiveWithPeer(t, b, Config{Clock: newFakeClock()})
		p.send(t, sendLines("b1nder", "Message-ID: b1nder", "-------b1nder$")...)
		expectResponse(t, p, "b1nder", tt.code)
	}
}

func TestABinderCannotHandOutASessionForAnotherURI(t *testing.T) {
	other := newTestSession(t, "msrp://as.example.org:9000/elsewhere;tcp", clientURI, newRecorder())
	b := binderFunc(func(*Conn, URI) (*Session, error) { return other, nil })
	_, p := passiveWithPeer(t, b, Config{Clock: newFakeClock()})
	p.send(t, sendLines("b1nder", "Message-ID: b1nder", "-------b1nder$")...)
	expectResponse(t, p, "b1nder", StatusNoSession)
}

func TestPassiveSessionWaitsForTheFirstRequestBeforeSending(t *testing.T) {
	reg := &Registry{}
	s := newTestSession(t, asURI, clientURI, newRecorder())
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Send(ctx, Outgoing{ContentType: "text/plain", Body: []byte("early")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send before binding = %v", err)
	}

	sent := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("later")})
		sent <- err
	}()
	p.send(t, sendLines("b1nd", "Message-ID: b1nd", "-------b1nd$")...)
	var gotResponse, gotSend bool
	for range 2 {
		m := p.next(t)
		switch {
		case !m.IsRequest() && m.TransactionID == "b1nd":
			gotResponse = true
		case m.Method == MethodSend && string(m.Body) == "later":
			gotSend = true
			if m.ToPath[0].String() != clientURI || m.FromPath[0].String() != asURI {
				t.Fatalf("paths %v %v", m.ToPath, m.FromPath)
			}
		}
	}
	if !gotResponse || !gotSend {
		t.Fatalf("response %v, send %v", gotResponse, gotSend)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

func TestSeveralSessionsShareOneConnection(t *testing.T) {
	reg := &Registry{}
	h1, h2 := newRecorder(), newRecorder()
	s1 := newTestSession(t, asURI, clientURI, h1)
	s2 := newTestSession(t, "msrp://as.example.org:9000/as9two;tcp", "msrp://client.example.com:2855/cl1two;tcp", h2)
	for _, s := range []*Session{s1, s2} {
		if err := reg.Add(s); err != nil {
			t.Fatal(err)
		}
	}
	_, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	p.send(t, sendLines("0ne1", "Message-ID: msg1", "Content-Type: text/plain", "", "for one", "-------0ne1$")...)
	expectResponse(t, p, "0ne1", StatusOK)
	p.send(t, "MSRP tw02 SEND", "To-Path: msrp://as.example.org:9000/as9two;tcp", "From-Path: msrp://client.example.com:2855/cl1two;tcp",
		"Message-ID: msg2", "Content-Type: text/plain", "", "for two", "-------tw02$")
	resp := expectResponse(t, p, "tw02", StatusOK)
	if resp.FromPath[0].SessionID != "as9two" {
		t.Fatalf("answered from %v", resp.FromPath)
	}
	if string(h1.message(t).Body) != "for one" || string(h2.message(t).Body) != "for two" {
		t.Fatal("messages crossed sessions")
	}
}

// endpoints connects an active and a passive Conn of this package.
func endpoints(t *testing.T, cfg Config, aliceH, bobH Handler) (alice, bob *Session) {
	t.Helper()
	a, b := net.Pipe()
	reg := &Registry{}
	bob = newTestSession(t, asURI, clientURI, bobH)
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	pc, err := NewPassiveConn(b, reg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := NewActiveConn(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ac.Close(); _ = pc.Close() })
	alice = newTestSession(t, clientURI, asURI, aliceH)
	if err := ac.Open(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	return alice, bob
}

func TestChunkedMessagesAreReassembledAndConfirmed(t *testing.T) {
	aliceH, bobH := newRecorder(), newRecorder()
	alice, _ := endpoints(t, Config{Clock: newFakeClock()}, aliceH, bobH)
	body := bodyOf(5000)
	id, err := alice.Send(context.Background(), Outgoing{
		ContentType: "message/cpim", Body: body, SuccessReport: true,
		Header: []Field{{"Content-Disposition", "render"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := bobH.message(t)
	if !equalBodies(m.Body, body) || m.MessageID != id || m.ContentType != "message/cpim" {
		t.Fatalf("delivered %d octets of %q", len(m.Body), m.MessageID)
	}
	if v, _ := m.Get("Content-Disposition"); v != "render" {
		t.Fatal("MIME header lost")
	}
	r := aliceH.report(t)
	if r.MessageID != id || r.Code != StatusOK || r.Range != (ByteRange{1, 5000, 5000}) {
		t.Fatalf("success report %+v", r)
	}
}

func TestHandlerErrorsBecomeFailureReports(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code int
	}{
		{&StatusError{Code: StatusMessageTooLarge}, StatusMessageTooLarge},
		{errors.New("storage unavailable"), StatusForbidden},
	} {
		aliceH, bobH := newRecorder(), newRecorder()
		bobH.failWith(tt.err)
		alice, _ := endpoints(t, Config{Clock: newFakeClock()}, aliceH, bobH)
		id, err := alice.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("hi")})
		if err != nil {
			t.Fatal(err)
		}
		bobH.message(t)
		if r := aliceH.report(t); r.MessageID != id || r.Code != tt.code {
			t.Fatalf("report %+v, want %d", r, tt.code)
		}
	}
}

func TestNoReportsWhenTheSenderAsksForNone(t *testing.T) {
	aliceH, bobH := newRecorder(), newRecorder()
	bobH.failWith(errors.New("refused"))
	alice, _ := endpoints(t, Config{Clock: newFakeClock()}, aliceH, bobH)
	if _, err := alice.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("hi"), FailureReport: ReportNo}); err != nil {
		t.Fatal(err)
	}
	bobH.message(t)
	// The next report alice sees is for a later message, not the first.
	bobH.failWith(nil)
	id, _ := alice.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("again"), SuccessReport: true})
	bobH.message(t)
	if r := aliceH.report(t); r.MessageID != id || r.Code != StatusOK {
		t.Fatalf("report %+v", r)
	}
}

func boundPassive(t *testing.T, h Handler, cfg Config, accept ...string) (*Session, *wirePeer) {
	t.Helper()
	reg := &Registry{}
	s, err := NewSession(SessionConfig{Local: mustURI(t, asURI), Remote: []URI{mustURI(t, clientURI)}, Handler: h, AcceptTypes: accept})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	if cfg.Clock == nil {
		cfg.Clock = newFakeClock()
	}
	_, p := passiveWithPeer(t, reg, cfg)
	sentinel(t, p)
	return s, p
}

func TestFailureReportNoSuppressesEveryResponse(t *testing.T) {
	h := newRecorder()
	_, p := boundPassive(t, h, Config{})
	p.send(t, sendLines("n0resp", "Message-ID: msg1", "Failure-Report: no", "Content-Type: text/plain", "", "hi", "-------n0resp$")...)
	p.send(t, sendLines("n0resp2", "Message-ID: msg2", "Failure-Report: no", "Content-Type: image/x-nope", "", "hi", "-------n0resp2+")...)
	h.message(t)
	sentinel(t, p)
}

func TestFailureReportPartialSuppressesOnlySuccess(t *testing.T) {
	h := newRecorder()
	_, p := boundPassive(t, h, Config{}, "text/plain")
	p.send(t, sendLines("p4rt1", "Message-ID: msg1", "Failure-Report: partial", "Content-Type: text/plain", "", "hi", "-------p4rt1$")...)
	h.message(t)
	sentinel(t, p)
	p.send(t, sendLines("p4rt2", "Message-ID: msg2", "Failure-Report: partial", "Content-Type: image/png", "", "hi", "-------p4rt2$")...)
	expectResponse(t, p, "p4rt2", StatusUnsupportedMediaType)
}

func TestMediaTypesOutsideAcceptTypesGet415(t *testing.T) {
	h := newRecorder()
	_, p := boundPassive(t, h, Config{}, "message/cpim", "Text/*")
	for tid, ct := range map[string]string{"cp1m": "message/cpim", "t3xt": "text/plain;charset=utf-8", "im4ge": "image/png", "msgx": "message/imdn+xml"} {
		p.send(t, sendLines(tid, "Message-ID: "+tid, "Content-Type: "+ct, "", "x", "-------"+tid+"$")...)
		want := StatusOK
		if ct == "image/png" || ct == "message/imdn+xml" {
			want = StatusUnsupportedMediaType
		}
		expectResponse(t, p, tid, want)
	}
	s := &Session{accept: []string{"*"}}
	if !s.accepts("image/png") {
		t.Fatal(`"*" must accept everything`)
	}
}

func TestExtensionMethodsGet501UnlessTheHandlerServesThem(t *testing.T) {
	nick := []string{"MSRP n1ck NICKNAME", "To-Path: " + asURI, "From-Path: " + clientURI, `Use-Nickname: "Alice"`, "-------n1ck$"}
	_, p := boundPassive(t, newRecorder(), Config{})
	p.send(t, nick...)
	expectResponse(t, p, "n1ck", StatusNotImplemented)

	h := nicknameRecorder{newRecorder()}
	h.code = 425
	_, p = boundPassive(t, h, Config{})
	p.send(t, nick...)
	resp := expectResponse(t, p, "n1ck", 425)
	if len(resp.ToPath) != 1 || resp.ToPath[0].String() != clientURI {
		t.Fatalf("To-Path %v", resp.ToPath)
	}
	if m := <-h.requests; m.Method != MethodNickname {
		t.Fatalf("handler got %q", m.Method)
	}
}

func TestReportsAreDeliveredAndNeverAnswered(t *testing.T) {
	h := newRecorder()
	_, p := boundPassive(t, h, Config{})
	report := func(tid, status string) []string {
		return []string{"MSRP " + tid + " REPORT", "To-Path: " + asURI, "From-Path: " + clientURI,
			"Message-ID: msg9", "Byte-Range: 1-10/10", "Status: " + status, "-------" + tid + "$"}
	}
	p.send(t, report("r3p0rt", "000 200 OK")...)
	p.send(t, report("r3p0rt2", "777 200 Elsewhere")...) // an unknown namespace means nothing (§7.3.2)
	sentinel(t, p)
	if r := h.report(t); r.MessageID != "msg9" || r.Code != 200 || r.Range != (ByteRange{1, 10, 10}) || r.Comment != "OK" {
		t.Fatalf("report %+v", r)
	}
	select {
	case r := <-h.reports:
		t.Fatalf("unexpected report %+v", r)
	default:
	}
}

func TestMalformedAndOversizedRequestsAreRefused(t *testing.T) {
	h := newRecorder()
	_, p := boundPassive(t, h, Config{MaxMessageSize: 8})
	p.send(t, sendLines("b4d1", "Message-ID: msg1", "Byte-Range: one", "-------b4d1$")...)
	expectResponse(t, p, "b4d1", StatusBadRequest)
	p.send(t, sendLines("b1g1", "Message-ID: msg1", "Content-Type: text/plain", "", "123456789", "-------b1g1$")...)
	expectResponse(t, p, "b1g1", StatusMessageTooLarge)
	p.send(t, sendLines("0ver", "Message-ID: msg1", "Byte-Range: 1-2/8", "Content-Type: text/plain", "", "1234", "-------0ver+")...)
	expectResponse(t, p, "0ver", StatusBadRequest)
	p.send(t, sendLines("b1g2", "Message-ID: msg2", "Byte-Range: 1-4/20", "Content-Type: text/plain", "", "1234", "-------b1g2+")...)
	expectResponse(t, p, "b1g2", StatusMessageTooLarge)
	big := make([]byte, maxNonSendBody+1)
	for i := range big {
		big[i] = 'n'
	}
	p.send(t, "MSRP b1g3 NICKNAME", "To-Path: "+asURI, "From-Path: "+clientURI, "Content-Type: text/plain", "", string(big), "-------b1g3$")
	expectResponse(t, p, "b1g3", StatusBadRequest)
	// Malformed responses and responses nobody waits for are dropped.
	p.send(t, "MSRP stray1 200 OK", "To-Path: "+asURI, "From-Path: "+clientURI, "-------stray1$")
	p.send(t, "MSRP stray2 200 OK", "From-Path: "+clientURI, "-------stray2$")
	sentinel(t, p)
}

func TestASessionWithoutHandlerRefusesContent(t *testing.T) {
	_, p := boundPassive(t, nil, Config{})
	p.send(t, sendLines("n0hd", "Message-ID: msg1", "Content-Type: text/plain", "", "x", "-------n0hd$")...)
	expectResponse(t, p, "n0hd", StatusForbidden)
}

func TestUnansweredRequestsTimeOutWith408(t *testing.T) {
	clock := newFakeClock()
	h := newRecorder()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	id, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	chunk := p.next(t)
	clock.Advance(DefaultTransactionTimeout - time.Second)
	clock.Advance(time.Second)
	if r := h.report(t); r.MessageID != id || r.Code != StatusRequestTimeout || r.Range != (ByteRange{1, 2, 2}) {
		t.Fatalf("report %+v", r)
	}
	// A response after the timeout finds no transaction.
	p.respond(t, chunk, StatusOK)
	p.sendMessage(t, &Message{TransactionID: "r3p0rt", Method: MethodReport, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: "late", Status: &Status{Code: 200}})
	if r := h.report(t); r.MessageID != "late" {
		t.Fatalf("report %+v", r)
	}
}

func TestPartialRequestsRunNoTimer(t *testing.T) {
	clock := newFakeClock()
	h := newRecorder()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("hi"), FailureReport: ReportPartial}); err != nil {
		t.Fatal(err)
	}
	chunk := p.next(t)
	clock.Advance(DefaultTransactionTimeout)
	// A failure response after that is too late to be matched; a later
	// REPORT is the first thing the handler sees.
	p.respond(t, chunk, StatusForbidden)
	p.sendMessage(t, NewReportForTest(t, chunk, 200))
	if r := h.report(t); r.Code != 200 {
		t.Fatalf("report %+v", r)
	}
}

func TestPartialRequestsStillReportFailures(t *testing.T) {
	h := newRecorder()
	c, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	s := newTestSession(t, clientURI, asURI, h)
	openWithPeer(t, c, p, s)
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("hi"), FailureReport: ReportPartial}); err != nil {
		t.Fatal(err)
	}
	chunk := p.next(t)
	p.respond(t, chunk, StatusForbidden)
	if r := h.report(t); r.Code != StatusForbidden {
		t.Fatalf("report %+v", r)
	}
}

// NewReportForTest builds the REPORT a peer would send about req.
func NewReportForTest(t *testing.T, req *Message, code int) *Message {
	t.Helper()
	r := NewReport(req, req.ToPath[0], req.Range(), code)
	r.TransactionID = "r3p0rt"
	return r
}

// activeWithSyncPeer opens a session toward a peer that reads on demand.
func activeWithSyncPeer(t *testing.T, cfg Config, h Handler) (*Session, *syncPeer) {
	t.Helper()
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	p := newSyncPeer(t, theirs)
	s := newTestSession(t, clientURI, asURI, h)
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	p.respond(t, p.next(t), StatusOK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestSendStopsAfterThePeerRefusesAChunk(t *testing.T) {
	h := newRecorder()
	s, p := activeWithSyncPeer(t, Config{Clock: newFakeClock(), ChunkSize: 4}, h)
	result := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("abcdefghijkl")})
		result <- err
	}()
	first := p.next(t)
	p.respond(t, first, StatusMessageTooLarge)
	if r := h.report(t); r.Code != StatusMessageTooLarge || r.Range != (ByteRange{1, 4, 12}) {
		t.Fatalf("report %+v", r)
	}
	// From here on read eagerly: the second chunk may or may not have been
	// on its way when the refusal came, but the third is checked against
	// the refusal only after the second has been read.
	rest := make(chan *Message, 8)
	go func() {
		for {
			_ = p.nc.SetReadDeadline(time.Now().Add(hangGuard))
			m, err := p.r.ReadMessage(DefaultMaxMessageSize)
			if err != nil {
				close(rest)
				return
			}
			rest <- m
		}
	}()
	if err := <-result; statusCode(err) != StatusMessageTooLarge {
		t.Fatalf("Send = %v, want 413", err)
	}
	newID, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	for m := range rest {
		if m.MessageID == newID {
			return
		}
		if m.MessageID == first.MessageID && m.Range().Start > 5 {
			t.Fatalf("more of the refused message was sent: %v", m.ByteRange)
		}
	}
	t.Fatal("the next message never arrived")
}

func TestCancelledSendEndsTheMessageWithAnAbortChunk(t *testing.T) {
	s, p := activeWithSyncPeer(t, Config{Clock: newFakeClock(), ChunkSize: 4}, newRecorder())
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := s.Send(ctx, Outgoing{ContentType: "text/plain", Body: []byte("abcdefghijklmnop")})
		result <- err
	}()
	last := p.next(t)
	cancel()
	for {
		m := p.next(t)
		if m.Continuation == FlagAbort {
			if len(m.Body) != 0 || m.Range().Start != last.Range().End+1 || m.MessageID != last.MessageID {
				t.Fatalf("abort chunk %+v after %v", m.ByteRange, last.ByteRange)
			}
			break
		}
		if m.Continuation == FlagEnd {
			t.Fatal("the whole message went out after the context ended")
		}
		last = m
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Send = %v", err)
	}
}

func TestSendNeedsAContentType(t *testing.T) {
	s := newTestSession(t, clientURI, asURI, newRecorder())
	if _, err := s.Send(context.Background(), Outgoing{Body: []byte("x")}); err == nil {
		t.Fatal("sent content without a Content-Type")
	}
}

func TestKeepAliveSendsABodilessSendAfterAQuietInterval(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)

	clock.Advance(DefaultKeepAliveInterval - time.Second)
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if m := p.next(t); !m.HasBody() {
		t.Fatal("keep-alive sent although the session was busy")
	} else {
		p.respond(t, m, StatusOK)
	}

	// Traffic received counts as well.
	clock.Advance(DefaultKeepAliveInterval - time.Second)
	p.sendMessage(t, &Message{TransactionID: "fr0mpeer", Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: "fr0mpeer"})
	expectResponse(t, p, "fr0mpeer", StatusOK)
	clock.Advance(DefaultKeepAliveInterval - time.Second)
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("y")}); err != nil {
		t.Fatal(err)
	}
	if m := p.next(t); string(m.Body) != "y" {
		t.Fatalf("got %+v, want the y chunk first", m)
	} else {
		p.respond(t, m, StatusOK)
	}

	clock.Advance(DefaultKeepAliveInterval)
	ka := p.next(t)
	if ka.Method != MethodSend || ka.HasBody() || *ka.ByteRange != (ByteRange{1, 0, 0}) || ka.FromPath[0].String() != clientURI {
		t.Fatalf("keep-alive %+v", ka)
	}
	p.respond(t, ka, StatusOK)
	// A request from the peer is answered only after the response before it
	// has been handled, so the keep-alive's timer is gone before time moves.
	p.sendMessage(t, &Message{TransactionID: "syncsync", Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: "syncsync"})
	expectResponse(t, p, "syncsync", StatusOK)
	clock.Advance(DefaultKeepAliveInterval)
	p.respond(t, p.next(t), StatusOK)
	if s.Err() != nil || c.Err() != nil {
		t.Fatalf("session %v, connection %v", s.Err(), c.Err())
	}
}

func TestAnUnansweredKeepAliveClosesTheConnection(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	clock.Advance(DefaultKeepAliveInterval)
	p.next(t)
	clock.Advance(DefaultTransactionTimeout)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrKeepAliveTimeout) || !errors.Is(s.Err(), ErrConnClosed) {
		t.Fatalf("connection %v, session %v", c.Err(), s.Err())
	}
	p.closed(t)
}

func TestARefusedKeepAliveEndsTheSession(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	clock.Advance(DefaultKeepAliveInterval)
	p.respond(t, p.next(t), StatusNoSession)
	waitDone(t, s.Done(), "session")
	if statusCode(s.Err()) != StatusNoSession || c.Err() != nil {
		t.Fatalf("session %v, connection %v", s.Err(), c.Err())
	}
}

func TestKeepAlivesCanBeTurnedOff(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: -1})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	clock.Advance(10 * DefaultKeepAliveInterval)
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if m := p.next(t); string(m.Body) != "x" {
		t.Fatalf("got %+v", m)
	}
}

func TestAConnectionThatNamesNoSessionIsClosed(t *testing.T) {
	clock := newFakeClock()
	c, p := passiveWithPeer(t, &Registry{}, Config{Clock: clock})
	clock.Advance(DefaultUnboundTimeout)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrUnbound) {
		t.Fatalf("Err = %v", c.Err())
	}
	p.closed(t)
}

func TestAConnectionIsClosedSomeTimeAfterItsLastSessionEnds(t *testing.T) {
	clock := newFakeClock()
	reg := &Registry{}
	s := newTestSession(t, asURI, clientURI, newRecorder())
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	c, p := passiveWithPeer(t, reg, Config{Clock: clock})
	clock.Advance(DefaultUnboundTimeout / 2)
	sentinel(t, p)
	clock.Advance(DefaultUnboundTimeout)
	if c.Err() != nil {
		t.Fatalf("closed while carrying a session: %v", c.Err())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Err(), ErrSessionClosed) {
		t.Fatalf("session Err = %v", s.Err())
	}
	clock.Advance(DefaultUnboundTimeout)
	waitDone(t, c.Done(), "connection")
}

func TestAFailedConnectionEndsEverySessionOnIt(t *testing.T) {
	reg := &Registry{}
	s := newTestSession(t, asURI, clientURI, newRecorder())
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	c, p := passiveWithPeer(t, reg, Config{Clock: newFakeClock()})
	sentinel(t, p)
	_ = p.nc.Close()
	waitDone(t, s.Done(), "session")
	if !errors.Is(s.Err(), ErrConnClosed) || c.Err() == nil {
		t.Fatalf("session %v, connection %v", s.Err(), c.Err())
	}
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain"}); err == nil {
		t.Fatal("sent on a failed session")
	}
	// A failed session cannot be bound again (§5.4).
	if _, err := reg.Bind(c, s.Local()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Bind after failure = %v", err)
	}
}

func TestGarbageOnTheWireClosesTheConnection(t *testing.T) {
	c, p := passiveWithPeer(t, &Registry{}, Config{Clock: newFakeClock()})
	p.send(t, "GET / HTTP/1.1")
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrFraming) {
		t.Fatalf("Err = %v", c.Err())
	}
}

func TestWritingToAClosedConnectionFails(t *testing.T) {
	c, _ := activeWithPeer(t, Config{Clock: newFakeClock()})
	_ = c.Close()
	if !errors.Is(c.Err(), ErrConnClosed) {
		t.Fatalf("Err = %v", c.Err())
	}
	if err := c.write(context.Background(), []byte("x")); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("write = %v", err)
	}
	if err := c.sendRequest(context.Background(), &Message{Method: MethodSend, ToPath: []URI{mustURI(t, asURI)}, FromPath: []URI{mustURI(t, clientURI)}, MessageID: "msg1"},
		sendWait, func(int, string) {}); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("sendRequest = %v", err)
	}
	s := newTestSession(t, clientURI, asURI, nil)
	if err := c.Open(context.Background(), s); err == nil {
		t.Fatal("opened a session on a closed connection")
	}
}

func TestAWriteThatFailsClosesTheConnection(t *testing.T) {
	ours, theirs := net.Pipe()
	c, err := NewActiveConn(ours, Config{Clock: newFakeClock()})
	if err != nil {
		t.Fatal(err)
	}
	_ = theirs.Close()
	if err := c.write(context.Background(), []byte("x")); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("write = %v", err)
	}
	waitDone(t, c.Done(), "connection")
}

func TestARandomSourceThatRepeatsItselfIsDetected(t *testing.T) {
	c, _ := activeWithPeer(t, Config{Clock: newFakeClock(), Rand: zeroReader{}})
	tid, err := c.newTransactionID(nil)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.pending[tid] = &transaction{}
	c.mu.Unlock()
	if _, err := c.newTransactionID(nil); err == nil {
		t.Fatal("reused a transaction id that is in flight")
	}
	if _, err := c.newTransactionID([]byte("-------" + tid)); err == nil {
		t.Fatal("chose a transaction id that occurs in the body")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestConfigRefusesChunksLargerThan2048(t *testing.T) {
	ours, theirs := net.Pipe()
	defer ours.Close()
	defer theirs.Close()
	if _, err := NewActiveConn(ours, Config{ChunkSize: 4096}); err == nil {
		t.Fatal("accepted a chunk size that would need interruption")
	}
	if _, err := NewPassiveConn(ours, nil, Config{}); err == nil {
		t.Fatal("accepted a passive connection without a binder")
	}
}

func TestNewSessionNeedsBothEnds(t *testing.T) {
	local, remote := mustURI(t, asURI), mustURI(t, clientURI)
	for name, cfg := range map[string]SessionConfig{
		"no session-id": {Local: mustURI(t, "msrp://as.example.org:9000;tcp"), Remote: []URI{remote}},
		"no remote":     {Local: local},
		"bad remote":    {Local: local, Remote: []URI{{Host: "a b"}}},
	} {
		if _, err := NewSession(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := NewSession(SessionConfig{Local: local, Remote: []URI{remote}})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Local().Equal(local) || !s.Remote()[0].Equal(remote) {
		t.Fatal("accessors lost the URIs")
	}
}

func TestRegistryHandsOutEachSessionOnce(t *testing.T) {
	reg := &Registry{}
	s := newTestSession(t, asURI, clientURI, nil)
	if err := reg.Add(s); err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(newTestSession(t, asURI, clientURI, nil)); err == nil {
		t.Fatal("registered one session id twice")
	}
	if got, err := reg.Bind(nil, mustURI(t, asURI)); err != nil || got != s {
		t.Fatalf("Bind = %v, %v", got, err)
	}
	_ = s.Close()
	if _, err := reg.Bind(nil, mustURI(t, asURI)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Bind after Close = %v", err)
	}
	closed := newTestSession(t, asURI, clientURI, nil)
	_ = closed.Close()
	if err := reg.Add(closed); err == nil {
		t.Fatal("registered a closed session")
	}
}

// autoPeer answers every request it reads with 200 and counts the
// connections it serves.
func autoPeer(t *testing.T, nc net.Conn) {
	t.Helper()
	p := newWirePeer(t, nc)
	go func() {
		for m := range p.msgs {
			if m.IsRequest() && m.Method != MethodReport {
				resp, _ := NewResponse(m, StatusOK, "OK")
				b, _ := resp.Marshal()
				if _, err := nc.Write(b); err != nil {
					return
				}
			}
		}
	}()
}

func TestPoolSharesOneConnectionPerSchemeHostAndPort(t *testing.T) {
	var dials atomic.Int32
	pool := &Pool{
		Config: Config{Clock: newFakeClock()},
		Dial: func(_ context.Context, to URI) (net.Conn, error) {
			dials.Add(1)
			ours, theirs := net.Pipe()
			autoPeer(t, theirs)
			return ours, nil
		},
	}
	t.Cleanup(func() { _ = pool.Close() })
	open := func(local, remote string) *Session {
		s := newTestSession(t, local, remote, newRecorder())
		if err := pool.Open(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	first := open("msrp://relay.internal:2855/r1;tcp", "msrp://as1.internal:9000/a1;tcp")
	open("msrp://relay.internal:2855/r2;tcp", "msrp://AS1.internal:9000/a2;tcp")
	if dials.Load() != 1 {
		t.Fatalf("%d dials for one host", dials.Load())
	}
	open("msrp://relay.internal:2855/r3;tcp", "msrp://as2.internal:9000/a3;tcp")
	if dials.Load() != 2 {
		t.Fatalf("%d dials for two hosts", dials.Load())
	}
	first.mu.Lock()
	c := first.conn
	first.mu.Unlock()
	_ = c.Close()
	open("msrp://relay.internal:2855/r4;tcp", "msrp://as1.internal:9000/a4;tcp")
	if dials.Load() != 3 {
		t.Fatalf("a closed connection was reused (%d dials)", dials.Load())
	}
}

func TestPoolReportsDialProblems(t *testing.T) {
	s := newTestSession(t, clientURI, asURI, nil)
	if err := (&Pool{}).Open(context.Background(), s); err == nil {
		t.Fatal("opened without a Dial function")
	}
	boom := errors.New("connection refused")
	p := &Pool{Dial: func(context.Context, URI) (net.Conn, error) { return nil, boom }}
	if err := p.Open(context.Background(), s); !errors.Is(err, boom) {
		t.Fatalf("Open = %v", err)
	}
	bad := &Pool{Config: Config{ChunkSize: 1 << 20}, Dial: func(context.Context, URI) (net.Conn, error) {
		ours, _ := net.Pipe()
		return ours, nil
	}}
	if err := bad.Open(context.Background(), s); err == nil {
		t.Fatal("dialled with an invalid Config")
	}
}

func TestPoolKeepsTheFirstOfTwoConcurrentDials(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{}, 2)
	pool := &Pool{
		Config: Config{Clock: newFakeClock()},
		Dial: func(context.Context, URI) (net.Conn, error) {
			entered <- struct{}{}
			<-release
			ours, theirs := net.Pipe()
			autoPeer(t, theirs)
			return ours, nil
		},
	}
	t.Cleanup(func() { _ = pool.Close() })
	errs := make(chan error, 2)
	for _, id := range []string{"r1", "r2"} {
		s := newTestSession(t, "msrp://relay.internal:2855/"+id+";tcp", "msrp://as1.internal:9000/a"+id+";tcp", nil)
		go func() { errs <- pool.Open(context.Background(), s) }()
	}
	<-entered
	<-entered
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	pool.mu.Lock()
	n := len(pool.conns)
	pool.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d pooled connections for one host", n)
	}
}

func TestBothSidesSendingAtOnceDoNotStallEachOther(t *testing.T) {
	// Over an unbuffered pipe, two read loops that each wrote their
	// answers in place would block on each other at once.
	aliceH, bobH := newRecorder(), newRecorder()
	aliceH.messages, bobH.messages = make(chan *Message, 100), make(chan *Message, 100)
	alice, bob := endpoints(t, Config{Clock: newFakeClock()}, aliceH, bobH)
	errs := make(chan error, 2)
	for _, s := range []*Session{alice, bob} {
		go func() {
			for range 50 {
				if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: bodyOf(3000)}); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for range 50 {
		aliceH.message(t)
		bobH.message(t)
	}
}

func TestAPeerThatNeverReadsItsAnswersIsDisconnected(t *testing.T) {
	reg := &Registry{}
	if err := reg.Add(newTestSession(t, asURI, clientURI, newRecorder())); err != nil {
		t.Fatal(err)
	}
	ours, theirs := net.Pipe()
	// The bound is a memory limit; a small one shows it holding quickly.
	c, err := NewPassiveConn(ours, reg, Config{Clock: newFakeClock(), MaxQueuedBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = theirs.Close() })
	req := []byte(wire(sendLines("fl00d", "Message-ID: fl00d", "-------fl00d$")...))
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
}

func TestKeepAlivesDefaultToWellInsideTheLoadBalancerIdleTimeout(t *testing.T) {
	// NLB TLS listeners close a connection idle for 350 s (ADR 0003).
	cfg, err := Config{}.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeepAliveInterval != 240*time.Second || cfg.KeepAliveInterval >= 350*time.Second {
		t.Fatalf("default keep-alive %v", cfg.KeepAliveInterval)
	}
}

func TestTheKeepAliveIntervalIsConfigurable(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: time.Minute})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	clock.Advance(time.Minute)
	if ka := p.next(t); ka.Method != MethodSend || ka.HasBody() {
		t.Fatalf("got %+v, want a keep-alive", ka)
	}
}

func TestNoKeepAliveGoesOutWhileTheBindingSendIsUnanswered(t *testing.T) {
	// The binding SEND is itself the session's traffic; keep-alives sent
	// while it waits for its answer would each name a session the relay
	// may not know yet, and a slow relay closes a connection that names
	// unknown sessions too often (MaxFailedBinds, #204).
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: time.Second})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	bind := p.next(t)
	clock.Advance(5 * time.Second)
	p.respond(t, bind, StatusNoSession)
	if err := <-done; statusCode(err) != StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
	_ = c.Close()
	for {
		select {
		case m, ok := <-p.msgs:
			if !ok {
				return
			}
			t.Fatalf("sent %s %s while the binding SEND was unanswered", m.TransactionID, m.Method)
		case <-time.After(hangGuard):
			t.Fatal("connection stayed open")
		}
	}
}

func TestKeepAlivesStartWhenTheBindingSendIsAnswered(t *testing.T) {
	// The quiet interval counts from the answer, not from the SEND.
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: time.Second})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	done := make(chan error, 1)
	go func() { done <- c.Open(context.Background(), s) }()
	bind := p.next(t)
	clock.Advance(900 * time.Millisecond)
	p.respond(t, bind, StatusOK)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	clock.Advance(900 * time.Millisecond)
	// Its answer comes first only if no keep-alive went out before it.
	p.sendMessage(t, &Message{TransactionID: "syncsync", Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: "syncsync"})
	expectResponse(t, p, "syncsync", StatusOK)
	clock.Advance(time.Second)
	if ka := p.next(t); ka.HasBody() || *ka.ByteRange != (ByteRange{1, 0, 0}) {
		t.Fatalf("keep-alive %+v", ka)
	}
}

func TestABoundPassiveSessionSendsKeepAlives(t *testing.T) {
	// QA on #217: the passive side, the relay toward clients and rcs-as,
	// starts its keep-alives at the bind (ADR 0003).
	clock := newFakeClock()
	_, p := boundPassive(t, newRecorder(), Config{Clock: clock, KeepAliveInterval: time.Second})
	clock.Advance(time.Second)
	ka := p.next(t)
	if ka.Method != MethodSend || ka.HasBody() || *ka.ByteRange != (ByteRange{1, 0, 0}) || ka.FromPath[0].String() != asURI {
		t.Fatalf("keep-alive %+v", ka)
	}
}

func TestASessionHasOneKeepAliveOutAtATime(t *testing.T) {
	// #218: with an interval shorter than the transaction timeout, the
	// ticks while a keep-alive waits for its answer send nothing more,
	// and that keep-alive's timeout closes the connection.
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: time.Second})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	clock.Advance(time.Second)
	if ka := p.next(t); ka.HasBody() {
		t.Fatalf("keep-alive %+v", ka)
	}
	for range 5 {
		clock.Advance(time.Second)
	}
	// Its answer comes next only if no other keep-alive went out.
	p.sendMessage(t, &Message{TransactionID: "syncsync", Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: "syncsync"})
	expectResponse(t, p, "syncsync", StatusOK)
	clock.Advance(DefaultTransactionTimeout - 5*time.Second)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrKeepAliveTimeout) {
		t.Fatalf("connection %v, want the keep-alive timeout", c.Err())
	}
	for m := range p.msgs {
		if m.IsRequest() {
			t.Fatalf("sent %s %s after the first keep-alive", m.TransactionID, m.Method)
		}
	}
}

func TestAnAnsweredKeepAliveLetsTheNextGoOnTime(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock, KeepAliveInterval: time.Second})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	for i, sync := range []string{"syncsyn0", "syncsyn1", "syncsyn2"} {
		clock.Advance(time.Second)
		ka := p.next(t)
		if ka.HasBody() || *ka.ByteRange != (ByteRange{1, 0, 0}) {
			t.Fatalf("keep-alive %d %+v", i, ka)
		}
		p.respond(t, ka, StatusOK)
		// Answered before the clock moves on: a request from the peer
		// is answered only after the response before it is handled.
		p.sendMessage(t, &Message{TransactionID: sync, Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
			FromPath: []URI{mustURI(t, asURI)}, MessageID: sync})
		expectResponse(t, p, sync, StatusOK)
	}
	if s.Err() != nil || c.Err() != nil {
		t.Fatalf("session %v, connection %v", s.Err(), c.Err())
	}
}
