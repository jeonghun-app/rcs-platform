package msrp

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	relayPublicURI   = "msrp://relay.example.net:2855/rel4ypub;tcp"
	relayInternalURI = "msrp://relay.internal:2855/rel4yint;tcp"
)

// testRelay plays msrp-relay: when a client connects it bridges the
// client's session with one it opens toward rcs-as (ADR 0004).
type testRelay struct {
	t        *testing.T
	pool     *Pool
	sessions chan [2]*Session
}

func (r *testRelay) Bind(_ *Conn, to URI) (*Session, error) {
	a, err := NewSession(SessionConfig{Local: to, Remote: []URI{mustURI(r.t, clientURI)}})
	if err != nil {
		return nil, err
	}
	b, err := NewSession(SessionConfig{Local: mustURI(r.t, relayInternalURI), Remote: []URI{mustURI(r.t, asURI)}})
	if err != nil {
		return nil, err
	}
	if err := Bridge(a, b); err != nil {
		return nil, err
	}
	if err := r.pool.Open(context.Background(), b); err != nil {
		_ = a.Close()
		return nil, err
	}
	r.sessions <- [2]*Session{a, b}
	return a, nil
}

// relayRig is a relay with raw peers on both sides: the client, and the
// rcs-as instance the relay dials.
type relayRig struct {
	clock  *fakeClock
	client *wirePeer
	as     *wirePeer
	a, b   *Session
}

func newRelayRig(t *testing.T, clientCfg Config) *relayRig {
	t.Helper()
	clock := newFakeClock()
	clientCfg.Clock = clock
	asEnds := make(chan net.Conn, 1)
	pool := &Pool{
		Config: Config{Clock: clock, TransactionTimeout: clientCfg.TransactionTimeout},
		Dial: func(context.Context, URI) (net.Conn, error) {
			ours, theirs := net.Pipe()
			asEnds <- theirs
			return ours, nil
		},
	}
	t.Cleanup(func() { _ = pool.Close() })
	relay := &testRelay{t: t, pool: pool, sessions: make(chan [2]*Session, 1)}
	_, client := passiveWithPeer(t, relay, clientCfg)

	// The client binds with a bodiless SEND; the relay opens its side
	// toward rcs-as, which accepts.
	client.send(t, "MSRP cl1b1nd SEND", "To-Path: "+relayPublicURI, "From-Path: "+clientURI, "Message-ID: cl1b1nd", "-------cl1b1nd$")
	as := newWirePeer(t, <-asEnds)
	bind := as.next(t)
	if bind.ToPath[0].String() != asURI || bind.FromPath[0].String() != relayInternalURI || bind.HasBody() {
		t.Fatalf("relay binding toward rcs-as %+v", bind)
	}
	as.respond(t, bind, StatusOK)
	expectResponse(t, client, "cl1b1nd", StatusOK)
	pair := <-relay.sessions
	return &relayRig{clock: clock, client: client, as: as, a: pair[0], b: pair[1]}
}

func clientSend(tid string, extra ...string) []string {
	return append([]string{"MSRP " + tid + " SEND", "To-Path: " + relayPublicURI, "From-Path: " + clientURI}, extra...)
}

// clientSentinel proves nothing reached the client before it.
func (r *relayRig) clientSentinel(t *testing.T) {
	t.Helper()
	r.client.send(t, clientSend("cs3ntnl", "Message-ID: cs3ntnl", "-------cs3ntnl$")...)
	expectResponse(t, r.client, "cs3ntnl", StatusOK)
}

// asSentinel proves nothing reached rcs-as before it.
func (r *relayRig) asSentinel(t *testing.T) {
	t.Helper()
	r.client.send(t, clientSend("as3ntnl", "Message-ID: as3ntnl", "Content-Type: text/plain", "", "sentinel", "-------as3ntnl$")...)
	m := r.as.next(t)
	if string(m.Body.Bytes()) != "sentinel" {
		t.Fatalf("rcs-as got %s %v before the sentinel", m.Method, m.ByteRange)
	}
	r.as.respond(t, m, StatusOK)
	expectResponse(t, r.client, "as3ntnl", StatusOK)
}

func TestRelayCarriesAMessageBetweenTwoEndpoints(t *testing.T) {
	clock := newFakeClock()
	reg := &Registry{}
	bobH := newRecorder()
	bob := newTestSession(t, asURI, relayInternalURI, bobH)
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	pool := &Pool{
		Config: Config{Clock: clock},
		Dial: func(context.Context, URI) (net.Conn, error) {
			ours, theirs := net.Pipe()
			c, err := NewPassiveConn(theirs, reg, Config{Clock: clock})
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = c.Close() })
			return ours, nil
		},
	}
	t.Cleanup(func() { _ = pool.Close() })
	relay := &testRelay{t: t, pool: pool, sessions: make(chan [2]*Session, 1)}

	clientEnd, relayEnd := net.Pipe()
	rc, err := NewPassiveConn(relayEnd, relay, Config{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := NewActiveConn(clientEnd, Config{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close(); _ = cc.Close() })
	aliceH := newRecorder()
	alice := newTestSession(t, clientURI, relayPublicURI, aliceH)
	if err := cc.Open(context.Background(), alice); err != nil {
		t.Fatal(err)
	}

	body := bodyOf(5000)
	id, err := alice.Send(context.Background(), Outgoing{ContentType: "message/cpim", Body: BodyOf(body), SuccessReport: true})
	if err != nil {
		t.Fatal(err)
	}
	m := bobH.message(t)
	if !equalBodies(m.Body.Bytes(), body) || m.MessageID != id || m.FromPath[0].String() != relayInternalURI {
		t.Fatalf("rcs-as got %d octets from %v", m.Body.Len(), m.FromPath)
	}
	r := aliceH.report(t)
	if r.MessageID != id || r.Code != StatusOK || r.Range != (ByteRange{1, 5000, 5000}) {
		t.Fatalf("success report %+v", r)
	}

	// And the other way.
	if _, err := bob.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("back"))}); err != nil {
		t.Fatal(err)
	}
	if m := aliceH.message(t); string(m.Body.Bytes()) != "back" || m.FromPath[0].String() != relayPublicURI {
		t.Fatalf("client got %q from %v", m.Body, m.FromPath)
	}
}

func TestRelayRewritesPathsAndTransactionIDsForTheNextHop(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.client.send(t, clientSend("cl1tid01", "Message-ID: msg1", "Byte-Range: 1-5/5", "Success-Report: yes",
		"Failure-Report: yes", "X-Ext: kept", "Content-Disposition: render", "Content-Type: text/plain", "", "hello", "-------cl1tid01$")...)
	resp := expectResponse(t, r.client, "cl1tid01", StatusOK)
	if resp.ToPath[0].String() != clientURI || resp.FromPath[0].String() != relayPublicURI {
		t.Fatalf("response paths %v %v", resp.ToPath, resp.FromPath)
	}
	fwd := r.as.next(t)
	if fwd.TransactionID == "cl1tid01" {
		t.Fatal("the transaction id crossed the relay (RFC 4976 §6.4)")
	}
	if len(fwd.ToPath) != 1 || fwd.ToPath[0].String() != asURI || len(fwd.FromPath) != 1 || fwd.FromPath[0].String() != relayInternalURI {
		t.Fatalf("forwarded paths %v %v", fwd.ToPath, fwd.FromPath)
	}
	if fwd.MessageID != "msg1" || *fwd.ByteRange != (ByteRange{1, 5, 5}) || string(fwd.Body.Bytes()) != "hello" || fwd.Continuation != FlagEnd ||
		fwd.SuccessReport != ReportYes || fwd.FailureReport != ReportYes || fwd.ContentType != "text/plain" {
		t.Fatalf("forwarded %+v", fwd)
	}
	if v, _ := fwd.Get("X-Ext"); v != "kept" {
		t.Fatal("extension header dropped")
	}
	if v, _ := fwd.Get("Content-Disposition"); v != "render" {
		t.Fatal("MIME header dropped")
	}
	r.as.respond(t, fwd, StatusOK)
	r.clientSentinel(t)
}

func TestRelayForwardsALargeChunkInPiecesAsItArrives(t *testing.T) {
	r := newRelayRig(t, Config{})
	body := bodyOf(5000)
	head := wire(clientSend("b1gchunk", "Message-ID: msg1", "Byte-Range: 1-5000/5000", "Content-Type: application/octet-stream", "")...)
	if _, err := r.client.nc.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.nc.Write(body[:2049]); err != nil {
		t.Fatal(err)
	}
	// The first piece leaves while the rest of the chunk is still to come.
	first := r.as.next(t)
	if *first.ByteRange != (ByteRange{1, 2048, 5000}) || first.Continuation != FlagMore || !equalBodies(first.Body.Bytes(), body[:2048]) {
		t.Fatalf("first piece %v %q", first.ByteRange, first.Continuation)
	}
	if _, err := r.client.nc.Write(append(append([]byte{}, body[2049:]...), "\r\n-------b1gchunk$\r\n"...)); err != nil {
		t.Fatal(err)
	}
	second, third := r.as.next(t), r.as.next(t)
	if *second.ByteRange != (ByteRange{2049, 4096, 5000}) || second.Continuation != FlagMore || !equalBodies(second.Body.Bytes(), body[2048:4096]) {
		t.Fatalf("second piece %v %q", second.ByteRange, second.Continuation)
	}
	if *third.ByteRange != (ByteRange{4097, 5000, 5000}) || third.Continuation != FlagEnd || !equalBodies(third.Body.Bytes(), body[4096:]) {
		t.Fatalf("third piece %v %q", third.ByteRange, third.Continuation)
	}
	for _, m := range []*Message{first, second, third} {
		r.as.respond(t, m, StatusOK)
	}
	expectResponse(t, r.client, "b1gchunk", StatusOK)
}

func TestRelayKeepsAnInterruptedChunkInterrupted(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.client.send(t, clientSend("1ntrpt", "Message-ID: msg1", "Byte-Range: 1-*/*", "Content-Type: text/plain", "", "abc", "-------1ntrpt+")...)
	expectResponse(t, r.client, "1ntrpt", StatusOK)
	if m := r.as.next(t); *m.ByteRange != (ByteRange{1, 3, Unknown}) || m.Continuation != FlagMore {
		t.Fatalf("forwarded %v %q", m.ByteRange, m.Continuation)
	}
	r.client.send(t, clientSend("1ntrpt2", "Message-ID: msg1", "Byte-Range: 4-*/*", "Content-Type: text/plain", "", "", "-------1ntrpt2#")...)
	expectResponse(t, r.client, "1ntrpt2", StatusOK)
	if m := r.as.next(t); *m.ByteRange != (ByteRange{4, 3, Unknown}) || m.Continuation != FlagAbort || m.Body.Len() != 0 {
		t.Fatalf("forwarded %v %q", m.ByteRange, m.Continuation)
	}
}

// Code review on #243: a client that stops inside a body, closing its
// connection after 3000 of 5000 octets, does not have the cut part
// forwarded as a finished message. rcs-as gets the first 2048 octets, as
// they arrived, and never an end ('$').
func TestRelayDoesNotFinishAMessageTheClientCutOff(t *testing.T) {
	for name, total := range map[string]string{"size unknown": "*", "size given": "5000"} {
		t.Run(name, func(t *testing.T) {
			r := newRelayRig(t, Config{})
			head := wire(clientSend("cutoff1", "Message-ID: cut1", "Byte-Range: 1-*/"+total, "Content-Type: text/plain", "")...)
			if _, err := r.client.nc.Write([]byte(head + strings.Repeat("x", 3000))); err != nil {
				t.Fatal(err)
			}
			_ = r.client.nc.Close()
			// The client's side ends on the cut; whatever the relay made of
			// the body has been handed on by then.
			select {
			case <-r.a.Done():
			case <-time.After(hangGuard):
				t.Fatal("the client's session outlived its connection")
			}
			for {
				select {
				case m, ok := <-r.as.msgs:
					if !ok {
						return
					}
					if m.IsRequest() && m.Continuation == FlagEnd {
						t.Fatalf("rcs-as got %v ending the message the client cut off", m.ByteRange)
					}
				case <-time.After(time.Second):
					// Nothing more on its way: what came was only the
					// first piece, not an end.
					return
				}
			}
		})
	}
}

func TestRelayAnswersBodilessSendsItself(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.client.send(t, clientSend("k33p", "Message-ID: k33p", "Byte-Range: 1-0/0", "-------k33p$")...)
	expectResponse(t, r.client, "k33p", StatusOK)
	r.asSentinel(t)
}

func TestRelayTurnsANextHopRefusalIntoAFailureReport(t *testing.T) {
	for _, mode := range []string{"yes", "partial"} {
		r := newRelayRig(t, Config{})
		r.client.send(t, clientSend("r3fused", "Message-ID: msg1", "Failure-Report: "+mode, "Content-Type: text/plain", "", "hi", "-------r3fused$")...)
		if mode == "yes" {
			expectResponse(t, r.client, "r3fused", StatusOK)
		}
		r.as.respond(t, r.as.next(t), StatusUnsupportedMediaType)
		rep := r.client.next(t)
		if rep.Method != MethodReport || rep.MessageID != "msg1" || rep.Status.Code != StatusUnsupportedMediaType ||
			*rep.ByteRange != (ByteRange{1, 2, Unknown}) || rep.ToPath[0].String() != clientURI || rep.FromPath[0].String() != relayPublicURI {
			t.Fatalf("Failure-Report %s: got %+v", mode, rep)
		}
	}
}

func TestRelaySendsNoReportWhenTheSenderWantsNone(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.client.send(t, clientSend("n0rep", "Message-ID: msg1", "Failure-Report: no", "Content-Type: text/plain", "", "hi", "-------n0rep$")...)
	fwd := r.as.next(t)
	if fwd.FailureReport != ReportNo {
		t.Fatalf("Failure-Report changed to %v", fwd.FailureReport)
	}
	r.as.respond(t, fwd, StatusForbidden) // against the rules; still not reported
	r.clientSentinel(t)
}

// rigTimeout tells the transaction timers in relay tests apart from the
// 30 s unbound-connection timer.
const rigTimeout = 20 * time.Second

func TestRelayReportsANextHopTimeoutAs408(t *testing.T) {
	r := newRelayRig(t, Config{TransactionTimeout: rigTimeout})
	r.clock.watchTimers()
	r.client.send(t, clientSend("t1meout", "Message-ID: msg1", "Content-Type: text/plain", "", "hi", "-------t1meout$")...)
	expectResponse(t, r.client, "t1meout", StatusOK)
	r.as.next(t)
	r.clock.waitTimer(t, rigTimeout)
	r.clock.Advance(rigTimeout)
	if rep := r.client.next(t); rep.Method != MethodReport || rep.Status.Code != StatusRequestTimeout {
		t.Fatalf("got %+v", rep)
	}
}

func TestRelayStopsForwardingAMessageTheNextHopRefused(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.client.send(t, clientSend("p4rt1", "Message-ID: msg1", "Byte-Range: 1-4/8", "Content-Type: text/plain", "", "abcd", "-------p4rt1+")...)
	expectResponse(t, r.client, "p4rt1", StatusOK)
	r.as.respond(t, r.as.next(t), StatusMessageTooLarge)
	if rep := r.client.next(t); rep.Method != MethodReport || rep.Status.Code != StatusMessageTooLarge {
		t.Fatalf("got %+v", rep)
	}
	r.client.send(t, clientSend("p4rt2", "Message-ID: msg1", "Byte-Range: 5-8/8", "Content-Type: text/plain", "", "efgh", "-------p4rt2$")...)
	expectResponse(t, r.client, "p4rt2", StatusMessageTooLarge)
	r.asSentinel(t)
}

func TestRelayRefusesMessagesOverItsSizeLimit(t *testing.T) {
	r := newRelayRig(t, Config{MaxMessageSize: 4000})
	r.client.send(t, clientSend("t00b1g", "Message-ID: msg1", "Byte-Range: 1-5000/5000", "Content-Type: text/plain", "",
		string(bodyOf(5000)), "-------t00b1g$")...)
	expectResponse(t, r.client, "t00b1g", StatusMessageTooLarge)

	// Without a declared total the relay notices on the way through and
	// abandons what it already forwarded.
	r.client.send(t, clientSend("gr0wing", "Message-ID: msg2", "Byte-Range: 1-*/*", "Content-Type: text/plain", "",
		string(bodyOf(5000)), "-------gr0wing$")...)
	first := r.as.next(t)
	if first.MessageID != "msg2" || *first.ByteRange != (ByteRange{1, 2048, Unknown}) || first.Continuation != FlagMore {
		t.Fatalf("first piece %+v", first.ByteRange)
	}
	abort := r.as.next(t)
	if abort.MessageID != "msg2" || abort.Continuation != FlagAbort || abort.Body.Len() != 0 || abort.Range().Start != 2049 {
		t.Fatalf("abort %v %q", abort.ByteRange, abort.Continuation)
	}
	expectResponse(t, r.client, "gr0wing", StatusMessageTooLarge)
	r.client.send(t, clientSend("gr0wing2", "Message-ID: msg2", "Byte-Range: 5001-5001/*", "Content-Type: text/plain", "", "z", "-------gr0wing2$")...)
	expectResponse(t, r.client, "gr0wing2", StatusMessageTooLarge)
	r.as.respond(t, first, StatusOK)
	r.asSentinel(t)
}

func TestRelayForwardsReportsWithoutAnsweringThem(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.as.send(t, "MSRP asr3p REPORT", "To-Path: "+relayInternalURI, "From-Path: "+asURI,
		"Message-ID: msg7", "Byte-Range: 1-3/3", "Status: 000 200 OK", "-------asr3p$")
	rep := r.client.next(t)
	if rep.Method != MethodReport || rep.TransactionID == "asr3p" || rep.MessageID != "msg7" || rep.Status.Code != 200 ||
		rep.ToPath[0].String() != clientURI || rep.FromPath[0].String() != relayPublicURI || *rep.ByteRange != (ByteRange{1, 3, 3}) {
		t.Fatalf("forwarded report %+v", rep)
	}
	// rcs-as gets no answer: the next thing it sees is new traffic.
	r.asSentinel(t)
}

func TestRelayForwardsSendsFromRcsAsToTheClient(t *testing.T) {
	r := newRelayRig(t, Config{})
	r.as.send(t, "MSRP fr0mas SEND", "To-Path: "+relayInternalURI, "From-Path: "+asURI,
		"Message-ID: msg8", "Byte-Range: 1-2/2", "Content-Type: message/cpim", "", "yo", "-------fr0mas$")
	expectResponse(t, r.as, "fr0mas", StatusOK)
	m := r.client.next(t)
	if m.Method != MethodSend || string(m.Body.Bytes()) != "yo" || m.ToPath[0].String() != clientURI || m.FromPath[0].String() != relayPublicURI {
		t.Fatalf("client got %+v", m)
	}
	r.client.respond(t, m, StatusOK)
	r.asSentinel(t)
}

func TestRelayCarriesExtensionMethodResponsesBack(t *testing.T) {
	r := newRelayRig(t, Config{TransactionTimeout: rigTimeout})
	r.client.send(t, "MSRP n1ckname NICKNAME", "To-Path: "+relayPublicURI, "From-Path: "+clientURI, `Use-Nickname: "Alice"`, "-------n1ckname$")
	fwd := r.as.next(t)
	if fwd.Method != MethodNickname || fwd.TransactionID == "n1ckname" || fwd.FromPath[0].String() != relayInternalURI {
		t.Fatalf("forwarded %+v", fwd)
	}
	if v, _ := fwd.Get("Use-Nickname"); v != `"Alice"` {
		t.Fatalf("Use-Nickname = %q", v)
	}
	resp, _ := NewResponse(fwd, 425, "Nickname reserved or already in use")
	r.as.sendMessage(t, resp)
	back := expectResponse(t, r.client, "n1ckname", 425)
	if back.Comment != "Nickname reserved or already in use" || back.ToPath[0].String() != clientURI {
		t.Fatalf("response %+v", back)
	}

	r.clock.watchTimers()
	r.client.send(t, "MSRP n1ck2 NICKNAME", "To-Path: "+relayPublicURI, "From-Path: "+clientURI, `Use-Nickname: "Al"`, "-------n1ck2$")
	r.as.next(t)
	r.clock.waitTimer(t, rigTimeout)
	r.clock.Advance(rigTimeout)
	expectResponse(t, r.client, "n1ck2", StatusRequestTimeout)
}

func TestBridgedSessionsEndTogether(t *testing.T) {
	r := newRelayRig(t, Config{})
	_ = r.client.nc.Close()
	waitDone(t, r.a.Done(), "client side")
	waitDone(t, r.b.Done(), "rcs-as side")
}

func TestBridgeRefusesSessionsThatCannotBeBridged(t *testing.T) {
	plain := func() *Session { return newTestSession(t, relayPublicURI, clientURI, nil) }
	a := plain()
	if err := Bridge(a, a); err == nil {
		t.Error("bridged a session to itself")
	}
	if err := Bridge(plain(), newTestSession(t, relayInternalURI, asURI, newRecorder())); err == nil {
		t.Error("bridged a session that has a Handler")
	}
	b, c := plain(), plain()
	if err := Bridge(a, b); err != nil {
		t.Fatal(err)
	}
	if err := Bridge(a, c); err == nil {
		t.Error("bridged a session twice")
	}
	conn, p := activeWithPeer(t, Config{Clock: newFakeClock()})
	d := newTestSession(t, clientURI, asURI, nil)
	openWithPeer(t, conn, p, d)
	if err := Bridge(c, d); err == nil {
		t.Error("bridged a bound session")
	}
}

// halfBridge has the client side bound and the rcs-as side never opened.
func halfBridge(t *testing.T, cfg Config) (*wirePeer, *Session) {
	t.Helper()
	a := newTestSession(t, relayPublicURI, clientURI, nil)
	b := newTestSession(t, relayInternalURI, asURI, nil)
	if err := Bridge(a, b); err != nil {
		t.Fatal(err)
	}
	reg := &Registry{}
	if err := reg.Add(a); err != nil {
		t.Fatal(err)
	}
	_, client := passiveWithPeer(t, reg, cfg)
	client.send(t, clientSend("b1nd", "Message-ID: b1nd", "-------b1nd$")...)
	expectResponse(t, client, "b1nd", StatusOK)
	return client, b
}

func TestRelayGivesUpOnAnOtherSideThatNeverBinds(t *testing.T) {
	clock := newFakeClock()
	client, _ := halfBridge(t, Config{Clock: clock, TransactionTimeout: rigTimeout})
	for _, lines := range [][]string{
		clientSend("w4it1", "Message-ID: msg1", "Content-Type: text/plain", "", "hi", "-------w4it1$"),
		{"MSRP w4it2 NICKNAME", "To-Path: " + relayPublicURI, "From-Path: " + clientURI, "-------w4it2$"},
	} {
		clock.watchTimers()
		client.send(t, lines...)
		clock.waitTimer(t, rigTimeout)
		clock.Advance(rigTimeout)
		expectResponse(t, client, strings.Fields(lines[0])[1], StatusRequestTimeout)
	}
}

func TestRelayAnswers481WhenTheOtherSideIsGone(t *testing.T) {
	client, b := halfBridge(t, Config{Clock: newFakeClock()})
	_ = b.Close()
	client.send(t, clientSend("g0ne", "Message-ID: msg1", "Content-Type: text/plain", "", "hi", "-------g0ne$")...)
	expectResponse(t, client, "g0ne", StatusNoSession)
}
