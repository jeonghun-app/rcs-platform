package sipas

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// firstMessageBody is a chat INVITE's body with the chat's first message,
// as rcsjta writes it (OriginatingOneToOneChatSession): the SDP part and
// the message/cpim part of a multipart/mixed body.
func firstMessageBody(parts ...[2]string) string {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "--boundary1\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s\r\n", p[0], len(p[1]), p[1])
	}
	b.WriteString("--boundary1--\r\n")
	return b.String()
}

// withFirstMessage is a chat INVITE carrying body as multipart/mixed.
func (r *chatRig) withFirstMessage(body string, fields ...string) msg {
	m := r.chatInvite(body, fields...)
	for i, f := range m.fields {
		if f == "Content-Type: application/sdp" {
			m.fields[i] = `Content-Type: multipart/mixed;boundary="boundary1"`
		}
	}
	return m
}

// Code review's major 1 on #252: a chat INVITE that carries its first
// message opens the session, and the message is stored and goes to the
// peer like any other on the session.
func TestAChatInviteCarriesItsFirstMessage(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	toBob := relayPath()
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
		}
		return nil
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	body := firstMessageBody([2]string{sdpType, offerSDP(fromAlice, "active")}, [2]string{cpim.ContentType, chatCPIM("first1", "hello in the INVITE")})
	s := answeredBy(t, p.send(r.withFirstMessage(body)))
	if ct := s.res.Header.Get("Content-Type"); ct != sdpType {
		t.Fatalf("answered with %q", ct)
	}
	p.ack(s)
	inv := r.core.nextOf(t, "INVITE")
	toLeg, _ := offered(t, inv)
	if m := r.connect(t, toBob, toLeg).next(t); !strings.Contains(string(m.Body.Bytes()), "hello in the INVITE") {
		t.Fatalf("bob got %q", m.Body.Bytes())
	}
}

func TestAFirstMessageINVITERCSASCannotTakeApartIsRefused(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	sdpPart := func() [2]string { return [2]string{sdpType, offerSDP(relayPath(), "active")} }
	first := [2]string{cpim.ContentType, chatCPIM("first1", "hi")}
	for name, c := range map[string]struct {
		m    msg
		code int
	}{
		"two descriptions":             {m: r.withFirstMessage(firstMessageBody(sdpPart(), sdpPart(), first)), code: 488},
		"two messages":                 {m: r.withFirstMessage(firstMessageBody(sdpPart(), first, first)), code: 488},
		"a resource list":              {m: r.withFirstMessage(firstMessageBody(sdpPart(), [2]string{"application/resource-lists+xml", "<resource-lists/>"})), code: 488},
		"no description":               {m: r.withFirstMessage(firstMessageBody(first)), code: 488},
		"a nested multipart":           {m: r.withFirstMessage(firstMessageBody(sdpPart(), [2]string{"multipart/mixed;boundary=x", "--x--"})), code: 488},
		"no closing delimiter":         {m: r.withFirstMessage(strings.TrimSuffix(firstMessageBody(sdpPart(), first), "--boundary1--\r\n")), code: 488},
		"a message the engine refuses": {m: r.withFirstMessage(firstMessageBody(sdpPart(), [2]string{cpim.ContentType, "not CPIM"})), code: 400},
		"large mode with a message": {m: func() msg {
			m := r.withFirstMessage(firstMessageBody(sdpPart(), first))
			m.fields[2] = "Accept-Contact: *;" + largeTag
			return m
		}(), code: 488},
	} {
		if res := p.send(c.m); res.StatusCode != c.code {
			t.Errorf("%s: answered %d, want %d", name, res.StatusCode, c.code)
		}
	}
	if n := r.metrics.get("sip.invite.answered"); n != 0 {
		t.Fatalf("%d sessions answered", n)
	}
}

// Code review's major 2 on #252: a refresh re-INVITE without an offer
// (rcsjta's SessionTimerManager) gets the session's last SDP as the offer
// in its 2xx, with the same o= version, and the timer starts again; an
// answer in the ACK that moves the leg ends the session.
func TestAnOfferlessRefreshGetsTheLastSDP(t *testing.T) {
	offerlessRefresh(t)
}

// #327: the same, with every ACK slower than T1, so that each 2xx is
// retransmitted (RFC 3261 §13.3.1.4) before its ACK and reaches the core
// again while its next request is under way. Each request still gets its
// own answer.
func TestAnOfferlessRefreshGetsTheLastSDPWhenTheACKsAreSlow(t *testing.T) {
	offerlessRefresh(t, func(pc *proxy.Config) { pc.Transaction.Clock = t1AtOnce{} })
}

func offerlessRefresh(t *testing.T, tune ...func(*proxy.Config)) {
	t.Helper()
	r := newChatRig(t, messaging.Config{}, tune...)
	p := r.a.dial(t)
	from := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(from, "active"), "Supported: timer", "Session-Expires: 1800")))
	p.ack(s)
	const expiry = 1800*time.Second - 32*time.Second
	r.clock.waitArmed(t, expiry)
	refresh := msg{method: "INVITE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2,
		fields: []string{"Supported: timer", "Session-Expires: 1800"}}
	res := p.send(refresh)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != sdpType {
		t.Fatalf("offerless re-INVITE answered %d with %q", res.StatusCode, res.Body)
	}
	// The offer is the session's answer made actpass, never passive (RFC
	// 6135 §4.2.2), at the next o= version (RFC 3264 §8), same path.
	offer, err := sdp.Parse(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	_, path, setup, err := firstMSRP(offer, "")
	answered, _ := strconv.Atoi(s.answer.Origin.SessionVersion)
	if err != nil || setup != sdp.SetupActPass || len(path) != 1 || path[0].String() != s.path.String() ||
		offer.Origin.SessionID != s.answer.Origin.SessionID || offer.Origin.SessionVersion != strconv.Itoa(answered+1) {
		t.Fatalf("offer %q: setup %q, path %v, %v; answer was %+v", res.Body, setup, path, err, s.answer.Origin)
	}
	// The answer keeps the path: the session goes on.
	ackWith := func(cseq int, path msrp.URI) {
		t.Helper()
		m := msg{method: "ACK", uri: bob, toTag: s.tag, callID: s.callID, cseq: cseq,
			body: offerSDP(path, "active"), fields: []string{"Content-Type: application/sdp"}}
		if _, err := p.try(m); err != nil {
			t.Fatal(err)
		}
	}
	ackWith(2, from)
	r.clock.waitArmed(t, expiry)
	if res := p.send(msg{method: "OPTIONS", uri: bob, toTag: s.tag, callID: s.callID, cseq: 3}); res.StatusCode != 200 {
		t.Fatalf("OPTIONS after the refresh answered %d", res.StatusCode)
	}
	// An answer that moves the leg ends it. Nothing changed: the same
	// offer, at the same version.
	refresh.cseq = 4
	if again := p.send(refresh); again.StatusCode != 200 || string(again.Body) != string(res.Body) {
		t.Fatalf("second offerless re-INVITE answered %d with %q, want %q", again.StatusCode, again.Body, res.Body)
	}
	ackWith(4, relayPath())
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
}

// Code review's minor 5 on #252: a 2xx that sets up no dialog fails the
// invitation once, however often it is retransmitted.
func TestA2xxWithoutADialogFailsTheInvitationOnce(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method != "INVITE" {
			return nil
		}
		res := r.answerInvite(t, req, relayPath(), "active")
		res.Header.Del("Contact")
		return []*sip.Response{res, res, res}
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	if err := r.e.nextFailure(t); err == nil {
		t.Fatal("no failure")
	}
	deadline := time.Now().Add(waitFor)
	for r.metrics.get("sip.invite.answer_ignored") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d retransmissions ignored, want 2", r.metrics.get("sip.invite.answer_ignored"))
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("failed again: %v", err)
	default:
	}
}

// Code review's minor 6 on #252 (ADR 0004): a BYE with SIP cause 488 in a
// session that carried messages is a BYE, not a client without sessions.
func TestADirectionBYEAfterTrafficIsAnEnd(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	toBob := relayPath()
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
		}
		return nil
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(fromAlice, "active"))))
	p.ack(s)
	if code := r.connect(t, fromAlice, s.path).send(t, chatCPIM("m1", "hi")); code != 200 {
		t.Fatalf("report %d", code)
	}
	inv := r.core.nextOf(t, "INVITE")
	r.core.nextOf(t, "ACK")
	toLeg, _ := offered(t, inv)
	r.connect(t, toBob, toLeg).next(t)
	from, _ := inv.Header.From()
	bye := msg{method: "BYE", uri: alice, callID: inv.Header.Get("Call-ID"), cseq: 1,
		from: "<" + bob + ">;tag=bob1", to: "<" + alice + ">;tag=" + from.Tag(), fields: []string{"Reason: " + directionRefused}}
	if res := p.send(bye); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("the engine was told %v", err)
	default:
	}
}

// QA's nit 3 on #252: a 2xx that names rcs-as the refresher, which it did
// not offer to be, gets no timer: rcs-as never refreshes.
func TestAnAnswerNamingRCSASTheRefresherGetsNoTimer(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "active", "Session-Expires: 90;refresher=uac", "Require: timer")}
		}
		return nil
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	inv := r.core.nextOf(t, "INVITE")
	if inv.Header.Has("Session-Expires") || inv.Header.Has("Supported") {
		t.Fatalf("INVITE Session-Expires %q, Supported %q", inv.Header.Get("Session-Expires"), inv.Header.Get("Supported"))
	}
	r.core.nextOf(t, "ACK")
	deadline := time.Now().Add(waitFor)
	for r.metrics.get("sip.invite.accepted") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	if armed := r.clock.armed(); len(armed) != 0 {
		t.Fatalf("timers %v", armed)
	}
}

// QA's minor 3 on #252: an INVITE still waiting for its answer holds its
// place under the bounds.
func TestAnInviteWaitingForItsAnswerCountsAgainstTheBounds(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{MaxSessions: 1})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			ringing, _ := sip.NewResponse(req, 180, "", "bob1")
			return []*sip.Response{ringing}
		}
		return nil
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	r.core.nextOf(t, "INVITE")
	other := invitation()
	other.Recipient = "tel:+15550100003"
	if err := r.a.srv.Invite(t.Context(), other); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("a second INVITE past the bound: %v", err)
	}
	if res := r.a.dial(t).send(r.chatInvite(offerSDP(relayPath(), "active"))); res.StatusCode != 500 {
		t.Fatalf("a client's INVITE past the bound answered %d", res.StatusCode)
	}
}

// QA's minor 2 on #252: store-and-forward until the recipient registers.
// bob is not reachable at first (480); his registration has rcs-as invite
// him again, and the message goes on the session.
func TestAMessageWaitsUntilTheRecipientRegisters(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	toBob := relayPath()
	var invites atomic.Int32
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			if invites.Add(1) == 1 {
				res, _ := sip.NewResponse(req, 480, "", "bob1")
				return []*sip.Response{res}
			}
			return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(fromAlice, "active"))))
	p.ack(s)
	if code := r.connect(t, fromAlice, s.path).send(t, chatCPIM("sf1", "stored for bob")); code != 200 {
		t.Fatalf("report %d", code)
	}
	r.core.nextOf(t, "INVITE")
	if err := r.e.nextFailure(t); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("failure %v", err)
	}
	reg := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1",
		to: "<" + bob + ">", fields: []string{"Expires: 600"}}
	if res := r.a.dial(t).send(reg); res.StatusCode != 200 {
		t.Fatalf("REGISTER %d", res.StatusCode)
	}
	inv := r.core.nextOf(t, "INVITE")
	toLeg, _ := offered(t, inv)
	r.core.nextOf(t, "ACK")
	if m := r.connect(t, toBob, toLeg).next(t); !strings.Contains(string(m.Body.Bytes()), "stored for bob") {
		t.Fatalf("bob got %q", m.Body.Bytes())
	}
}

// #653, the order the captures on #602's two-task stack show: bob
// registered through task y, his de-registration went to task x, y's
// invitation for alice's message got 480, and his next registration came
// to y, which had not seen him leave and took it for a refresh. The
// refresh has y invite him at once, not RCSAS_INVITE_TIMEOUT later.
func TestARegistrationTakenForARefreshInvitesAfterA480(t *testing.T) {
	st := store.NewMemory()
	x := newChatRigStore(t, messaging.Config{InstanceID: "task-x"}, Config{}, transport.Config{}, st)
	y := newChatRigStore(t, messaging.Config{InstanceID: "task-y"}, Config{}, transport.Config{}, st)
	toBob := relayPath()
	var invites atomic.Int32
	y.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			if invites.Add(1) == 1 {
				res, _ := sip.NewResponse(req, 480, "", "bob1")
				return []*sip.Response{res}
			}
			return []*sip.Response{y.answerInvite(t, req, toBob, "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	register := func(r *chatRig, expires string) {
		t.Helper()
		reg := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1",
			to: "<" + bob + ">", fields: []string{"Expires: " + expires}}
		if res := r.a.dial(t).send(reg); res.StatusCode != 200 {
			t.Fatalf("REGISTER answered %d", res.StatusCode)
		}
	}
	register(y, "600")
	register(x, "0")
	p := y.a.dial(t)
	fromAlice := relayPath()
	s := answeredBy(t, p.send(y.chatInvite(offerSDP(fromAlice, "active"))))
	p.ack(s)
	if code := y.connect(t, fromAlice, s.path).send(t, chatCPIM("sf1", "stored for bob")); code != 200 {
		t.Fatalf("report %d", code)
	}
	y.core.nextOf(t, "INVITE")
	if err := y.e.nextFailure(t); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("failure %v", err)
	}
	register(y, "600")
	inv := y.core.nextOf(t, "INVITE")
	toLeg, _ := offered(t, inv)
	y.core.nextOf(t, "ACK")
	if m := y.connect(t, toBob, toLeg).next(t); !strings.Contains(string(m.Body.Bytes()), "stored for bob") {
		t.Fatalf("bob got %q", m.Body.Bytes())
	}
}

// QA's minor 2 on #252, AC 7 again: the first chunk of a 20 KB message is
// refused while the send window is one. That outcome is a report about
// the leg's own send, which Send waits on; a HandleReport that waited on
// Send would stall the leg until DeliveryTimeout. The relay is raw MSRP,
// so that it can refuse one chunk.
func TestAChunkRefusalDuringASendDoesNotStallTheLeg(t *testing.T) {
	r := newChatRig(t, messaging.Config{MSRP: msrp.Config{SendWindow: 1}})
	toBob := relayPath()
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
		}
		return nil
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(fromAlice, "active"))))
	p.ack(s)
	relayA := r.connect(t, fromAlice, s.path)
	relayA.send(t, chatCPIM("big1", strings.Repeat("y", 20_000)))
	relayA.send(t, chatCPIM("small2", "z"))
	inv := r.core.nextOf(t, "INVITE")
	toLeg, _ := offered(t, inv)
	nc, err := net.Dial("tcp", r.msrp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(waitFor))
	br := bufio.NewReader(nc)
	me, them := toBob.String(), toLeg.String()
	fmt.Fprintf(nc, "MSRP open1 SEND\r\nTo-Path: %s\r\nFrom-Path: %s\r\nMessage-ID: open\r\nByte-Range: 1-0/0\r\n-------open1$\r\n", them, me)
	// Its 200 and the leg's first chunk may come in either order: the loop
	// below skips everything but SENDs (QA on #252, #260).
	refused := false
	for {
		f := readRawFrame(t, br)
		if !strings.HasSuffix(f.first, " SEND") {
			continue
		}
		if !refused && strings.HasPrefix(f.headers["Byte-Range"], "1-2048/") {
			refused = true
			fmt.Fprintf(nc, "MSRP %s 413 Too large\r\nTo-Path: %s\r\nFrom-Path: %s\r\n-------%s$\r\n", f.tid, them, me, f.tid)
			continue
		}
		fmt.Fprintf(nc, "MSRP %s 200 OK\r\nTo-Path: %s\r\nFrom-Path: %s\r\n-------%s$\r\n", f.tid, them, me, f.tid)
		if refused && f.flag == '#' {
			t.Fatal("the refused message was abandoned: Send stalled")
		}
		if refused && f.flag == '$' && !strings.HasPrefix(f.headers["Byte-Range"], "2049-") && strings.HasPrefix(f.headers["Byte-Range"], "1-") {
			return // the next message went on
		}
	}
}

type rawFrame struct {
	tid, first string
	headers    map[string]string
	flag       byte
}

// readRawFrame reads one MSRP frame: its first line, its header fields
// and its end-line flag.
func readRawFrame(t *testing.T, br *bufio.Reader) rawFrame {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		t.Fatalf("frame %q", line)
	}
	f := rawFrame{tid: parts[1], first: line, headers: map[string]string{}}
	end := "-------" + f.tid
	inHeaders := true
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		l = strings.TrimRight(l, "\r\n")
		if strings.HasPrefix(l, end) && len(l) == len(end)+1 {
			f.flag = l[len(l)-1]
			return f
		}
		if inHeaders {
			if l == "" {
				inHeaders = false
				continue
			}
			k, v, _ := strings.Cut(l, ": ")
			f.headers[k] = v
		}
	}
}

// QA's minor 2 on #252, AC 8's wiring: a send rcs-as cannot make because
// the transport has no room for another connection is a passing failure
// (errNextHopBusy), for a pager MESSAGE and for an INVITE alike, and the
// INVITE gives its place under the bounds back.
func TestASendTheTransportHasNoRoomForIsAPassingFailure(t *testing.T) {
	// Made first, so that it closes after the transport, whose connection
	// it serves.
	other := newFakeCore(t)
	r := newChatRigOn(t, messaging.Config{}, Config{MaxSessions: 1}, transport.Config{MaxDialedConnections: 1})
	// The one connection the transport may open goes to other.
	d := delivery()
	d.Notification, d.Route, d.SenderName = true, other.uri().String(), ""
	if err := r.a.srv.Pager(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	if err := r.a.srv.Pager(t.Context(), delivery()); !errors.Is(err, errNextHopBusy) || errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("Pager: %v", err)
	}
	for range 2 { // the second finds the first's place given back
		if err := r.a.srv.Invite(t.Context(), invitation()); !errors.Is(err, errNextHopBusy) || errors.Is(err, messaging.ErrOffline) {
			t.Fatalf("Invite: %v", err)
		}
	}
}

// Security review's minor on #252: the sessions a user opens and those
// rcs-as opens to it are bounded apart, so other users' messages cannot
// take the user's own room; and one sender has one large-mode session at a
// time with one recipient.
func TestTheBoundsOfAUserAreKeptApartByDirection(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{MaxOutgoingPerUser: 2, MaxIncomingPerUser: 1})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" { // bob's client rings and rings
			ringing, _ := sip.NewResponse(req, 180, "", "bob1")
			return []*sip.Response{ringing}
		}
		return nil
	})
	// Others fill bob's incoming room...
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	other := invitation()
	other.Peer = "tel:+15550100003"
	if err := r.a.srv.Invite(t.Context(), other); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("a second session to bob: %v", err)
	}
	// ...and bob still opens his own.
	m := r.chatInvite(offerSDP(relayPath(), "active"))
	m.uri = alice
	m.fields[0] = "P-Asserted-Identity: <" + bob + ">"
	p := r.a.dial(t)
	for range 2 {
		s := answeredBy(t, p.send(m))
		p.ack(s)
	}
	if res := p.send(m); res.StatusCode != 486 {
		t.Fatalf("bob's third session answered %d", res.StatusCode)
	}
}

func TestOneLargeModeSessionAtATimeGoesFromASenderToARecipient(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			ringing, _ := sip.NewResponse(req, 180, "", "bob1")
			return []*sip.Response{ringing}
		}
		return nil
	})
	large := func(id string) messaging.Invitation {
		inv := invitation()
		inv.Mode, inv.QueueID = store.Standalone, id
		return inv
	}
	if err := r.a.srv.Invite(t.Context(), large("q1")); err != nil {
		t.Fatal(err)
	}
	if err := r.a.srv.Invite(t.Context(), large("q2")); !errors.Is(err, errLargeBusy) || !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("a second large-mode session from alice to bob: %v", err)
	}
	other := large("q3")
	other.Peer = "tel:+15550100003"
	if err := r.a.srv.Invite(t.Context(), other); err != nil {
		t.Fatalf("one from another sender: %v", err)
	}
}

// Security review's major on #252: a session whose MSRP connection never
// comes ends at the leg's bind deadline (AnswerTimeout), with a BYE, and
// gives its room back. It has no session timer, and its ACK came.
func TestASessionWithoutItsMSRPConnectionEnds(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{AnswerTimeout: 200 * time.Millisecond}, Config{MaxOutgoingPerUser: 1})
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
	p.ack(s)
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
	// The room is back for alice's next session.
	answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
}

// Code review's question 8 on #252: rcsjta, the reference client, asks for
// a chat with the OMA SIMPLE IM tag alone; it is a chat as the CPM ICSI is.
func TestAChatInviteWithTheOMAIMTagIsAChat(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	m := r.chatInvite(offerSDP(relayPath(), "active"))
	m.fields[1] = "Contact: <sip:" + r.core.l.Addr().String() + ";transport=tcp>;+g.oma.sip-im"
	m.fields[2] = "Accept-Contact: *;+g.oma.sip-im"
	s := answeredBy(t, r.a.dial(t).send(m))
	if types, _ := s.answer.Media[0].AcceptTypes(); len(types) != 2 || types[1] != messaging.IsComposingType {
		t.Fatalf("accept-types %v, want a chat's", types)
	}
}

// blockingResolver resolves numerically, but holds a lookup of host until
// release is closed.
type blockingResolver struct {
	host    string
	held    chan struct{}
	release chan struct{}
}

func (b *blockingResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	if u.Host == b.host {
		b.held <- struct{}{}
		<-b.release
	}
	return proxy.NumericResolver{}.Resolve(ctx, u)
}

// QA's nit 2 on #252: a BYE that ends a session rcs-as started while its
// ACK is still on the way leaves the engine told once, by the BYE.
func TestAnEarlyBYELeavesTheEngineToldOnce(t *testing.T) {
	block := &blockingResolver{host: "127.0.0.2", held: make(chan struct{}, 1), release: make(chan struct{})}
	r := newChatRigWith(t, messaging.Config{}, Config{Resolver: block})
	t.Cleanup(func() {
		select {
		case <-block.release:
		default:
			close(block.release)
		}
	})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method != "INVITE" {
			return nil
		}
		// The 2xx's Contact, where its ACK goes, is one the resolver holds.
		res := r.answerInvite(t, req, relayPath(), "active")
		_ = res.Header.Set("Contact", "<sip:127.0.0.2:5060;transport=tcp>")
		return []*sip.Response{res}
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	inv := r.core.nextOf(t, "INVITE")
	select {
	case <-block.held:
	case <-time.After(waitFor):
		t.Fatal("the ACK's lookup did not start")
	}
	from, _ := inv.Header.From()
	bye := msg{method: "BYE", uri: alice, callID: inv.Header.Get("Call-ID"), cseq: 1,
		from: "<" + bob + ">;tag=bob1", to: "<" + alice + ">;tag=" + from.Tag(), fields: []string{"Reason: " + directionRefused}}
	if res := r.a.dial(t).send(bye); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
	if err := r.e.nextFailure(t); !errors.Is(err, messaging.ErrNoSessions) {
		t.Fatalf("failed with %v", err)
	}
	close(block.release)
	deadline := time.Now().Add(waitFor)
	for r.metrics.get("sip.invite.ended_early") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the session went on after its BYE")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("the engine was told again: %v", err)
	default:
	}
}

// Code review's major on #252 (re-check): the bounds are taken before a
// first message is stored. An INVITE past them is refused and stores
// nothing, which its client, told it failed, would send again.
func TestAFirstMessagePastABoundIsNotStored(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  Config
		code int
	}{
		"the user's bound": {Config{MaxOutgoingPerUser: 1}, 486},
		"the task's bound": {Config{MaxSessions: 1}, 500},
	} {
		t.Run(name, func(t *testing.T) {
			r := newChatRigWith(t, messaging.Config{}, c.cfg)
			p := r.a.dial(t)
			s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
			p.ack(s)
			body := firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{cpim.ContentType, chatCPIM("first1", "refused")})
			if res := p.send(r.withFirstMessage(body)); res.StatusCode != c.code {
				t.Fatalf("answered %d, want %d", res.StatusCode, c.code)
			}
			queued, err := r.store.Pending(t.Context(), bob, "", time.Now().Add(time.Hour), 10)
			if err != nil || len(queued) != 0 {
				t.Fatalf("%d stored for bob, %v", len(queued), err)
			}
			// The room the refused INVITE did not take is still there for
			// the first session's end: one more session fits after it.
			if res := p.send(msg{method: "BYE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2}); res.StatusCode != 200 {
				t.Fatalf("BYE answered %d", res.StatusCode)
			}
			answeredBy(t, p.send(r.withFirstMessage(firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{cpim.ContentType, chatCPIM("first2", "taken")}))))
		})
	}
}

// A first message the engine refuses gives its session's place back.
func TestARefusedFirstMessageGivesItsPlaceBack(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{MaxOutgoingPerUser: 1})
	p := r.a.dial(t)
	bad := firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{cpim.ContentType, "not CPIM"})
	if res := p.send(r.withFirstMessage(bad)); res.StatusCode != 400 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
}

// Code review's minor on #252 (re-check): rcsjta asks for a file transfer
// over MSRP with the same +g.oma.sip-im tag as a chat; its offer carries
// a=file-selector (RFC 5547 §6), and it is not served here.
func TestAFileTransferInviteIsRefused(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	m := r.chatInvite(strings.Replace(offerSDP(relayPath(), "active"), "a=sendrecv\r\n",
		"a=sendrecv\r\na=file-selector:name:\"a.jpg\" type:image/jpeg size:1000\r\n", 1))
	m.fields[2] = "Accept-Contact: *;+g.oma.sip-im"
	if res := r.a.dial(t).send(m); res.StatusCode != 403 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	if n := r.metrics.get("sip.invite.service_refused"); n != 1 {
		t.Fatalf("service_refused %d", n)
	}
	// And an offer with no type in common is counted as refused.
	if res := r.a.dial(t).send(r.chatInvite(offerSDP(relayPath(), "active", "image/jpeg"))); res.StatusCode != 488 || r.metrics.get("sip.invite.offer_refused") != 1 {
		t.Fatalf("answered %d, offer_refused %d", res.StatusCode, r.metrics.get("sip.invite.offer_refused"))
	}
}

// Code review on #279: rcsjta's chat INVITE carries a Contribution-ID and
// no Conversation-ID, and is answered.
func TestAChatInviteWithOnlyAContributionIDIsAnswered(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	m := r.chatInvite(offerSDP(relayPath(), "active"))
	m.fields = slices.DeleteFunc(m.fields, func(f string) bool { return strings.HasPrefix(f, "Conversation-ID:") })
	p := r.a.dial(t)
	if res := p.send(m); res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	bad := r.chatInvite(offerSDP(relayPath(), "active"))
	bad.fields = slices.DeleteFunc(bad.fields, func(f string) bool { return strings.HasPrefix(f, "Contribution-ID:") })
	if res := p.send(bad); res.StatusCode != 400 {
		t.Fatalf("a Conversation-ID without a Contribution-ID answered %d", res.StatusCode)
	}
}
