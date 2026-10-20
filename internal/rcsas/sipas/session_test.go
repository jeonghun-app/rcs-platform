package sipas

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// #137 AC 1, 7 and 8 end to end: alice's chat INVITE is answered passive
// with the leg's path, msrp-relay connects there, and her message is
// stored; bob is offline, so rcs-as starts a session to him, offering
// actpass, and delivers it on the leg the relay connects to once bob's
// answer gives its path. Each BYE ends its session.
func TestAChatMessageGoesThroughTwoSessionsRcsASAnchors(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	toBob := relayPath()
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, toBob, "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(fromAlice, "active"))))
	h := &s.res.Header
	if c := h.Get("Contact"); !strings.Contains(c, chatTag) || !strings.Contains(c, r.a.addr.String()) {
		t.Errorf("Contact %q", c)
	}
	if h.Get("Content-Type") != sdpType || h.Has("Session-Expires") || h.Has("Require") {
		t.Errorf("Content-Type %q, Session-Expires %q, Require %q", h.Get("Content-Type"), h.Get("Session-Expires"), h.Get("Require"))
	}
	if setup, err := s.answer.MediaSetup(0); err != nil || setup != sdp.SetupPassive {
		t.Errorf("answered setup %q, %v; rcs-as is always connected to", setup, err)
	}
	if s.path.Host != "127.0.0.1" || s.path.Port != r.msrpPort() || s.answer.Connection.Address != "127.0.0.1" {
		t.Errorf("answered path %s, c=%s; want the task's MSRP address", s.path, s.answer.Connection.Address)
	}
	if types, _ := s.answer.Media[0].AcceptTypes(); !slices.Equal(types, []string{cpim.ContentType, messaging.IsComposingType}) {
		t.Errorf("accept-types %v", types)
	}
	p.ack(s)

	relayA := r.connect(t, fromAlice, s.path)
	if code := relayA.send(t, chatCPIM("m1", "hi bob")); code != 200 {
		t.Fatalf("alice's message reported %d", code)
	}

	inv := r.core.nextOf(t, "INVITE")
	ih := &inv.Header
	for name, want := range map[string]string{
		"Route":               "<" + r.core.uri().String() + ">",
		"To":                  "<" + bob + ">",
		"P-Asserted-Identity": "<" + alice + ">",
		"P-Served-User":       "<" + bob + ">;sescase=term",
		"P-Asserted-Service":  chatICSI,
		"Accept-Contact":      "*;" + chatTag,
		"Conversation-ID":     "c0nv1",
		"Content-Type":        sdpType,
	} {
		if got := ih.Get(name); got != want {
			t.Errorf("INVITE %s: %q, want %q", name, got, want)
		}
	}
	if inv.URI.String() != bob || ih.Has("Supported") {
		t.Errorf("INVITE %s, Supported %q", inv.URI.String(), ih.Get("Supported"))
	}
	toLeg, setup := offered(t, inv)
	if setup != sdp.SetupActPass || toLeg.Port != s.path.Port {
		t.Errorf("offered %s with setup %q", toLeg, setup)
	}
	if ack := r.core.nextOf(t, "ACK"); ack.Header.Get("Call-ID") != ih.Get("Call-ID") {
		t.Fatalf("ACK for another dialog: %q", ack.Header.Get("Call-ID"))
	}
	relayB := r.connect(t, toBob, toLeg)
	if m := relayB.next(t); !strings.Contains(string(m.Body), "hi bob") {
		t.Fatalf("bob's leg got %q", m.Body)
	}

	// bob hangs up: his BYE comes in the dialog rcs-as started.
	from, _ := ih.From()
	bye := msg{method: "BYE", uri: alice, callID: ih.Get("Call-ID"), cseq: 1,
		from: "<" + bob + ">;tag=bob1", to: "<" + alice + ">;tag=" + from.Tag()}
	if res := p.send(bye); res.StatusCode != 200 {
		t.Fatalf("bob's BYE answered %d", res.StatusCode)
	}
	if res := p.send(bye); res.StatusCode != 481 {
		t.Fatalf("bob's BYE again answered %d; the session should be gone", res.StatusCode)
	}
	if res := p.send(msg{method: "BYE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2}); res.StatusCode != 200 {
		t.Fatalf("alice's BYE answered %d", res.StatusCode)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("an invitation failed: %v", err)
	default:
	}
}

// #137 AC 7, the MSRP Handler contract: the leg takes the reports about
// its own sends while it is sending (HandleReport never waits on Send of
// its session). With a send window of one, a leg that waited would stop
// at the first chunk; bob's gets every message, chunked, in turn.
func TestReportsAreTakenWhileTheLegSends(t *testing.T) {
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
	const n = 3
	for i := range n {
		if code := relayA.send(t, chatCPIM(fmt.Sprint("m", i), strings.Repeat("x", 10_000))); code != 200 {
			t.Fatalf("message %d reported %d", i, code)
		}
	}
	inv := r.core.nextOf(t, "INVITE")
	toLeg, _ := offered(t, inv)
	relayB := r.connect(t, toBob, toLeg)
	for i := range n {
		if m := relayB.next(t); !strings.Contains(string(m.Body), "imdn.Message-ID: m") || len(m.Body) < 10_000 {
			t.Fatalf("message %d: %d bytes", i, len(m.Body))
		}
	}
}

func TestOffersRCSASCannotTakeAre488(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	relay := relayPath()
	for name, m := range map[string]msg{
		"passive":   r.chatInvite(offerSDP(relayPath(), "passive")),
		"no offer":  r.chatInvite(""),
		"not SDP":   r.chatInvite("--b\r\n\r\n--b--", "Content-Type: multipart/mixed;boundary=b"),
		"no MSRP":   r.chatInvite("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\n"),
		"bad path":  r.chatInvite(strings.Replace(offerSDP(relay, "active"), relay.String(), "http://x", 1)),
		"no common": r.chatInvite(offerSDP(relayPath(), "active", "text/plain")),
	} {
		if name == "not SDP" {
			// The second Content-Type wins nothing: the field is single.
			m.fields = slices.DeleteFunc(m.fields, func(f string) bool { return f == "Content-Type: application/sdp" })
		}
		if res := p.send(m); res.StatusCode != 488 {
			t.Errorf("%s: answered %d", name, res.StatusCode)
		}
	}
}

// Sessions are bounded per task and per user (threat model T9): past the
// task's bound the client may try again (500 with Retry-After, which scscf
// passes on), past the user's it is refused (403), and a session rcs-as
// would start waits.
func TestSessionsAreBounded(t *testing.T) {
	for name, c := range map[string]struct {
		cfg    Config
		code   int
		header [2]string
	}{
		"per task": {cfg: Config{MaxSessions: 1}, code: 500, header: [2]string{"Retry-After", "1"}},
		"per user": {cfg: Config{MaxSessionsPerUser: 1}, code: 403},
	} {
		t.Run(name, func(t *testing.T) {
			r := newChatRigWith(t, messaging.Config{}, c.cfg)
			p := r.a.dial(t)
			s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
			p.ack(s)
			res := p.send(r.chatInvite(offerSDP(relayPath(), "active")))
			if res.StatusCode != c.code || c.header[0] != "" && res.Header.Get(c.header[0]) != c.header[1] {
				t.Fatalf("a second session answered %d, %s %q", res.StatusCode, c.header[0], res.Header.Get(c.header[0]))
			}
			inv := invitation()
			inv.Recipient = alice
			inv.Peer = bob
			if err := r.a.srv.Invite(t.Context(), inv); !errors.Is(err, messaging.ErrOffline) {
				t.Fatalf("Invite past the bound: %v", err)
			}
			// Ending the session makes room.
			if res := p.send(msg{method: "BYE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2}); res.StatusCode != 200 {
				t.Fatalf("BYE answered %d", res.StatusCode)
			}
			answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
		})
	}
}

func TestAnInviteRCSASCannotServeIsRefusedWithItsStatus(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	for name, c := range map[string]struct {
		m      func(msg) msg
		code   int
		header [2]string
	}{
		"no asserted identity": {m: func(m msg) msg { m.fields = m.fields[1:]; return m }, code: 403},
		"file transfer": {m: func(m msg) msg {
			m.fields[2] = `Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.filetransfer"`
			return m
		}, code: 403},
		"peer no user": {m: func(m msg) msg { m.uri = "sip:" + domain; return m }, code: 404},
		"bad conversation": {m: func(m msg) msg {
			m.fields = slices.DeleteFunc(m.fields, func(f string) bool { return strings.HasPrefix(f, "Conversation-ID:") })
			m.fields = append(m.fields, "Conversation-ID: <bad>")
			return m
		}, code: 400},
		"unknown extension": {m: func(m msg) msg { m.fields = append(m.fields, "Require: 100rel, timer"); return m }, code: 420,
			header: [2]string{"Unsupported", "100rel"}},
		"short session timer": {m: func(m msg) msg {
			m.fields = append(m.fields, "Supported: timer", "Session-Expires: 60")
			return m
		}, code: 422, header: [2]string{"Min-SE", "90"}},
	} {
		res := p.send(c.m(r.chatInvite(offerSDP(relayPath(), "active"))))
		if res.StatusCode != c.code {
			t.Errorf("%s: answered %d, want %d", name, res.StatusCode, c.code)
		}
		if c.header[0] != "" && res.Header.Get(c.header[0]) != c.header[1] {
			t.Errorf("%s: %s %q", name, c.header[0], res.Header.Get(c.header[0]))
		}
	}
}

// A large-mode INVITE opens a leg that only takes CPIM (RCC.07 §3.3).
func TestALargeModeInviteIsAnsweredForCPIMOnly(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	m := r.chatInvite(offerSDP(relayPath(), "active"))
	m.fields[2] = "Accept-Contact: *;" + largeTag
	s := answeredBy(t, p.send(m))
	if types, _ := s.answer.Media[0].AcceptTypes(); !slices.Equal(types, []string{cpim.ContentType}) {
		t.Errorf("accept-types %v", types)
	}
	if c := s.res.Header.Get("Contact"); !strings.Contains(c, largeTag) {
		t.Errorf("Contact %q", c)
	}
}

// RFC 4028 as the UAS that never refreshes: the client refreshes, and a
// session it stops refreshing is ended before it expires (§10).
func TestASessionTimerIsTakenRefreshedAndEndsTheSession(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	from := relayPath()
	offer := offerSDP(from, "active")
	s := answeredBy(t, p.send(r.chatInvite(offer, "Supported: timer", "Session-Expires: 1800")))
	if got := s.res.Header.Get("Session-Expires"); got != "1800;refresher=uac" || s.res.Header.Get("Require") != "timer" {
		t.Fatalf("Session-Expires %q, Require %q", got, s.res.Header.Get("Require"))
	}
	p.ack(s)
	const expiry = 1800*time.Second - 32*time.Second
	r.clock.waitArmed(t, expiry)

	// A refresh with the same offer gets the same answer, and the timer
	// starts again; UPDATE needs no offer.
	reinvite := r.chatInvite(offer, "Supported: timer", "Session-Expires: 1800")
	reinvite.toTag, reinvite.callID, reinvite.cseq = s.tag, s.callID, 2
	res := p.send(reinvite)
	if res.StatusCode != 200 || string(res.Body) != string(s.res.Body) {
		t.Fatalf("re-INVITE answered %d with %q, want %q", res.StatusCode, res.Body, s.res.Body)
	}
	if _, err := p.try(msg{method: "ACK", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2}); err != nil {
		t.Fatal(err)
	}
	r.clock.waitArmed(t, expiry)
	update := msg{method: "UPDATE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 3,
		fields: []string{"Supported: timer", "Session-Expires: 900"}}
	if res := p.send(update); res.StatusCode != 200 || len(res.Body) != 0 || res.Header.Get("Session-Expires") != "900;refresher=uac" {
		t.Fatalf("UPDATE answered %d, %q, Session-Expires %q", res.StatusCode, res.Body, res.Header.Get("Session-Expires"))
	}
	const shorter = 900*time.Second - 32*time.Second
	r.clock.waitArmed(t, shorter)

	r.clock.fire(shorter)
	bye := r.core.nextOf(t, "BYE")
	if bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
	if res := p.send(msg{method: "BYE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 4}); res.StatusCode != 481 {
		t.Fatalf("a BYE after rcs-as ended the session answered %d", res.StatusCode)
	}
}

func TestASessionTimerRCSASWouldRefreshIsNotTaken(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	for name, fields := range map[string][]string{
		"refresher=uas":     {"Supported: timer", "Session-Expires: 1800;refresher=uas"},
		"timer unsupported": {"Session-Expires: 1800"},
	} {
		s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"), fields...)))
		if s.res.Header.Has("Session-Expires") || s.res.Header.Has("Require") {
			t.Errorf("%s: Session-Expires %q, Require %q", name, s.res.Header.Get("Session-Expires"), s.res.Header.Get("Require"))
		}
	}
	if armed := r.clock.armed(); len(armed) != 0 {
		t.Fatalf("timers %v", armed)
	}
}

// A leg does not move: a re-INVITE with another path, or with no offer, is
// refused and the session goes on.
func TestARefreshThatMovesTheLegIsRefused(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
	p.ack(s)
	cseq := 2
	for name, body := range map[string]string{"moved": offerSDP(relayPath(), "active"), "no offer": ""} {
		m := r.chatInvite(body)
		m.toTag, m.callID, m.cseq = s.tag, s.callID, cseq
		cseq++
		if res := p.send(m); res.StatusCode != 488 {
			t.Errorf("%s: re-INVITE answered %d", name, res.StatusCode)
		}
	}
	if res := p.send(msg{method: "OPTIONS", uri: bob, toTag: s.tag, callID: s.callID, cseq: cseq}); res.StatusCode != 200 {
		t.Fatalf("OPTIONS in the session answered %d", res.StatusCode)
	}
	cseq++
	if res := p.send(msg{method: "MESSAGE", uri: bob, toTag: s.tag, callID: s.callID, cseq: cseq}); res.StatusCode != 405 {
		t.Fatalf("MESSAGE in the session answered %d", res.StatusCode)
	}
	if res := p.send(msg{method: "BYE", uri: bob, toTag: s.tag, callID: s.callID, cseq: 1}); res.StatusCode != 500 {
		t.Fatalf("a BYE with an old CSeq answered %d", res.StatusCode)
	}
}

// When msrp-relay drops its connection the leg ends, and rcs-as ends the
// session with a BYE.
func TestALegThatEndsEndsItsSession(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	from := relayPath()
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(from, "active"))))
	p.ack(s)
	relay := r.connect(t, from, s.path)
	_ = relay.conn.Close()
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
}

// A 2xx without its ACK ends the session (RFC 3261 §13.3.1.4).
func TestA2xxWithoutAnACKEndsTheSession(t *testing.T) {
	r := newChatRig(t, messaging.Config{}, func(c *proxy.Config) { c.Transaction = transaction.Config{T1: 5 * time.Millisecond} })
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
}

// What becomes of rcs-as's INVITE reaches the engine, once.
func TestAnInvitationThatFailsIsReported(t *testing.T) {
	for name, c := range map[string]struct {
		reply func(r *chatRig, req *sip.Request) []*sip.Response
		bye   string
		want  error
	}{
		"offline": {reply: status(480), want: messaging.ErrOffline},
		"unknown": {reply: status(404), want: messaging.ErrUndeliverable},
		// The client answered passive, which the relay never dials.
		"passive answer": {reply: func(r *chatRig, req *sip.Request) []*sip.Response {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "passive")}
		}, bye: directionRefused, want: messaging.ErrNoSessions},
		"no setup in the answer": {reply: func(r *chatRig, req *sip.Request) []*sip.Response {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "")}
		}, bye: directionRefused, want: messaging.ErrNoSessions},
	} {
		t.Run(name, func(t *testing.T) {
			r := newChatRig(t, messaging.Config{})
			r.core.setReply(func(req *sip.Request) []*sip.Response {
				if req.Method == "INVITE" {
					return c.reply(r, req)
				}
				res, _ := sip.NewResponse(req, 200, "", "core1")
				return []*sip.Response{res}
			})
			if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
				t.Fatal(err)
			}
			if err := r.e.nextFailure(t); !errors.Is(err, c.want) {
				t.Fatalf("failed with %v, want %v", err, c.want)
			}
			if c.bye != "" {
				r.core.nextOf(t, "ACK")
				if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Reason") != c.bye {
					t.Fatalf("BYE Reason %q", bye.Header.Get("Reason"))
				}
			}
			select {
			case err := <-r.e.failed:
				t.Fatalf("failed again: %v", err)
			default:
			}
		})
	}
}

func status(code int) func(*chatRig, *sip.Request) []*sip.Response {
	return func(_ *chatRig, req *sip.Request) []*sip.Response {
		res, _ := sip.NewResponse(req, code, "", "bob1")
		return []*sip.Response{res}
	}
}

func invitation() messaging.Invitation {
	return messaging.Invitation{Recipient: bob, Peer: alice, Mode: store.Chat, Conversation: messaging.Conversation{ID: "c0nv1"}}
}

// pcscf ends a session whose client answered passive with a BYE that says
// so (ADR 0004): the engine learns the client takes no sessions.
func TestABYEForTheMSRPDirectionTellsTheEngine(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{r.answerInvite(t, req, relayPath(), "active")}
		}
		return nil
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	inv := r.core.nextOf(t, "INVITE")
	r.core.nextOf(t, "ACK")
	from, _ := inv.Header.From()
	bye := msg{method: "BYE", uri: alice, callID: inv.Header.Get("Call-ID"), cseq: 1,
		from: "<" + bob + ">;tag=bob1", to: "<" + alice + ">;tag=" + from.Tag(), fields: []string{"Reason: " + directionRefused}}
	if res := r.a.dial(t).send(bye); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
	if err := r.e.nextFailure(t); !errors.Is(err, messaging.ErrNoSessions) {
		t.Fatalf("failed with %v", err)
	}
}

// An INVITE that rings and is not answered is cancelled when its leg gives
// up waiting (AnswerTimeout): its 487 is the failure the engine hears of.
func TestAnInviteLeftRingingIsCancelled(t *testing.T) {
	r := newChatRig(t, messaging.Config{AnswerTimeout: 50 * time.Millisecond})
	var invite *sip.Request
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		switch req.Method {
		case "INVITE":
			invite = req
			ringing, _ := sip.NewResponse(req, 180, "", "bob1")
			return []*sip.Response{ringing}
		case "CANCEL":
			ok, _ := sip.NewResponse(req, 200, "", "bob1")
			terminated, _ := sip.NewResponse(invite, 487, "", "bob1")
			return []*sip.Response{ok, terminated}
		}
		return nil
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	inv := r.core.nextOf(t, "INVITE")
	cancel := r.core.nextOf(t, "CANCEL")
	iv, _ := inv.Header.Via()
	cv, _ := cancel.Header.Via()
	if cancel.URI.String() != inv.URI.String() || cancel.Header.Get("CSeq") != "1 CANCEL" || cv[0].Branch() != iv[0].Branch() {
		t.Fatalf("CANCEL %s, CSeq %q, branch %q for %q", cancel.URI.String(), cancel.Header.Get("CSeq"), cv[0].Branch(), iv[0].Branch())
	}
	if err := r.e.nextFailure(t); err == nil || errors.Is(err, messaging.ErrNoSessions) {
		t.Fatalf("failed with %v", err)
	}
}

// Each 2xx is acknowledged, a retransmission too, and one from a second
// fork is ended (RFC 3261 §13.2.2.4); the first one's session stands.
func TestA2xxFromAnotherForkIsEnded(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method != "INVITE" {
			res, _ := sip.NewResponse(req, 200, "", "core1")
			return []*sip.Response{res}
		}
		first := r.answerInvite(t, req, relayPath(), "active")
		second := r.answerInvite(t, req, relayPath(), "active")
		to, _ := second.Header.To()
		to.Params.Set("tag", "bob2")
		_ = second.Header.Set("To", to.String())
		// The first 2xx comes twice: its ACK was taken as lost.
		return []*sip.Response{first, first, second}
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	var tags []string
	for len(tags) < 4 {
		req := r.core.next(t)
		if req.Method == "INVITE" {
			continue
		}
		to, _ := req.Header.To()
		tags = append(tags, req.Method+" "+to.Tag())
	}
	slices.Sort(tags)
	if want := []string{"ACK bob1", "ACK bob1", "ACK bob2", "BYE bob2"}; !slices.Equal(tags, want) {
		t.Fatalf("sent %v, want %v", tags, want)
	}
	// The first session stands until rcs-as ends it: its BYE is the next
	// one, and only one fork was dropped.
	r.a.srv.Close()
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") == "" {
		t.Fatal("no BYE")
	} else if to, _ := bye.Header.To(); to.Tag() != "bob1" {
		t.Fatalf("BYE to %q, want the session's", to.Tag())
	}
	if n := r.metrics.get("sip.invite.fork_dropped"); n != 1 {
		t.Fatalf("%d forks dropped, want 1", n)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("an invitation failed: %v", err)
	default:
	}
}

// Shutdown ends the sessions with a BYE while the transport still carries
// it, and takes no new one.
func TestCloseEndsTheSessions(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	s := answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active"))))
	p.ack(s)
	r.a.srv.Close()
	if bye := r.core.nextOf(t, "BYE"); bye.Header.Get("Call-ID") != s.callID {
		t.Fatalf("BYE for %q", bye.Header.Get("Call-ID"))
	}
	if res := p.send(r.chatInvite(offerSDP(relayPath(), "active"))); res.StatusCode != 500 {
		t.Fatalf("an INVITE after Close answered %d", res.StatusCode)
	}
}

// rcs-as's INVITE carries its loop marker, as a pager MESSAGE does: one
// that a profile without the P-Served-User exclusion sends back to rcs-as
// is refused with 482, and the invitation fails.
func TestAnInviteThatComesBackIsRefusedAsALoop(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p := r.a.dial(t)
	bounced := make(chan int, 1)
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method != "INVITE" {
			return nil
		}
		fwd := req.Clone()
		_ = fwd.Header.Set("Route", "<sip:"+r.a.addr.String()+";transport=tcp;lr>")
		_ = fwd.Header.Prepend("Via", "SIP/2.0/TCP 192.0.2.30:5060;branch=z9hG4bK-scscf-loop-invite")
		code := 0
		if res, err := p.forward(fwd); err == nil {
			code = res.StatusCode
		}
		bounced <- code
		res, _ := sip.NewResponse(req, 482, "", "core1")
		return []*sip.Response{res}
	})
	if err := r.a.srv.Invite(t.Context(), invitation()); err != nil {
		t.Fatal(err)
	}
	if code := <-bounced; code != 482 {
		t.Fatalf("the returning INVITE was answered %d", code)
	}
	if err := r.e.nextFailure(t); err == nil {
		t.Fatal("no failure")
	}
}

func TestGroupSessionsAreNotServedYet(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	inv := invitation()
	inv.Mode = store.Group
	if err := r.a.srv.Invite(t.Context(), inv); !errors.Is(err, errGroupNotServed) {
		t.Fatalf("Invite: %v", err)
	}
}

// scscf's third-party REGISTER (TS 24.229 §5.4.1.7) tells the engine the
// user registered: anew when rcs-as had not heard of a live registration.
func TestAThirdPartyRegisterTellsTheEngine(t *testing.T) {
	e := &fakeEngine{}
	clock := newFakeClock()
	a := startASWith(t, e, Config{Core: newFakeCore(t).uri(), Clock: clock})
	p := a.dial(t)
	register := func(expires string) {
		t.Helper()
		m := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1",
			to: "<" + aliceSIP + ">", fields: []string{"Expires: " + expires}}
		if res := p.send(m); res.StatusCode != 200 {
			t.Fatalf("REGISTER answered %d", res.StatusCode)
		}
	}
	register("600")
	register("600")
	clock.Advance(601 * time.Second)
	register("600")
	register("0")
	register("600")
	want := []registration{{alice, true}, {alice, false}, {alice, true}, {alice, true}}
	if got := e.registrations(); !slices.Equal(got, want) {
		t.Fatalf("registrations %v, want %v", got, want)
	}
	m := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1", to: "<" + aliceSIP + ">"}
	if res := p.send(m); res.StatusCode != 400 {
		t.Fatalf("REGISTER without Expires answered %d", res.StatusCode)
	}
}
