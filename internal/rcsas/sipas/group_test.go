package sipas

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// carol is a third participant, on .github/allowed-test-identifiers.txt.
const carol = "tel:+15550100003"

// groupList is rcsjta's resource list of a group's invitees
// (ChatUtils.generateChatResourceList).
func groupList(uris ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\r\n" +
		`<resource-lists xmlns="urn:ietf:params:xml:ns:resource-lists" xmlns:cp="urn:ietf:params:xml:ns:copycontrol"><list>`)
	for _, u := range uris {
		fmt.Fprintf(&b, `<entry uri="%s" cp:copyControl="to"/>`, u)
	}
	b.WriteString("</list></resource-lists>")
	return b.String()
}

// groupInvite is alice's INVITE to a group chat as scscf hands it to
// rcs-as: to uri, with body as its multipart/mixed or SDP body (rcsjta's
// OriginatingAdhocGroupChatSession and RejoinGroupChatSession).
func (r *chatRig) groupInvite(uri, contentType, body string, fields ...string) msg {
	return msg{method: "INVITE", uri: uri, body: body, from: `"Alice" <` + alice + ">;tag=a1", to: "<" + uri + ">",
		fields: append([]string{
			"P-Asserted-Identity: <" + alice + ">",
			"Contact: <sip:" + r.core.l.Addr().String() + ";transport=tcp>;" + omaIMTag,
			"Accept-Contact: *;" + omaIMTag,
			"Conversation-ID: gc0nv1", "Contribution-ID: gch4t1",
			"Content-Type: " + contentType,
		}, fields...)}
}

// factoryInvite is alice's INVITE to the conference factory that creates
// a group of her and invitees, with the subject Lunch.
func (r *chatRig) factoryInvite(path msrp.URI, invitees ...string) msg {
	body := firstMessageBody([2]string{sdpType, offerSDP(path, "active")}, [2]string{resourcelists.ContentType, groupList(invitees...)})
	return r.groupInvite(confFactory, `multipart/mixed;boundary="boundary1"`, body, "Require: recipient-list-invite", "Subject: Lunch")
}

// create has alice create a group of her and invitees at the factory, and
// returns its URI and her session.
func (r *chatRig) create(t *testing.T, p *peer, path msrp.URI, invitees ...string) (string, answered) {
	t.Helper()
	s := answeredBy(t, p.send(r.factoryInvite(path, invitees...)))
	p.ack(s)
	contact, err := sip.ParseAddress(s.res.Header.Get("Contact"))
	if err != nil {
		t.Fatal(err)
	}
	return contact.URI.String(), s
}

// focusInvites are the next n INVITEs the focus sent the core, by
// recipient.
func (r *chatRig) focusInvites(t *testing.T, n int) map[string]*sip.Request {
	t.Helper()
	out := map[string]*sip.Request{}
	for len(out) < n {
		inv := r.core.nextOf(t, "INVITE")
		out[inv.URI.String()] = inv
	}
	return out
}

// stateOf waits until who is in state want in the group uri.
func (r *chatRig) stateOf(t *testing.T, uri, who string, want groupstore.State) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		g, err := r.groups.Get(context.Background(), uri)
		if err != nil {
			t.Fatal(err)
		}
		p, ok := g.Participant(who)
		if ok && p.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is %v in the group, want %v", who, p.State, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// #137 PR C: alice's INVITE to the conference factory creates a group of
// her, joined, and the invitees in its resource list; the 200 names the
// conference URI as a focus, which rcsjta keeps to rejoin. The focus then
// invites each invitee from the conference URI, without rcs-as's loop
// marker, and a 2xx joins it: what alice writes reaches bob on his
// session with the group.
func TestAGroupIsCreatedAtTheFactoryAndItsInviteesInvited(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	toBob, toCarol := relayPath(), relayPath()
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			path := toBob
			if req.URI.String() == carol {
				path = toCarol
			}
			return []*sip.Response{r.answerInvite(t, req, path, "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	uri, s := r.create(t, p, fromAlice, bob, "sip:+15550100003@"+domain)
	contact := s.res.Header.Get("Contact")
	if !strings.HasPrefix(uri, "sip:chat-") || !strings.HasSuffix(uri, "@"+confHost) ||
		!strings.Contains(contact, ";isfocus") || !strings.Contains(contact, chatTag) {
		t.Fatalf("Contact %q", contact)
	}
	g, err := r.groups.Get(t.Context(), uri)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := g.Participant(alice); a.State != groupstore.Joined || a.Role != groupstore.Chairman || a.DisplayName != "Alice" ||
		g.Subject != "Lunch" || g.Conversation != "gc0nv1" || len(g.Participants) != 3 {
		t.Fatalf("group %+v", g)
	}

	invites := r.focusInvites(t, 2)
	for who, inv := range invites {
		h := &inv.Header
		from, _ := h.From()
		for name, want := range map[string]string{
			"P-Asserted-Identity": "<" + uri + ">",
			"P-Served-User":       "<" + who + ">;sescase=term",
			"Contact":             "<" + uri + ">;isfocus;" + chatTag,
			"Subject":             "Lunch",
			"Conversation-ID":     "gc0nv1",
			"Contribution-ID":     "gch4t1",
		} {
			if got := h.Get(name); got != want {
				t.Errorf("INVITE to %s: %s %q, want %q", who, name, got, want)
			}
		}
		// The SIP URI of carol's number at the home domain is carol.
		if (who != bob && who != carol) || from.URI.String() != uri || strings.HasPrefix(from.Tag(), ownTagPrefix) {
			t.Errorf("INVITE to %s from %s", who, h.Get("From"))
		}
	}
	r.stateOf(t, uri, bob, groupstore.Joined)
	r.stateOf(t, uri, carol, groupstore.Joined)

	relayA := r.connect(t, fromAlice, s.path)
	toBobLeg, _ := offered(t, invites[bob])
	toCarolLeg, _ := offered(t, invites[carol])
	relayB, relayC := r.connect(t, toBob, toBobLeg), r.connect(t, toCarol, toCarolLeg)
	if code := relayA.send(t, chatCPIM("g1", "hi all")); code != 200 {
		t.Fatalf("alice's message reported %d", code)
	}
	for who, relay := range map[string]*relayEnd{bob: relayB, carol: relayC} {
		c, err := cpim.Parse(relay.next(t).Body)
		if err != nil {
			t.Fatal(err)
		}
		from, _ := c.From()
		to, _ := c.To()
		if from.URI != alice || from.Name != "Alice" || len(to) != 1 || to[0].URI != uri || string(c.Body) != "hi all" {
			t.Fatalf("%s got From %v To %v: %q", who, from, to, c.Body)
		}
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("an invitation failed: %v", err)
	default:
	}
}

// A 603 Decline to the focus's INVITE is the invitee leaving the group,
// not a failure to try again (docs/rcs-as.md): rcsjta declines the first
// INVITE of a group it left while offline (RCC.07 6.3.3.1), so the focus
// must not keep inviting it into the group. What is queued for it from the
// group is given up.
func TestADeclineToTheFocusIsLeaving(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 200
		if req.Method == "INVITE" {
			code = 603
		}
		res, _ := sip.NewResponse(req, code, "", "bob1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	fromAlice := relayPath()
	uri, s := r.create(t, p, fromAlice, bob, carol)
	r.focusInvites(t, 2)
	r.stateOf(t, uri, bob, groupstore.Left)
	r.stateOf(t, uri, carol, groupstore.Left)
	if n := r.metrics.get("sip.group.declined"); n != 2 {
		t.Fatalf("%d declined", n)
	}
	select {
	case err := <-r.e.failed:
		t.Fatalf("a decline went to InviteFailed: %v", err)
	default:
	}
	// alice is still in a group of her own; what she writes is kept for
	// no one and invites no one back.
	relayA := r.connect(t, fromAlice, s.path)
	if code := relayA.send(t, chatCPIM("g1", "anyone?")); code != 200 {
		t.Fatalf("alice's message to a group of one reported %d", code)
	}
	for _, who := range []string{bob, carol} {
		if ms, err := r.store.Pending(t.Context(), who, "", r.clock.Now(), 10); err != nil || len(ms) != 0 {
			t.Fatalf("%s's queue %+v, %v", who, ms, err)
		}
	}
}

// A participant's INVITE to the conference URI joins the group again
// (RCC.07 rejoin); anyone else's is refused, and none of them becomes a
// 1-to-1 chat with the conference URI, with or without a resource list
// (security review on #252).
func TestAnInviteToTheConferenceURIJoinsOrIsRefused(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(*sip.Request) int { return 486 })
	p := r.a.dial(t)
	uri, _ := r.create(t, p, relayPath(), bob)
	r.core.nextOf(t, "INVITE")

	rejoin := func(who string) *sip.Response {
		m := r.groupInvite(uri, sdpType, offerSDP(relayPath(), "active"))
		m.from = "<" + who + ">;tag=r1"
		m.fields[0] = "P-Asserted-Identity: <" + who + ">"
		return p.send(m)
	}
	s := answeredBy(t, rejoin(bob))
	if c := s.res.Header.Get("Contact"); c != "<"+uri+">;isfocus;"+chatTag {
		t.Fatalf("Contact %q", c)
	}
	// bob's ACK, in his dialog, which stops the 2xx's retransmissions.
	if _, err := p.try(msg{method: "ACK", uri: uri, callID: s.callID, cseq: 1,
		from: "<" + bob + ">;tag=r1", to: "<" + uri + ">;tag=" + s.tag}); err != nil {
		t.Fatal(err)
	}
	r.stateOf(t, uri, bob, groupstore.Joined)
	if res := rejoin(carol); res.StatusCode != 403 {
		t.Fatalf("carol's INVITE to the group answered %d", res.StatusCode)
	}
	// A conference URI of no group, and one with a resource list, which
	// only the factory takes.
	none := r.groupInvite("sip:chat-0000@"+confHost, sdpType, offerSDP(relayPath(), "active"))
	if res := p.send(none); res.StatusCode != 404 {
		t.Fatalf("an INVITE to no group answered %d", res.StatusCode)
	}
	listed := r.groupInvite(uri, `multipart/mixed;boundary="boundary1"`,
		firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active")}, [2]string{resourcelists.ContentType, groupList(carol)}))
	if res := p.send(listed); res.StatusCode != 488 {
		t.Fatalf("an INVITE to the group with a resource list answered %d", res.StatusCode)
	}
	// alice's session, the focus's offer to bob and bob's own session.
	if n := r.metrics.get("leg.opened"); n != 3 {
		t.Fatalf("%d legs opened", n)
	}
	// Nothing of it was taken for a 1-to-1 chat: no message was queued.
	for _, who := range []string{alice, bob, carol, uri} {
		if ms, _ := r.store.Pending(t.Context(), who, "", r.clock.Now(), 10); len(ms) != 0 {
			t.Fatalf("%s's queue %+v", who, ms)
		}
	}
}

// A BYE with which the participant leaves (Reason SIP cause 200, rcsjta's
// for a user who closes the chat) is Leave; any other BYE, as for a
// session idle too long, only ends the session, and the participant can
// rejoin.
func TestAByeLeavesTheGroupOnlyWhenItSaysSo(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(*sip.Request) int { return 486 })
	p := r.a.dial(t)
	uri, s := r.create(t, p, relayPath(), bob)
	r.core.nextOf(t, "INVITE")
	bye := func(s answered, cseq int, fields ...string) {
		t.Helper()
		m := msg{method: "BYE", uri: uri, toTag: s.tag, callID: s.callID, cseq: cseq, fields: fields,
			from: "<" + alice + ">;tag=a1", to: "<" + uri + ">;tag=" + s.tag}
		if res := p.send(m); res.StatusCode != 200 {
			t.Fatalf("BYE answered %d", res.StatusCode)
		}
	}
	bye(s, 2)
	r.stateOf(t, uri, alice, groupstore.Joined)
	m := r.groupInvite(uri, sdpType, offerSDP(relayPath(), "active"))
	again := answeredBy(t, p.send(m))
	p.ack(again)
	bye(again, 2, `Reason: SIP;cause=200;text="Call completed"`)
	r.stateOf(t, uri, alice, groupstore.Left)
	if res := p.send(m); res.StatusCode != 403 {
		t.Fatalf("alice's INVITE after she left answered %d", res.StatusCode)
	}
}

// The focus's INVITE carries no loop marker (requests to and from a
// conference URI pass between tasks, #121), so one that comes back to
// rcs-as is known by its From, a conference URI: refused with 482, never
// taken for a 1-to-1 chat from the group to the participant, which would
// be stored and sent again without end.
func TestAFocusInviteThatComesBackIsRefusedAsALoop(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	p, core := r.a.dial(t), r.a.dial(t)
	bounced := make(chan int, 4)
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method != "INVITE" {
			res, _ := sip.NewResponse(req, 200, "", "core1")
			return []*sip.Response{res}
		}
		fwd := req.Clone()
		_ = fwd.Header.Set("Route", "<sip:"+r.a.addr.String()+";transport=tcp;lr>")
		_ = fwd.Header.Prepend("Via", "SIP/2.0/TCP 192.0.2.30:5060;branch=z9hG4bK-scscf-loop-focus")
		code := 0
		if res, err := core.forward(fwd); err == nil {
			code = res.StatusCode
		}
		bounced <- code
		res, _ := sip.NewResponse(req, 482, "", "core1")
		return []*sip.Response{res}
	})
	uri, _ := r.create(t, p, relayPath(), bob)
	if code := <-bounced; code != 482 {
		t.Fatalf("the returning INVITE was answered %d", code)
	}
	if n := r.metrics.get("sip.loop"); n != 1 {
		t.Fatalf("%d loops", n)
	}
	// alice's leg and the one the focus offered bob; the returning
	// INVITE opened none.
	if n := r.metrics.get("leg.opened"); n != 2 {
		t.Fatalf("%d legs opened", n)
	}
	r.stateOf(t, uri, bob, groupstore.Invited)
	if ms, _ := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10); len(ms) != 0 {
		t.Fatalf("bob's queue %+v", ms)
	}
}

// A resource list longer than a group holds is refused before anything is
// stored (docs/rcs-as.md), as is a factory INVITE without one, one whose
// offer has no type in common with rcs-as, one without a Contribution-ID,
// one that requires an extension rcs-as lacks, and one past the creator's
// bound on sessions.
func TestAFactoryInviteIsCheckedBeforeAGroupIsMade(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{MaxGroupParticipants: 3, MaxOutgoingPerUser: 1})
	p := r.a.dial(t)
	if res := p.send(r.factoryInvite(relayPath(), bob, carol, "tel:+15550100004", "tel:+15550100005")); res.StatusCode != 403 {
		t.Fatalf("a list of four for a group of three answered %d", res.StatusCode)
	}
	noList := r.groupInvite(confFactory, sdpType, offerSDP(relayPath(), "active"), "Require: recipient-list-invite")
	if res := p.send(noList); res.StatusCode != 488 {
		t.Fatalf("a factory INVITE without a list answered %d", res.StatusCode)
	}
	plain := r.groupInvite(confFactory, `multipart/mixed;boundary="boundary1"`,
		firstMessageBody([2]string{sdpType, offerSDP(relayPath(), "active", "text/plain")}, [2]string{resourcelists.ContentType, groupList(bob)}),
		"Require: recipient-list-invite")
	if res := p.send(plain); res.StatusCode != 488 {
		t.Fatalf("a factory INVITE with no type in common answered %d", res.StatusCode)
	}
	// The Contribution-ID names the chat to rcsjta; a group without one
	// could not be told from the next.
	anon := r.factoryInvite(relayPath(), bob)
	anon.fields = slices.DeleteFunc(anon.fields, func(f string) bool {
		return strings.HasPrefix(f, "Contribution-ID:") || strings.HasPrefix(f, "Conversation-ID:")
	})
	if res := p.send(anon); res.StatusCode != 400 {
		t.Fatalf("a factory INVITE without a Contribution-ID answered %d", res.StatusCode)
	}
	m := r.factoryInvite(relayPath(), bob)
	m.fields = append(m.fields, "Require: 100rel")
	if res := p.send(m); res.StatusCode != 420 {
		t.Fatalf("a factory INVITE requiring 100rel answered %d", res.StatusCode)
	}
	if n := r.metrics.get("group.created") + r.metrics.get("leg.opened"); n != 0 {
		t.Fatalf("%d groups and legs made", n)
	}
	// alice's one session, which is all she may open, leaves no room for
	// a group's: refused before the group is made.
	p.ack(answeredBy(t, p.send(r.chatInvite(offerSDP(relayPath(), "active")))))
	if res := p.send(r.factoryInvite(relayPath(), bob)); res.StatusCode != 486 {
		t.Fatalf("a factory INVITE past alice's bound answered %d", res.StatusCode)
	}
	if n := r.metrics.get("group.created"); n != 0 {
		t.Fatalf("%d groups made", n)
	}
	// A conference URI takes nothing but INVITE outside a session.
	pager := pager(cpimBody("x1", "hi"))
	pager.uri, pager.from, pager.to = "sip:chat-0000@"+confHost, "<"+alice+">;tag=a1", "<sip:chat-0000@"+confHost+">"
	if res := p.send(pager); res.StatusCode != 405 || res.Header.Get("Allow") != groupAllowed {
		t.Fatalf("a MESSAGE to a conference URI answered %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
}
