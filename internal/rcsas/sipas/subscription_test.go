package sipas

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// More participants, on .github/allowed-test-identifiers.txt.
const (
	dave = "tel:+15550100004"
	erin = "tel:+15550100005"
)

// groupRig is a group of alice, joined, and invitees whose clients do not
// answer the focus (486): they stay invited. alice's session is s.
type groupRig struct {
	*chatRig
	p   *peer
	uri string
	s   answered
}

func newGroupRig(t *testing.T, invitees ...string) *groupRig {
	t.Helper()
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 486
		}
		return 200
	})
	p := r.a.dial(t)
	uri, s := r.create(t, p, relayPath(), invitees...)
	for range invitees {
		r.core.nextOf(t, "INVITE")
	}
	return &groupRig{chatRig: r, p: p, uri: uri, s: s}
}

// subscription is a subscriber's side of a subscription: its dialog.
type subscribed struct {
	who, callID, fromTag, toTag string
	cseq                        int
}

// subscribe has who subscribe to the group's roster for expires seconds,
// and returns the 200.
func (g *groupRig) subscribe(t *testing.T, who, expires string, fields ...string) (*sip.Response, subscribed) {
	t.Helper()
	tag := "s" + who[len(who)-2:]
	m := msg{method: "SUBSCRIBE", uri: g.uri, from: "<" + who + ">;tag=" + tag, to: "<" + g.uri + ">", fields: append([]string{
		"P-Asserted-Identity: <" + who + ">",
		"Contact: <sip:" + g.core.l.Addr().String() + ";transport=tcp>",
		"Event: conference", "Expires: " + expires, "Accept: application/conference-info+xml",
	}, fields...)}
	res := g.p.send(m)
	to, _ := res.Header.To()
	return res, subscribed{who: who, callID: res.Header.Get("Call-ID"), fromTag: tag, toTag: to.Tag(), cseq: 1}
}

// again sends a SUBSCRIBE in sub's dialog for expires seconds.
func (g *groupRig) again(t *testing.T, sub *subscribed, expires string) *sip.Response {
	t.Helper()
	sub.cseq++
	return g.p.send(msg{method: "SUBSCRIBE", uri: g.uri, callID: sub.callID, cseq: sub.cseq,
		from: "<" + sub.who + ">;tag=" + sub.fromTag, to: "<" + g.uri + ">;tag=" + sub.toTag,
		fields: []string{"Event: conference", "Expires: " + expires}})
}

// notified is a NOTIFY rcs-as sent and the document it carries, if any.
type notified struct {
	req   *sip.Request
	state sip.SubscriptionState
	doc   *conference.Info
}

// nextNotify is the next NOTIFY the core got.
func (g *groupRig) nextNotify(t *testing.T) notified {
	t.Helper()
	req := g.core.nextOf(t, "NOTIFY")
	n := notified{req: req}
	var err error
	if n.state, err = req.Header.SubscriptionState(); err != nil {
		t.Fatal(err)
	}
	if ev := req.Header.Get("Event"); ev != "conference" {
		t.Fatalf("NOTIFY Event %q", ev)
	}
	if len(req.Body) > 0 {
		if ct := req.Header.Get("Content-Type"); ct != conference.ContentType {
			t.Fatalf("NOTIFY Content-Type %q", ct)
		}
		if n.doc, err = conference.Parse(req.Body); err != nil {
			t.Fatal(err)
		}
	}
	return n
}

// noNotify fails if the core gets a NOTIFY soon.
func (g *groupRig) noNotify(t *testing.T, what string) {
	t.Helper()
	deadline := time.After(100 * time.Millisecond)
	for {
		select {
		case req := <-g.core.got:
			if req.Method == "NOTIFY" {
				t.Fatalf("%s: a NOTIFY %q", what, req.Header.Get("Subscription-State"))
			}
		case <-deadline:
			return
		}
	}
}

// rejoin is who's INVITE to the conference URI, with its dialog's From
// tag; it returns the session, acknowledged.
func (g *groupRig) rejoin(t *testing.T, who string) answered {
	t.Helper()
	tag := "r" + who[len(who)-2:]
	m := g.groupInvite(g.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to = "<"+who+">;tag="+tag, "<"+g.uri+">"
	m.fields[0] = "P-Asserted-Identity: <" + who + ">"
	s := answeredBy(t, g.p.send(m))
	if _, err := g.p.try(msg{method: "ACK", uri: g.uri, callID: s.callID, cseq: 1,
		from: "<" + who + ">;tag=" + tag, to: "<" + g.uri + ">;tag=" + s.tag}); err != nil {
		t.Fatal(err)
	}
	return s
}

// inSession sends who's request in its session s with the group, whose
// From tag rejoin or create gave it.
func (g *groupRig) inSession(t *testing.T, who, fromTag string, s answered, cseq int, method string, fields []string, body string) *sip.Response {
	t.Helper()
	return g.p.send(msg{method: method, uri: g.uri, callID: s.callID, cseq: cseq, body: body, fields: fields,
		from: "<" + who + ">;tag=" + fromTag, to: "<" + g.uri + ">;tag=" + s.tag})
}

func userOf(t *testing.T, doc *conference.Info, entity string) conference.User {
	t.Helper()
	if doc == nil || doc.Users == nil {
		t.Fatal("no users in the document")
	}
	for _, u := range doc.Users.List {
		if u.Entity == entity {
			return u
		}
	}
	t.Fatalf("%s is not in the document", entity)
	return conference.User{}
}

// #137 PR C2: a participant's SUBSCRIBE to the conference event package
// (RFC 4575) is answered 200, and its first NOTIFY carries the full
// roster; every change then comes as a partial document one version up.
func TestASubscriberGetsTheRosterThenEachChange(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	res, _ := g.subscribe(t, alice, "600")
	if res.StatusCode != 200 || res.Header.Get("Expires") != "600" || res.Header.Get("Contact") != "<"+g.uri+">" {
		t.Fatalf("SUBSCRIBE answered %d, Expires %q, Contact %q", res.StatusCode, res.Header.Get("Expires"), res.Header.Get("Contact"))
	}
	first := g.nextNotify(t)
	if first.state.State != "active" || first.state.Params.Has("reason") {
		t.Fatalf("Subscription-State %v", first.state)
	}
	if e, _ := first.state.Expires(); e != 600 {
		t.Fatalf("expires %d", e)
	}
	grp, err := g.groups.Get(t.Context(), g.uri)
	if err != nil {
		t.Fatal(err)
	}
	if d := first.doc; d.State != conference.Full || d.Version != grp.Version || d.Entity != g.uri || len(d.Users.List) != 3 {
		t.Fatalf("first document %+v", d)
	}
	if from, _ := first.req.Header.From(); from.URI.String() != g.uri {
		t.Fatalf("NOTIFY from %s", from.URI)
	}

	// bob joins; then he leaves.
	s := g.rejoin(t, bob)
	joined := g.nextNotify(t)
	if d := joined.doc; d.State != conference.Partial || d.Version != grp.Version+1 || len(d.Users.List) != 1 {
		t.Fatalf("on bob's join %+v", d)
	}
	if u := userOf(t, joined.doc, bob); len(u.Endpoints) == 0 || u.Endpoints[0].Status != conference.Connected {
		t.Fatalf("bob %+v", u)
	}
	if res := g.inSession(t, bob, "r02", s, 2, "BYE", []string{`Reason: SIP;cause=200;text="Call completed"`}, ""); res.StatusCode != 200 {
		t.Fatalf("bob's BYE answered %d", res.StatusCode)
	}
	left := g.nextNotify(t)
	if left.doc.Version != grp.Version+2 {
		t.Fatalf("on bob's leaving, version %d", left.doc.Version)
	}
	if u := userOf(t, left.doc, bob); len(u.Endpoints) == 0 || u.Endpoints[0].DisconnectionMethod != conference.Departed {
		t.Fatalf("bob %+v", u)
	}
}

// Leave and Remove end that participant's subscriptions with a last NOTIFY
// (terminated, rejected: it may not subscribe again), and it learns of no
// later change; the others go on.
func TestLeavingEndsTheLeaversSubscriptionOnly(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	s := g.rejoin(t, bob)
	_, aliceSub := g.subscribe(t, alice, "600")
	g.nextNotify(t)
	_, bobSub := g.subscribe(t, bob, "600")
	g.nextNotify(t)

	if res := g.inSession(t, bob, "r02", s, 2, "BYE", []string{"Reason: SIP;cause=200"}, ""); res.StatusCode != 200 {
		t.Fatalf("bob's BYE answered %d", res.StatusCode)
	}
	byDialog := map[string][]notified{}
	for range 3 {
		n := g.nextNotify(t)
		byDialog[n.req.Header.Get("Call-ID")] = append(byDialog[n.req.Header.Get("Call-ID")], n)
	}
	if ns := byDialog[aliceSub.callID]; len(ns) != 1 || ns[0].state.State != "active" {
		t.Fatalf("alice got %+v", ns)
	}
	ns := byDialog[bobSub.callID]
	last := ns[len(ns)-1]
	if last.state.State != "terminated" || last.state.Reason() != reasonRejected || last.doc != nil {
		t.Fatalf("bob's last NOTIFY %v with %+v", last.state, last.doc)
	}
	// carol joins: alice hears of it, bob does not.
	g.rejoin(t, carol)
	if n := g.nextNotify(t); n.req.Header.Get("Call-ID") != aliceSub.callID {
		t.Fatal("a NOTIFY for bob's ended subscription")
	}
	g.noNotify(t, "after carol joined")
	if res := g.again(t, &bobSub, "600"); res.StatusCode != 481 {
		t.Fatalf("bob's refresh of an ended subscription answered %d", res.StatusCode)
	}
	if res, _ := g.subscribe(t, bob, "600"); res.StatusCode != 403 {
		t.Fatalf("bob's new SUBSCRIBE answered %d", res.StatusCode)
	}
}

// A refresh gets the full roster again, Expires 0 ends the subscription,
// and one left unrefreshed ends when its time runs out; each with a NOTIFY
// (RFC 6665 §4.1.2, §4.2.2).
func TestASubscriptionIsRefreshedEndedAndExpires(t *testing.T) {
	g := newGroupRig(t, bob)
	_, sub := g.subscribe(t, alice, "600")
	g.nextNotify(t)
	if res := g.again(t, &sub, "1200"); res.StatusCode != 200 || res.Header.Get("Expires") != "1200" {
		t.Fatalf("refresh answered %d, Expires %q", res.StatusCode, res.Header.Get("Expires"))
	}
	if n := g.nextNotify(t); n.state.State != "active" || n.doc.State != conference.Full {
		t.Fatalf("after the refresh %v %+v", n.state, n.doc)
	}
	if res := g.again(t, &sub, "0"); res.StatusCode != 200 {
		t.Fatalf("unsubscribe answered %d", res.StatusCode)
	}
	if n := g.nextNotify(t); n.state.State != "terminated" || n.state.Reason() != reasonTimeout {
		t.Fatalf("after unsubscribing %v", n.state)
	}

	g.subscribe(t, alice, "120")
	g.nextNotify(t)
	g.clock.fire(120 * time.Second)
	if n := g.nextNotify(t); n.state.State != "terminated" || n.state.Reason() != reasonTimeout {
		t.Fatalf("on expiry %v", n.state)
	}
	g.rejoin(t, bob)
	g.noNotify(t, "after every subscription ended")
}

// What a SUBSCRIBE may not be: for another package (489), for too short a
// time (423), for documents of another type (406), from someone outside
// the group (403), to no group (404).
// With Expires 0 it fetches the roster once.
func TestASubscribeIsCheckedAndMayFetch(t *testing.T) {
	g := newGroupRig(t, bob)
	if res, _ := g.subscribe(t, alice, "600", "Event: presence"); res.StatusCode != 400 && res.StatusCode != 489 {
		t.Fatalf("two Events answered %d", res.StatusCode)
	}
	m := msg{method: "SUBSCRIBE", uri: g.uri, from: "<" + alice + ">;tag=x1", to: "<" + g.uri + ">",
		fields: []string{"P-Asserted-Identity: <" + alice + ">", "Contact: <sip:" + g.core.l.Addr().String() + ";transport=tcp>", "Event: presence"}}
	if res := g.p.send(m); res.StatusCode != 489 || res.Header.Get("Allow-Events") != "conference" {
		t.Fatalf("presence answered %d, Allow-Events %q", res.StatusCode, res.Header.Get("Allow-Events"))
	}
	if res, _ := g.subscribe(t, alice, "30"); res.StatusCode != 423 || res.Header.Get("Min-Expires") != "60" {
		t.Fatalf("30 s answered %d, Min-Expires %q", res.StatusCode, res.Header.Get("Min-Expires"))
	}
	accept := m
	accept.fields = []string{"P-Asserted-Identity: <" + alice + ">", "Contact: <sip:" + g.core.l.Addr().String() + ";transport=tcp>",
		"Event: conference", "Accept: application/pidf+xml"}
	if res := g.p.send(accept); res.StatusCode != 406 || res.Header.Get("Accept") != conference.ContentType {
		t.Fatalf("an Accept without conference-info answered %d, Accept %q", res.StatusCode, res.Header.Get("Accept"))
	}
	if res, _ := g.subscribe(t, carol, "600"); res.StatusCode != 403 {
		t.Fatalf("carol's SUBSCRIBE answered %d", res.StatusCode)
	}
	saved := g.uri
	g.uri = "sip:chat-0000@" + confHost
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 404 {
		t.Fatalf("a SUBSCRIBE to no group answered %d", res.StatusCode)
	}
	g.uri = saved
	g.noNotify(t, "after refused SUBSCRIBEs")
	if res, _ := g.subscribe(t, alice, "0"); res.StatusCode != 200 {
		t.Fatalf("a fetch answered %d", res.StatusCode)
	}
	if n := g.nextNotify(t); n.state.State != "terminated" || n.doc == nil || n.doc.State != conference.Full {
		t.Fatalf("the fetch's NOTIFY %v %+v", n.state, n.doc)
	}
	g.rejoin(t, bob)
	g.noNotify(t, "after a fetch")
}

// One participant holds a few subscriptions to a group at most, so that it
// cannot fill a task with them.
func TestAParticipantHoldsAFewSubscriptionsAtMost(t *testing.T) {
	g := newGroupRig(t, bob)
	for i := range MaxSubscriptionsPerParticipant {
		m := msg{method: "SUBSCRIBE", uri: g.uri, from: "<" + alice + ">;tag=m" + string(rune('a'+i)), to: "<" + g.uri + ">",
			fields: []string{"P-Asserted-Identity: <" + alice + ">", "Contact: <sip:" + g.core.l.Addr().String() + ";transport=tcp>", "Event: conference"}}
		if res := g.p.send(m); res.StatusCode != 200 {
			t.Fatalf("subscription %d answered %d", i, res.StatusCode)
		}
		g.nextNotify(t)
	}
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 486 {
		t.Fatalf("one subscription too many answered %d", res.StatusCode)
	}
	// A fetch holds none: bob fetches more often than he may subscribe,
	// and may still subscribe.
	for range MaxSubscriptionsPerParticipant + 1 {
		if res, _ := g.subscribe(t, bob, "0"); res.StatusCode != 200 {
			t.Fatalf("bob's fetch answered %d", res.StatusCode)
		}
		g.nextNotify(t)
	}
	if res, _ := g.subscribe(t, bob, "600"); res.StatusCode != 200 {
		t.Fatalf("bob's SUBSCRIBE after his fetches answered %d", res.StatusCode)
	}
}

// A 603 to the focus's INVITE is the invitee leaving: its subscription
// ends as on any Leave.
func TestADeclineEndsTheDeclinersSubscription(t *testing.T) {
	g := newGroupRig(t, bob)
	_, sub := g.subscribe(t, bob, "600")
	g.nextNotify(t)
	g.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 603
		}
		return 200
	})
	inv := messaging.Invitation{Recipient: bob, Peer: g.uri, Mode: store.Group, Conversation: messaging.Conversation{ID: "gc0nv1", Contribution: "gch4t1"}}
	if err := g.a.srv.Invite(t.Context(), inv); err != nil {
		t.Fatal(err)
	}
	for {
		n := g.nextNotify(t)
		if n.req.Header.Get("Call-ID") == sub.callID && n.state.State == "terminated" {
			if n.state.Reason() != reasonRejected {
				t.Fatalf("bob's subscription ended %v", n.state)
			}
			return
		}
	}
}

// A subscriber that would see a gap in the versions, as when a change
// reaches no subscription here, gets the full roster with the next change
// instead of a partial document it could not apply.
func TestAGapInTheVersionsSendsTheFullRoster(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	g.subscribe(t, alice, "600")
	first := g.nextNotify(t)
	g.skipRoster.Store(1)
	g.rejoin(t, bob)
	g.rejoin(t, carol)
	n := g.nextNotify(t)
	if n.doc.State != conference.Full || n.doc.Version != first.doc.Version+2 {
		t.Fatalf("after a gap %s version %d, want full %d", n.doc.State, n.doc.Version, first.doc.Version+2)
	}
	if u := userOf(t, n.doc, bob); u.Endpoints[0].Status != conference.Connected {
		t.Fatalf("bob %+v", u)
	}
	// A change the subscriber has already, as one that raced its full
	// roster, is not sent again.
	g.a.srv.RosterChanged(t.Context(), group.RosterUpdate{Group: g.uri, Version: n.doc.Version, Document: n.req.Body})
	g.noNotify(t, "for a version the subscriber has")
}

// A NOTIFY the subscriber refuses ends the subscription without another
// (RFC 6665 §4.2.2).
func TestARefusedNotifyEndsTheSubscription(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	g.subscribe(t, alice, "600")
	g.nextNotify(t)
	g.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "NOTIFY" {
			return 481
		}
		return 200
	})
	g.rejoin(t, bob)
	g.nextNotify(t)
	waitUntil(t, "the subscription removed", func() bool { return g.metrics.get("sip.subscription.notify_failed") == 1 })
	g.rejoin(t, carol)
	g.noNotify(t, "after a refused NOTIFY")
}

// A participant adds someone by a REFER in its session (RFC 4579 §5.5):
// 202, and the focus invites them. With Refer-Sub: false, as rcsjta sends,
// nothing more; without it, one NOTIFY ends the implicit subscription. A
// REFER to a cid: URI adds everyone in its resource list (RFC 5368).
func TestAReferAddsAndTheFocusInvites(t *testing.T) {
	g := newGroupRig(t, bob)
	res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">", "Refer-Sub: false"}, "")
	if res.StatusCode != 202 || res.Header.Get("Refer-Sub") != "false" {
		t.Fatalf("REFER answered %d, Refer-Sub %q", res.StatusCode, res.Header.Get("Refer-Sub"))
	}
	if inv := g.core.nextOf(t, "INVITE"); inv.URI.String() != carol || inv.Header.Get("Subject") != "Lunch" ||
		inv.Header.Get("Contribution-ID") != "gch4t1" {
		t.Fatalf("INVITE %s, Subject %q, Contribution-ID %q", inv.URI, inv.Header.Get("Subject"), inv.Header.Get("Contribution-ID"))
	}
	g.stateOf(t, g.uri, carol, groupstore.Invited)

	res = g.inSession(t, alice, "a1", g.s, 3, "REFER", []string{"Refer-To: <cid:list1@" + domain + ">",
		"Require: multiple-refer, norefersub", "Content-Type: " + resourcelists.ContentType}, groupList(dave, "sip:+15550100005@"+domain))
	if res.StatusCode != 202 {
		t.Fatalf("a REFER with a list answered %d", res.StatusCode)
	}
	got := map[string]bool{}
	for range 2 {
		got[g.core.nextOf(t, "INVITE").URI.String()] = true
	}
	if !got[dave] || !got[erin] {
		t.Fatalf("invited %v", got)
	}
	g.stateOf(t, g.uri, erin, groupstore.Invited)

	// Without Refer-Sub: false, rcs-as ends the implicit subscription at
	// once.
	grp, _ := g.groups.Get(t.Context(), g.uri)
	if res := g.inSession(t, alice, "a1", g.s, 4, "REFER", []string{"Refer-To: <" + bob + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("a REFER for bob answered %d", res.StatusCode)
	}
	n := g.core.nextOf(t, "NOTIFY")
	if n.Header.Get("Event") != "refer;id=4" || !strings.HasPrefix(n.Header.Get("Subscription-State"), "terminated") ||
		n.Header.Get("Content-Type") != "message/sipfrag" {
		t.Fatalf("refer NOTIFY Event %q, State %q, Content-Type %q", n.Header.Get("Event"), n.Header.Get("Subscription-State"), n.Header.Get("Content-Type"))
	}
	// bob, invited already, was left alone.
	if after, _ := g.groups.Get(t.Context(), g.uri); after.Version != grp.Version {
		t.Fatalf("version %d after re-adding bob, was %d", after.Version, grp.Version)
	}
}

// The chairman removes someone by a REFER with method=BYE (RFC 4579
// §5.11): their session gets a BYE and their subscription ends. Nobody
// else may remove, and a 1-to-1 session takes no REFER.
func TestAReferWithByeRemoves(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	bobSession := g.rejoin(t, bob)
	_, bobSub := g.subscribe(t, bob, "600")
	g.nextNotify(t)
	carolSession := g.rejoin(t, carol)
	g.nextNotify(t) // bob hears of carol

	if res := g.inSession(t, carol, "r03", carolSession, 2, "REFER", []string{"Refer-To: <sip:+15550100002@" + domain + ";method=BYE>", "Refer-Sub: false"}, ""); res.StatusCode != 403 {
		t.Fatalf("carol removing bob answered %d", res.StatusCode)
	}
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <sip:+15550100002@" + domain + ";method=BYE>", "Refer-Sub: false"}, ""); res.StatusCode != 202 {
		t.Fatalf("alice removing bob answered %d", res.StatusCode)
	}
	g.stateOf(t, g.uri, bob, groupstore.Removed)
	var bye *sip.Request
	var ended bool
	for bye == nil || !ended {
		req := g.core.next(t)
		switch {
		case req.Method == "BYE" && req.Header.Get("Call-ID") == bobSession.callID:
			bye = req
		case req.Method == "NOTIFY" && req.Header.Get("Call-ID") == bobSub.callID:
			if st, _ := req.Header.SubscriptionState(); st.State == "terminated" {
				if st.Reason() != reasonRejected {
					t.Fatalf("bob's subscription ended %v", st)
				}
				ended = true
			}
		}
	}

	chat := g.chatRig
	p := chat.a.dial(t)
	s := answeredBy(t, p.send(chat.chatInvite(offerSDP(relayPath(), "active"))))
	p.ack(s)
	if res := p.send(msg{method: "REFER", uri: bob, toTag: s.tag, callID: s.callID, cseq: 2, fields: []string{"Refer-To: <" + carol + ">"}}); res.StatusCode != 405 {
		t.Fatalf("a REFER in a 1-to-1 session answered %d", res.StatusCode)
	}
}

// A shutdown ends every subscription with a NOTIFY that lets the
// subscriber subscribe again at once, to another task (deactivated).
func TestShutdownDeactivatesSubscriptions(t *testing.T) {
	g := newGroupRig(t, bob)
	g.subscribe(t, alice, "600")
	g.nextNotify(t)
	go g.a.srv.Close()
	for {
		n := g.nextNotify(t)
		if n.state.State == "terminated" {
			if n.state.Reason() != reasonDeactivated {
				t.Fatalf("on shutdown %v", n.state)
			}
			return
		}
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
