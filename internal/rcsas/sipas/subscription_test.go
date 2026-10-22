package sipas

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
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
	return newGroupRigWith(t, Config{}, invitees...)
}

// newGroupRigWith is newGroupRig on a Server configured by cfg.
func newGroupRigWith(t *testing.T, cfg Config, invitees ...string) *groupRig {
	t.Helper()
	r := newChatRigWith(t, messaging.Config{}, cfg)
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

// after reports whether req is a NOTIFY of the subscription of first that
// came after it: the core's answer to first may be made only after a test
// changes how the core answers.
func after(req, first *sip.Request) bool {
	c, err1 := req.Header.CSeq()
	f, err2 := first.Header.CSeq()
	return err1 == nil && err2 == nil && req.Method == "NOTIFY" &&
		req.Header.Get("Call-ID") == first.Header.Get("Call-ID") && c.Seq > f.Seq
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
// (RFC 6665 §4.2.2), from its answer on, not from the removal that follows
// under the subscription's lock (#423): the test holds that removal back
// while carol's rejoin changes the roster, and the change must send
// nothing. Each outcome shows: the NOTIFY, or the count of one not sent.
func TestARefusedNotifyEndsTheSubscription(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	g.subscribe(t, alice, "600")
	first := g.nextNotify(t)
	g.core.setAnswer(func(req *sip.Request) int {
		// Not the first NOTIFY, which the core may answer only now.
		if after(req, first.req) {
			return 481
		}
		return 200
	})
	release := holdRefusals(t)
	g.rejoin(t, bob)
	g.nextNotify(t)
	waitUntil(t, "the refusal", func() bool { return g.metrics.get("sip.subscription.notify_failed") == 1 })
	g.rejoin(t, carol)
	g.dropsNotify(t, "after a refused NOTIFY")
	release()
	g.noNotify(t, "after a refused NOTIFY")
}

// holdRefusals holds every failed NOTIFY's removal of its subscription
// until release, or the test's end (refusalTakesLock).
func holdRefusals(t *testing.T) (release func()) {
	t.Helper()
	hold := make(chan struct{})
	release = sync.OnceFunc(func() { close(hold) })
	t.Cleanup(func() { refusalTakesLock.Store(nil); release() })
	wait := func() { <-hold }
	refusalTakesLock.Store(&wait)
	return release
}

// dropsNotify waits for the roster change just made to end one way or the
// other: a NOTIFY reaches the core, which fails the test, or one is
// counted as not sent after a refusal.
func (g *groupRig) dropsNotify(t *testing.T, what string) {
	t.Helper()
	deadline := time.After(waitFor)
	for g.metrics.get("sip.subscription.notify_after_refusal") == 0 {
		select {
		case req := <-g.core.got:
			if req.Method == "NOTIFY" {
				t.Fatalf("%s: a NOTIFY %q", what, req.Header.Get("Subscription-State"))
			}
		case <-deadline:
			t.Fatalf("%s: the change neither sent a NOTIFY nor dropped one", what)
		case <-time.After(time.Millisecond):
		}
	}
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
	// Referred-By names alice, who added carol.
	if inv := g.core.nextOf(t, "INVITE"); inv.URI.String() != carol || inv.Header.Get("Subject") != "Lunch" ||
		inv.Header.Get("Contribution-ID") != "gch4t1" || inv.Header.Get("Referred-By") != "<"+alice+">" {
		t.Fatalf("INVITE %s, Subject %q, Contribution-ID %q, Referred-By %q", inv.URI, inv.Header.Get("Subject"),
			inv.Header.Get("Contribution-ID"), inv.Header.Get("Referred-By"))
	}
	// The factory is nobody to add (security review on #279).
	if res := g.inSession(t, alice, "a1", g.s, 3, "REFER", []string{"Refer-To: <" + confFactory + ">", "Refer-Sub: false"}, ""); res.StatusCode != 400 {
		t.Fatalf("a REFER adding the factory answered %d", res.StatusCode)
	}
	g.stateOf(t, g.uri, carol, groupstore.Invited)

	res = g.inSession(t, alice, "a1", g.s, 4, "REFER", []string{"Refer-To: <cid:list1@" + domain + ">",
		"Require: multiple-refer, norefersub", "Content-Type: " + resourcelists.ContentType}, strings.Replace(groupList(dave, "sip:+15550100005@"+domain), "</list>", `<entry uri="sip:a b@example.net"/></list>`, 1))
	if res.StatusCode != 202 {
		t.Fatalf("a REFER with a list answered %d", res.StatusCode)
	}
	got := map[string]bool{}
	for range 2 {
		got[g.core.nextOf(t, "INVITE").URI.String()] = true
	}
	// A bad entry in the list is left out and counted, not a reason to
	// refuse it; the factory above is the other skip.
	if !got[dave] || !got[erin] || g.metrics.get("sip.group.invitee_skipped.loop") != 1 || g.metrics.get("sip.group.invitee_skipped.malformed") != 1 {
		t.Fatalf("invited %v, %d and %d skipped", got, g.metrics.get("sip.group.invitee_skipped.loop"), g.metrics.get("sip.group.invitee_skipped.malformed"))
	}
	g.stateOf(t, g.uri, erin, groupstore.Invited)

	// Without Refer-Sub: false, the implicit subscription starts with
	// "100 Trying" (RFC 3515 §2.4.4) and ends with how the focus's INVITE
	// ended. bob, invited already and rung at the group's creation, gets
	// no second INVITE, so the subscription ends at its bound, with 480 as
	// for any failure.
	grp, _ := g.groups.Get(t.Context(), g.uri)
	if res := g.inSession(t, alice, "a1", g.s, 5, "REFER", []string{"Refer-To: <" + bob + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("a REFER for bob answered %d", res.StatusCode)
	}
	n := g.core.nextOf(t, "NOTIFY")
	if n.Header.Get("Event") != "refer;id=5" || !strings.HasPrefix(n.Header.Get("Subscription-State"), "active") ||
		n.Header.Get("Content-Type") != "message/sipfrag" || string(n.Body) != "SIP/2.0 100 Trying\r\n" {
		t.Fatalf("refer NOTIFY Event %q, State %q, Content-Type %q: %q", n.Header.Get("Event"), n.Header.Get("Subscription-State"), n.Header.Get("Content-Type"), n.Body)
	}
	g.clock.fire(referWait)
	n = g.core.nextOf(t, "NOTIFY")
	if !strings.HasPrefix(n.Header.Get("Subscription-State"), "terminated") || string(n.Body) != "SIP/2.0 480 Temporarily Unavailable\r\n" {
		t.Fatalf("refer NOTIFY State %q: %q", n.Header.Get("Subscription-State"), n.Body)
	}
	g.a.srv.mu.Lock()
	waiting := len(g.a.srv.refers)
	g.a.srv.mu.Unlock()
	if waiting != 0 {
		t.Fatalf("%d REFERs kept after their bound", waiting)
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

// Close waits for the answer to a subscription's last NOTIFY, as it does
// for a BYE's: the transport closing at once could drop it.
func TestCloseWaitsForTheLastNotifysAnswer(t *testing.T) {
	g := newGroupRigWith(t, Config{closeWait: time.Hour}, bob)
	g.subscribe(t, alice, "600")
	g.nextNotify(t)
	// alice's session ends (she stays in the group), so that the only
	// answer Close waits for is the NOTIFY's: the core answers in turn,
	// and a BYE behind the held NOTIFY would hold Close too.
	if res := g.inSession(t, alice, "a1", g.s, 2, "BYE", nil, ""); res.StatusCode != 200 {
		t.Fatalf("alice's BYE answered %d", res.StatusCode)
	}
	got, held := make(chan struct{}, 1), make(chan struct{})
	release := sync.OnceFunc(func() { close(held) })
	defer release()
	t.Cleanup(release)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "NOTIFY" {
			got <- struct{}{}
			<-held
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	closed := make(chan struct{})
	go func() { g.a.srv.Close(); close(closed) }()
	select {
	case <-got:
	case <-time.After(waitFor):
		t.Fatal("no NOTIFY on shutdown")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before its NOTIFY was answered")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case <-closed:
	case <-time.After(waitFor):
		t.Fatal("Close did not return after the answer")
	}
}

// QA on #340: a REFER's implicit subscription ends with the outcome of the
// focus's INVITE it caused, not a 200 sent before the INVITE went out. A
// failure, here the invitee's 486, is told as 480 alone, so that the
// referrer does not learn whether the number is a subscriber or online
// (security review on #340).
func TestAReferNotifiesTheInvitesOutcome(t *testing.T) {
	g := newGroupRig(t, bob)
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	var bodies []string
	for len(bodies) < 2 {
		n := g.core.nextOf(t, "NOTIFY")
		if n.Header.Get("Event") == "refer;id=2" {
			bodies = append(bodies, n.Header.Get("Subscription-State")+" "+string(n.Body))
		}
	}
	if !strings.HasPrefix(bodies[0], "active") || !strings.HasSuffix(bodies[0], "100 Trying\r\n") ||
		!strings.HasPrefix(bodies[1], "terminated") || !strings.HasSuffix(bodies[1], "480 Temporarily Unavailable\r\n") {
		t.Fatalf("refer NOTIFYs %q", bodies)
	}
}

// QA on #340: a REFER's implicit subscription ends with 200 once the
// invitee's session is up, and with 200 for a removal, rather than with a
// failure at its bound.
func TestAReferReportsTheSuccessOfAnAdditionAndARemoval(t *testing.T) {
	g := newGroupRig(t, bob)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		if req.Method == "INVITE" {
			return []*sip.Response{g.answerInvite(t, req, relayPath(), "active")}
		}
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	final := func(id string) string {
		t.Helper()
		for {
			n := g.core.nextOf(t, "NOTIFY")
			if n.Header.Get("Event") == "refer;id="+id && strings.HasPrefix(n.Header.Get("Subscription-State"), "terminated") {
				return string(n.Body)
			}
		}
	}
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	if body := final("2"); body != "SIP/2.0 200 OK\r\n" {
		t.Fatalf("addition ended with %q", body)
	}
	if res := g.inSession(t, alice, "a1", g.s, 3, "REFER", []string{"Refer-To: <" + carol + ";method=BYE>"}, ""); res.StatusCode != 202 {
		t.Fatalf("remove answered %d", res.StatusCode)
	}
	if body := final("3"); body != "SIP/2.0 200 OK\r\n" {
		t.Fatalf("removal ended with %q", body)
	}
}

// QA on #340: a focus INVITE whose 2xx sets up no dialog, here one
// without a Contact, fails at once, and so does the REFER that asked for
// it: 480 then, not at the bound.
func TestAReferReportsAnInviteWithoutADialogAsAFailure(t *testing.T) {
	g := newGroupRig(t, bob)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		res, _ := sip.NewResponse(req, 200, "", "core1")
		return []*sip.Response{res}
	})
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	for {
		n := g.core.nextOf(t, "NOTIFY")
		if n.Header.Get("Event") != "refer;id=2" || !strings.HasPrefix(n.Header.Get("Subscription-State"), "terminated") {
			continue
		}
		if string(n.Body) != "SIP/2.0 480 Temporarily Unavailable\r\n" || g.metrics.get("sip.invite.no_dialog") != 1 {
			t.Fatalf("ended with %q, %d INVITEs without a dialog", n.Body, g.metrics.get("sip.invite.no_dialog"))
		}
		return
	}
}

// A referrer that refuses the REFER's first NOTIFY (RFC 6665 §4.2.2) has
// ended its implicit subscription: the outcome of the INVITE is not sent
// (#429). The core holds its answer to that INVITE until the refusal has
// been taken, so the outcome comes after it; then the test waits for the
// outcome's NOTIFY, which fails it, or the count of one not sent.
func TestAReferWhoseFirstNotifyIsRefusedSendsNoOutcome(t *testing.T) {
	g := newGroupRig(t, bob)
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(release)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 200
		switch {
		case req.Method == "NOTIFY" && strings.HasPrefix(req.Header.Get("Event"), "refer"):
			code = 481
		case req.Method == "INVITE":
			<-hold
			code = 486
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		return []*sip.Response{res}
	})
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	waitUntil(t, "the refusal", func() bool { return g.metrics.get("sip.refer.notify_failed") == 1 })
	release()
	g.referOutcomeDropped(t)
}

// referOutcomeDropped waits for a REFER's outcome to be settled one way or
// the other: its NOTIFY reaches the core, which fails the test, or it is
// counted as not sent; and then requires it was not counted as told.
func (g *groupRig) referOutcomeDropped(t *testing.T) {
	t.Helper()
	deadline := time.After(waitFor)
	for g.metrics.get("sip.refer.notify_after_refusal") == 0 {
		select {
		case req := <-g.core.got:
			if req.Method == "NOTIFY" && strings.HasPrefix(req.Header.Get("Subscription-State"), "terminated") {
				t.Fatalf("the outcome %q went after the referrer ended the subscription", req.Body)
			}
		case <-deadline:
			t.Fatal("the INVITE's outcome was neither sent nor dropped")
		case <-time.After(time.Millisecond):
		}
	}
	if n := g.metrics.get("sip.refer.notified"); n != 0 {
		t.Fatalf("%d REFER subscriptions counted as told their outcome", n)
	}
}

// A REFER's first NOTIFY that times out ends its implicit subscription as
// a refused one does (RFC 6665 §4.2.2): the outcome is not sent (#429,
// #465). The transactions run on a fake clock (#430's txClock): Timer F of
// that NOTIFY is the first 64*T1 timer armed after the REFER, since the
// NOTIFY goes before the focus's INVITE does.
func TestAReferWhoseFirstNotifyTimesOutSendsNoOutcome(t *testing.T) {
	txc := newFakeClock()
	r := newChatRigWith(t, messaging.Config{}, Config{}, func(c *proxy.Config) { c.Transaction = transaction.Config{Clock: txClock{txc}} })
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(release)
	var held atomic.Bool
	r.core.setReply(func(req *sip.Request) []*sip.Response {
		switch {
		case req.Method == "NOTIFY" && strings.HasPrefix(req.Header.Get("Event"), "refer"):
			return nil // never answered
		case req.Method == "INVITE" && held.Load():
			<-hold
		}
		code := 200
		if req.Method == "INVITE" {
			code = 486
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		return []*sip.Response{res}
	})
	p := r.a.dial(t)
	uri, s := r.create(t, p, relayPath(), bob)
	r.core.nextOfEach(t, "INVITE", "ACK")
	g := &groupRig{chatRig: r, p: p, uri: uri, s: s}
	held.Store(true)
	since := txc.mark()
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	txc.fireFirstSince(t, since, 64*transaction.DefaultT1)
	waitUntil(t, "the NOTIFY's timeout", func() bool { return g.metrics.get("sip.refer.notify_failed") == 1 })
	release()
	g.referOutcomeDropped(t)
}

// A REFER's NOTIFY refused for a passing reason, a 503 say (RFC 5057), does
// not end its subscription: the outcome still goes (QA of #433).
func TestAReferWhoseFirstNotifyFailsForAPassingReasonStillTellsItsOutcome(t *testing.T) {
	g := newGroupRig(t, bob)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 200
		switch {
		case req.Method == "NOTIFY" && strings.HasPrefix(req.Header.Get("Event"), "refer") &&
			!strings.HasPrefix(req.Header.Get("Subscription-State"), "terminated"):
			code = 503
		case req.Method == "INVITE":
			code = 486
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		return []*sip.Response{res}
	})
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	for {
		n := g.core.nextOf(t, "NOTIFY")
		if strings.HasPrefix(n.Header.Get("Event"), "refer") && strings.HasPrefix(n.Header.Get("Subscription-State"), "terminated") {
			if string(n.Body) != "SIP/2.0 480 Temporarily Unavailable\r\n" {
				t.Fatalf("outcome %q, want 480", n.Body)
			}
			break
		}
	}
	if n := g.metrics.get("sip.refer.notify_after_refusal"); n != 0 {
		t.Fatalf("%d REFER NOTIFYs dropped after a 503 that keeps the subscription", n)
	}
}

// The refusal takes effect before it is counted (QA of #433): with the
// INVITE held, the REFER's own bound ends it at the moment the refusal is
// counted (the counter's hook runs before the count), and its outcome must
// already be held back.
func TestAReferRefusalHoldsBackAnOutcomeDueAtOnce(t *testing.T) {
	g := newGroupRig(t, bob)
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })
	t.Cleanup(release)
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 200
		switch {
		case req.Method == "NOTIFY" && strings.HasPrefix(req.Header.Get("Event"), "refer"):
			code = 481
		case req.Method == "INVITE":
			<-hold
			code = 486
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		return []*sip.Response{res}
	})
	var once sync.Once
	fired := make(chan struct{})
	h := func(name string) {
		if name == "sip.refer.notify_failed" {
			once.Do(func() { g.clock.fire(referWait); close(fired) }) // finish runs here
		}
	}
	g.metrics.hook.Store(&h)
	t.Cleanup(func() { g.metrics.hook.Store(nil) })
	if res := g.inSession(t, alice, "a1", g.s, 2, "REFER", []string{"Refer-To: <" + carol + ">"}, ""); res.StatusCode != 202 {
		t.Fatalf("REFER answered %d", res.StatusCode)
	}
	select {
	case <-fired:
	case <-time.After(waitFor):
		t.Fatal("no refusal counted")
	}
	g.referOutcomeDropped(t)
}

// Code review and QA on #340: Referred-By names whoever sent the REFER,
// here bob, who is not the group's creator.
func TestAReferredInviteNamesTheReferrerNotTheCreator(t *testing.T) {
	g := newGroupRig(t, bob)
	bs := g.rejoin(t, bob)
	g.stateOf(t, g.uri, bob, groupstore.Joined)
	if res := g.inSession(t, bob, "r02", bs, 2, "REFER", []string{"Refer-To: <" + dave + ">", "Refer-Sub: false"}, ""); res.StatusCode != 202 {
		t.Fatalf("bob's REFER answered %d", res.StatusCode)
	}
	if inv := g.core.nextOf(t, "INVITE"); inv.URI.String() != dave || inv.Header.Get("Referred-By") != "<"+bob+">" {
		t.Fatalf("INVITE %s, Referred-By %q", inv.URI, inv.Header.Get("Referred-By"))
	}
}

// A NOTIFY that is not answered, as when the subscriber's flow is gone,
// ends the subscription at the transaction's timeout (RFC 6665 §4.2.2).
// txClock is a fakeClock as a transaction layer's Clock: its timers run
// only when the test says, so no ACK wait or safety net of a short T1
// expires under load before the timeout a test is about (#430).
type txClock struct{ *fakeClock }

func (c txClock) AfterFunc(d time.Duration, f func()) transaction.Timer {
	return c.fakeClock.AfterFunc(d, f)
}

func TestAnUnansweredNotifyEndsTheSubscription(t *testing.T) {
	txc := newFakeClock()
	r := newChatRigWith(t, messaging.Config{}, Config{}, func(c *proxy.Config) { c.Transaction = transaction.Config{Clock: txClock{txc}} })
	r.core.setAnswer(func(req *sip.Request) int {
		switch req.Method {
		case "INVITE":
			return 486
		case "NOTIFY":
			return 0 // never answered
		}
		return 200
	})
	p := r.a.dial(t)
	uri, s := r.create(t, p, relayPath(), bob, carol)
	// Both INVITEs, and the ACKs of their 486s, in whatever order: the
	// transactions are done with their Timer B before the mark below
	// (#430).
	r.core.nextOfEach(t, "INVITE", "INVITE", "ACK", "ACK")
	g := &groupRig{chatRig: r, p: p, uri: uri, s: s}
	since := txc.mark()
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE answered %d", res.StatusCode)
	}
	g.nextNotify(t)
	// Timer F of the NOTIFY, the one 64*T1 timer set since the SUBSCRIBE
	// (#430: a T1 of 5 ms, for a quick Timer F, left the creator's ACK
	// 320 ms, which a loaded host passed, and the group invited no one).
	txc.fireSince(t, since, 64*transaction.DefaultT1)
	waitUntil(t, "the subscription removed at the NOTIFY's timeout", func() bool {
		g.a.srv.mu.Lock()
		defer g.a.srv.mu.Unlock()
		return len(g.a.srv.subs) == 0
	})
	if n := g.metrics.get("sip.subscription.stale"); n != 0 {
		t.Fatalf("%d subscriptions marked stale", n)
	}
	g.rejoin(t, bob)
	g.noNotify(t, "after an unanswered NOTIFY")
}

// Code review of #427: a NOTIFY that times out ends the subscription from
// its timeout on, as a refused one does: with the removal held back, a
// roster change right after sends nothing.
func TestAChangeRightAfterATimedOutNotifySendsNothing(t *testing.T) {
	txc := newFakeClock()
	r := newChatRigWith(t, messaging.Config{}, Config{}, func(c *proxy.Config) { c.Transaction = transaction.Config{Clock: txClock{txc}} })
	r.core.setAnswer(func(req *sip.Request) int {
		switch req.Method {
		case "INVITE":
			return 486
		case "NOTIFY":
			return 0 // never answered
		}
		return 200
	})
	p := r.a.dial(t)
	uri, s := r.create(t, p, relayPath(), bob, carol)
	// Both INVITEs, and the ACKs of their 486s, in whatever order: the
	// transactions are done with their Timer B before the mark below
	// (#430).
	r.core.nextOfEach(t, "INVITE", "INVITE", "ACK", "ACK")
	g := &groupRig{chatRig: r, p: p, uri: uri, s: s}
	release := holdRefusals(t)
	since := txc.mark()
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE answered %d", res.StatusCode)
	}
	g.nextNotify(t)
	txc.fireSince(t, since, 64*transaction.DefaultT1) // its Timer F (#430)
	waitUntil(t, "the NOTIFY's timeout", func() bool { return g.metrics.get("sip.subscription.notify_failed") == 1 })
	g.rejoin(t, bob)
	g.dropsNotify(t, "right after a timed-out NOTIFY")
	release()
	g.noNotify(t, "right after a timed-out NOTIFY")
}

// Code review on #340: a NOTIFY refused for a passing reason, a 503 from a
// proxy whose queue is full (RFC 5057), keeps the subscription. The
// subscriber missed a document, so the next change brings the full roster,
// and its refresh is answered 200.
func TestANotifyRefusedForAPassingReasonKeepsTheSubscription(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	_, sub := g.subscribe(t, alice, "600")
	first := g.nextNotify(t)
	var refused atomic.Bool
	g.core.setReply(func(req *sip.Request) []*sip.Response {
		code := 200
		if req.Method == "INVITE" {
			code = 486
		}
		// Not the first NOTIFY, which the core may answer only now.
		if after(req, first.req) && refused.CompareAndSwap(false, true) {
			code = 503
		}
		res, _ := sip.NewResponse(req, code, "", "core1")
		if code == 503 {
			_ = res.Header.Add("Retry-After", "1")
		}
		return []*sip.Response{res}
	})
	g.rejoin(t, bob)
	g.nextNotify(t) // refused
	waitUntil(t, "the subscription marked stale", func() bool { return g.metrics.get("sip.subscription.stale") == 1 })
	g.rejoin(t, carol)
	if n := g.nextNotify(t); n.doc.State != conference.Full {
		t.Fatalf("after a refused NOTIFY, %s document", n.doc.State)
	}
	if res := g.again(t, &sub, "600"); res.StatusCode != 200 {
		t.Fatalf("refresh answered %d", res.StatusCode)
	}
	g.nextNotify(t) // the refresh's full roster
	// A refresh's full roster also brings a stale subscription up to
	// date: the change after it is a partial document again.
	refused.Store(false)
	if err := g.groups.Add(t.Context(), g.uri, alice, []group.Invitee{{Identity: dave}}); err != nil {
		t.Fatal(err)
	}
	g.nextNotify(t) // refused
	waitUntil(t, "the subscription marked stale again", func() bool { return g.metrics.get("sip.subscription.stale") == 2 })
	if res := g.again(t, &sub, "600"); res.StatusCode != 200 {
		t.Fatalf("refresh answered %d", res.StatusCode)
	}
	if n := g.nextNotify(t); n.doc.State != conference.Full {
		t.Fatalf("refresh sent a %s document", n.doc.State)
	}
	if err := g.groups.Add(t.Context(), g.uri, alice, []group.Invitee{{Identity: erin}}); err != nil {
		t.Fatal(err)
	}
	if n := g.nextNotify(t); n.doc.State != conference.Partial {
		t.Fatalf("after a refresh, a %s document", n.doc.State)
	}
}

// Code review on #340: a refresh that comes as the expiry timer fires, and
// takes the lock first, keeps the subscription: the timer it replaced no
// longer ends it.
func TestARefreshRacingTheExpiryKeepsTheSubscription(t *testing.T) {
	g := newGroupRig(t, bob)
	_, sub := g.subscribe(t, alice, "120")
	g.nextNotify(t)
	g.clock.mu.Lock()
	var expiry func()
	for _, tm := range g.clock.timers {
		if tm.d == 120*time.Second && !tm.stopped {
			expiry = tm.f
		}
	}
	g.clock.mu.Unlock()
	if expiry == nil {
		t.Fatal("no expiry timer")
	}
	if res := g.again(t, &sub, "600"); res.StatusCode != 200 {
		t.Fatalf("refresh answered %d", res.StatusCode)
	}
	g.nextNotify(t)
	expiry() // fired already, and ran once the refresh let go of the lock
	g.noNotify(t, "after the replaced timer ran")
	if res := g.again(t, &sub, "600"); res.StatusCode != 200 {
		t.Fatalf("a refresh after the replaced timer answered %d", res.StatusCode)
	}
}

// QA on #340: a change made between the store write of bob's Leave and the
// end of his subscriptions never reaches him; his subscription ends with
// the Leave's own NOTIFY.
func TestNoNotifyAfterLeaveEvenWithAConcurrentChange(t *testing.T) {
	g := newGroupRig(t, bob, carol)
	s := g.rejoin(t, bob)
	_, bobSub := g.subscribe(t, bob, "600")
	g.nextNotify(t)
	var once sync.Once
	h := func(name string) {
		if name == "sip.group.left" { // Leave returned, subscriptions not ended yet
			once.Do(func() { _, _ = g.groups.Join(context.Background(), g.uri, carol, "") })
		}
	}
	g.metrics.hook.Store(&h)
	defer g.metrics.hook.Store(nil)
	if res := g.inSession(t, bob, "r02", s, 2, "BYE", []string{"Reason: SIP;cause=200"}, ""); res.StatusCode != 200 {
		t.Fatalf("bob's BYE answered %d", res.StatusCode)
	}
	for {
		n := g.nextNotify(t)
		if n.req.Header.Get("Call-ID") != bobSub.callID {
			continue
		}
		if n.state.State == "terminated" {
			return
		}
		if n.doc != nil && n.doc.Users != nil {
			for _, u := range n.doc.Users.List {
				if u.Entity == carol {
					t.Fatalf("bob, who left, heard of carol's join (version %d)", n.doc.Version)
				}
			}
		}
	}
}

// QA on #340: Close keeps its bound while a SUBSCRIBE holds its
// subscription's lock to read the roster from a slow store.
func TestCloseIsBoundedWhileARosterReadIsHeld(t *testing.T) {
	g := newGroupRig(t, bob)
	hold, entered := make(chan struct{}), make(chan struct{}, 1)
	release := sync.OnceFunc(func() { close(hold) })
	defer release()
	t.Cleanup(release)
	var once sync.Once
	h := func() { once.Do(func() { entered <- struct{}{}; <-hold }) }
	g.groupReads.getHook.Store(&h)
	defer g.groupReads.getHook.Store(nil)
	go func() {
		_, _ = g.p.try(msg{method: "SUBSCRIBE", uri: g.uri, from: "<" + alice + ">;tag=sh1", to: "<" + g.uri + ">",
			fields: []string{"P-Asserted-Identity: <" + alice + ">", "Contact: <sip:" + g.core.l.Addr().String() + ";transport=tcp>", "Event: conference"}})
	}()
	<-entered
	start := time.Now()
	g.a.srv.Close()
	if took, bound := time.Since(start), 2*g.a.srv.closeWait(); took > bound+500*time.Millisecond {
		t.Errorf("Close took %v, documented bound 2*closeWait=%v", took, bound)
	}
}

// Security review on #340: one user's subscriptions across all its groups
// are bounded, so that it cannot take the task's whole share from others:
// alice past her bound gets 486, and bob still subscribes.
func TestAUsersSubscriptionsAreBoundedAcrossGroups(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{MaxSubscriptionsPerUser: 2})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 486
		}
		return 200
	})
	p := r.a.dial(t)
	first, _ := r.create(t, p, relayPath(), bob)
	r.core.nextOf(t, "INVITE")
	m := r.factoryInvite(relayPath(), carol)
	m.fields[3] = "Contribution-ID: gch4t2"
	s := answeredBy(t, p.send(m))
	p.ack(s)
	contact, _ := sip.ParseAddress(s.res.Header.Get("Contact"))
	second := contact.URI.String()
	r.core.nextOf(t, "INVITE")
	sub := func(uri, who, tag string) int {
		return p.send(msg{method: "SUBSCRIBE", uri: uri, from: "<" + who + ">;tag=" + tag, to: "<" + uri + ">",
			fields: []string{"P-Asserted-Identity: <" + who + ">", "Contact: <sip:" + r.core.l.Addr().String() + ";transport=tcp>", "Event: conference"}}).StatusCode
	}
	if a, b := sub(first, alice, "u1"), sub(second, alice, "u2"); a != 200 || b != 200 {
		t.Fatalf("alice's subscriptions answered %d, %d", a, b)
	}
	if c := sub(first, alice, "u3"); c != 486 {
		t.Fatalf("alice's third subscription answered %d", c)
	}
	if b := sub(first, bob, "u4"); b != 200 {
		t.Fatalf("bob's subscription answered %d", b)
	}
}

// Security review on #340: the factory is found in any spelling of its
// user part, escaped or upper case, and of its host, with a trailing dot,
// so that none of them takes a group's INVITE onto the 1-to-1 path.
func TestTheFactoryIsFoundInAnySpelling(t *testing.T) {
	r := newChatRig(t, messaging.Config{})
	r.core.setAnswer(func(req *sip.Request) int {
		if req.Method == "INVITE" {
			return 486
		}
		return 200
	})
	p := r.a.dial(t)
	for i, uri := range []string{
		"sip:conf%2Dfactory@" + domain, "sip:CONF-FACTORY@" + strings.ToUpper(domain), "sip:conf-factory@" + domain + ".",
		"sip:%63onf-factory@" + domain,
	} {
		m := r.factoryInvite(relayPath(), bob)
		m.uri = uri
		m.fields[3] = fmt.Sprintf("Contribution-ID: spelled%d", i)
		s := answeredBy(t, p.send(m))
		p.ack(s)
		if c := s.res.Header.Get("Contact"); !strings.Contains(c, ";isfocus") {
			t.Fatalf("%s: answered as no group, Contact %q", uri, c)
		}
		r.core.nextOf(t, "INVITE")
	}
}

// Security review on #340: with group chat off (RCSAS_GROUP_CHAT_ENABLED),
// a request to the factory or a conference URI is 404 and makes nothing;
// it is not taken for a 1-to-1 chat either. The engine's invitation of a
// group's participant is answered offline, not undeliverable, so that
// what is queued for it waits for group chat to be turned on again (code
// review and QA on #340).
func TestGroupChatOffRefusesEveryGroupRequest(t *testing.T) {
	r := newChatRigWith(t, messaging.Config{}, Config{groupChatOff: true})
	p := r.a.dial(t)
	if res := p.send(r.factoryInvite(relayPath(), bob)); res.StatusCode != 404 {
		t.Fatalf("a factory INVITE answered %d", res.StatusCode)
	}
	uri := "sip:chat-" + strings.Repeat("0", 32) + "@" + confHost
	if res := p.send(r.groupInvite(uri, sdpType, offerSDP(relayPath(), "active"))); res.StatusCode != 404 {
		t.Fatalf("an INVITE to a conference URI answered %d", res.StatusCode)
	}
	if n := r.metrics.get("group.created") + r.metrics.get("leg.opened"); n != 0 {
		t.Fatalf("%d groups and legs made", n)
	}
	if n := r.groupReads.gets.Load(); n != 0 {
		t.Fatalf("%d store reads", n)
	}
	err := r.a.srv.Invite(t.Context(), messaging.Invitation{Recipient: bob, Peer: uri, Mode: store.Group})
	if !errors.Is(err, messaging.ErrOffline) || errors.Is(err, messaging.ErrUndeliverable) {
		t.Fatalf("a group invitation with group chat off: %v", err)
	}
	if n := r.metrics.get("leg.opened"); n != 0 {
		t.Fatalf("%d legs opened for it", n)
	}
}

// Code review on #340: the subscriptions that need the full roster for one
// change share one read of the group, so that a gap costs the change that
// made it one read, not one per subscription.
func TestAGapIsMendedWithOneReadForAllSubscriptions(t *testing.T) {
	g := newGroupRig(t, bob)
	for i := range 3 {
		g.subscribe(t, alice, "600")
		if n := g.nextNotify(t); i == 2 {
			before := g.groupReads.gets.Load()
			// A version none of them can reach from theirs.
			g.a.srv.RosterChanged(t.Context(), group.RosterUpdate{Group: g.uri, Version: n.doc.Version + 2})
			if reads := g.groupReads.gets.Load() - before; reads != 1 {
				t.Fatalf("%d reads of the group for 3 subscriptions", reads)
			}
		}
	}
}

// A subscription that ends gives its place under
// RCSAS_MAX_SUBSCRIPTIONS_PER_USER back.
func TestAnEndedSubscriptionGivesItsPlaceBack(t *testing.T) {
	g := newGroupRigWith(t, Config{MaxSubscriptionsPerUser: 2}, bob)
	_, first := g.subscribe(t, alice, "600")
	g.nextNotify(t)
	g.subscribe(t, alice, "600")
	g.nextNotify(t)
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 486 {
		t.Fatalf("a third subscription answered %d", res.StatusCode)
	}
	if res := g.again(t, &first, "0"); res.StatusCode != 200 {
		t.Fatalf("unsubscribing answered %d", res.StatusCode)
	}
	// The place is given back before the last NOTIFY is sent, and the
	// 200 goes before both (RFC 6665 §4.2.1.4).
	if n := g.nextNotify(t); n.state.State != "terminated" {
		t.Fatalf("after unsubscribing, a NOTIFY %s", n.state.State)
	}
	if res, _ := g.subscribe(t, alice, "600"); res.StatusCode != 200 {
		t.Fatalf("a subscription in the place given back answered %d", res.StatusCode)
	}
}
