package sipas

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// loopbackPeers forwards to the tests' tasks, on loopback, each on a port
// of its own (Config.peers).
func loopbackPeers(ap netip.AddrPort) bool { return ap.Addr().IsLoopback() }

// twoTasks are tasks a and b of rcs-as sharing the messages and groups
// stores, each with its core, MSRP listener and clock, both beating, as
// two tasks of a deployment are (#121). a has made a group of alice,
// joined, and invitees whose clients do not answer the focus (486), so
// that a owns it; ga is that group as seen from a, and gb the same group
// reached through b.
func twoTasks(t *testing.T, invitees ...string) (ga, gb *groupRig) {
	t.Helper()
	return twoTasksWith(t, twoTaskOptions{}, invitees...)
}

// twoTaskOptions change both tasks of twoTasksWith: their transports, and
// their group services' configuration.
type twoTaskOptions struct {
	transport transport.Config
	group     func(*group.Config)
}

// twoTasksWith is twoTasks with o.
func twoTasksWith(t *testing.T, o twoTaskOptions, invitees ...string) (ga, gb *groupRig) {
	t.Helper()
	st, groups := store.NewMemory(), groupstore.NewMemory()
	cfg := Config{peers: loopbackPeers}
	a := newChatRigShared(t, messaging.Config{}, cfg, o.transport, rigShare{store: st, groups: groups, task: "task-a", beat: true, group: o.group})
	b := newChatRigShared(t, messaging.Config{}, cfg, o.transport, rigShare{store: st, groups: groups, task: "task-b", beat: true, group: o.group})
	for _, r := range []*chatRig{a, b} {
		r.core.setAnswer(func(req *sip.Request) int {
			if req.Method == "INVITE" {
				return 486
			}
			return 200
		})
	}
	pa := a.a.dial(t)
	uri, s := a.create(t, pa, relayPath(), invitees...)
	for range invitees {
		a.core.nextOf(t, "INVITE")
	}
	return &groupRig{chatRig: a, p: pa, uri: uri, s: s}, &groupRig{chatRig: b, p: b.a.dial(t), uri: uri}
}

// sessionsOf counts the sessions srv holds with the group uri.
func sessionsOf(srv *Server, uri string) int {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	n := 0
	for _, ss := range srv.sessions {
		if ss.group == uri {
			n++
		}
	}
	return n
}

// #121 T1 and the loop guard (#242): bob's rejoin INVITE, which the core
// may give any task, reaches b, which forwards it to a, the group's owner:
// it is served there, not taken for a loop, and the session, its MSRP leg
// included, is a's. Its ACK and BYE, sent to the conference URI, reach
// b too and go on to a.
func TestARequestForAGroupIsServedByItsOwner(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	s := gb.rejoin(t, bob)
	if s.path.Port != ga.msrpPort() {
		t.Fatalf("the session's MSRP path is at port %d, not the owner's %d", s.path.Port, ga.msrpPort())
	}
	if c, _ := sip.ParseAddress(s.res.Header.Get("Contact")); c.URI.String() != ga.uri {
		t.Fatalf("Contact %q", s.res.Header.Get("Contact"))
	}
	waitUntil(t, "the ACK at the owner", func() bool {
		ga.a.srv.mu.Lock()
		defer ga.a.srv.mu.Unlock()
		for _, ss := range ga.a.srv.sessions {
			if ss.group == ga.uri && ss.user == bob {
				return ss.acknowledged()
			}
		}
		return false
	})
	if n := sessionsOf(gb.a.srv, ga.uri); n != 0 {
		t.Fatalf("b holds %d sessions with the group", n)
	}
	if gb.metrics.get("group.forwarded") != 2 || gb.metrics.get("sip.loop") != 0 || ga.metrics.get("sip.loop") != 0 {
		t.Fatalf("b forwarded %d; loops %d, %d", gb.metrics.get("group.forwarded"), gb.metrics.get("sip.loop"), ga.metrics.get("sip.loop"))
	}
	ga.stateOf(t, ga.uri, bob, groupstore.Joined)
	if res := gb.inSession(t, bob, "r02", s, 2, "BYE", nil, ""); res.StatusCode != 200 {
		t.Fatalf("the BYE through b answered %d", res.StatusCode)
	}
	if n := sessionsOf(ga.a.srv, ga.uri); n != 1 {
		t.Fatalf("a holds %d sessions with the group, want alice's", n)
	}
}

// #121 T2: a SUBSCRIBE to the group's roster that reaches b is a's: a
// sends the NOTIFYs, with each change, to the subscriber's Contact (b's
// core here), and a refresh through b reaches the subscription there.
func TestASubscriptionToAGroupIsHeldByItsOwner(t *testing.T) {
	ga, gb := twoTasks(t, bob, carol)
	gb.rejoin(t, bob)
	res, sub := gb.subscribe(t, bob, "600")
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE through b answered %d", res.StatusCode)
	}
	if n := gb.nextNotify(t); n.doc == nil || n.doc.State != conference.Full {
		t.Fatalf("first NOTIFY %+v", n)
	}
	gb.rejoin(t, carol) // a change, on a
	n := gb.nextNotify(t)
	if u := userOf(t, n.doc, carol); n.doc.State != conference.Partial || len(u.Endpoints) == 0 || u.Endpoints[0].Status != conference.Connected {
		t.Fatalf("the change's NOTIFY %+v", n.doc)
	}
	if res := gb.again(t, &sub, "600"); res.StatusCode != 200 {
		t.Fatalf("the refresh through b answered %d", res.StatusCode)
	}
	ga.a.srv.mu.Lock()
	onA := len(ga.a.srv.groupSubs[ga.uri])
	ga.a.srv.mu.Unlock()
	gb.a.srv.mu.Lock()
	onB := len(gb.a.srv.groupSubs[ga.uri])
	gb.a.srv.mu.Unlock()
	if onA != 1 || onB != 0 {
		t.Fatalf("subscriptions: %d on a, %d on b", onA, onB)
	}
}

// #121 T7: a request forwarded to a task that does not own the group, as
// when two tasks' views of its owner differ for a moment, is not
// forwarded again: it is answered 500 with Retry-After, never 404, which
// rcsjta takes for the group's end and restarts at the factory.
func TestAForwardedRequestIsNotForwardedAgain(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	m := gb.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag=f1", "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	m.fields = append(m.fields, "Route: <sip:"+gb.a.addr.String()+";transport=tcp;lr;"+fwdParam+">")
	res := gb.p.send(m)
	if res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if gb.metrics.get("group.forwarded") != 0 || gb.metrics.get("group.forward_refused") != 1 || ga.metrics.get("sip.group.joined") != 0 {
		t.Fatalf("forwarded %d, refused %d; joined on a %d", gb.metrics.get("group.forwarded"),
			gb.metrics.get("group.forward_refused"), ga.metrics.get("sip.group.joined"))
	}
}

// #121 (rcsjta's restart rule): an owner that does not answer, its
// address closed, has the request answered with no 404 either.
func TestAnOwnerThatDoesNotAnswerIsNoEndOfTheGroup(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := l.Addr().String()
	_ = l.Close()
	// a's address in the store is one nothing listens on now.
	mine, err := ga.groupStore.Owner(t.Context(), ga.uri)
	if err != nil {
		t.Fatal(err)
	}
	moved := groupstore.Owner{Task: mine.Task, SIP: gone}
	if _, err := ga.groupStore.TakeOver(t.Context(), ga.uri, mine, moved, ga.clock.Now().Add(time.Hour), "t1"); err != nil {
		t.Fatal(err)
	}
	m := gb.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag=g1", "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	if res := gb.p.send(m); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// #121 (the lead's decision on Q4): a task that finds another took its
// group over ends the sessions it holds with it, with a BYE, so that the
// participants rejoin through the new owner, where the next request goes.
func TestATaskThatLostAGroupEndsItsSessions(t *testing.T) {
	ga, gb := twoTasks(t, bob, carol)
	ga.rejoin(t, bob)
	if res, _ := ga.subscribe(t, bob, "600"); res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE answered %d", res.StatusCode)
	}
	ga.nextNotify(t)
	// b takes the group over, as when a was paused.
	mine, err := ga.groupStore.Owner(t.Context(), ga.uri)
	if err != nil {
		t.Fatal(err)
	}
	bOwner := groupstore.Owner{Task: "task-b", SIP: gb.a.addr.String()}
	if _, err := ga.groupStore.TakeOver(t.Context(), ga.uri, mine, bOwner, ga.clock.Now().Add(time.Hour), "t1"); err != nil {
		t.Fatal(err)
	}
	// carol's join on a, which still takes the group for its own, is
	// refused by the store: a gives the group up, and ends what it holds.
	m := ga.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+carol+">;tag=c1", "<"+ga.uri+">", "P-Asserted-Identity: <"+carol+">"
	if res := ga.p.send(m); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("carol's join on a answered %d", res.StatusCode)
	}
	var bye, ended bool
	for !bye || !ended {
		switch req := ga.core.next(t); req.Method {
		case "BYE":
			to, _ := req.Header.To()
			bye = bye || to.URI.String() == bob
		case "NOTIFY":
			st, _ := req.Header.SubscriptionState()
			reason, _ := st.Params.Get("reason")
			ended = st.State == "terminated" && reason == reasonDeactivated
		}
	}
	waitUntil(t, "a's sessions with the group ended", func() bool { return sessionsOf(ga.a.srv, ga.uri) == 0 })
	// Tried again, it goes to b.
	m.from = "<" + carol + ">;tag=c2"
	if res := ga.p.send(m); res.StatusCode != 200 || ga.metrics.get("group.forwarded") != 1 {
		t.Fatalf("carol's join again answered %d; a forwarded %d", res.StatusCode, ga.metrics.get("group.forwarded"))
	}
}

// #121 T8: bob registers on b, which finds a copy of a's group for him:
// b invites nobody, and has a, the owner, read his queue (a wake MESSAGE
// straight to a, without rcs-as's loop marker, #242).
func TestARegistrationOnAnotherTaskWakesTheOwner(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	now := time.Now() // the engines' clock
	if err := gb.store.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "c1", Sender: ga.uri, Author: alice, Mode: store.Group,
		CPIM: []byte(cpimBody("m1", "hi")), Enqueued: now, Expires: now.Add(time.Hour)}, store.Limit{}); err != nil {
		t.Fatal(err)
	}
	reg := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1",
		to: "<sip:+15550100002@" + domain + ";user=phone>", fields: []string{"Expires: 600"}}
	if res := gb.p.send(reg); res.StatusCode != 200 {
		t.Fatalf("REGISTER answered %d", res.StatusCode)
	}
	waitUntil(t, "a woken", func() bool { return ga.metrics.get("sip.group.woken") == 1 })
	if gb.metrics.get("group.wake_sent") != 1 || gb.metrics.get("sip.loop") != 0 || ga.metrics.get("sip.loop") != 0 {
		t.Fatalf("wakes sent %d; loops %d, %d", gb.metrics.get("group.wake_sent"), gb.metrics.get("sip.loop"), ga.metrics.get("sip.loop"))
	}
	waitUntil(t, "the wake answered", func() bool { return gb.metrics.get("sip.group.wake.200") == 1 })
	// The wake tells of the registration, so a invites bob at once, though
	// it asked for his session already, at the group's creation, within
	// InviteTimeout (code review and QA on #464).
	ownerInvites(t, ga, bob)
	select {
	case req := <-gb.core.got:
		if req.Method == "INVITE" {
			t.Fatalf("b invited %s", req.URI)
		}
	case <-time.After(100 * time.Millisecond):
	}
}

// #121: the creator's INVITE to the factory tried again, which reaches
// another task, goes to the group's owner as well: the group its
// Contribution-ID names is a's.
func TestAFactoryInviteForAnOwnedGroupGoesToItsOwner(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	res := gb.p.send(gb.factoryInvite(relayPath(), carol))
	// alice's group is established, so another INVITE under its
	// Contribution-ID is refused (#279), by a.
	if res.StatusCode != 403 || gb.metrics.get("group.forwarded") != 1 || ga.metrics.get("group.rejected.taken") != 1 {
		t.Fatalf("answered %d; forwarded %d; refused on a %d", res.StatusCode, gb.metrics.get("group.forwarded"), ga.metrics.get("group.rejected.taken"))
	}
}

// #121: the address of a group's owner, though only tasks write it, is
// one rcs-as forwards to only if it is a private address on rcs-as's own
// SIP port, and not this task's.
func TestTheOwnersAddressIsCheckedBeforeForwarding(t *testing.T) {
	core, err := sip.ParseURI("sip:10.0.0.9:5060;transport=tcp;lr")
	if err != nil {
		t.Fatal(err)
	}
	contact, err := sip.ParseURI("sip:10.0.0.1:5060;transport=tcp")
	if err != nil {
		t.Fatal(err)
	}
	factory, err := sip.ParseURI(confFactory)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{Core: core, Host: "10.0.0.1", HomeDomain: domain, Contact: contact,
		ConferenceFactory: factory, ConferenceHost: confHost})
	if err != nil {
		t.Fatal(err)
	}
	for at, want := range map[string]bool{
		"10.0.0.2:5060":          true,
		"172.16.3.4:5060":        true,
		"192.168.1.1:5060":       true,
		"[fd00::2]:5060":         true,
		"10.0.0.1:5060":          false, // this task
		"[::ffff:10.0.0.1]:5060": false, // this task, mapped
		"[::ffff:10.0.0.2]:5060": true,
		"[fd00::2%eth0]:5060":    false, // a zone
		"10.0.0.2:5061":          false, // not rcs-as's port
		"192.0.2.1:5060":         false, // not private
		"127.0.0.1:5060":         false,
		"":                       false,
		"10.0.0.2":               false,
		"rcs-as:5060":            false,
	} {
		u, ok := srv.peer(at)
		if ok != want {
			t.Errorf("peer(%q) = %v, want %v", at, ok, want)
		}
		if ok && (!u.Params.Has("lr") || !u.Params.Has(fwdParam)) {
			t.Errorf("peer(%q) = %s", at, u)
		}
	}
}

// #121: a wake MESSAGE is taken only from another task, by the marked
// Route a task's own sets; from the core, a MESSAGE to a conference URI
// is refused as before. A task that does not own the group answers a
// wake and does nothing.
func TestAWakeIsTakenOnlyFromAnotherTask(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	wakeMsg := func(r *groupRig, route bool) msg {
		m := msg{method: "MESSAGE", uri: ga.uri, from: "<sip:" + r.core.l.Addr().String() + ">;tag=w1", to: "<" + ga.uri + ">",
			body: `{"user":"` + bob + `"}`, fields: []string{"Content-Type: " + wakeType}}
		if route {
			m.fields = append(m.fields, "Route: <sip:"+r.a.addr.String()+";transport=tcp;lr;"+fwdParam+">")
		}
		return m
	}
	if res := ga.p.send(wakeMsg(ga, false)); res.StatusCode != 405 || ga.metrics.get("sip.group.woken") != 0 {
		t.Fatalf("a wake from the core answered %d", res.StatusCode)
	}
	if res := gb.p.send(wakeMsg(gb, true)); res.StatusCode != 200 || gb.metrics.get("sip.group.woken") != 0 {
		t.Fatalf("a wake to a task that does not own the group answered %d; woken %d", res.StatusCode, gb.metrics.get("sip.group.woken"))
	}
	if res := ga.p.send(wakeMsg(ga, true)); res.StatusCode != 200 || ga.metrics.get("sip.group.woken") != 1 {
		t.Fatalf("a wake to the owner answered %d; woken %d", res.StatusCode, ga.metrics.get("sip.group.woken"))
	}
}

// #121: a request in a session or subscription this task still holds is
// served here, even once another task owns the group: the BYE ends the
// session where it is, and the SUBSCRIBE ends the subscription, rather
// than reaching the owner, which knows no such dialog.
func TestARequestInADialogThisTaskHoldsIsServedHere(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	s := ga.rejoin(t, bob)
	res, sub := ga.subscribe(t, bob, "600")
	if res.StatusCode != 200 {
		t.Fatalf("SUBSCRIBE answered %d", res.StatusCode)
	}
	mine, err := ga.groupStore.Owner(t.Context(), ga.uri)
	if err != nil {
		t.Fatal(err)
	}
	bOwner := groupstore.Owner{Task: "task-b", SIP: gb.a.addr.String()}
	if _, err := ga.groupStore.TakeOver(t.Context(), ga.uri, mine, bOwner, ga.clock.Now().Add(time.Hour), "t1"); err != nil {
		t.Fatal(err)
	}
	// a reads the owner again for whatever it does not hold.
	ga.clock.Advance(group.DefaultTaskHeartbeat)
	if res := ga.inSession(t, bob, "r02", s, 2, "BYE", nil, ""); res.StatusCode != 200 || ga.metrics.get("group.forwarded") != 0 {
		t.Fatalf("bob's BYE answered %d; forwarded %d", res.StatusCode, ga.metrics.get("group.forwarded"))
	}
	if res := ga.again(t, &sub, "0"); res.StatusCode != 200 || ga.metrics.get("group.forwarded") != 0 {
		t.Fatalf("bob's unsubscribe answered %d; forwarded %d", res.StatusCode, ga.metrics.get("group.forwarded"))
	}
}
