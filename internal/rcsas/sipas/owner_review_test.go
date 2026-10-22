package sipas

import (
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// ownerInvites waits for r's core to get the focus's INVITE to who.
func ownerInvites(t *testing.T, r *groupRig, who string) {
	t.Helper()
	deadline := time.After(waitFor)
	for {
		select {
		case req := <-r.core.got:
			if req.Method == "INVITE" && req.URI.String() == who {
				return
			}
		case <-deadline:
			t.Fatalf("the owner did not invite %s", who)
		}
	}
}

// QA's reproduction (#464): bob, whose invitation by the owner failed
// within InviteTimeout, registers on a new flow, on the owner or on the
// other task: either way the owner invites him at once.
func TestQA464WokenOwnerInvites(t *testing.T) {
	for _, where := range []string{"owner", "other"} {
		t.Run(where, func(t *testing.T) {
			ga, gb := twoTasks(t, bob) // bob's focus INVITE was answered 486
			now := time.Now()
			if err := gb.store.Enqueue(t.Context(), store.Message{Recipient: bob, ID: "c1", Sender: ga.uri, Author: alice, Mode: store.Group,
				CPIM: []byte(cpimBody("m1", "hi")), Enqueued: now, Expires: now.Add(time.Hour)}, store.Limit{}); err != nil {
				t.Fatal(err)
			}
			reg := msg{method: "REGISTER", uri: "sip:rcs-as." + domain, from: "<sip:scscf." + domain + ">;tag=s1",
				to: "<sip:+15550100002@" + domain + ";user=phone>", fields: []string{"Expires: 600"}}
			r := gb
			if where == "owner" {
				r = ga
			}
			if res := r.p.send(reg); res.StatusCode != 200 {
				t.Fatalf("REGISTER answered %d", res.StatusCode)
			}
			ownerInvites(t, ga, bob)
		})
	}
}

// QA on #464: an owner whose address does not answer the connection, past
// the dial timeout, is no end of the group either: 500 with Retry-After.
func TestAnOwnerThatCannotBeDialledIsNoEndOfTheGroup(t *testing.T) {
	ga, gb := twoTasksWith(t, twoTaskOptions{transport: transport.Config{DialTimeout: 200 * time.Millisecond}}, bob)
	gb.a.srv.cfg.peers = func(netip.AddrPort) bool { return true }
	mine, err := ga.groupStore.Owner(t.Context(), ga.uri)
	if err != nil {
		t.Fatal(err)
	}
	// An address no host answers: the dial times out.
	moved := groupstore.Owner{Task: mine.Task, SIP: "10.255.255.1:5060"}
	if _, err := ga.groupStore.TakeOver(t.Context(), ga.uri, mine, moved, ga.clock.Now().Add(time.Hour), "t1"); err != nil {
		t.Fatal(err)
	}
	m := gb.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag=g2", "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	if res := gb.p.send(m); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// QA on #464: while this task's own heartbeat has lapsed, a group's request
// it cannot serve is answered 500 with Retry-After, an initial one and one
// in a dialog it does not hold alike: never 481, which would end the
// dialog, nor 404.
func TestALapsedTaskAnswersGroupRequestsToBeTriedAgain(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	s := ga.rejoin(t, bob)
	// b's beats fail, and its last stored one's hold runs out (the rig's
	// clock fires no timer: b beats no more either way).
	gb.groupReads.failBeats.Store(true)
	gb.clock.Advance(group.DefaultTaskLease)
	m := gb.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag=l1", "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	if res := gb.p.send(m); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("the rejoin through b answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
	if res := gb.inSession(t, bob, "r02", s, 2, "BYE", nil, ""); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("the BYE through b answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}

// Security review on #464: a creator over its rate for new groups costs
// no read of the groups store: its factory INVITE is refused by Create,
// which reads nothing, before any owner is looked for.
func TestACreatorOverItsRateCostsNoRead(t *testing.T) {
	_, gb := twoTasksWith(t, twoTaskOptions{group: func(c *group.Config) {
		c.CreateRate = messaging.Rate{PerMinute: 1, Burst: 1}
	}}, bob)
	// alice created her group on a; on b she has one creation left.
	other := func(contribution string) msg {
		m := gb.factoryInvite(relayPath(), carol)
		for i, f := range m.fields {
			if strings.HasPrefix(f, "Contribution-ID:") {
				m.fields[i] = "Contribution-ID: " + contribution
			}
		}
		return m
	}
	if res := gb.p.send(other("second-chat")); res.StatusCode != 200 {
		t.Fatalf("the first factory INVITE on b answered %d", res.StatusCode)
	}
	gets, owners := gb.groupReads.gets.Load(), gb.groupReads.owners.Load()
	if res := gb.p.send(other("third-chat")); res.StatusCode != 403 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	if g, o := gb.groupReads.gets.Load()-gets, gb.groupReads.owners.Load()-owners; g != 0 || o != 0 {
		t.Fatalf("%d group reads and %d owner reads for a creator over its rate", g, o)
	}
}

// Code review on #464: a task that loses a group ends a session whose 2xx
// has no ACK yet only once the ACK comes (RFC 3261 §15).
func TestADisownedSessionGetsItsByeAfterItsACK(t *testing.T) {
	ga, _ := twoTasks(t, bob)
	const tag = "u02"
	m := ga.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag="+tag, "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	s := answeredBy(t, ga.p.send(m))
	toBob := func(req *sip.Request) bool {
		to, _ := req.Header.To()
		return req.Method == "BYE" && to.URI.String() == bob
	}
	ga.a.srv.Disowned(ga.uri) // alice's session, acknowledged, gets its BYE at once
	deadline := time.After(200 * time.Millisecond)
	for waiting := true; waiting; {
		select {
		case req := <-ga.core.got:
			if toBob(req) {
				t.Fatal("a BYE to bob before his ACK")
			}
		case <-deadline:
			waiting = false
		}
	}
	if _, err := ga.p.try(msg{method: "ACK", uri: ga.uri, callID: s.callID, cseq: 1,
		from: "<" + bob + ">;tag=" + tag, to: "<" + ga.uri + ">;tag=" + s.tag}); err != nil {
		t.Fatal(err)
	}
	for {
		if req := ga.core.next(t); toBob(req) {
			return
		}
	}
}

// QA on #464: an owner that takes the forward and never answers it is
// given up on before the client's own transaction ends: 500 with
// Retry-After.
func TestAnOwnerThatNeverAnswersIsNoEndOfTheGroup(t *testing.T) {
	ga, gb := twoTasks(t, bob)
	gb.a.srv.cfg.forwardWait = 300 * time.Millisecond
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	mine, err := ga.groupStore.Owner(t.Context(), ga.uri)
	if err != nil {
		t.Fatal(err)
	}
	silent := groupstore.Owner{Task: mine.Task, SIP: l.Addr().String()}
	if _, err := ga.groupStore.TakeOver(t.Context(), ga.uri, mine, silent, ga.clock.Now().Add(time.Hour), "t1"); err != nil {
		t.Fatal(err)
	}
	m := gb.groupInvite(ga.uri, sdpType, offerSDP(relayPath(), "active"))
	m.from, m.to, m.fields[0] = "<"+bob+">;tag=g3", "<"+ga.uri+">", "P-Asserted-Identity: <"+bob+">"
	if res := gb.p.send(m); res.StatusCode != 500 || res.Header.Get("Retry-After") == "" {
		t.Fatalf("answered %d, Retry-After %q", res.StatusCode, res.Header.Get("Retry-After"))
	}
}
