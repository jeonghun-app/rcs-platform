package group

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// asSeen parses what a participant received.
func asSeen(t *testing.T, m *msrp.Message) *cpim.Message {
	t.Helper()
	c, err := cpim.Parse(m.Body)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fromTo(t *testing.T, c *cpim.Message) (cpim.Address, string) {
	t.Helper()
	from, err := c.From()
	if err != nil {
		t.Fatal(err)
	}
	to, err := c.To()
	if err != nil || len(to) != 1 {
		t.Fatalf("To = %v, %v", to, err)
	}
	return from, to[0].URI
}

func expectNothing(t *testing.T, c *client, what string) {
	t.Helper()
	select {
	case m := <-c.got:
		t.Fatalf("%s: got %q", what, m.Body)
	case <-time.After(50 * time.Millisecond):
	}
}

// Fan-out over loopback MSRP: bob is there, carol is slow to take what
// she is sent, dave has no session. Bob is not held up by either, carol
// gets it once she takes it, and dave's copy waits for his session.
func TestAMessageReachesEveryParticipantWithoutWaitingForTheSlowOrTheOffline(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol, dave)
	a := r.connect(g, alice, nil)
	b := r.connect(g, bob, nil)
	slow := make(chan struct{})
	c := r.connect(g, carol, slow)

	msg := message(t, alice, "m1", "hello all", imdn.PositiveDelivery|imdn.Display)
	if code := a.send(t, msg); code != msrp.StatusOK {
		t.Fatalf("alice's message answered %d", code)
	}
	got := asSeen(t, b.next(t))
	from, to := fromTo(t, got)
	// From is alice's asserted identity, under her name in the roster
	// rather than the one her client wrote; To is the group; everything
	// else is hers.
	if from.URI != alice || from.Name != "Alice" || to != g.URI || string(got.Body) != "hello all" {
		t.Fatalf("bob got From %v To %s: %q", from, to, got.Body)
	}
	if h, ok := got.Get(imdn.Namespace, imdn.HeaderMessageID); !ok || h.Value != "m1" {
		t.Fatalf("Message-ID %v", h)
	}
	// carol has not taken hers yet; dave's waits in his queue.
	expectNothing(t, c, "carol before she reads")
	waitFor(t, "dave's copy queued", func() bool { return r.queues.Len(dave) == 1 })
	close(slow)
	if got := asSeen(t, c.next(t)); string(got.Body) != "hello all" {
		t.Fatalf("carol got %q", got.Body)
	}
	expectNothing(t, a, "alice, the author")
	// No pager mode for a group; dave is asked back into the group.
	pagers, invites := r.d.counts()
	if pagers != 0 || len(invites) != 1 || invites[0].Recipient != dave || invites[0].Peer != g.URI || invites[0].Mode != store.Group {
		t.Fatalf("pagers %d, invites %+v", pagers, invites)
	}
	d := r.connect(g, dave, nil)
	if got := asSeen(t, d.next(t)); string(got.Body) != "hello all" {
		t.Fatalf("dave got %q", got.Body)
	}
	waitFor(t, "every copy delivered", func() bool { return r.m.get("delivery.msrp") == 3 })
	if r.m.get("group.fanout.deliveries") != 3 || r.m.get("group.message.accepted") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestNotificationsGoBackToTheAuthorInTheGroup(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	a := r.connect(g, alice, nil)
	b := r.connect(g, bob, nil)
	r.connect(g, carol, nil)
	if code := a.send(t, message(t, alice, "m1", "hi", imdn.PositiveDelivery|imdn.Display)); code != msrp.StatusOK {
		t.Fatalf("answered %d", code)
	}
	b.next(t)
	// bob's client writes alice's number as it knows it in To (rcsjta
	// GroupChatSession); the group's record finds the message anyway.
	rcpt := receipt(t, bob, "tel:+15550100001", "m1", imdn.DisplayNotification, imdn.Displayed)
	for range 2 {
		if code := b.send(t, rcpt); code != msrp.StatusOK {
			t.Fatalf("bob's notification answered %d", code)
		}
	}
	got := asSeen(t, a.next(t))
	from, err := got.From()
	if err != nil || from.URI != bob || !imdn.IsNotification(got) {
		t.Fatalf("alice got %v from %v", got, from)
	}
	n, err := imdn.ParseNotificationMessage(got)
	if err != nil || n.MessageID != "m1" || n.Status != imdn.Displayed {
		t.Fatalf("notification %+v, %v", n, err)
	}
	expectNothing(t, a, "the repeat")
	// Someone who was not sent the message cannot report on it.
	if err := r.s.Add(t.Context(), g.URI, alice, []Invitee{{Identity: dave}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Join(t.Context(), g.URI, dave, ""); err != nil {
		t.Fatal(err)
	}
	dv := r.connect(g, dave, nil)
	if code := dv.send(t, receipt(t, dave, alice, "m1", imdn.DisplayNotification, imdn.Displayed)); code != msrp.StatusForbidden {
		t.Fatalf("dave's notification answered %d", code)
	}
	if code := b.send(t, receipt(t, bob, alice, "m9", imdn.DisplayNotification, imdn.Displayed)); code != msrp.StatusForbidden {
		t.Fatalf("a notification about nothing answered %d", code)
	}
	if r.m.get("message.rejected.imdn_forged") != 1 || r.m.get("message.rejected.imdn_unknown") != 1 || r.m.get("imdn.duplicate") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestOnlyJoinedParticipantsWriteInAGroup(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	b := r.connect(g, bob, nil)
	c := r.connect(g, carol, nil)
	if err := r.s.Leave(t.Context(), g.URI, carol); err != nil {
		t.Fatal(err)
	}
	// carol's session is still up (the SIP layer ends it); what she sends
	// is refused.
	if code := c.send(t, message(t, carol, "m1", "still here?", 0)); code != msrp.StatusForbidden {
		t.Fatalf("a former participant's message answered %d", code)
	}
	expectNothing(t, b, "bob")
	// Nor does anyone write to a group that is not there.
	err := r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: "sip:chat-none@" + host, Sender: bob, CPIM: message(t, bob, "m2", "x", 0)})
	if rej, ok := err.(*messaging.Rejection); !ok || rej.Reason != messaging.ReasonNoGroup {
		t.Fatalf("to no group: %v", err)
	}
	if r.m.get("message.rejected.not_participant") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestAGroupBoundsEachSenderAndItsFanOut(t *testing.T) {
	send := func(r *rig, g groupstore.Group, from, id string) error {
		return r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: g.URI, Sender: from, CPIM: message(t, from, id, "x", 0)})
	}
	// Each participant's own rate in the group.
	r := newRig(t, Config{SenderRate: messaging.Rate{PerMinute: 60, Burst: 2}, FanoutRate: rateOff})
	g := r.create(bob, carol)
	for _, id := range []string{"a1", "a2"} {
		if err := send(r, g, alice, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := send(r, g, alice, "a3"); err == nil {
		t.Fatal("alice's rate in the group did not hold")
	}
	if err := send(r, g, bob, "b1"); err != nil {
		t.Fatalf("bob: %v", err)
	}
	// The group's budget: each message to the four others costs four
	// deliveries, and each sender may use a quarter of the 16, so four
	// senders use it up and the fifth waits for it to refill.
	r = newRig(t, Config{MaxParticipants: 5, FanoutRate: messaging.Rate{PerMinute: 60, Burst: 16}})
	g = r.create(bob, carol, dave, erin)
	for _, from := range []string{alice, bob, carol, dave} {
		if err := send(r, g, from, "m-"+from); err != nil {
			t.Fatal(err)
		}
	}
	if err := send(r, g, erin, "e1"); err == nil {
		t.Fatal("the group's fan-out budget did not hold")
	}
	r.clock.Advance(16 * time.Second)
	if err := send(r, g, erin, "e2"); err != nil {
		t.Fatalf("erin once the budget refilled: %v", err)
	}
	if r.m.get("group.fanout_budget_exceeded") != 1 || r.m.get("group.fanout_share_exceeded") != 0 || r.m.get("message.rejected.rate_limited") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
	// The engine's size limit applies to group messages too.
	big := message(t, alice, "big", strings.Repeat("x", messaging.DefaultMaxMessageSize), 0)
	if rej, ok := r.e.SubmitGroup(t.Context(), messaging.GroupOrigin{Group: g.URI, Sender: bob, CPIM: big}).(*messaging.Rejection); !ok ||
		rej.Reason != messaging.ReasonTooLarge {
		t.Fatalf("a large message: %v", rej)
	}
}

// QA's reproduction (PR #118): in a full group of 100, one participant
// writing a message a second, within its own rate, used the whole fan-out
// budget and the others were refused 80% of the time. Its share of the
// budget now holds it to a quarter.
func TestOneMemberCannotSilenceAFullGroup(t *testing.T) {
	r := newRig(t, Config{})
	var in []Invitee
	for i := range 99 {
		in = append(in, Invitee{Identity: fmt.Sprintf("sip:u%d@example.net", i)})
	}
	g, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: in})
	if err != nil {
		t.Fatal(err)
	}
	mallory, other := "sip:u0@example.net", "sip:u1@example.net"
	for _, who := range []string{mallory, other} {
		if _, err := r.s.Join(t.Context(), g.URI, who, ""); err != nil {
			t.Fatal(err)
		}
	}
	var ok, no int
	for sec := range 300 {
		_, _ = r.s.Recipients(t.Context(), g.URI, mallory, messaging.GroupText)
		if sec%5 == 0 {
			if _, err := r.s.Recipients(t.Context(), g.URI, other, messaging.GroupText); err == nil {
				ok++
			} else {
				no++
			}
		}
		r.clock.Advance(time.Second)
	}
	if no != 0 {
		t.Fatalf("the other member: ok %d, refused %d", ok, no)
	}
	if r.m.get("group.fanout_share_exceeded") == 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

// QA's reproduction (PR #118): with the largest size limit, a group of
// that size can be created at once.
func TestTheLargestGroupCanBeCreatedAtOnce(t *testing.T) {
	r := newRig(t, Config{MaxParticipants: LimitParticipants})
	var in []Invitee
	for i := range LimitParticipants - 1 {
		in = append(in, Invitee{Identity: fmt.Sprintf("sip:u%d@example.net", i)})
	}
	if _, err := r.s.Create(t.Context(), CreateRequest{Creator: alice, Invitees: in}); err != nil {
		t.Fatal(err)
	}
}

func TestIsComposingReachesTheOthersWithoutBeingStored(t *testing.T) {
	r := newRig(t, Config{})
	g := r.create(bob, carol)
	a := r.connect(g, alice, nil)
	b := r.connect(g, bob, nil)
	// carol is invited but has no session: nothing to show it on.
	ind := `<?xml version="1.0" encoding="UTF-8"?><isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state></isComposing>`
	// As rcsjta sends it in a group: in CPIM, so that From says who.
	wrapped := "From: <" + alice + ">\r\nTo: <" + messaging.AnonymousURI + ">\r\nDateTime: 2026-03-04T05:06:07.000Z\r\n\r\n" +
		"Content-Type: " + messaging.IsComposingType + ";charset=UTF-8\r\n\r\n" + ind
	if code := a.send(t, []byte(wrapped)); code != msrp.StatusOK {
		t.Fatalf("answered %d", code)
	}
	got := asSeen(t, b.next(t))
	if from, to := fromTo(t, got); from.URI != alice || to != g.URI || string(got.Body) != ind {
		t.Fatalf("bob got From %v To %s: %q", from, to, got.Body)
	}
	// A bare indication is wrapped for the others.
	if code := b.sendType(t, messaging.IsComposingType, []byte(ind)); code != msrp.StatusOK {
		t.Fatalf("answered %d", code)
	}
	got = asSeen(t, a.next(t))
	if from, _ := fromTo(t, got); from.URI != bob || !bytes.Contains(got.Body, []byte("isComposing")) {
		t.Fatalf("alice got %v", got)
	}
	if r.queues.Len(bob) != 0 || r.queues.Len(carol) != 0 || r.m.get("group.message.accepted") != 0 {
		t.Fatalf("an indication was stored; metrics %v", r.m)
	}
}

// A copy that expires before its participant comes back sends the
// author the negative delivery notification it asked for, in the group.
func TestAnExpiredCopyTellsTheAuthorInTheGroup(t *testing.T) {
	r := newRigWith(t, Config{}, messaging.Config{StoreTTL: time.Hour}, store.NewMemory(), groupstore.NewMemory(), newFakeClock(), 1)
	g := r.create(bob)
	a := r.connect(g, alice, nil)
	if code := a.send(t, message(t, alice, "m1", "hi", imdn.NegativeDelivery)); code != msrp.StatusOK {
		t.Fatalf("answered %d", code)
	}
	waitFor(t, "bob's copy queued", func() bool { return r.queues.Len(bob) == 1 })
	r.clock.Advance(time.Hour)
	if n, err := r.e.Sweep(t.Context()); err != nil || n != 1 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	got := asSeen(t, a.next(t))
	n, err := imdn.ParseNotificationMessage(got)
	if from, _ := got.From(); err != nil || n.MessageID != "m1" || n.Status != imdn.Failed || from.URI != bob {
		t.Fatalf("alice got %+v from %v, %v", n, from, err)
	}
}
