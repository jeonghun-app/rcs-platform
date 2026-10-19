package messaging

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

const groupURI = "sip:chat-1@conf.ims.example.net"

// members is a GroupHandler of one group whose participants all write to
// each other, under the names in names, or refuse when refuse is set.
// Member leaves out those in left: a copy written to them before they
// left.
type members struct {
	all    []string
	left   []string
	names  map[string]string
	refuse error
}

func (h members) Recipients(_ context.Context, group, sender string, kind GroupKind) (Audience, error) {
	if h.refuse != nil {
		return Audience{}, h.refuse
	}
	if group != groupURI {
		return Audience{}, Reject(ReasonNoGroup)
	}
	aud := Audience{SenderName: h.names[sender]}
	for _, m := range h.all {
		if m != sender {
			aud.Recipients = append(aud.Recipients, m)
		}
	}
	return aud, nil
}

func (h members) Member(_ context.Context, group, user string) (bool, error) {
	if h.refuse != nil && !errors.As(h.refuse, new(*Rejection)) {
		return false, h.refuse
	}
	return group == groupURI && slices.Contains(h.all, user) && !slices.Contains(h.left, user), nil
}

func groupFrom(sender string, body []byte) GroupOrigin {
	return GroupOrigin{Group: groupURI, Sender: sender, Conversation: conv, CPIM: body}
}

func TestAGroupMessageIsQueuedOncePerOtherParticipant(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.PositiveDelivery))); err != nil {
		t.Fatal(err)
	}
	mem := r.store.(*store.Memory)
	if mem.Len(bob) != 1 || mem.Len(carol) != 1 || mem.Len(alice) != 0 {
		t.Fatalf("queues: alice %d, bob %d, carol %d", mem.Len(alice), mem.Len(bob), mem.Len(carol))
	}
	ms, _ := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
	m := ms[0]
	if m.Sender != groupURI || m.Author != alice || m.Mode != store.Group || m.MessageID != "m1" || m.Conversation != conv.ID {
		t.Fatalf("bob's copy %+v", m)
	}
	c, err := cpim.Parse(m.CPIM)
	if err != nil {
		t.Fatal(err)
	}
	from, _ := c.From()
	to, _ := c.To()
	if from.URI != alice || len(to) != 1 || to[0].URI != groupURI {
		t.Fatalf("From %v To %v", from, to)
	}
	sent, err := r.store.Sent(t.Context(), groupURI, "m1", r.clock.Now())
	if err != nil || sent.Author != alice || len(sent.Recipients) != 2 {
		t.Fatalf("Sent = %+v, %v", sent, err)
	}
	// Never pager mode: nobody has a session, so the engine asks for one.
	inv := r.d.nextInvite(t)
	if inv.Peer != groupURI || inv.Mode != store.Group {
		t.Fatalf("invitation %+v", inv)
	}
	waitFor(t, "idle", r.idle)
	if len(r.d.pagers) != 0 {
		t.Fatal("a group message went in pager mode")
	}
}

func TestAMessageIDIsTheAuthorsWithinAGroup(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	msg := chat(t, "m1", "hi", imdn.PositiveDelivery)
	for range 2 {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, msg)); err != nil {
			t.Fatal(err)
		}
	}
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(bob, chat(t, "m1", "mine now", imdn.PositiveDelivery)))); got != ReasonMessageIDReused {
		t.Fatalf("bob reusing alice's Message-ID: %q", got)
	}
	if r.m.get("message.resent") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestOneFullQueueCostsOnlyThatParticipantTheMessage(t *testing.T) {
	r := newRig(t, Config{MaxQueueMessages: 1, QueueSenderShare: 1})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	mem := r.store.(*store.Memory)
	// carol's queue is full already.
	if err := r.e.Submit(t.Context(), standalone(bob, carol, chat(t, "x", "x", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.onPager(func(Delivery) error { return ErrOffline })
	waitFor(t, "idle", r.idle)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.NegativeDelivery))); err != nil {
		t.Fatal(err)
	}
	if mem.Len(bob) != 1 || mem.Len(carol) != 1 {
		t.Fatalf("bob %d, carol %d", mem.Len(bob), mem.Len(carol))
	}
	// alice learns that carol did not get it, in the group.
	ms, _ := r.store.Pending(t.Context(), alice, "", r.clock.Now(), 10)
	if len(ms) != 1 || !ms[0].Notification || ms[0].Sender != groupURI || ms[0].Author != carol || ms[0].Mode != store.Group {
		t.Fatalf("alice's queue %+v", ms)
	}
	if r.m.get("group.fanout.queue_full") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestGroupMessagesNeedAGroupHandlerThatAgrees(t *testing.T) {
	r := newRig(t, Config{})
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0)))); got != ReasonNoGroup {
		t.Fatalf("without a handler: %q", got)
	}
	r.e.SetGroupHandler(members{refuse: Reject(ReasonNotParticipant)})
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0)))); got != ReasonNotParticipant {
		t.Fatalf("refused by the handler: %q", got)
	}
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	for name, c := range map[string]struct {
		o    GroupOrigin
		want Reason
	}{
		"someone else's From": {groupFrom(alice, cpimMessage(t, cpim.Address{URI: carol}, "m2", "x", 0)), ReasonFromMismatch},
		"no sender":           {GroupOrigin{Group: groupURI, CPIM: chat(t, "m3", "x", 0)}, ReasonMalformed},
		"not CPIM":            {groupFrom(alice, []byte("x")), ReasonMalformed},
	} {
		if got := rejected(r.e.SubmitGroup(t.Context(), c.o)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m4", "x", 0)))
	if err != nil {
		t.Fatal(err)
	}
	r.e.SetGroupHandler(members{refuse: errStore})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m5", "x", 0))); !errors.Is(err, errStore) || rejected(err) != "" {
		t.Fatalf("a failing handler: %v", err)
	}
}

func TestGroupLegsTakeCPIMAndIsComposing(t *testing.T) {
	if got := AcceptTypes(store.Group); len(got) != 2 || got[0] != cpim.ContentType || got[1] != IsComposingType {
		t.Fatalf("AcceptTypes(group) = %v", got)
	}
	r := newRig(t, Config{})
	if _, err := r.e.OpenLeg(LegParams{Remote: nil, User: alice, Peer: groupURI, Mode: store.Group, Direction: Originating}); err == nil {
		t.Fatal("a group leg without a path opened")
	}
	if _, err := r.e.Offer(LegParams{User: alice, Peer: groupURI, Mode: store.Group, Direction: Terminating, QueueID: "q"}); err == nil {
		t.Fatal("a group leg named a queued message")
	}
}

func TestGroupViewSetsTheAuthorAndTheGroup(t *testing.T) {
	raw := "From: \"Al\" <" + AnonymousURI + ">\r\nTo: <" + AnonymousURI + ">\r\nTo: <" + bob + ">\r\nDateTime: 2026-03-04T05:06:07Z\r\n\r\n" +
		"Content-Type: text/plain\r\n\r\nhi"
	c, err := cpim.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, err := groupView(c, cpim.Address{Name: "Al", URI: alice}, groupURI)
	if err != nil {
		t.Fatal(err)
	}
	got := readAddresses(t, out, cpim.Address{Name: "Al", URI: alice}, "<"+groupURI+">")
	if string(got.Body) != "hi" {
		t.Fatalf("body %q", got.Body)
	}
	if dt, ok := got.Get(cpim.CoreNamespace, cpim.HeaderDateTime); !ok || dt.Value != "2026-03-04T05:06:07Z" {
		t.Fatalf("DateTime %v", dt)
	}
}

// A group over loopback MSRP at the engine's level: a message, its
// notification back, and is-composing either way.
func TestAGroupRunsOverItsParticipantsSessions(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	if code := a.outcome(t, cpim.ContentType, chat(t, "m1", "hi", imdn.Display)); code != 200 {
		t.Fatalf("answered %d", code)
	}
	got, err := cpim.Parse(b.next(t).Body)
	if err != nil {
		t.Fatal(err)
	}
	if from, _ := got.From(); from.URI != alice || string(got.Body) != "hi" {
		t.Fatalf("bob got %v", got)
	}
	if code := b.outcome(t, cpim.ContentType, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)); code != 200 {
		t.Fatalf("bob's notification answered %d", code)
	}
	n, err := cpim.Parse(a.next(t).Body)
	if err != nil || !imdn.IsNotification(n) {
		t.Fatalf("alice got %v, %v", n, err)
	}
	if from, _ := n.From(); from.URI != bob {
		t.Fatalf("notification from %v", from)
	}
	// is-composing, bare and in CPIM, reaches the other unstored.
	ind := []byte(`<isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state></isComposing>`)
	if code := a.outcome(t, IsComposingType, ind); code != 200 {
		t.Fatalf("answered %d", code)
	}
	if c, err := cpim.Parse(b.next(t).Body); err != nil || !isComposing(c) {
		t.Fatalf("bob got %v, %v", c, err)
	}
	wrapped := "From: <" + bob + ">\r\nTo: <" + AnonymousURI + ">\r\n\r\nContent-Type: " + IsComposingType + "\r\n\r\n" + string(ind)
	waitFor(t, "the first indication to be out", func() bool { return r.m.get("iscomposing.forwarded") == 1 })
	if code := b.outcome(t, cpim.ContentType, []byte(wrapped)); code != 200 {
		t.Fatalf("answered %d", code)
	}
	if c, err := cpim.Parse(a.next(t).Body); err != nil || !isComposing(c) {
		t.Fatalf("alice got %v, %v", c, err)
	}
	mem := r.store.(*store.Memory)
	if mem.Len(alice) != 0 || mem.Len(bob) != 0 {
		t.Fatal("something was left queued")
	}
	// Other media types are refused, and so is everything once the
	// handler says no.
	if code := a.outcome(t, "text/plain", []byte("x")); code != 415 {
		t.Fatalf("text/plain answered %d", code)
	}
	r.e.SetGroupHandler(members{refuse: Reject(ReasonNotParticipant)})
	if code := a.outcome(t, cpim.ContentType, chat(t, "m2", "x", 0)); code != 403 {
		t.Fatalf("refused message answered %d", code)
	}
	r.e.SetGroupHandler(members{refuse: errStore})
	if code := a.outcome(t, cpim.ContentType, chat(t, "m3", "x", 0)); code != StatusTryAgain {
		t.Fatalf("failing handler answered %d", code)
	}
}

func TestGroupNotificationsAreCheckedLikeAnyOther(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.PositiveDelivery))); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		o    GroupOrigin
		want Reason
	}{
		"about nothing":     {groupFrom(bob, receipt(t, "m9", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNUnknown},
		"not asked for":     {groupFrom(bob, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)), ReasonIMDNNotRequested},
		"from the author":   {groupFrom(alice, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNForged},
		"in another group":  {GroupOrigin{Group: "sip:chat-2@x", Sender: bob, CPIM: receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)}, ReasonIMDNUnknown},
		"too large to send": {groupFrom(bob, bigReceipt(t)), ReasonTooLarge},
	} {
		if got := rejected(r.e.SubmitGroup(t.Context(), c.o)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered))); err != nil {
		t.Fatal(err)
	}
	ms, _ := r.store.Pending(t.Context(), alice, "", r.clock.Now(), 10)
	if len(ms) != 1 || ms[0].Author != bob || ms[0].Sender != groupURI || !ms[0].Notification {
		t.Fatalf("alice's queue %+v", ms)
	}
}

// A client that takes no sessions has nothing to show a group message on:
// it waits, uninvited, for a session of its own.
func TestAGroupMessageForAClientWithoutSessionsWaits(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.d.onInvite(func(Invitation) error { return ErrNoSessions })
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m2", "again", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if len(r.d.invites) != 0 || len(r.d.pagers) != 0 || r.store.(*store.Memory).Len(bob) != 2 {
		t.Fatalf("invites %d, pagers %d", len(r.d.invites), len(r.d.pagers))
	}
}

func TestAnExportedLimiterTakesSeveralTokensAtOnce(t *testing.T) {
	now := newFakeClock().Now()
	l := NewLimiter(Rate{PerMinute: 60, Burst: 5}, 10)
	if !l.Allow("g", now, 3) || l.Allow("g", now, 3) || !l.Allow("g", now, 2) || l.Allow("g", now, 1) {
		t.Fatal("the burst of 5 was not taken 3 + 2")
	}
	if l.Allow("h", now, 6) {
		t.Fatal("more than a burst at once")
	}
	if !l.Allow("g", now.Add(2*time.Second), 2) {
		t.Fatal("two tokens did not refill in two seconds")
	}
	if !NewLimiter(Rate{PerMinute: -1}, 1).Allow("x", now, 1000) {
		t.Fatal("a disabled limit limited")
	}
}

// bigReceipt is a notification beyond the pager limit, by its subject.
func bigReceipt(t *testing.T) []byte {
	t.Helper()
	n := imdn.Notification{MessageID: "m1", DateTime: "2026-03-04T05:06:07.000Z", Kind: imdn.DeliveryNotification,
		Status: imdn.Delivered, Subject: strings.Repeat("s", DefaultPagerLimit)}
	m, err := n.Message(imdn.Envelope{From: cpim.Address{URI: AnonymousURI}, To: cpim.Address{URI: AnonymousURI}, MessageID: "r1", DateTime: newFakeClock().Now()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An author holds one sender's share of a recipient's queue, whether it
// writes in a group or 1-to-1: the group is not a second sender.
func TestAnAuthorHoldsOneShareOfAQueueInGroupsAnd1To1(t *testing.T) {
	r := newRig(t, Config{MaxQueueMessages: 80, QueueSenderShare: 8, SenderRate: Rate{PerMinute: -1}})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.d.onPager(func(Delivery) error { return ErrOffline })
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	drainInvites(t, r.d)
	for i := range 20 {
		_ = r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, fmt.Sprint("g", i), "in the group", 0)))
		_ = r.e.Submit(t.Context(), standalone(alice, bob, chat(t, fmt.Sprint("d", i), "directly", 0)))
	}
	ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 10 {
		t.Fatalf("alice holds %d of bob's queue, one share is 10", len(ms))
	}
	if r.m.get("group.fanout.queue_full") == 0 || r.m.get("message.rejected.queue_share_full") == 0 {
		t.Fatalf("metrics %v", r.m)
	}
	// Someone else still gets through.
	if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, "c1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
}

// An offline author of a few messages to a large group gets every
// participant's receipts: they take one share of its queue, the rest are
// taken and dropped rather than refused, and 1-to-1 messages still reach
// it.
func TestReceiptsFromALargeGroupDoNotFillTheAuthorsQueue(t *testing.T) {
	everyone := []string{alice}
	for i := range 99 {
		everyone = append(everyone, fmt.Sprintf("sip:u%d@example.net", i))
	}
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	for i := range 6 {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, fmt.Sprint("m", i), "hi all", imdn.PositiveDelivery|imdn.Display))); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range everyone[1:] {
		for i := range 6 {
			for _, k := range []struct {
				kind   imdn.Kind
				status imdn.Status
			}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
				if err := r.e.SubmitGroup(t.Context(), groupFrom(p, receipt(t, fmt.Sprint("m", i), k.kind, k.status))); err != nil {
					t.Fatalf("%s's receipt: %v", p, err)
				}
			}
		}
	}
	share := queueLimit(r.e.cfg).SenderCount
	if got := r.store.(*store.Memory).Len(alice); got != share {
		t.Fatalf("%d receipts queued for alice, one share is %d", got, share)
	}
	if got := r.m.get("group.notification.dropped"); got != 99*12-int64(share) {
		t.Fatalf("dropped %d; metrics %v", got, r.m)
	}
	if err := r.e.Submit(t.Context(), standalone(bob, alice, chat(t, "d1", "are you there?", 0))); err != nil {
		t.Fatalf("a 1-to-1 message to alice: %v", err)
	}
}

// ParticipantLeft makes the next attempt ask the GroupHandler, even with
// a session open; an answer that the recipient is in the group after all
// (added back on another path) costs it nothing.
func TestADepartureIsCheckedWithTheGroup(t *testing.T) {
	r := newRig(t, Config{MaxTracked: 4})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	l := r.listen(t)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "one", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	r.e.ParticipantLeft(groupURI, bob)
	// Still a member: invited again at once, the mark forgotten.
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v", inv)
	}
	_, b := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	if got := b.next(t); !strings.HasSuffix(string(got.Body), "one") {
		t.Fatalf("bob got %q", got.Body)
	}
	// Gone now, with the session still open: the next copy is not sent on
	// it.
	r.e.SetGroupHandler(members{all: []string{alice, bob}, left: []string{bob}})
	r.e.ParticipantLeft(groupURI, bob)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m2", "two", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the copy given up", func() bool { return r.m.get("delivery.not_participant") == 1 })
	select {
	case m := <-b.got:
		t.Fatalf("a former participant got %q", m.Body)
	case <-time.After(50 * time.Millisecond):
	}
	// The marks are bounded.
	for i := range 10 {
		r.e.ParticipantLeft(groupURI, fmt.Sprintf("sip:u%d@example.net", i))
	}
	r.e.mu.Lock()
	n := len(r.e.departed)
	r.e.mu.Unlock()
	if n > 4 {
		t.Fatalf("%d departures tracked, MaxTracked 4", n)
	}
}

// Without a GroupHandler that can answer, a copy is kept, uninvited.
func TestAGroupCopyWaitsWhenTheGroupCannotSay(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	r.d.nextInvite(t)
	waitFor(t, "idle", r.idle)
	for _, h := range []GroupHandler{members{refuse: errStore}, nil} {
		r.e.SetGroupHandler(h)
		r.clock.Advance(DefaultInviteTimeout)
		r.e.UserRegistered(bob, true)
		waitFor(t, "idle", r.idle)
	}
	if len(r.d.invites) != 0 || r.store.(*store.Memory).Len(bob) != 1 || r.m.get("store.failed") != 1 {
		t.Fatalf("invites %d, metrics %v", len(r.d.invites), r.m)
	}
}
