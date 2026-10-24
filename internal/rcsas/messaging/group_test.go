package messaging

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

const groupURI = "sip:chat-1@conf.ims.example.net"

// members is a GroupHandler of one group whose participants all write to
// each other, under the names in names, or refuse when refuse is set.
// Member leaves out those in left: a copy written to them before they
// left. The group is this task's unless another, alive, owns it
// (notMine), and its copies are queued under fence; lost counts the
// groups the engine said it lost, and woken the owners it asked to read a
// queue.
type members struct {
	all     []string
	left    []string
	names   map[string]string
	refuse  error
	notMine bool
	fence   *store.Fence
	lost    *atomic.Int64
	woken   *atomic.Int64
	// registered counts the wakes that told of a registration on a new
	// flow, and hold, when set, holds every wake until it is closed.
	registered *atomic.Int64
	hold       chan struct{}
}

func (h members) Owns(_ context.Context, group string) (bool, error) {
	return group == groupURI && !h.notMine, nil
}

func (h members) Lost(group string) {
	if h.lost != nil && group == groupURI {
		h.lost.Add(1)
	}
}

func (h members) WakeOwner(_ context.Context, group, user string, registered bool) {
	if h.hold != nil {
		<-h.hold
	}
	if h.woken != nil && group == groupURI {
		h.woken.Add(1)
	}
	if h.registered != nil && registered {
		h.registered.Add(1)
	}
}

func (h members) Recipients(_ context.Context, group, sender string, kind GroupKind) (Audience, error) {
	if h.refuse != nil {
		return Audience{}, h.refuse
	}
	if group != groupURI {
		return Audience{}, Reject(ReasonNoGroup)
	}
	aud := Audience{SenderName: h.names[sender], Fence: h.fence}
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
	return GroupOrigin{Group: groupURI, Sender: sender, Conversation: conv, CPIM: content.BodyOf(body)}
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
	c, err := cpim.Parse(m.CPIM.Bytes())
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
	// It names the author as who brings the recipient back (Referred-By).
	inv := r.d.nextInvite(t)
	if inv.Peer != groupURI || inv.Mode != store.Group || inv.Referrer != alice {
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
	// carol's queue is full already: she is offline before it is sent.
	r.d.onPager(func(Delivery) error { return ErrOffline })
	if err := r.e.Submit(t.Context(), standalone(bob, carol, chat(t, "x", "x", 0))); err != nil {
		t.Fatal(err)
	}
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
		"no sender":           {GroupOrigin{Group: groupURI, CPIM: content.BodyOf(chat(t, "m3", "x", 0))}, ReasonMalformed},
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
	if string(got.Body.Bytes()) != "hi" {
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
	got, err := cpim.Parse(b.next(t).Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if from, _ := got.From(); from.URI != alice || string(got.Body.Bytes()) != "hi" {
		t.Fatalf("bob got %v", got)
	}
	if code := b.outcome(t, cpim.ContentType, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)); code != 200 {
		t.Fatalf("bob's notification answered %d", code)
	}
	n, err := cpim.Parse(a.next(t).Body.Bytes())
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
	if c, err := cpim.Parse(b.next(t).Body.Bytes()); err != nil || !isComposing(c) {
		t.Fatalf("bob got %v, %v", c, err)
	}
	wrapped := "From: <" + bob + ">\r\nTo: <" + AnonymousURI + ">\r\n\r\nContent-Type: " + IsComposingType + "\r\n\r\n" + string(ind)
	waitFor(t, "the first indication to be out", func() bool { return r.m.get("iscomposing.forwarded") == 1 })
	if code := b.outcome(t, cpim.ContentType, []byte(wrapped)); code != 200 {
		t.Fatalf("answered %d", code)
	}
	if c, err := cpim.Parse(a.next(t).Body.Bytes()); err != nil || !isComposing(c) {
		t.Fatalf("alice got %v, %v", c, err)
	}
	// A delivered copy is removed once its success report is in, after
	// the client has it.
	mem := r.store.(*store.Memory)
	waitFor(t, "every queue empty", func() bool { return mem.Len(alice) == 0 && mem.Len(bob) == 0 })
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
		"in another group":  {GroupOrigin{Group: "sip:chat-2@x", Sender: bob, CPIM: content.BodyOf(receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered))}, ReasonIMDNUnknown},
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
	// bob wrote the anonymous URI in its To; rcs-as writes alice there.
	readAddresses(t, ms[0].CPIM.Bytes(), cpim.Address{URI: bob}, "<"+alice+">")
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
	// Every item counts, claimed or not: the engine keeps trying bob's
	// standalone messages, and one it holds at this moment is not Pending
	// (#207).
	if n := r.store.(*store.Memory).Len(bob); n != 10 {
		t.Fatalf("alice holds %d of bob's queue, one share is 10", n)
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
	// The rest are summarized: one summary per message (#166).
	if notes, sums := queuedReceipts(t, r, alice); notes != share || sums != 6 {
		t.Fatalf("%d receipts and %d summaries queued for alice, one share is %d", notes, sums, share)
	}
	if got := r.m.get("group.notification.summarized"); got != 99*12-int64(share) || r.m.get("group.notification.dropped") != 0 {
		t.Fatalf("summarized %d; metrics %v", got, r.m)
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
	reads := new(atomic.Int64)
	r.e.SetGroupHandler(counted{members{all: []string{alice, bob}}, reads})
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
	if got := b.next(t); !strings.HasSuffix(string(got.Body.Bytes()), "one") {
		t.Fatalf("bob got %q", got.Body.Bytes())
	}
	// With the mark gone, a copy goes on the open session unasked.
	before := reads.Load()
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1b", "again", 0))); err != nil {
		t.Fatal(err)
	}
	if got := b.next(t); !strings.HasSuffix(string(got.Body.Bytes()), "again") || reads.Load() != before+1 {
		t.Fatalf("bob got %q after %d reads, want the Recipients one alone", got.Body.Bytes(), reads.Load()-before)
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
		t.Fatalf("a former participant got %q", m.Body.Bytes())
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
	// The retry timer and the registration may each make an attempt.
	if len(r.d.invites) != 0 || r.store.(*store.Memory).Len(bob) != 1 || r.m.get("store.failed") == 0 {
		t.Fatalf("invites %d, metrics %v", len(r.d.invites), r.m)
	}
}

// slowStore takes step of the fake clock for each enqueue: a store that
// answers, but slowly.
type slowStore struct {
	store.Store
	clock *fakeClock
	step  time.Duration
	calls atomic.Int64

	mu      sync.Mutex
	reached map[string]bool
}

func (s *slowStore) Enqueue(ctx context.Context, m store.Message, l store.Limit) error {
	s.calls.Add(1)
	s.mu.Lock()
	if s.reached == nil {
		s.reached = map[string]bool{}
	}
	s.reached[m.Recipient] = true
	s.mu.Unlock()
	s.clock.Advance(s.step)
	return s.Store.Enqueue(ctx, m, l)
}

func (s *slowStore) recipients() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.reached)
}

// The fan-out runs on the sender's session one recipient after another; a
// slow store cannot hold the sender past FanoutTimeout. The recipients not
// reached are left out and the sender is told to try again.
func TestASlowFanOutAnswersTheSenderInTime(t *testing.T) {
	clock := newFakeClock()
	st := &slowStore{Store: store.NewMemory(), clock: clock, step: 3 * time.Second}
	r := newRigWith(t, Config{}, st, clock)
	everyone := []string{alice}
	for i := range 99 {
		everyone = append(everyone, fmt.Sprintf("sip:u%d@example.net", i))
	}
	r.e.SetGroupHandler(members{all: everyone})
	drainInvites(t, r.d)
	start := clock.Now()
	err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi all", 0)))
	if err == nil || rejected(err) != "" {
		t.Fatalf("SubmitGroup = %v, want a failure to retry", err)
	}
	if took := clock.Now().Sub(start); took > DefaultFanoutTimeout+st.step {
		t.Fatalf("the sender waited %v", took)
	}
	n := st.calls.Load()
	if n >= 99 || r.m.get("group.fanout.timed_out") != 99-n {
		t.Fatalf("%d enqueues; metrics %v", n, r.m)
	}
	// The client may send it again; the copies go to others first, not
	// to the same ones every time.
	first := st.recipients()
	for range 3 {
		_ = r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi all", 0)))
	}
	if got := len(st.recipients()); got <= len(first) {
		t.Fatalf("four attempts reached %d recipients, the first alone %d", got, len(first))
	}
}

// As in a 1-to-1 chat: a new group copy tried on its own does not go ahead
// of an older one from the group waiting for the same session, when that
// session opens just before it is tried (QA mutant M12).
func TestANewGroupMessageDoesNotOvertakeOnesWaitingForTheSession(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}, RetryInterval: time.Hour})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	l := r.listen(t)
	drainInvites(t, r.d)
	// alice's g1 waits for bob's session with the group.
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "g1", "g1", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	// carol's pager-mode messages hold the worker, one at a time.
	entered, proceed := make(chan struct{}, 4), make(chan struct{}, 4)
	r.d.onPager(func(Delivery) error { entered <- struct{}{}; <-proceed; return nil })
	if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, "c1", "c1", 0))); err != nil {
		t.Fatal(err)
	}
	<-entered
	// While it is held, carol's c2 and alice's g2 arrive: the next pass
	// tries them on their own, c2 first.
	if err := r.e.Submit(t.Context(), standalone(carol, bob, chat(t, "c2", "c2", 0))); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "g2", "g2", 0))); err != nil {
		t.Fatal(err)
	}
	proceed <- struct{}{}
	<-entered // c2
	// bob's session with the group opens now, before g2 is tried.
	_, b := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	proceed <- struct{}{}
	for _, want := range []string{"g1", "g2"} {
		if got := b.next(t); !strings.HasSuffix(string(got.Body.Bytes()), want) {
			t.Fatalf("got %q, want %s", got.Body.Bytes(), want)
		}
	}
}

// The size limit holds for what is queued, after the rewrite: a long
// identity and roster name in place of the anonymous From can take a
// message that fit beyond it (QA mutant M14).
func TestTheRewrittenGroupMessageMustFitTheSizeLimit(t *testing.T) {
	const limit = 1024
	long := "sip:" + strings.Repeat("a", 200) + "@example.net"
	r := newRig(t, Config{MaxMessageSize: limit, SenderRate: Rate{PerMinute: -1}})
	r.e.SetGroupHandler(members{all: []string{long, bob}, names: map[string]string{long: strings.Repeat("N", 200)}})
	base := len(chat(t, "m1", "", 0))
	body := chat(t, "m1", strings.Repeat("x", limit-base), 0)
	if len(body) != limit {
		t.Fatalf("body of %d bytes", len(body))
	}
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(long, body))); got != ReasonTooLarge {
		t.Fatalf("a rewrite beyond the limit: %q", got)
	}
	if r.store.(*store.Memory).Len(bob) != 0 {
		t.Fatal("it was queued")
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(long, chat(t, "m2", strings.Repeat("x", limit-base-500), 0))); err != nil {
		t.Fatalf("one that fits after the rewrite: %v", err)
	}
}

// A group message's sender is named in canonical form, as the group names
// its participants: its author, its share and its From are the ones its
// own legs and records go by.
func TestAGroupSenderIsNamedInCanonicalForm(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom("tel:+1-555-010-0001", chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 1 || ms[0].Author != alice {
		t.Fatalf("bob's queue %+v, %v", ms, err)
	}
	readAddresses(t, ms[0].CPIM.Bytes(), cpim.Address{URI: alice}, "<"+groupURI+">")
	if _, err := r.store.Sent(t.Context(), alice, "m1", r.clock.Now()); err != nil {
		t.Fatalf("alice's own record: %v", err)
	}
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom("not a URI", chat(t, "m2", "hi", 0)))); got != ReasonNotParticipant {
		t.Fatalf("a sender that is no URI: %q", got)
	}
}

// The SIP layer invites a new group's participants through Invite, which
// keeps the engine's own count: once for each, and a message queued for
// one meanwhile waits for that session rather than ringing its client a
// second time (#137).
func TestInviteAsksOnceForAParticipantsSession(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	inv := Invitation{Recipient: bob, Peer: groupURI, Conversation: conv, Mode: store.Group}
	r.e.Invite(t.Context(), inv)
	r.e.Invite(t.Context(), inv)
	if got := r.d.nextInvite(t); got != inv {
		t.Fatalf("invitation %+v", got)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 {
		t.Fatalf("%d more invitations", n)
	}
	// A recipient that takes no sessions from the network is not rung.
	r.e.InviteFailed(Invitation{Recipient: alice, Peer: bob, Mode: store.Chat}, ErrNoSessions)
	r.e.Invite(t.Context(), Invitation{Recipient: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 {
		t.Fatalf("%d invitations to a pager-only recipient", n)
	}
}

// A group's invitation that will never reach its recipient
// (ErrUndeliverable: an address that does not exist, or one that comes
// back to rcs-as) gives up the copies queued for it from the group, rather
// than keeping them, and inviting again, for StoreTTL (security review on
// #279). Being added again lifts that.
func TestAnUndeliverableGroupInvitationGivesTheCopiesUp(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.d.onInvite(func(inv Invitation) error {
		if inv.Recipient == bob {
			return ErrUndeliverable
		}
		return nil
	})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob's copy given up", func() bool { return r.store.(*store.Memory).Len(bob) == 0 })
	if n := r.m.get("delivery.undeliverable"); n != 1 {
		t.Fatalf("%d given up", n)
	}
	r.e.ParticipantAdded(groupURI, bob)
	r.d.onInvite(func(Invitation) error { return nil })
	r.clock.Advance(r.e.cfg.InviteTimeout)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m2", "again", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if n := r.store.(*store.Memory).Len(bob); n != 1 {
		t.Fatalf("bob's queue holds %d after he was added again", n)
	}
}

// QA on #279: a participant the group's invitation found unreachable
// that opens a session with the group itself is reachable again: once
// that session has ended, its next copy waits for it, rather than being
// given up.
func TestAParticipantsOwnSessionLiftsTheUnreachableMark(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.InviteFailed(Invitation{Recipient: bob, Peer: groupURI, Mode: store.Group}, ErrUndeliverable)
	l := r.listen(t)
	leg, _ := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	_ = leg.Close()
	waitFor(t, "bob's leg gone", func() bool { return r.e.chatLeg(bob, groupURI) == nil })
	r.clock.Advance(r.e.cfg.InviteTimeout)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if n := r.store.(*store.Memory).Len(bob); n != 1 || r.m.get("delivery.undeliverable") != 0 {
		t.Fatalf("bob's queue holds %d, %d given up", n, r.m.get("delivery.undeliverable"))
	}
}

// #121 D2 (T8): a copy of a group another task owns is not used to invite
// its recipient from here: that would open the group's session on this
// task, and the owner's next message would invite back. The owner, told
// (Wake), reads the queue again and invites.
func TestOnlyTheGroupsOwnerInvitesForItsCopies(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}, notMine: true})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 || r.m.get("delivery.group_not_owned") == 0 {
		t.Fatalf("%d invitations from a task that does not own the group; %d skipped", n, r.m.get("delivery.group_not_owned"))
	}
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.Wake(bob, groupURI, false)
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI || r.m.get("group.wake") != 1 {
		t.Fatalf("invitation %+v after the wake", inv)
	}
}

// #121 T8: a task's queue pass that leaves a group's copy to the group's
// owner asks the owner to read the queue, which it may not know needs it
// (a registration here, say): once per InviteTimeout, as often as the
// owner would invite.
func TestANonOwnersQueuePassWakesTheOwner(t *testing.T) {
	r := newRig(t, Config{})
	h := members{all: []string{alice, bob}, notMine: true, woken: new(atomic.Int64), registered: new(atomic.Int64)}
	r.e.SetGroupHandler(h)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the owner woken", func() bool { return h.woken.Load() == 1 })
	pass := func(newFlow bool) {
		t.Helper()
		before := r.m.get("delivery.group_not_owned")
		if newFlow {
			r.e.UserRegistered(bob, true)
		} else {
			r.e.Wake(bob, groupURI, false)
		}
		waitFor(t, "the next pass", func() bool { return r.m.get("delivery.group_not_owned") > before })
		waitFor(t, "idle", r.idle)
	}
	pass(false)
	if n := h.woken.Load(); n != 1 || h.registered.Load() != 0 {
		t.Fatalf("woken %d times within InviteTimeout, %d telling of a registration", n, h.registered.Load())
	}
	// A registration on a new flow here wakes the owner at once, and says
	// so (code review on #464), once.
	pass(true)
	waitFor(t, "the owner woken for the registration", func() bool { return h.woken.Load() == 2 })
	if n := h.registered.Load(); n != 1 {
		t.Fatalf("%d wakes told of the registration", n)
	}
	pass(false)
	r.clock.Advance(DefaultInviteTimeout)
	pass(false)
	waitFor(t, "the owner woken again", func() bool { return h.woken.Load() == 3 })
	if n := h.registered.Load(); n != 1 {
		t.Fatalf("%d wakes told of the one registration", n)
	}
}

// Code review on #464: a wake goes off the queue pass, which a connection
// to the owner still to be made would hold up: with one worker, a pager
// message for someone else goes while the wake waits.
func TestAWakeDoesNotHoldTheQueuePass(t *testing.T) {
	r := newRig(t, Config{Workers: 1})
	h := members{all: []string{alice, bob}, notMine: true, woken: new(atomic.Int64), hold: make(chan struct{})}
	r.e.SetGroupHandler(h)
	defer close(h.hold)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the pass", func() bool { return r.m.get("delivery.group_not_owned") > 0 })
	if err := r.e.Submit(t.Context(), standalone(alice, carol, chat(t, "p1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); d.Recipient != carol {
		t.Fatalf("delivered %+v", d)
	}
	if n := h.woken.Load(); n != 0 {
		t.Fatalf("the held wake finished %d times", n)
	}
}

// Code review and QA on #464: a wake that tells of a registration on a new
// flow has the owner forget the invitation it last asked for the
// participant in the group, which held its copies back, and invite at once;
// one that does not leaves the invitation's wait.
func TestAWakeForARegistrationInvitesAtOnce(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	if inv := r.d.nextInvite(t); inv.Recipient != bob {
		t.Fatalf("invitation %+v", inv)
	}
	waitFor(t, "idle", r.idle)
	r.e.Wake(bob, groupURI, false)
	waitFor(t, "idle", r.idle)
	select {
	case inv := <-r.d.invites:
		t.Fatalf("invited again within InviteTimeout: %+v", inv)
	default:
	}
	r.e.Wake(bob, groupURI, true)
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v after the registration's wake", inv)
	}
}

// #564: the owner's invitation to the group fails, and its failure comes
// in only after a wake told of the participant's registration on a new
// flow on another task. The registration overtakes the failure, as one on
// this task does (TestARegistrationOvertakesALateInvitationFailure): the
// failure is not marked, and the wake's read of the queue invites again.
func TestAWakeForARegistrationOvertakesALateInvitationFailure(t *testing.T) {
	r := newRig(t, Config{InviteTimeout: time.Hour, RetryInterval: time.Hour})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	first := r.d.nextInvite(t)
	if first.Recipient != bob || first.Peer != groupURI {
		t.Fatalf("invitation %+v", first)
	}
	waitFor(t, "idle", r.idle)
	r.e.Wake(bob, groupURI, true)
	r.e.InviteFailed(first, ErrOffline) // the 486 of the group's INVITE, come late
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v after the registration's wake", inv)
	}
	if n := r.m.get("invite.failed_overtaken"); n != 1 {
		t.Fatalf("%d overtaken failures", n)
	}
}

// #121 D2 (T4): every copy is queued under the group's owner the handler
// names; once the store no longer holds it, the fan-out stops at the first
// refused copy and the sender is answered as for a store failure.
func TestACopyIsQueuedOnlyUnderTheGroupsOwner(t *testing.T) {
	r := newRig(t, Config{})
	mem := r.store.(*store.Memory)
	owner := atomic.Int64{}
	owner.Store(1)
	mem.SetFence(func(f store.Fence) bool { return f.Group == groupURI && f.Epoch == owner.Load() })
	h := members{all: []string{alice, bob, carol}, fence: &store.Fence{Group: groupURI, Task: "task-a", Epoch: 1}, lost: new(atomic.Int64)}
	r.e.SetGroupHandler(h)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	if mem.Len(bob) != 1 || mem.Len(carol) != 1 {
		t.Fatalf("queues: bob %d, carol %d", mem.Len(bob), mem.Len(carol))
	}
	owner.Store(2) // another task took the group over
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m2", "hi", 0))); !errors.Is(err, store.ErrNotOwner) {
		t.Fatalf("SubmitGroup after the takeover = %v", err)
	}
	if mem.Len(bob)+mem.Len(carol) != 2 || r.m.get("group.fanout.not_owner") != 1 {
		t.Fatalf("queues: bob %d, carol %d; %d refused", mem.Len(bob), mem.Len(carol), r.m.get("group.fanout.not_owner"))
	}
	// The group package hears of it, and reads the owner again before it
	// invites for the group (QA on #440).
	if h.lost.Load() != 1 {
		t.Fatalf("the handler was told %d times", h.lost.Load())
	}
}

// QA on #464: a wake telling of a registration on a new flow forgets the
// participant's pager-only mark too, as the registration would here: a
// client that once answered passive is offered the group's session again.
func TestAWakeForARegistrationForgetsPagerOnly(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	inv := r.d.nextInvite(t)
	r.e.InviteFailed(inv, ErrNoSessions) // bob answered passive
	waitFor(t, "idle", r.idle)
	r.e.Wake(bob, groupURI, false)
	waitFor(t, "idle", r.idle)
	select {
	case inv := <-r.d.invites:
		t.Fatalf("invited a pager-only client: %+v", inv)
	default:
	}
	r.e.Wake(bob, groupURI, true)
	if inv := r.d.nextInvite(t); inv.Recipient != bob {
		t.Fatalf("invitation %+v after the registration's wake", inv)
	}
}

// QA on #464: past maxWakesOut wakes on their way, a wake is counted and
// tried again after wakeRetry, not left to the queue's own retry, up to an
// hour away: every participant's owner is woken within a few seconds.
func TestWakesPastTheBoundAreTriedAgainSoon(t *testing.T) {
	const n = maxWakesOut + 36
	var all []string
	for i := range n {
		all = append(all, fmt.Sprintf("sip:p%03d@%s", i, "ims.example.net"))
	}
	r := newRig(t, Config{})
	release := make(chan struct{})
	h := members{all: append([]string{alice}, all...), notMine: true, woken: new(atomic.Int64), hold: release}
	r.e.SetGroupHandler(h)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a wake skipped", func() bool { return r.m.get("group.wake_skipped") > 0 })
	close(release) // the wakes on their way are answered
	for range 5 {
		r.clock.Advance(wakeRetry)
		if h.woken.Load() == n {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	waitFor(t, "every owner woken", func() bool { return h.woken.Load() == n })
}

// Code review on #628: while the SIP layer serves a participant's own
// INVITE to the group (Joining), a queue pass that finds its copy and no
// leg yet does not invite it: the focus's INVITE would ring the client
// with a second session with the group. The copy goes on the leg the
// INVITE opens, and the join's end then reads the queue no more.
func TestAJoiningParticipantIsNotInvited(t *testing.T) {
	st := &pendingReads{Store: store.NewMemory()}
	r := newRigWith(t, Config{}, st, newFakeClock())
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	done := r.e.Joining(bob, groupURI)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the invitation held", func() bool { return r.m.get("invite.held_for_join") == 1 })
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 {
		t.Fatalf("%d invitations to a participant joining", n)
	}
	l := r.listen(t)
	_, c := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	if m := c.next(t); !strings.Contains(string(m.Body.Bytes()), "hi") {
		t.Fatalf("delivered %q", m.Body.Bytes())
	}
	waitFor(t, "idle", r.idle)
	reads := st.n.Load()
	done()
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 || r.m.get("invite.held_for_join") != 1 {
		t.Fatalf("%d invitations, %d held, after the join", n, r.m.get("invite.held_for_join"))
	}
	if n := st.n.Load() - reads; n != 0 {
		t.Fatalf("the join's end read a queue %d times", n)
	}
}

// pendingReads counts the reads of the queues.
type pendingReads struct {
	store.Store
	n atomic.Int64
}

func (p *pendingReads) PendingHeld(ctx context.Context, r, after, owner string, now time.Time, n int) ([]store.Message, time.Time, error) {
	p.n.Add(1)
	return p.Store.PendingHeld(ctx, r, after, owner, now, n)
}

// Code review on #628: a join that opens no leg, refused say, has the
// queue read again as it ends, so that the copy it held back is invited
// for at once rather than at the next message or retry. Ending it twice
// is ending it once.
func TestARefusedJoinInvitesForTheCopyItHeld(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	done := r.e.Joining(bob, groupURI)
	other := r.e.Joining(bob, groupURI) // the same client's INVITE twice
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the invitation held", func() bool { return r.m.get("invite.held_for_join") == 1 })
	waitFor(t, "idle", r.idle)
	done()
	done()
	waitFor(t, "idle", r.idle)
	if n := len(r.d.invites); n != 0 {
		t.Fatalf("%d invitations while the other join is served", n)
	}
	other()
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v", inv)
	}
}

// Code review on #628: a join whose end never comes, as for a request the
// proxy, closing, never serves, holds the invitations back for no more
// than AnswerTimeout.
func TestAJoinHoldsBackForAnswerTimeoutAtMost(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.Joining(bob, groupURI)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the invitation held", func() bool { return r.m.get("invite.held_for_join") == 1 })
	waitFor(t, "idle", r.idle)
	r.clock.Advance(r.e.cfg.AnswerTimeout)
	r.e.Wake(bob, groupURI, false)
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v", inv)
	}
}

// Code review on #628: a join holds back the invitations to its own group
// only.
func TestAJoinHoldsBackOnlyItsGroupsInvitations(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.Joining(bob, "sip:chat-2@conf.ims.example.net")
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	if inv := r.d.nextInvite(t); inv.Recipient != bob || inv.Peer != groupURI {
		t.Fatalf("invitation %+v", inv)
	}
}

// Code review on #628: past MaxTracked joins held, the next is not, and
// its participant is invited as before.
func TestJoinsPastTheBoundAreNotHeld(t *testing.T) {
	r := newRig(t, Config{MaxTracked: 1})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	r.e.Joining(alice, groupURI)
	r.e.Joining(bob, groupURI)()
	if r.m.get("invite.join_untracked") != 1 {
		t.Fatalf("%d joins untracked", r.m.get("invite.join_untracked"))
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", 0))); err != nil {
		t.Fatal(err)
	}
	if inv := r.d.nextInvite(t); inv.Recipient != bob {
		t.Fatalf("invitation %+v", inv)
	}
}
