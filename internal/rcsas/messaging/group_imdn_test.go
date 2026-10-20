package messaging

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// receiptAs is receipt with a recipient-uri, as a notifier's client
// writes its own address there (RFC 5438 §11.1.3).
func receiptAs(t testing.TB, id string, k imdn.Kind, s imdn.Status, recipientURI string) []byte {
	t.Helper()
	n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: k, Status: s, RecipientURI: recipientURI}
	m, err := n.Message(imdn.Envelope{From: cpim.Address{URI: AnonymousURI}, To: cpim.Address{URI: AnonymousURI},
		MessageID: "r" + id, DateTime: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// counted counts the GroupHandler's reads of the group.
type counted struct {
	members
	reads *atomic.Int64
}

func (h counted) Recipients(ctx context.Context, group, sender string, kind GroupKind) (Audience, error) {
	h.reads.Add(1)
	return h.members.Recipients(ctx, group, sender, kind)
}

func (h counted) Member(ctx context.Context, group, user string) (bool, error) {
	h.reads.Add(1)
	return h.members.Member(ctx, group, user)
}

// rcsjta sends a display notification about a group message as a SIP
// MESSAGE to the author when the group session is gone, with anonymous
// From and To. The author's own record of the message finds the group's,
// and the notification reaches the author in the group, From the notifier
// and To the author, once, whichever way it is repeated.
func TestAGroupReceiptSentOutsideTheGroupReachesTheAuthorInIt(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.PositiveDelivery|imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if own, err := r.store.Sent(t.Context(), alice, "m1", r.clock.Now()); err != nil || own.Group != groupURI {
		t.Fatalf("alice's own record %+v, %v", own, err)
	}
	pager := Origin{Sender: bob, Recipient: alice, Mode: store.Standalone, Pager: true,
		CPIM: receiptAs(t, "m1", imdn.DisplayNotification, imdn.Displayed, bob)}
	if err := r.e.Submit(t.Context(), pager); err != nil {
		t.Fatalf("bob's pager-mode receipt: %v", err)
	}
	ms, err := r.store.Pending(t.Context(), alice, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 1 {
		t.Fatalf("alice's queue %+v, %v", ms, err)
	}
	q := ms[0]
	if !q.Notification || q.Mode != store.Group || q.Sender != groupURI || q.Author != bob {
		t.Fatalf("queued %+v", q)
	}
	readAddresses(t, q.CPIM, cpim.Address{URI: bob}, "<"+alice+">")
	// The same receipt again, by pager or in the group, is a repeat.
	if err := r.e.Submit(t.Context(), pager); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed))); err != nil {
		t.Fatal(err)
	}
	if r.store.(*store.Memory).Len(alice) != 1 || r.m.get("imdn.duplicate") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
	// The group's rules hold outside it too.
	for name, c := range map[string]struct {
		o    Origin
		want Reason
	}{
		"not a recipient": {Origin{Sender: elsewhere, Recipient: alice, Mode: store.Standalone, Pager: true,
			CPIM: receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)}, ReasonIMDNForged},
		"for someone else": {Origin{Sender: carol, Recipient: alice, Mode: store.Standalone, Pager: true,
			CPIM: receiptAs(t, "m1", imdn.DeliveryNotification, imdn.Delivered, bob)}, ReasonIMDNForged},
		"not asked for": {Origin{Sender: carol, Recipient: alice, Mode: store.Standalone, Pager: true,
			CPIM: receipt(t, "m1", imdn.ProcessingNotification, imdn.Processed)}, ReasonIMDNNotRequested},
	} {
		if got := rejected(r.e.Submit(t.Context(), c.o)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// A participant may report only for itself, in the group as outside it.
func TestAGroupReceiptForAnotherParticipantIsRefused(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "m1", "hi", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	o := groupFrom(carol, receiptAs(t, "m1", imdn.DisplayNotification, imdn.Displayed, bob))
	if got := rejected(r.e.SubmitGroup(t.Context(), o)); got != ReasonIMDNForged {
		t.Fatalf("carol reporting for bob: %q", got)
	}
	for _, own := range []string{carol, AnonymousURI} {
		if err := r.e.SubmitGroup(t.Context(), groupFrom(carol, receiptAs(t, "m1", imdn.DisplayNotification, imdn.Displayed, own))); err != nil {
			t.Fatalf("carol reporting as %s: %v", own, err)
		}
	}
	// One of carol's own identities is hers too.
	o = GroupOrigin{Group: groupURI, Sender: bob, Identities: []string{"sip:bob@example.net"}, Conversation: conv,
		CPIM: receiptAs(t, "m1", imdn.DisplayNotification, imdn.Displayed, "sip:bob@example.net")}
	if err := r.e.SubmitGroup(t.Context(), o); err != nil {
		t.Fatalf("bob reporting under his other identity: %v", err)
	}
}

// A notification about a message the group has no record of is refused
// before the group's item is read.
func TestAGroupReceiptAboutNothingCostsNoGroupRead(t *testing.T) {
	r := newRig(t, Config{})
	reads := new(atomic.Int64)
	r.e.SetGroupHandler(counted{members{all: []string{alice, bob}}, reads})
	for range 5 {
		if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(bob, receipt(t, "m9", imdn.DisplayNotification, imdn.Displayed)))); got != ReasonIMDNUnknown {
			t.Fatalf("about nothing: %q", got)
		}
	}
	if n := reads.Load(); n != 0 {
		t.Fatalf("%d group reads for notifications about nothing", n)
	}
}

// One Message-ID names one message: an author cannot use the ID of a
// 1-to-1 message for a group message, nor the other way round.
func TestAMessageIDIsNotSharedBetweenAGroupAnd1To1(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}})
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "d1", "direct", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "d1", "in the group", imdn.Display)))); got != ReasonMessageIDReused {
		t.Fatalf("a 1-to-1 ID in the group: %q", got)
	}
	if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, chat(t, "g1", "in the group", imdn.Display))); err != nil {
		t.Fatal(err)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "g1", "direct", imdn.Display)))); got != ReasonMessageIDReused {
		t.Fatalf("a group ID to bob, who got it in the group: %q", got)
	}
}

// Is-composing in a group reads the group only when another participant
// has a session open here, and at most IsComposingRate's burst at once.
func TestGroupIsComposingIsBoundedAndReadsTheGroupOnlyForSomeone(t *testing.T) {
	r := newRig(t, Config{})
	reads := new(atomic.Int64)
	r.e.SetGroupHandler(counted{members{all: []string{alice, bob}}, reads})
	ind := "From: <" + alice + ">\r\nTo: <" + AnonymousURI + ">\r\n\r\nContent-Type: " + IsComposingType + "\r\n\r\n" +
		`<isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state></isComposing>`
	send := func() {
		t.Helper()
		if err := r.e.SubmitGroup(t.Context(), groupFrom(alice, []byte(ind))); err != nil {
			t.Fatal(err)
		}
	}
	l := r.listen(t)
	r.connect(t, l, LegParams{User: alice, Peer: groupURI, Conversation: conv, Mode: store.Group})
	send()
	if n := reads.Load(); n != 0 {
		t.Fatalf("%d group reads with nobody else here", n)
	}
	r.clock.Advance(time.Minute)
	_, b := r.connect(t, l, LegParams{User: bob, Peer: groupURI, Conversation: conv, Mode: store.Group})
	for range 3 * IsComposingRate.Burst {
		send()
	}
	if n := reads.Load(); n != int64(IsComposingRate.Burst) {
		t.Fatalf("%d group reads for %d indications, burst %d", n, 3*IsComposingRate.Burst, IsComposingRate.Burst)
	}
	b.next(t)
	if r.m.get("iscomposing.dropped") < int64(2*IsComposingRate.Burst) {
		t.Fatalf("metrics %v", r.m)
	}
}

// everyGroup is members of any group URI: the same people in each.
type everyGroup struct{ members }

func (h everyGroup) Recipients(ctx context.Context, _, sender string, kind GroupKind) (Audience, error) {
	return h.members.Recipients(ctx, groupURI, sender, kind)
}

func (h everyGroup) Member(ctx context.Context, _, user string) (bool, error) {
	return h.members.Member(ctx, groupURI, user)
}

// The reviews' reproduction (PR #118, round 3): with a share per group, an
// offline author of one message in each of nine full groups had its queue
// filled by receipts, and a 1-to-1 message to it was refused. All groups'
// notifications together now hold at most a quarter of the queue.
func TestReceiptsFromManyGroupsDoNotFillTheAuthorsQueue(t *testing.T) {
	everyone := []string{alice}
	for i := range 99 {
		everyone = append(everyone, fmt.Sprintf("sip:u%d@example.net", i))
	}
	r := newRig(t, Config{})
	r.e.SetGroupHandler(everyGroup{members{all: everyone}})
	drainInvites(t, r.d)
	r.d.onInvite(func(Invitation) error { return ErrOffline })
	for g := range 9 {
		o := GroupOrigin{Group: fmt.Sprintf("sip:chat-%d@conf.example.net", g), Sender: alice, Conversation: conv,
			CPIM: chat(t, fmt.Sprint("g", g), "hi all", imdn.PositiveDelivery|imdn.Display)}
		if err := r.e.SubmitGroup(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		for _, p := range everyone[1:] {
			for _, k := range []struct {
				kind   imdn.Kind
				status imdn.Status
			}{{imdn.DeliveryNotification, imdn.Delivered}, {imdn.DisplayNotification, imdn.Displayed}} {
				n := GroupOrigin{Group: o.Group, Sender: p, Conversation: conv, CPIM: receipt(t, fmt.Sprint("g", g), k.kind, k.status)}
				if err := r.e.SubmitGroup(t.Context(), n); err != nil {
					t.Fatalf("%s's receipt: %v", p, err)
				}
			}
		}
	}
	l := queueLimit(r.e.cfg)
	if notes, sums := queuedReceipts(t, r, alice); notes != l.GroupCount || notes != 250 || sums != 9 {
		t.Fatalf("%d receipts and %d summaries queued for alice, the total is %d", notes, sums, l.GroupCount)
	}
	if err := r.e.Submit(t.Context(), standalone(bob, alice, chat(t, "d1", "are you there?", 0))); err != nil {
		t.Fatalf("a 1-to-1 message to alice: %v", err)
	}
}
