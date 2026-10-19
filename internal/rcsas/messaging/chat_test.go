package messaging

import (
	"bytes"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

func TestChatFlowsBetweenTwoClientsOverLoopbackMSRP(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})

	msg := chat(t, "Xs8kLz1", "hello bob", imdn.PositiveDelivery|imdn.Display)
	a.send(t, msg)
	if rep := a.report(t); rep.Code != msrp.StatusOK {
		t.Fatalf("alice's message was answered with %d", rep.Code)
	}
	got := b.next(t)
	if !bytes.Equal(got.Body, msg) || got.MediaType() != cpim.ContentType {
		t.Fatalf("bob got %q", got.Body)
	}

	// Bob's client confirms delivery and display; both reach alice.
	for _, s := range []imdn.Status{imdn.Delivered, imdn.Displayed} {
		k := imdn.DeliveryNotification
		if s == imdn.Displayed {
			k = imdn.DisplayNotification
		}
		rcpt := receipt(t, "Xs8kLz1", k, s)
		b.send(t, rcpt)
		if rep := b.report(t); rep.Code != msrp.StatusOK {
			t.Fatalf("bob's %s notification was answered with %d", s, rep.Code)
		}
		got := a.next(t)
		if !bytes.Equal(got.Body, rcpt) {
			t.Fatalf("alice got %q", got.Body)
		}
		if n := readNotification(t, got.Body); n.Status != s || n.MessageID != "Xs8kLz1" {
			t.Fatalf("alice got %+v", n)
		}
	}
	waitFor(t, "the three deliveries to be confirmed", func() bool { return r.m.get("delivery.msrp") == 3 })
	if r.queued(t, bob) != 0 || r.queued(t, alice) != 0 || r.m.get("message.accepted") != 1 || r.m.get("message.accepted.notification") != 2 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestChatQueuedForAnAbsentRecipientWaitsForItsSession(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})

	first, second := chat(t, "m1", "one", 0), chat(t, "m2", "two", 0)
	a.send(t, first)
	a.send(t, second)
	inv := r.d.nextInvite(t)
	if inv.Recipient != bob || inv.Peer != alice || inv.Mode != store.Chat || inv.Conversation != conv {
		t.Fatalf("invitation %+v", inv)
	}
	waitFor(t, "both messages stored", func() bool { return r.queued(t, bob) == 2 })
	select {
	case inv := <-r.d.invites:
		t.Fatalf("a second invitation while the first is pending: %+v", inv)
	default:
	}

	// The SIP layer gets bob's answer and opens his leg; the stored
	// messages arrive in order.
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	if got := b.next(t); !bytes.Equal(got.Body, first) {
		t.Fatalf("first delivery %q", got.Body)
	}
	if got := b.next(t); !bytes.Equal(got.Body, second) {
		t.Fatalf("second delivery %q", got.Body)
	}
	waitFor(t, "both deliveries to be confirmed", func() bool { return r.m.get("delivery.msrp") == 2 })
}

func TestARecipientThatRefusesAMessageCausesANegativeNotification(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	b.refuse = &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}

	a.send(t, chat(t, "m1", "hi", imdn.NegativeDelivery))
	b.next(t)
	got := a.next(t)
	if n := readNotification(t, got.Body); n.Status != imdn.Failed || n.MessageID != "m1" || n.Kind != imdn.DeliveryNotification {
		t.Fatalf("alice got %+v", n)
	}
	waitFor(t, "the refusal to be counted", func() bool { return r.m.get("delivery.refused") == 1 })
	if r.queued(t, bob) != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestMessagesOnALegAreRefusedWithTheMSRPCodeOfTheirReason(t *testing.T) {
	r := newRig(t, Config{MaxMessageSize: 2048})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	for name, c := range map[string]struct {
		body []byte
		want int
	}{
		"malformed":    {[]byte("not cpim"), msrp.StatusBadRequest},
		"too large":    {chat(t, "m1", string(bytes.Repeat([]byte("x"), 2048)), 0), msrp.StatusMessageTooLarge},
		"someone else": {cpimMessage(t, cpim.Address{URI: carol}, "m2", "hi", 0), msrp.StatusForbidden},
		"unknown imdn": {receipt(t, "nope", imdn.DeliveryNotification, imdn.Delivered), msrp.StatusForbidden},
	} {
		if code := a.outcome(t, cpim.ContentType, c.body); code != c.want {
			t.Errorf("%s: %d, want %d", name, code, c.want)
		}
	}
	if code := a.outcome(t, "text/plain", []byte("hi")); code != msrp.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", code)
	}
	if r.queued(t, bob) != 0 {
		t.Fatal("a refused message was queued")
	}
}

func TestLegsNeedAUserAPeerAModeAndADirection(t *testing.T) {
	r := newRig(t, Config{})
	remote := []msrp.URI{clientURI()}
	for _, p := range []LegParams{
		{Remote: remote, Peer: bob, Mode: store.Chat, Direction: Originating},
		{Remote: remote, User: alice, Mode: store.Chat, Direction: Originating},
		{Remote: remote, User: alice, Peer: bob, Direction: Originating},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Chat},
		{User: alice, Peer: bob, Mode: store.Chat, Direction: Originating}, // OpenLeg needs the path
		{Remote: remote, User: alice, Peer: bob, Mode: store.Standalone, Direction: Terminating},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Chat, Direction: Terminating, QueueID: "q"},
		{Remote: remote, User: alice, Peer: bob, Mode: store.Standalone, Direction: Originating, QueueID: "q"},
	} {
		if _, err := r.e.OpenLeg(p); err == nil {
			t.Errorf("OpenLeg(%+v) succeeded", p)
		}
	}
	if _, err := r.e.Offer(LegParams{Remote: remote, User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating}); err == nil {
		t.Error("Offer with a remote path succeeded")
	}
}

// The race ADR 0004 leaves open: in a session rcs-as offers, the relay can
// connect before the answer has come back through the CSCFs. The offered
// leg binds at once and sends only once it has the path.
func TestARelayConnectingBeforeTheAnswerIsServed(t *testing.T) {
	r := newRig(t, Config{MSRPHost: "127.0.0.1", MSRPPort: 2855})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	a.send(t, chat(t, "m1", "for bob", 0))
	inv := r.d.nextInvite(t)
	leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	if u := leg.Local(); u.Host != "127.0.0.1" || u.Port != 2855 || len(u.SessionID) < 26 || u.Transport != "tcp" {
		t.Fatalf("Local = %v", u)
	}
	// Bob's side connects and binds before the answer arrives, and may
	// already send.
	bobURI := clientURI()
	b := r.dial(t, l, bobURI, leg.Local())
	b.send(t, chat(t, "m2", "early from bob", 0))
	if got := a.next(t); !bytes.Equal(got.Body, chat(t, "m2", "early from bob", 0)) {
		t.Fatalf("alice got %q", got.Body)
	}
	select {
	case m := <-b.got:
		t.Fatalf("delivered before the answer: %q", m.Body)
	case <-time.After(50 * time.Millisecond):
	}
	if err := leg.Answer([]msrp.URI{bobURI}); err != nil {
		t.Fatal(err)
	}
	if got := b.next(t); !bytes.Equal(got.Body, chat(t, "m1", "for bob", 0)) {
		t.Fatalf("bob got %q", got.Body)
	}
	if err := leg.Answer([]msrp.URI{bobURI}); err == nil {
		t.Fatal("answered twice")
	}
}

func TestAnOfferWithoutAnAnswerExpires(t *testing.T) {
	r := newRig(t, Config{AnswerTimeout: 10 * time.Second})
	leg, err := r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(9 * time.Second)
	select {
	case <-leg.Done():
		t.Fatal("closed before the answer timeout")
	default:
	}
	r.clock.Advance(time.Second)
	waitDone(t, leg.Done())
	if err := leg.Answer([]msrp.URI{clientURI()}); err == nil {
		t.Fatal("an expired offer was answered")
	}
	if r.m.get("leg.unanswered") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
	// An answered offer does not expire.
	leg, err = r.e.Offer(LegParams{User: bob, Peer: alice, Mode: store.Chat, Direction: Terminating})
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	if err := leg.Answer([]msrp.URI{clientURI()}); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(time.Minute)
	select {
	case <-leg.Done():
		t.Fatal("an answered leg expired")
	default:
	}
}

func waitDone(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(hangGuard):
		t.Fatal("not done")
	}
}

func TestIsComposingIsForwardedToThePeerWithoutBeingStored(t *testing.T) {
	r := newRig(t, Config{})
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	// As rcsjta sends it: in the chat session, not wrapped in CPIM.
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<isComposing xmlns="urn:ietf:params:xml:ns:im-iscomposing"><state>active</state><contenttype>text/plain</contenttype><refresh>60</refresh></isComposing>`)
	// With no leg to bob it is dropped, and still answered 200.
	if code := a.outcome(t, IsComposingType, body); code != msrp.StatusOK {
		t.Fatalf("is-composing answered %d", code)
	}
	_, b := r.connect(t, l, LegParams{User: bob, Peer: alice, Conversation: conv, Mode: store.Chat})
	if code := a.outcome(t, IsComposingType, body); code != msrp.StatusOK {
		t.Fatalf("is-composing answered %d", code)
	}
	got := b.next(t)
	if got.MediaType() != IsComposingType || !bytes.Equal(got.Body, body) {
		t.Fatalf("bob got %s %q", got.MediaType(), got.Body)
	}
	waitFor(t, "the count", func() bool { return r.m.get("iscomposing.forwarded") == 1 })
	if r.queued(t, bob) != 0 || r.m.get("iscomposing.dropped") != 1 || r.m.get("message.accepted") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
	if got := AcceptTypes(store.Chat); len(got) != 2 || got[1] != IsComposingType {
		t.Fatalf("AcceptTypes(chat) = %v", got)
	}
	// A large-mode session carries one CPIM message and nothing else.
	_, s := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Standalone})
	if code := s.outcome(t, IsComposingType, body); code != msrp.StatusUnsupportedMediaType {
		t.Fatalf("is-composing on a large-mode leg answered %d", code)
	}
}

func TestAStoreFailureOnALegIsAnsweredAsRetryable(t *testing.T) {
	r := newRigWith(t, Config{}, failingStore{store.NewMemory()}, newFakeClock())
	l := r.listen(t)
	_, a := r.connect(t, l, LegParams{User: alice, Peer: bob, Conversation: conv, Mode: store.Chat})
	if code := a.outcome(t, cpim.ContentType, chat(t, "m1", "hi", 0)); code != StatusTryAgain {
		t.Fatalf("a message rcs-as could not store was answered %d", code)
	}
}
