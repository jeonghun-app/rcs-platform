package messaging

import (
	"bytes"
	"testing"

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
		t.Fatalf("metrics %v", r.m.n)
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
		t.Fatalf("metrics %v", r.m.n)
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

func TestLegsNeedAUserAPeerAndAMode(t *testing.T) {
	r := newRig(t, Config{})
	for _, p := range []LegParams{
		{Peer: bob, Mode: store.Chat},
		{User: alice, Mode: store.Chat},
		{User: alice, Peer: bob},
		{User: alice, Peer: bob, Mode: store.Chat}, // no remote path
	} {
		if _, err := r.e.OpenLeg(p); err == nil {
			t.Errorf("OpenLeg(%+v) succeeded", p)
		}
	}
}

func TestALegKeepsTheOfferedURI(t *testing.T) {
	r := newRig(t, Config{MSRPHost: "10.0.0.7", MSRPPort: 2855})
	u, err := r.e.LocalURI()
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "10.0.0.7" || u.Port != 2855 || len(u.SessionID) < 26 || u.Transport != "tcp" {
		t.Fatalf("LocalURI = %v", u)
	}
	remote := msrp.URI{Host: "10.0.0.9", Port: 2856, SessionID: "relay1", Transport: "tcp"}
	leg, err := r.e.OpenLeg(LegParams{Local: u, Remote: []msrp.URI{remote}, User: bob, Peer: alice, Mode: store.Chat})
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	if !leg.Local().Equal(u) {
		t.Fatalf("Local = %v, want %v", leg.Local(), u)
	}
	if _, err := r.e.OpenLeg(LegParams{Local: u, Remote: []msrp.URI{remote}, User: bob, Peer: alice, Mode: store.Chat}); err == nil {
		t.Fatal("a second leg took the same URI")
	}
}
