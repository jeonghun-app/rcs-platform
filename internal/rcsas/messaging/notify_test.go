package messaging

import (
	"bytes"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// sentToBob has alice send bob message m1 asking for d, which bob's
// client then answers.
func sentToBob(t *testing.T, r *rig, d imdn.Disposition) {
	t.Helper()
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, "m1", "hi", d))); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
}

func TestForgedNotificationsAreRefused(t *testing.T) {
	r := newRig(t, Config{Intermediaries: []string{intermediary}})
	sentToBob(t, r, imdn.PositiveDelivery|imdn.NegativeDelivery)
	for name, c := range map[string]struct {
		o    Origin
		want Reason
	}{
		"about a message alice never sent": {
			standalone(bob, alice, receipt(t, "m9", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNUnknown},
		"from someone the message did not go to": {
			standalone(carol, alice, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNForged},
		"sent to someone other than the sender": {
			standalone(bob, carol, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNUnknown},
		"of a kind nobody asked for": {
			standalone(bob, alice, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)), ReasonIMDNNotRequested},
		"claiming delivery on behalf of the recipient": {
			standalone(intermediary, alice, receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)), ReasonIMDNForged},
		"naming another sender in CPIM": {
			Origin{Sender: carol, Recipient: alice, Mode: store.Standalone, CPIM: forgedFrom(t, bob, "m1")}, ReasonFromMismatch},
	} {
		if got := rejected(r.e.Submit(t.Context(), c.o)); got != c.want {
			t.Errorf("a notification %s: %q, want %q", name, got, c.want)
		}
	}
	if r.queued(t, alice) != 0 || r.queued(t, carol) != 0 {
		t.Fatal("a forged notification was queued")
	}
	if r.m.get("message.rejected.imdn_forged") != 2 || r.m.get("message.rejected.imdn_unknown") != 2 {
		t.Fatalf("metrics %v", r.m.n)
	}
}

// forgedFrom is a notification whose CPIM From names from.
func forgedFrom(t *testing.T, from, id string) []byte {
	t.Helper()
	n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: imdn.DeliveryNotification, Status: imdn.Delivered}
	m, err := n.Message(imdn.Envelope{From: cpim.Address{URI: from}, To: cpim.Address{URI: alice}, MessageID: "x" + id, DateTime: newFakeClock().Now()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGenuineNotificationsReachTheSender(t *testing.T) {
	r := newRig(t, Config{Intermediaries: []string{intermediary}})
	sentToBob(t, r, imdn.PositiveDelivery|imdn.NegativeDelivery|imdn.Processing)
	for name, o := range map[string]Origin{
		"from the recipient":                  {Sender: bob, Recipient: alice, Mode: store.Standalone, CPIM: receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)},
		"from the recipient's other identity": {Sender: bob, Identities: []string{"sip:bob@ims.example.net"}, Recipient: alice, Mode: store.Standalone, CPIM: forgedFrom(t, "sip:bob@ims.example.net", "m1")},
		"of failure from an intermediary":     {Sender: intermediary, Recipient: alice, Mode: store.Standalone, CPIM: receipt(t, "m1", imdn.DeliveryNotification, imdn.Failed)},
		"of processing from an intermediary":  {Sender: intermediary, Recipient: alice, Mode: store.Standalone, CPIM: receipt(t, "m1", imdn.ProcessingNotification, imdn.Stored)},
	} {
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Errorf("a notification %s: %v", name, err)
			continue
		}
		if d := r.d.nextPager(t); d.Recipient != alice || !d.Notification || !bytes.Equal(d.CPIM, o.CPIM) {
			t.Errorf("a notification %s was delivered as %+v", name, d)
		}
	}
}

func TestANotificationLeavesRcsAsOutOfItsRoute(t *testing.T) {
	r := newRig(t, Config{})
	sentToBob(t, r, imdn.PositiveDelivery)
	body := receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered, self, elsewhere)
	if err := r.e.Submit(t.Context(), standalone(bob, alice, body)); err != nil {
		t.Fatal(err)
	}
	d := r.d.nextPager(t)
	m, err := cpim.Parse(d.CPIM)
	if err != nil {
		t.Fatal(err)
	}
	routes := m.All(imdn.Namespace, imdn.HeaderRoute)
	if len(routes) != 1 || routes[0].Value != "<"+elsewhere+">" || d.Route != elsewhere {
		t.Fatalf("routes %+v, Route %q", routes, d.Route)
	}
	if n := readNotification(t, d.CPIM); n.MessageID != "m1" || n.Status != imdn.Delivered {
		t.Fatalf("notification %+v", n)
	}
}

func TestANotificationRoutedElsewhereIsForwardedAsItIs(t *testing.T) {
	r := newRig(t, Config{})
	sentToBob(t, r, imdn.PositiveDelivery)
	body := receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered, elsewhere)
	if err := r.e.Submit(t.Context(), standalone(bob, alice, body)); err != nil {
		t.Fatal(err)
	}
	if d := r.d.nextPager(t); !bytes.Equal(d.CPIM, body) || d.Route != elsewhere {
		t.Fatalf("delivery %+v", d)
	}
}

func TestANegativeNotificationFollowsTheRecordRoute(t *testing.T) {
	r := newRig(t, Config{})
	r.d.onPager(func(d Delivery) error {
		if d.Recipient == bob {
			return ErrUndeliverable
		}
		return nil
	})
	m, err := cpim.Parse(chat(t, "m1", "hi", imdn.NegativeDelivery))
	if err != nil {
		t.Fatal(err)
	}
	if err := imdn.AddRecordRoute(m, cpim.Address{URI: elsewhere}); err != nil {
		t.Fatal(err)
	}
	body, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, body)); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	if d := r.d.nextPager(t); d.Recipient != alice || d.Route != elsewhere {
		t.Fatalf("notification delivery %+v", d)
	}
}

func TestAResendKeepsItsRecordAndAReusedMessageIDIsRefused(t *testing.T) {
	r := newRig(t, Config{})
	msg := chat(t, "m1", "hi", imdn.PositiveDelivery)
	for range 2 {
		if err := r.e.Submit(t.Context(), standalone(alice, bob, msg)); err != nil {
			t.Fatal(err)
		}
		r.d.nextPager(t)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, carol, msg))); got != ReasonMessageIDReused {
		t.Fatalf("the same Message-ID to carol: %q", got)
	}
	if r.m.get("message.resent") != 1 {
		t.Fatalf("metrics %v", r.m.n)
	}
}
