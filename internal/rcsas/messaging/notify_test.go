package messaging

import (
	"bytes"
	"errors"
	"strings"
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
		t.Fatalf("metrics %v", r.m)
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
	sentToBob(t, r, imdn.PositiveDelivery|imdn.NegativeDelivery|imdn.Processing|imdn.Display)
	for name, o := range map[string]Origin{
		"from the recipient":                  {Sender: bob, Recipient: alice, Mode: store.Standalone, CPIM: receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)},
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

// trustedRoutes is a configuration trusting the domain of elsewhere.
var trustedRoutes = Config{TrustedRouteDomains: []string{"Example.org"}}

func TestANotificationLeavesRcsAsOutOfItsRoute(t *testing.T) {
	r := newRig(t, trustedRoutes)
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

// A client writes IMDN-Route itself. Following it would let any subscriber
// choose where rcs-as sends a request from inside the network.
func TestOnlyATrustedRouteIsFollowed(t *testing.T) {
	for route, want := range map[string]string{
		elsewhere:                         elsewhere,
		"sips:as.ims.EXAMPLE.org:5061;lr": "sips:as.ims.EXAMPLE.org:5061;lr",
		"sip:10.0.0.9:5060":               "",
		"sip:mstore@evilexample.org":      "",
		"sip:example.org.evil.net":        "",
		"tel:+15550100005":                "",
		"http://example.org/":             "",
	} {
		r := newRig(t, trustedRoutes)
		sentToBob(t, r, imdn.PositiveDelivery)
		body := receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered, route)
		if err := r.e.Submit(t.Context(), standalone(bob, alice, body)); err != nil {
			t.Fatal(err)
		}
		d := r.d.nextPager(t)
		if !bytes.Equal(d.CPIM, body) || d.Route != want {
			t.Errorf("route %s: Route %q, want %q", route, d.Route, want)
		}
		if untrusted := r.m.get("imdn.route_untrusted"); (want == "") != (untrusted == 1) {
			t.Errorf("route %s: metrics %v", route, r.m)
		}
	}
}

func TestSIPHostsAreFoundWithoutTheRestOfTheURI(t *testing.T) {
	for uri, want := range map[string]string{
		"sip:as.example.org":                 "as.example.org",
		"SIP:Alice@AS.Example.org:5060;lr":   "as.example.org",
		"sips:[2001:db8::1]:5061":            "[2001:db8::1]",
		"sip:a@b@host.example?x=y":           "host.example",
		"<sip:host.example>":                 "",
		"sips:[2001:db8::1":                  "",
		"tel:+15550100005;phone-context=x.y": "",
	} {
		if got := sipHost(uri); got != want {
			t.Errorf("sipHost(%q) = %q, want %q", uri, got, want)
		}
	}
}

func TestANegativeNotificationKeepsOnlyTrustedRecordRoutes(t *testing.T) {
	r := newRig(t, trustedRoutes)
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
	// Each entry goes on top: the attacker's ends up first.
	for _, u := range []string{elsewhere, "sip:10.0.0.9:5060"} {
		if err := imdn.AddRecordRoute(m, cpim.Address{URI: u}); err != nil {
			t.Fatal(err)
		}
	}
	body, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.e.Submit(t.Context(), standalone(alice, bob, body)); err != nil {
		t.Fatal(err)
	}
	r.d.nextPager(t)
	d := r.d.nextPager(t)
	n, err := cpim.Parse(d.CPIM)
	if err != nil {
		t.Fatal(err)
	}
	routes := n.All(imdn.Namespace, imdn.HeaderRoute)
	if d.Recipient != alice || d.Route != elsewhere || len(routes) != 1 || routes[0].Value != "<"+elsewhere+">" {
		t.Fatalf("notification delivery %+v, routes %+v", d, routes)
	}
	if r.m.get("imdn.route_dropped") != 1 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestEachDispositionIsAcceptedOnce(t *testing.T) {
	r := newRig(t, Config{Intermediaries: []string{intermediary}})
	sentToBob(t, r, imdn.PositiveDelivery|imdn.NegativeDelivery|imdn.Display)
	delivered := receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)
	for range 3 {
		if err := r.e.Submit(t.Context(), standalone(bob, alice, delivered)); err != nil {
			t.Fatal(err)
		}
	}
	r.d.nextPager(t)
	// Another kind, or another notifier, is another notification.
	for _, o := range []Origin{
		standalone(bob, alice, receipt(t, "m1", imdn.DisplayNotification, imdn.Displayed)),
		standalone(intermediary, alice, receipt(t, "m1", imdn.DeliveryNotification, imdn.Failed)),
	} {
		if err := r.e.Submit(t.Context(), o); err != nil {
			t.Fatal(err)
		}
		r.d.nextPager(t)
	}
	waitFor(t, "the deliveries", r.idle)
	if r.m.get("imdn.duplicate") != 2 || r.m.get("message.accepted.notification") != 3 || len(r.d.pagers) != 0 {
		t.Fatalf("metrics %v, %d more deliveries", r.m, len(r.d.pagers))
	}
}

func TestANotificationThatCannotBeQueuedMayBeSentAgain(t *testing.T) {
	st := &flakyStore{Store: store.NewMemory()}
	r := newRigWith(t, Config{}, st, newFakeClock())
	sentToBob(t, r, imdn.PositiveDelivery)
	body := receipt(t, "m1", imdn.DeliveryNotification, imdn.Delivered)
	st.set("enqueue")
	if err := r.e.Submit(t.Context(), standalone(bob, alice, body)); !errors.Is(err, errStore) {
		t.Fatalf("Submit = %v", err)
	}
	st.set()
	if err := r.e.Submit(t.Context(), standalone(bob, alice, body)); err != nil {
		t.Fatalf("the retry = %v", err)
	}
	if d := r.d.nextPager(t); !d.Notification {
		t.Fatalf("delivery %+v", d)
	}
}

func TestAnOverlongMessageIDIsMalformedNotAStoreFailure(t *testing.T) {
	r := newRig(t, Config{})
	long := strings.Repeat("a", MaxMessageIDLength+1)
	if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, chat(t, long, "hi", imdn.PositiveDelivery)))); got != ReasonMalformed {
		t.Fatalf("a message: %q", got)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone(bob, alice, receipt(t, long, imdn.DeliveryNotification, imdn.Delivered)))); got != ReasonIMDNMalformed {
		t.Fatalf("a notification: %q", got)
	}
	ok := strings.Repeat("a", MaxMessageIDLength)
	if err := r.e.Submit(t.Context(), standalone(alice, bob, chat(t, ok, "hi", imdn.PositiveDelivery))); err != nil {
		t.Fatalf("the longest Message-ID: %v", err)
	}
	if got := rejected(r.e.Submit(t.Context(), standalone("sip:"+strings.Repeat("a", MaxIdentityLength)+"@x", bob, chat(t, "m", "hi", 0)))); got != ReasonMalformed {
		t.Fatalf("an overlong identity: %q", got)
	}
	if r.m.get("store.failed") != 0 {
		t.Fatalf("metrics %v", r.m)
	}
}

func TestANotificationLargerThanThePagerLimitIsRefused(t *testing.T) {
	r := newRig(t, Config{})
	sentToBob(t, r, imdn.PositiveDelivery)
	n := imdn.Notification{MessageID: "m1", DateTime: "2026-03-04T05:06:07.000Z", Kind: imdn.DeliveryNotification, Status: imdn.Delivered, Subject: strings.Repeat("s", 1400)}
	m, err := n.Message(imdn.Envelope{From: cpim.Address{URI: AnonymousURI}, To: cpim.Address{URI: AnonymousURI}, MessageID: "r1", DateTime: newFakeClock().Now()})
	if err != nil {
		t.Fatal(err)
	}
	body, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	o := standalone(bob, alice, body)
	o.Pager = false // as from an MSRP leg
	if got := rejected(r.e.Submit(t.Context(), o)); got != ReasonTooLarge {
		t.Fatalf("Submit = %q", got)
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
		t.Fatalf("metrics %v", r.m)
	}
}
