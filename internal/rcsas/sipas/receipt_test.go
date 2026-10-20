package sipas

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
)

// The QA reproductions on #242: the core asserts a user's SIP and tel
// identities together (#208), and every form of them, in the
// P-Asserted-Identity, the CPIM From or the Request-URI of a receipt, is
// one user. Each was refused with 403 when the forms were keys of their
// own.

// cpimFrom is a standalone message from from, asking for disposition d.
func cpimFrom(from, id string, d imdn.Disposition, text string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: <%s>\r\n", from, messaging.AnonymousURI)
	fmt.Fprintf(&b, "NS: imdn <%s>\r\nimdn.Message-ID: %s\r\nDateTime: 2026-03-04T05:06:07.000Z\r\n", imdn.Namespace, id)
	if d != 0 {
		fmt.Fprintf(&b, "imdn.Disposition-Notification: %s\r\n", d)
	}
	fmt.Fprintf(&b, "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", text)
	return b.String()
}

// deliveredBody is the delivery notification about message id, as rcsjta
// writes it.
func deliveredBody(t *testing.T, id string) string {
	t.Helper()
	n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: imdn.DeliveryNotification, Status: imdn.Delivered}
	m, err := n.Message(imdn.Envelope{
		From: cpim.Address{URI: messaging.AnonymousURI}, To: cpim.Address{URI: messaging.AnonymousURI},
		MessageID: "r" + id, DateTime: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pagerAs is a MESSAGE to uri asserted as pai, one header field each.
func pagerAs(uri, body string, pai ...string) msg {
	m := msg{method: "MESSAGE", uri: uri, body: body, fields: []string{"Content-Type: message/cpim"}}
	for _, p := range pai {
		m.fields = append(m.fields, "P-Asserted-Identity: "+p)
	}
	return m
}

// alice is asserted in both forms and names herself by her number; bob's
// client sends its receipt there, to her CPIM From (RFC 5438 §7.1.1.1).
func TestAReceiptToTheSecondAssertedIdentityFindsItsMessage(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	m := pagerAs(bob, cpimFrom("<"+alice+">", "m1", imdn.PositiveDelivery, "hi"), "<sip:+15550100001@"+domain+">", "<"+alice+">")
	if res := p.send(m); res.StatusCode != 202 {
		t.Fatalf("alice's message answered %d", res.StatusCode)
	}
	core.next(t)
	if res := p.send(pagerAs(alice, deliveredBody(t, "m1"), "<"+bob+">")); res.StatusCode != 202 {
		t.Fatalf("bob's receipt answered %d", res.StatusCode)
	}
}

// alice writes to bob's number; bob is asserted with his SIP identity
// first.
func TestAReceiptFromARecipientAssertedInSIPFormFindsItsMessage(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	if res := p.send(pagerAs(bob, cpimFrom("<"+messaging.AnonymousURI+">", "m1", imdn.PositiveDelivery, "hi"), "<"+alice+">")); res.StatusCode != 202 {
		t.Fatalf("alice's message answered %d", res.StatusCode)
	}
	core.next(t)
	res := p.send(pagerAs(alice, deliveredBody(t, "m1"), "<sip:+15550100002@"+domain+">", "<"+bob+">"))
	if res.StatusCode != 202 {
		t.Fatalf("bob's receipt answered %d", res.StatusCode)
	}
}

// alice is asserted by her tel URI and names herself in CPIM by its SIP
// form with user=phone.
func TestACPIMFromInTheOtherFormOfTheSenderIsTheSender(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	if res := a.dial(t).send(pagerAs(bob, cpimFrom("<"+aliceSIP+">", "m1", 0, "hi"), "<"+alice+">")); res.StatusCode != 202 {
		t.Fatalf("answered %d", res.StatusCode)
	}
}
