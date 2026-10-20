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

// alice is asserted by her tel URI and names herself in CPIM by a SIP
// form of it: with user=phone, or at the home domain without.
func TestACPIMFromInTheOtherFormOfTheSenderIsTheSender(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	for i, from := range []string{aliceSIP, "sip:+15550100001@" + domain} {
		if res := p.send(pagerAs(bob, cpimFrom("<"+from+">", fmt.Sprint("m", i), 0, "hi"), "<"+alice+">")); res.StatusCode != 202 {
			t.Fatalf("CPIM From %s answered %d", from, res.StatusCode)
		}
	}
}

// The code review's case on #242 (round 2): pcscf asserts a non-numeric
// SIP identity with the tel URI of its set (#208), and that is one user,
// keyed by the tel URI. A message written to the SIP identity finds its
// receipt from that user too.
func TestANonNumericSIPIdentityAndItsTelURIAreOneUser(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	aliceName := "sip:alice@" + domain
	pair := []string{"<" + aliceName + ">", "<" + alice + ">"}
	for i, pai := range [][]string{pair, {"<" + aliceName + ">"}, {"<" + alice + ">"}} {
		if res := p.send(pagerAs(bob, cpimFrom("<"+messaging.AnonymousURI+">", fmt.Sprint("m", i), 0, "hi"), pai...)); res.StatusCode != 202 {
			t.Fatalf("asserted %v: answered %d", pai, res.StatusCode)
		}
		core.next(t)
	}
	// bob writes to alice's SIP identity; her receipt comes asserted as
	// the pair.
	if res := p.send(pagerAs(aliceName, cpimFrom("<"+messaging.AnonymousURI+">", "b1", imdn.PositiveDelivery, "hi"), "<"+bob+">")); res.StatusCode != 202 {
		t.Fatalf("bob's message answered %d", res.StatusCode)
	}
	core.next(t)
	if res := p.send(pagerAs(bob, deliveredBody(t, "b1"), pair...)); res.StatusCode != 202 {
		t.Fatalf("alice's receipt answered %d", res.StatusCode)
	}
}

// The pairs pcscf asserts (#208), from QA's second report on #242, with
// the lead's rule: one SIP identity and one tel URI are one user, keyed by
// the tel URI, unless the SIP identity is a home-domain number other than
// the tel URI's. A number at another host, and a home-domain number marked
// user=ip, count as names.
func TestTheAssertedPairsPcscfMakesAreOneUser(t *testing.T) {
	for name, c := range map[string]struct {
		pai  []string
		want int
	}{
		"home sip number + tel":                           {[]string{"<sip:+15550100001@" + domain + ">", "<" + alice + ">"}, 202},
		"home sip number upper host + tel":                {[]string{"<sip:+15550100001@" + strings.ToUpper(domain) + ">", "<" + alice + ">"}, 202},
		"sips number + tel":                               {[]string{"<sips:+15550100001@" + domain + ">", "<" + alice + ">"}, 202},
		"tel first then sip":                              {[]string{"<" + alice + ">", "<sip:+15550100001@" + domain + ">"}, 202},
		"non-number sip + tel":                            {[]string{"<sip:alice@" + domain + ">", "<" + alice + ">"}, 202},
		"number sip other host + tel":                     {[]string{"<sip:+15550100001@other.example.net>", "<" + alice + ">"}, 202},
		"number at another host, user=phone, another tel": {[]string{"<sip:+15550100003@other.example.net;user=phone>", "<" + alice + ">"}, 202},
		"home number user=ip + tel":                       {[]string{"<sip:+15550100001@" + domain + ";user=ip>", "<" + alice + ">"}, 202},
		"sip + tel different numbers":                     {[]string{"<sip:+15550100001@" + domain + ">", "<" + bob + ">"}, 403},
		"two sip same user":                               {[]string{"<sip:+15550100001@" + domain + ">", "<" + aliceSIP + ">"}, 403},
		"sip + sips same user":                            {[]string{"<sip:+15550100001@" + domain + ">", "<sips:+15550100001@" + domain + ">"}, 403},
		"two tel same user":                               {[]string{"<" + alice + ">", "<tel:+1-555-010-0001>"}, 403},
		"comma list of three":                             {[]string{"<" + alice + ">, <sip:+15550100001@" + domain + ">, <" + aliceSIP + ">"}, 403},
	} {
		t.Run(name, func(t *testing.T) {
			e := &fakeEngine{}
			a := startAS(t, e, newFakeCore(t))
			res := a.dial(t).send(pagerAs(bob, cpimBody("m1", "hi"), c.pai...))
			if res.StatusCode != c.want {
				t.Fatalf("%v: %d, want %d", c.pai, res.StatusCode, c.want)
			}
			if o := e.origins(); c.want == 202 && (len(o) != 1 || o[0].Sender != alice) {
				t.Fatalf("%v: origins %+v, want alice's tel URI as the sender", c.pai, o)
			}
		})
	}
}
