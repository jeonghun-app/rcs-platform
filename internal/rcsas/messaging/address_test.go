package messaging

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// looseAddress is how a receiver that compares header names loosely reads
// one: in any case, after any namespace prefix, with surrounding space
// ignored. It is the test's own reading, kept apart from addressHeader.
func looseAddress(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	switch name {
	case "from", "to":
		return name
	}
	return ""
}

// readAddresses checks body as receivers read it. Parsed with the CPIM
// parser and its namespace resolution, it has exactly one From, from, and
// exactly one To, whose value is to; read loosely, no other message or
// content header could be taken for either. It returns the parsed body.
func readAddresses(t testing.TB, body []byte, from cpim.Address, to string) *cpim.Message {
	t.Helper()
	c, err := cpim.Parse(body)
	if err != nil {
		t.Fatalf("%v\n%q", err, body)
	}
	froms, tos := c.All(cpim.CoreNamespace, cpim.HeaderFrom), c.All(cpim.CoreNamespace, cpim.HeaderTo)
	if len(froms) != 1 || len(tos) != 1 {
		t.Fatalf("%d From and %d To headers in the core namespace\n%q", len(froms), len(tos), body)
	}
	if got, err := cpim.ParseAddress(froms[0].Value); err != nil || got != from {
		t.Fatalf("From %+v, %v, want %+v", got, err, from)
	}
	if tos[0].Value != to {
		t.Fatalf("To %q, want %q", tos[0].Value, to)
	}
	n := map[string]int{}
	for _, h := range c.Headers {
		n[looseAddress(h.Name)]++
	}
	for _, f := range c.ContentHeaders {
		if looseAddress(f.Name) != "" {
			t.Fatalf("content header %q\n%q", f.Name, body)
		}
	}
	if n["from"] != 1 || n["to"] != 1 {
		t.Fatalf("read loosely, %d From and %d To headers\n%q", n["from"], n["to"], body)
	}
	return c
}

// secondSender are messages from the anonymous URI, which both paths
// accept as From, that carry another header a receiver could take for
// their From or To. Each parses as CPIM.
var secondSender = map[string]string{
	"a lower-case from":              "from: <" + carol + ">\r\n",
	"an upper-case FROM":             "FROM: <" + carol + ">\r\n",
	"a second From":                  "From: <" + carol + ">\r\n",
	"a second From without a space":  "From:<" + carol + ">\r\n",
	"a second From with wide spaces": "From:\t  <" + carol + ">  \r\n",
	"a prefix bound to the core":     "NS: x <" + cpim.CoreNamespace + ">\r\nx.From: <" + carol + ">\r\n",
	"the core URN in upper case":     "NS: x <URN:IETF:PARAMS:CPIM-HEADERS:>\r\nx.From: <" + carol + ">\r\n",
	"another default namespace":      "NS: <urn:example:other>\r\nFrom: <" + carol + ">\r\n",
	"an unbound-looking prefix":      "NS: y <urn:example:other>\r\ny.from: <" + carol + ">\r\n",
	"a lower-case to":                "to: <" + carol + ">\r\n",
	"a second To":                    "To: <" + carol + ">\r\n",
	"a prefixed To":                  "NS: x <" + cpim.CoreNamespace + ">\r\nx.To: <" + carol + ">\r\n",
}

func withHeaders(extra, content string) []byte {
	return []byte("From: <" + AnonymousURI + ">\r\nTo: <" + AnonymousURI + ">\r\n" + extra +
		"DateTime: 2026-03-04T05:06:07Z\r\n\r\nContent-Type: text/plain\r\n" + content + "\r\nhi")
}

// The 1-to-1 path forwards a message as it came (RFC 3862 §2.2), so it
// refuses one that a receiver could read as coming from, or going to,
// someone other than the From and To the engine checked.
func TestAOneToOneMessageNamesItsSenderOnce(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	cases := map[string][]byte{"a content header From": withHeaders("", "From: <"+carol+">\r\n")}
	for name, extra := range secondSender {
		cases[name] = withHeaders(extra, "")
	}
	for name, body := range cases {
		if _, err := cpim.Parse(body); err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		for _, mode := range []store.Mode{store.Chat, store.Standalone} {
			o := Origin{Sender: alice, Recipient: bob, Conversation: conv, Mode: mode, CPIM: content.BodyOf(body)}
			if got := rejected(r.e.Submit(t.Context(), o)); got != ReasonMalformed {
				t.Errorf("%s (%v): %q", name, mode, got)
			}
		}
	}
	// Folded or spaced-out names do not even parse.
	for _, extra := range []string{" From: <" + carol + ">\r\n", "From : <" + carol + ">\r\n"} {
		if got := rejected(r.e.Submit(t.Context(), standalone(alice, bob, withHeaders(extra, "")))); got != ReasonMalformed {
			t.Errorf("%q: %q", extra, got)
		}
	}
	if r.store.(*store.Memory).Len(bob) != 0 || len(r.d.pagers) != 0 {
		t.Fatal("a refused message was queued")
	}
	// What the path accepts goes out as it came, and reads the same way.
	body := withHeaders("", "")
	if err := r.e.Submit(t.Context(), standalone(alice, bob, body)); err != nil {
		t.Fatal(err)
	}
	d := r.d.nextPager(t)
	if string(d.CPIM.Bytes()) != string(body) {
		t.Fatalf("delivered %q", d.CPIM)
	}
	readAddresses(t, d.CPIM.Bytes(), cpim.Address{URI: AnonymousURI}, "<"+AnonymousURI+">")
}

// A group's participants read the author rcs-as checked, under the name the
// roster gives it, from every message: a message with a second sender is
// refused, and the header block groupView writes has one From and one To
// even for what ParseMessage would refuse.
func TestAGroupMessageNamesItsAuthorOnce(t *testing.T) {
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	r.e.SetGroupHandler(members{all: []string{alice, bob}, names: map[string]string{alice: "Alice"}})
	for name, extra := range secondSender {
		body := withHeaders(extra, "")
		if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(alice, body))); got != ReasonMalformed {
			t.Errorf("%s: %q", name, got)
		}
		c, err := cpim.Parse(body)
		if err != nil {
			t.Fatal(err)
		}
		out, err := groupView(c, cpim.Address{Name: "Alice", URI: alice}, groupURI)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := readAddresses(t, out, cpim.Address{Name: "Alice", URI: alice}, "<"+groupURI+">")
		// Every other header keeps its place and its namespace.
		var others []cpim.Header
		for _, h := range c.Headers {
			if looseAddress(h.Name) == "" {
				others = append(others, h)
			}
		}
		want, _ := c.Get(cpim.CoreNamespace, cpim.HeaderDateTime)
		if dt, _ := got.Get(cpim.CoreNamespace, cpim.HeaderDateTime); dt != want || !slices.Equal(got.Headers[2:], others) {
			t.Errorf("%s: DateTime %v, headers %v", name, dt, got.Headers)
		}
		// A notification is To the author, whatever its notifier wrote.
		out, err = groupView(c, cpim.Address{URI: bob}, alice)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		readAddresses(t, out, cpim.Address{URI: bob}, "<"+alice+">")
	}
	c, err := cpim.Parse(withHeaders("", "From: <"+carol+">\r\nto: <"+carol+">\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := groupView(c, cpim.Address{URI: alice}, groupURI)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAddresses(t, out, cpim.Address{URI: alice}, "<"+groupURI+">"); got.ContentType() != "text/plain" {
		t.Fatalf("content headers %v", got.ContentHeaders)
	}
}

// The name in a group message's From is the roster's, whatever the
// author's client wrote there.
func TestTheRosterNamesTheAuthorOfAGroupMessage(t *testing.T) {
	r := newRig(t, Config{})
	r.e.SetGroupHandler(members{all: []string{alice, bob, carol}, names: map[string]string{alice: "Alice"}})
	for _, c := range []struct {
		sender, want string
	}{{alice, "Alice"}, {carol, ""}} {
		body := cpimMessage(t, cpim.Address{Name: "Bob", URI: c.sender}, "m-"+c.sender, "hi", 0)
		if err := r.e.SubmitGroup(t.Context(), groupFrom(c.sender, body)); err != nil {
			t.Fatal(err)
		}
	}
	ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 2 {
		t.Fatalf("bob's queue %+v, %v", ms, err)
	}
	readAddresses(t, ms[0].CPIM.Bytes(), cpim.Address{Name: "Alice", URI: alice}, "<"+groupURI+">")
	readAddresses(t, ms[1].CPIM.Bytes(), cpim.Address{URI: carol}, "<"+groupURI+">")
}

// The fuzz targets check the same: what ParseMessage accepts names one
// sender and at most one recipient however it is read.
func checkAccepted(t *testing.T, m *Message) {
	t.Helper()
	n := map[string]int{}
	for _, h := range m.CPIM.Headers {
		n[looseAddress(h.Name)]++
	}
	for _, f := range m.CPIM.ContentHeaders {
		if looseAddress(f.Name) != "" {
			t.Fatalf("accepted a content header %q", f.Name)
		}
	}
	froms, tos := m.CPIM.All(cpim.CoreNamespace, cpim.HeaderFrom), m.CPIM.All(cpim.CoreNamespace, cpim.HeaderTo)
	if n["from"] != 1 || len(froms) != 1 || n["to"] > 1 || len(tos) != n["to"] {
		t.Fatalf("accepted %d/%d From and %d/%d To headers", n["from"], len(froms), n["to"], len(tos))
	}
	if a, err := cpim.ParseAddress(froms[0].Value); err != nil || a != m.From {
		t.Fatalf("From %+v, %v, read %+v", a, err, m.From)
	}
}

// The code review's reproduction (PR #118, round 3): a client writes its
// provisioned public URI in the From as it was given, ;user=phone or an
// upper-case host included. The group path names the sender in canonical
// form and must still take it; so must the 1-to-1 path, and a
// recipient-uri. Someone else's address is still refused.
func TestASendersOwnAddressInAnotherFormIsItsOwn(t *testing.T) {
	const asserted = "sip:+15550100002@ims.example.net;user=phone"
	r := newRig(t, Config{SenderRate: Rate{PerMinute: -1}})
	r.e.SetGroupHandler(members{all: []string{alice, "sip:+15550100002@ims.example.net"}})
	for i, from := range []string{asserted, "sip:+15550100002@IMS.example.net", "sip:+15550100002@ims.example.net"} {
		body := cpimMessage(t, cpim.Address{URI: from}, fmt.Sprint("m", i), "hi", 0)
		if err := r.e.SubmitGroup(t.Context(), groupFrom(asserted, body)); err != nil {
			t.Errorf("in the group, From %s: %v", from, err)
		}
		if err := r.e.Submit(t.Context(), Origin{Sender: asserted, Recipient: alice, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(body)}); err != nil {
			t.Errorf("1-to-1, From %s: %v", from, err)
		}
	}
	other := cpimMessage(t, cpim.Address{URI: "sip:+15550100003@ims.example.net;user=phone"}, "x", "hi", 0)
	if got := rejected(r.e.SubmitGroup(t.Context(), groupFrom(asserted, other))); got != ReasonFromMismatch {
		t.Fatalf("someone else's From in the group: %q", got)
	}
	if got := rejected(r.e.Submit(t.Context(), Origin{Sender: asserted, Recipient: alice, Conversation: conv, Mode: store.Chat, CPIM: content.BodyOf(other)})); got != ReasonFromMismatch {
		t.Fatalf("someone else's From 1-to-1: %q", got)
	}
	for uri, want := range map[string]bool{
		asserted: true, "sip:+15550100002@IMS.example.net": true, AnonymousURI: true,
		"sip:+15550100003@ims.example.net": false, "not a URI": false,
	} {
		if got := namesSender(uri, "sip:+15550100002@ims.example.net", nil, ""); got != want {
			t.Errorf("namesSender(%q) = %v", uri, got)
		}
	}
	// One number, written as a tel URI or a SIP one, is one user (UserOf,
	// QA on #242): with user=phone anywhere, without it at the home domain.
	for uri, want := range map[string]bool{
		"tel:+15550100002": true, "tel:+1-555-010-0002": true, "sip:+15550100002@other.example.net;user=phone": true,
		"sip:+15550100002@other.example.net": false, "tel:+15550100003": false,
	} {
		if got := namesSender(uri, "sip:+15550100002@ims.example.net", nil, "ims.example.net"); got != want {
			t.Errorf("namesSender(%q) at the home domain = %v", uri, got)
		}
	}
	if !namesSender("sip:+15550100002@ims.example.net;user=phone", "tel:+15550100002", nil, "") {
		t.Error("a tel sender does not name itself as sip:...;user=phone")
	}
}

// A group message's sender is named as UserOf names it at the home domain,
// the form the group keys its participants by: alice asserted by her SIP
// URI at the home domain is the author tel:+…, which the GroupHandler
// knows, and her copies say so; her From may still be her SIP URI.
func TestAGroupSenderIsNamedAsTheGroupNamesIt(t *testing.T) {
	const home = "ims.example.net"
	r := newRig(t, Config{HomeDomain: home})
	r.e.SetGroupHandler(members{all: []string{alice, bob}})
	sipAlice := "sip:+15550100001@" + home
	body := cpimMessage(t, cpim.Address{URI: sipAlice}, "m1", "hi", 0)
	if err := r.e.SubmitGroup(t.Context(), groupFrom(sipAlice, body)); err != nil {
		t.Fatal(err)
	}
	ms, err := r.store.Pending(t.Context(), bob, "", r.clock.Now(), 10)
	if err != nil || len(ms) != 1 || ms[0].Author != alice {
		t.Fatalf("bob's queue %+v, %v", ms, err)
	}
	readAddresses(t, ms[0].CPIM.Bytes(), cpim.Address{URI: alice}, "<"+groupURI+">")
}
