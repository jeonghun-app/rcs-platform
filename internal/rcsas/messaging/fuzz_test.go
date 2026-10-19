package messaging

import (
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"strings"
	"testing"
)

func FuzzParseConversationHeaders(f *testing.F) {
	f.Add("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "c0ffee01", "")
	f.Add(" a ", "\tb", "c")
	f.Add("a b", "c\r\n", "\xff")
	f.Fuzz(func(t *testing.T, conv, contrib, reply string) {
		c, err := ParseConversationHeaders(conv, contrib, reply)
		if err != nil {
			return
		}
		for _, v := range []string{c.ID, c.Contribution, c.InReplyTo} {
			if len(v) > MaxIDLength || strings.ContainsAny(v, " \t\r\n;,\"<>") {
				t.Fatalf("accepted %q", v)
			}
		}
		if c == (Conversation{}) {
			// Only a request without any of the headers has none.
			if strings.Trim(conv+contrib+reply, " \t") != "" {
				t.Fatalf("%q, %q, %q gave no conversation", conv, contrib, reply)
			}
			return
		}
		if c.ID == "" || c.Contribution == "" {
			t.Fatalf("accepted %+v", c)
		}
		// Parsing what was accepted gives it back.
		if again, err := ParseConversationHeaders(c.ID, c.Contribution, c.InReplyTo); err != nil || again != c {
			t.Fatalf("reparse %+v, %v", again, err)
		}
	})
}

func FuzzParseMessage(f *testing.F) {
	f.Add(chat(f, "m1", "hi", 3))
	f.Add(receipt(f, "m1", "delivery-notification", "delivered", self))
	f.Add([]byte("From: <tel:+15550100001>\n\nContent-Type: text/plain\n\nhi"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseMessage(data, 4096)
		if err != nil {
			if rejected(err) == "" {
				t.Fatalf("an error that is not a rejection: %v", err)
			}
			return
		}
		if string(m.Raw) != string(data) || (m.Notification != nil && m.Request.Dispositions != 0) {
			t.Fatalf("message %+v", m)
		}
		checkAccepted(t, m)
	})
}

func FuzzEscapeDisplayName(f *testing.F) {
	f.Add("Alice")
	f.Add("a\r\nb\"c\\")
	f.Fuzz(func(t *testing.T, name string) {
		got := EscapeDisplayName(name)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || r == '"' || (0x80 <= r && r < 0xa0) || r == 0x2028 || r == 0x2029 || r == 0x061c || (0x200b <= r && r <= 0x200f) || (0x202a <= r && r <= 0x202e) || (0x2066 <= r && r <= 0x2069) {
				t.Fatalf("EscapeDisplayName(%q) = %q", name, got)
			}
		}
	})
}

func FuzzGroupView(f *testing.F) {
	f.Add(chat(f, "m1", "hi", 3), "Alice")
	f.Add([]byte("From: \"A\" <sip:a@x>\r\nTo: <sip:b@x>\r\nTo: <sip:c@x>\r\n\r\nContent-Type: text/plain\r\n\r\nhi"), "")
	for _, extra := range secondSender {
		f.Add(withHeaders(extra, ""), "A \"name\"")
	}
	f.Add(withHeaders("", "From: <"+carol+">\r\n"), "")
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		c, err := cpim.Limits{MaxSize: 4096}.Parse(data)
		if err != nil {
			return
		}
		// What participants get, as any receiver reads it, is from the
		// author under the roster's name to the group, and names nobody
		// else as either.
		// A roster name is valid UTF-8 (the group package checks).
		author := cpim.Address{Name: strings.ToValidUTF8(name, "\ufffd"), URI: alice}
		if out, err := groupView(c, author, groupURI); err == nil {
			if from := readAddresses(t, out, author, "<"+groupURI+">"); string(from.Body) != string(c.Body) {
				t.Fatalf("body %q, want %q", from.Body, c.Body)
			}
		}
		// A notification is From the notifier, To the author.
		if out, err := groupView(c, cpim.Address{URI: bob}, alice); err == nil {
			readAddresses(t, out, cpim.Address{URI: bob}, "<"+alice+">")
		}
	})
}
