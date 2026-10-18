package cpim

import (
	"bytes"
	"reflect"
	"testing"
	"unicode/utf8"
)

// FuzzParse checks that Parse never panics and that whatever it accepts
// survives Marshal: the same message comes back and the message headers are
// byte-identical, as RFC 3862 §2.2 requires of anything that relays them.
func FuzzParse(f *testing.F) {
	f.Add(chatMessage)
	f.Add(crlf("From: \"A \\\"B\\\"\" <" + alice + ">\nSubject:;lang=fr;x=\"a b\" Bonjour\nNS: <urn:example:wily>\nrunner-trap: set\n\ncontent-type: multipart/mixed;\n boundary=b\n\n--b--"))
	f.Add(crlf("NS: x <urn:ietf:params:imdn>\nx.Message-ID: 1\nRequire: x.Message-ID\n\nContent-Type: text/plain\n\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		out, err := m.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed message failed: %v", err)
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse of a marshalled message failed: %v\n%q", err, out)
		}
		if !reflect.DeepEqual(again, m) {
			t.Fatalf("round trip changed the message:\n%#v\n%#v", m, again)
		}
		if len(m.Headers) == 0 {
			return
		}
		// With at least one header, the first empty line ends the headers.
		headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
		if !bytes.Equal(out[:headerEnd], data[:headerEnd]) {
			t.Fatalf("message headers changed:\n%q\n%q", data[:headerEnd], out[:headerEnd])
		}
	})
}

// FuzzParseAddress checks that an accepted address formats back to a value
// that parses to the same address.
func FuzzParseAddress(f *testing.F) {
	f.Add("<" + alice + ">")
	f.Add("Alice B <" + alice + ">")
	f.Add(`"Smith, \"Al\" é" <` + alice + ">")
	f.Fuzz(func(t *testing.T, v string) {
		a, err := ParseAddress(v)
		if err != nil {
			return
		}
		back, err := ParseAddress(a.String())
		if err != nil || back != a {
			t.Fatalf("ParseAddress(%q) = %+v, then %q parsed to %+v, %v", v, a, a.String(), back, err)
		}
	})
}

// FuzzUnescape checks that Unescape never panics and that Escape output
// always decodes to the original string.
func FuzzUnescape(f *testing.F) {
	f.Add(`😀 \\ \q \u12`)
	f.Add("tab\tnewline\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = Unescape(s)
		if !utf8.ValidString(s) {
			return
		}
		if got := Unescape(Escape(s)); got != s {
			t.Fatalf("Unescape(Escape(%q)) = %q", s, got)
		}
	})
}
