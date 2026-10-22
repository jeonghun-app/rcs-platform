package cpim

import (
	"bytes"
	"encoding/json"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzParse checks that Parse never panics, that every rejection carries a
// Reason, that Marshal refuses a parsed message only for its values, and that
// whatever Marshal accepts is a fixed point: it parses back to the same
// message, with no deviations, and marshals to the same bytes. Byte-identity
// with canonical input is TestParseThenMarshalReproducesMessageHeadersExactly.
func FuzzParse(f *testing.F) {
	f.Add(chatMessage)
	f.Add(crlf("From: \"A \\\"B\\\"\" <" + alice + ">\nSubject:;lang=fr;x=\"a b\" Bonjour\nNS: <urn:example:wily>\nrunner-trap: set\n\ncontent-type: multipart/mixed;\n boundary=b\n\n--b--"))
	f.Add(crlf("NS: x <urn:ietf:params:imdn>\nx.Message-ID: 1\nRequire: x.Message-ID\n\nContent-Type: text/plain\n\n"))
	f.Add([]byte("From:<" + alice + ">  \nSubject:\nDateTime: 2016-12-31t23:59:60z\n\nContent-Type: text/plain\n\nHi"))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			if ReasonOf(err) == "" {
				t.Fatalf("rejection without a reason: %v", err)
			}
			return
		}
		out, err := m.Marshal()
		if err != nil {
			// Parse already vouched for everything but the values, so a
			// parsed message can fail to marshal only because of a value
			// sending refuses: an empty one or an invalid core header.
			if ReasonOf(err) != ReasonValue {
				t.Fatalf("Marshal of a parsed message failed for another reason: %v", err)
			}
			return
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse of a marshalled message failed: %v\n%q", err, out)
		}
		if again.Deviations() != 0 {
			t.Fatalf("Marshal output deviates from the canonical layout: %v\n%q", again.Deviations(), out)
		}
		tolerated := *m
		tolerated.deviations = 0
		if !sameMessage(again, &tolerated) {
			t.Fatalf("round trip changed the message:\n%#v\n%#v", m, again)
		}
		if twice, err := again.Marshal(); err != nil || !bytes.Equal(twice, out) {
			t.Fatalf("Marshal is not stable:\n%q\n%q, %v", out, twice, err)
		}
	})
}

// FuzzParseAddress checks that an accepted address formats back to a value
// that parses to the same address, and that its log form keeps no run of
// eight digits, as internal/pii promises of every log line.
func FuzzParseAddress(f *testing.F) {
	f.Add("<" + alice + ">")
	f.Add("Alice B <" + alice + ">")
	f.Add(`"Smith, \"Al\" é" <` + alice + ">")
	f.Add("<im:15550100001@[2001:db8:5:6::7]?subject=15550100002>")
	f.Add("<x15550100001:15550100002@10.20.30.40>")
	f.Fuzz(func(t *testing.T, v string) {
		a, err := ParseAddress(v)
		if err != nil {
			return
		}
		back, err := ParseAddress(a.String())
		if err != nil || back != a {
			t.Fatalf("ParseAddress(%q) = %+v, then %q parsed to %+v, %v", v, a, a.String(), back, err)
		}
		// Read back, as JSON escapes digits of its own ("\u0026").
		var logged map[string]string
		if j, err := json.Marshal(a); err != nil || json.Unmarshal(j, &logged) != nil {
			t.Fatalf("ParseAddress(%q) logs %s, %v", v, j, err)
		}
		run := 0
		for _, c := range logged["uri"] {
			if run = run + 1; !unicode.IsDigit(c) {
				run = 0
			}
			if run >= 8 {
				t.Fatalf("ParseAddress(%q) logs %s", v, logged)
			}
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
