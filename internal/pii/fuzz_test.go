package pii

import (
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzRedact checks the guarantee services rely on: whatever the input, keyed
// or not, the output has no run of minRun or more decimal digits of any
// script and no number written in groups, in any script's digits, that
// Redact promises to mask, and valid UTF-8 stays valid. The grouped
// rules are restated here independently of numberAt: a national number is any
// group of two or more digits starting with 0, not preceded by a letter or
// digit, followed by eight digits in total. The one documented exception is
// checked separately in nationalNumberIn, so a mistake in it cannot hide behind
// the same mistake in the pattern.
var (
	groupedInternational = regexp.MustCompile(`\+[0-9](?:[ ().-]{0,2}[0-9]){7,}`)
	groupedNational      = regexp.MustCompile(`^0[0-9](?:[ ().-]{0,2}[0-9]){6,}`)
)

// nationalNumberIn returns a national number left in s, if any. A match counts
// unless what comes before it makes it part of a word: a letter or digit, or a
// '.' or '-' that itself follows a digit (an address, version or date).
func nationalNumberIn(s string) string {
	for p := range len(s) {
		if s[p] == '0' && !partOfWord(s, p) {
			if m := groupedNational.FindString(s[p:]); m != "" {
				return m
			}
		}
	}
	return ""
}

func partOfWord(s string, p int) bool {
	if p == 0 {
		return false
	}
	c := s[p-1]
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
		return true
	}
	return (c == '.' || c == '-') && p >= 2 && '0' <= s[p-2] && s[p-2] <= '9'
}

func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		"",
		"imsi=" + testIMSI,
		testIMSI + "@" + testDomain,
		"From: <sip:" + testMSISDN + "@" + testDomain + ">;tag=1",
		"tel:+1-555-010-0001;phone-context=example.com",
		"sip:sip:sip:alice@",
		"SIPS:" + testMSISDN + ":pw@host",
		"urn:gsma:imei:00101000-000003-1;svn=42",
		"1234567.1234567",
		"tel:12345678tel:12345678",
		"+15550100sip:@1234567890",
		"メッセージ 15550100002",
		"+1 (555) 010-0001",
		"tel:+1 555 010 0001",
		"msisdn=010-0000-0001",
		"(07700) 900-001",
		"2026-10-19 10.0.255.255",
		"+1 555   0100001",
		"0.0.0.0 0 1 2 3 4 5 6 7",
		"Tel.010-0000-0001 H.P.010 0000 0001",
		"bytes=0-1048575 [0.25 0.5 0.75]",
		"From: <im:alice.smith@" + testDomain + ">",
		"pres:" + testMSISDN + "@" + testDomain,
		"msisdn=１５５５０１００００１ ２０２６年",
		"imsi ٠٠١٠١٠٠٠٠٠٠٠٠٠١ 1555０１００\xff００1",
		"tel:+15550100001-２３４５６７",
		"0000000 0０１0000",
		"urn:gsma:imei:00101000-１７６１４８-１",
		"０１０-００００-０００１ +１ ５５５ ０１００ ００１",
		"call ０１０－００００－０００１ ＋１\u3000５５５\u3000０１０\u3000０００１ （０７７００）９００．００１",
		"+1\u00a0555\u202f010\u20090001 ０１０ー００００\u2212０００１ 010\u2013 0000\u2014 0001 名前\u3000（注）\u300010 tel:（０３）１２３４",
		`From: <im:"bob smith"@` + testDomain + `> pres:"a \"" im:"x`,
		`im:"` + testMSISDN + `"@` + testDomain,
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	unkeyed := NewRedactor(nil)
	keyed := NewRedactor(testKey)
	f.Fuzz(func(t *testing.T, s string, withKey bool) {
		r := unkeyed
		if withKey {
			r = keyed
		}
		out := r.Redact(s)
		if utf8.ValidString(s) && !utf8.ValidString(out) {
			t.Fatalf("Redact(%q) = %q is not valid UTF-8", s, out)
		}
		for _, a := range []string{out, r.URI("k", s).Value.String(), r.Identity("k", s).Value.String()} {
			if run := longestDigitRun(a); run >= minRun {
				t.Fatalf("redacting %q gave %q, which keeps a %d-digit run", s, a, run)
			}
			// The grouped rules read ASCII; a number in another script's
			// digits, spaces or dashes must be masked as well. asciiForm
			// reads every such character as ASCII wherever it is, which
			// is stricter than Redact's reading of a number.
			if m := groupedInternational.FindString(asciiForm(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
			if m := nationalNumberIn(asciiForm(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
		}
		if !strings.ContainsRune(s, ':') && !strings.ContainsFunc(s, unicode.IsDigit) && out != s {
			t.Fatalf("Redact(%q) = %q changed text with no digits or schemes", s, out)
		}
	})
}

// FuzzRedactAnyForm is the differential check of
// TestRedactReadsANumberInAnyFormAsInASCII on any ASCII text: the ASCII
// characters of s, with every digit and number character replaced at random
// (from seed) by a form from another script, are redacted as the ASCII text
// is, after the forms left in the output are read back as ASCII. Texts with a
// sip, sips, im or pres scheme are left to the test: Redact masks such a user
// whole whatever its characters, and when it is not a number written as
// asciiNumberChars reads one, a form left in it changes the hint, or a space
// outside ASCII does not end it.
func FuzzRedactAnyForm(f *testing.F) {
	for _, s := range []string{
		"call +1 (555) 010-0001 or 010-0000-0001.",
		"tel:(03)1234-5678;phone-context=example.net tel: 0000000",
		"urn:gsma:imei:35-209900-176148-1 (1) 10-20 1 - 2",
		"+0 (000) 000 0000 tel:1.736-.4-.5)) (1)-89553",
	} {
		f.Add(s, uint64(0))
		f.Add(s, uint64(1))
	}
	unkeyed, keyed := NewRedactor(nil), NewRedactor(testKey)
	f.Fuzz(func(t *testing.T, s string, seed uint64) {
		var b strings.Builder
		for i := range len(s) {
			if s[i] < utf8.RuneSelf {
				b.WriteByte(s[i])
			}
		}
		ascii := b.String()
		if !strings.ContainsAny(ascii, "0123456789") {
			return
		}
		for i := range len(ascii) {
			if n := schemeLen(ascii[i:]); n > 0 && hasUserinfo(ascii[i:i+n]) {
				return
			}
		}
		wide := anyFormOf(rand.New(rand.NewPCG(seed, 0)), ascii)
		for _, r := range []*Redactor{unkeyed, keyed} {
			if want, got := r.Redact(ascii), r.Redact(wide); asciiForm(got) != want {
				t.Fatalf("Redact(%q) = %q\nRedact(%q) = %q", ascii, want, wide, got)
			}
		}
	})
}

// longestDigitRun counts decimal digits of every script, as Redact promises
// to mask runs of any of them.
func longestDigitRun(s string) int {
	longest, run := 0, 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

// TruncateIPsIn leaves no whole IPv4 address standing alone in text, is
// idempotent, and leaves text without an address character as it was.
func FuzzTruncateIPsIn(f *testing.F) {
	for _, s := range []string{
		"http: TLS handshake error from 203.0.113.5:51234: EOF",
		"error reading preface from client [2001:db8::1]:443: EOF",
		"10.0.0.0/8 192.0.2.7/32 1.2.3.4.5 go1.2.3.4 ::ffff:1.2.3.4",
		"a:b:c::1 ::: [::1] [::1%25lo]:5 1.02.003.4:00",
		"peer 203.0.113.250 closed, 255.255.255.254.",
	} {
		f.Add(s)
	}
	quad := regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)
	f.Fuzz(func(t *testing.T, s string) {
		got := TruncateIPsIn(s)
		if again := TruncateIPsIn(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, got, again)
		}
		if !strings.ContainsAny(s, ".:[") && got != s {
			t.Fatalf("%q changed to %q", s, got)
		}
		// The oracle reads addresses its own way, not with the code under
		// test: four parts of up to three digits, each at most 255, with
		// no letter, digit, "_", non-ASCII byte or dot around them.
		word := func(c byte) bool {
			return c == '_' || c == '.' || c >= 0x80 || unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))
		}
		for _, m := range quad.FindAllStringIndex(got, -1) {
			if m[0] > 0 && word(got[m[0]-1]) || m[1] < len(got) && word(got[m[1]]) {
				continue // part of a longer token, not an address alone
			}
			valid := true
			for _, part := range strings.Split(got[m[0]:m[1]], ".") {
				if n, err := strconv.Atoi(part); err != nil || n > 255 {
					valid = false
				}
			}
			if valid && (m[1] == len(got) || got[m[1]] != '/') {
				t.Fatalf("%q left %q whole in %q", s, got[m[0]:m[1]], got)
			}
		}
	})
}
