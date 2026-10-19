package pii

import (
	"regexp"
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
			// The grouped rules read ASCII digits; a number in another
			// script's digits must be masked as well.
			if m := groupedInternational.FindString(asciiNumberChars(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
			if m := nationalNumberIn(asciiNumberChars(a)); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
		}
		if !strings.ContainsRune(s, ':') && !strings.ContainsFunc(s, unicode.IsDigit) && out != s {
			t.Fatalf("Redact(%q) = %q changed text with no digits or schemes", s, out)
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
