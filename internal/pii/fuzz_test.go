package pii

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzRedact checks the guarantee services rely on: whatever the input, keyed or
// not, the output has no run of minRun or more digits and no number written in
// groups that Redact promises to mask, and valid UTF-8 stays valid. The grouped
// rules are restated as regular expressions here, independently of numberAt.
var (
	groupedInternational = regexp.MustCompile(`\+[0-9](?:[ ().-]{0,2}[0-9]){7,}`)
	groupedNational      = regexp.MustCompile(`(?:^|[^0-9A-Za-z.-])0(?:[ ().-]{0,2}[0-9]){7,}`)
)

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
			if m := groupedInternational.FindString(a); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
			if m := groupedNational.FindString(a); m != "" {
				t.Fatalf("redacting %q gave %q, which keeps the number %q", s, a, m)
			}
		}
		if !strings.ContainsAny(s, "0123456789:") && out != s {
			t.Fatalf("Redact(%q) = %q changed text with no digits or schemes", s, out)
		}
	})
}

func longestDigitRun(s string) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}
