package pii

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzRedact checks the guarantee services rely on: whatever the input, no run
// of minRun or more digits reaches the output, keyed or not, and valid UTF-8
// stays valid.
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
		if run := longestDigitRun(out); run >= minRun {
			t.Fatalf("Redact(%q) = %q keeps a %d-digit run", s, out, run)
		}
		if utf8.ValidString(s) && !utf8.ValidString(out) {
			t.Fatalf("Redact(%q) = %q is not valid UTF-8", s, out)
		}
		for _, a := range []string{r.URI("k", s).Value.String(), r.Identity("k", s).Value.String()} {
			if run := longestDigitRun(a); run >= minRun {
				t.Fatalf("attribute for %q = %q keeps a %d-digit run", s, a, run)
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
