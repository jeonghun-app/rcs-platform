package pii

import (
	"strings"
	"testing"
)

// Test alias IDs come from .github/allowed-test-identifiers.txt: 26 lower-case
// base32 characters, as maap writes them (ADR 0009 §10), spelt so that no
// random draw is likely to produce them.
const (
	testAlias  = "aliasforthetestsonly23456a"
	testAlias2 = "secondtestaliasonly234567a"
	aliasHost  = "alias.example.net"
)

func aliasURI(id string) string { return "sip:" + id + "@" + aliasHost + ";user=rcstk" }

// URI and Identity mask the alias ID of an alias, whatever its case; base32
// reads upper and lower case alike (RFC 4648 §6), so the hint is the lower-case
// ID's.
func TestURIAndIdentityMaskTheAliasIDInEitherCase(t *testing.T) {
	upperID := "sip:" + strings.ToUpper(testAlias) + "@" + aliasHost + ";user=rcstk"
	tests := []struct {
		name, attr, in, want string
	}{
		{"URI keeps the host and parameters", "uri", aliasURI(testAlias), "sip:***6a@" + aliasHost + ";user=rcstk"},
		{"URI of an upper-case ID", "uri", upperID, "sip:***6a@" + aliasHost + ";user=rcstk"},
		{"URI written all in upper case", "uri", strings.ToUpper(aliasURI(testAlias)), "SIP:***6a@" + strings.ToUpper(aliasHost) + ";USER=RCSTK"},
		{"URI of a sips alias", "uri", "sips:" + testAlias + "@" + aliasHost, "sips:***6a@" + aliasHost},
		{"Identity masks the alias whole", "identity", aliasURI(testAlias), "***6a"},
		{"Identity of an upper-case alias", "identity", strings.ToUpper(aliasURI(testAlias)), "***6a"},
		{"Identity of a sips alias", "identity", "sips:" + strings.ToUpper(testAlias) + "@" + aliasHost, "***6a"},
		{"Identity of a bare alias ID", "identity", testAlias, "***6a"},
		{"Identity of an upper-case bare alias ID", "identity", strings.ToUpper(testAlias), "***6a"},
	}
	unkeyed, keyed := NewRedactor(nil), NewRedactor(testKey)
	attr := func(r *Redactor, kind, v string) string {
		if kind == "uri" {
			return r.URI("alias", v).Value.String()
		}
		return r.Identity("alias", v).Value.String()
	}
	var hints []string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := attr(unkeyed, tt.attr, tt.in)
			if got != tt.want {
				t.Fatalf("%s(%q)\n got %q\nwant %q", tt.attr, tt.in, got, tt.want)
			}
			k := attr(keyed, tt.attr, tt.in)
			for _, out := range []string{got, k} {
				if strings.Contains(strings.ToLower(out), testAlias) {
					t.Fatalf("%s(%q) = %q keeps the alias ID", tt.attr, tt.in, out)
				}
			}
			hints = append(hints, hintOf(t, k))
		})
	}
	for i, h := range hints {
		if h != hints[0] {
			t.Fatalf("%q has keyed hint %q, %q has %q", tests[i].in, h, tests[0].in, hints[0])
		}
	}
	if other := hintOf(t, keyed.Identity("alias", aliasURI(testAlias2)).Value.String()); other == hints[0] {
		t.Fatalf("two aliases share the keyed hint %q", other)
	}
}

// Only an alias ID is read in lower case: a value of another length or with
// a character outside base32 keeps its case in the hint, as before #714.
func TestOnlyAnAliasIDLosesItsCase(t *testing.T) {
	r := NewRedactor(nil)
	upper := strings.ToUpper(testAlias)
	for _, tt := range []struct{ in, want string }{
		{upper + "B", "***AB"},
		{"8" + upper[1:], "***6A"},
		{"sip:" + upper + "B@" + aliasHost, "***et"},
	} {
		if got := r.Identity("alias", tt.in).Value.String(); got != tt.want {
			t.Errorf("Identity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Redact masks an alias wherever a line carries it: in prose, a JSON value, a
// header, next to another alias, and with a character a log viewer hides
// inside its ID.
func TestRedactMasksAnAliasInFreeText(t *testing.T) {
	masked := "sip:***6a@" + aliasHost + ";user=rcstk"
	tests := []struct{ in, want string }{
		{"no conversation for " + aliasURI(testAlias) + " at this chatbot", "no conversation for " + masked + " at this chatbot"},
		{`{"to":"` + aliasURI(testAlias) + `"}`, `{"to":"` + masked + `"}`},
		{"To: <SIP:" + strings.ToUpper(testAlias) + "@" + aliasHost + ";user=rcstk>;tag=1", "To: <SIP:***6a@" + aliasHost + ";user=rcstk>;tag=1"},
		{aliasURI(testAlias) + "," + aliasURI(testAlias2), masked + ",sip:***7a@" + aliasHost + ";user=rcstk"},
		{"to sip:" + testAlias[:13] + "\u200b" + testAlias[13:] + "@" + aliasHost + ";user=rcstk", "to " + masked},
	}
	unkeyed, keyed := NewRedactor(nil), NewRedactor(testKey)
	for _, tt := range tests {
		if got := unkeyed.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
		got := strings.ToLower(keyed.Redact(tt.in))
		if strings.Contains(got, testAlias[:13]) || strings.Contains(got, testAlias[13:]) || strings.Contains(got, testAlias2) {
			t.Errorf("keyed Redact(%q) = %q keeps an alias ID", tt.in, got)
		}
	}
}

// Redact masks an alias ID that stands alone, as the chatbot API names a
// recipient by it (#719): between characters that are not ASCII letters or
// digits, or after a percent-escape, all in lower or all in upper case.
func TestRedactMasksAStandaloneAliasID(t *testing.T) {
	upper := strings.ToUpper(testAlias)
	tests := []struct{ name, in, want string }{
		{"in prose", "no alias " + testAlias + " at this chatbot", "no alias ***6a at this chatbot"},
		{"in upper case", "alias=" + upper, "alias=***6a"},
		{"in JSON", `{"to":"` + testAlias + `"}`, `{"to":"***6a"}`},
		{"in a URL path", "POST /v1/conversations/" + testAlias + "/messages", "POST /v1/conversations/***6a/messages"},
		{"in angle brackets", "<" + testAlias + ">", "<***6a>"},
		{"after an underscore", "conv_" + testAlias, "conv_***6a"},
		{"in a percent-encoded alias", "sip%3A" + testAlias + "%40" + aliasHost + "%3Buser%3Drcstk", "sip%3A***6a%40" + aliasHost + "%3Buser%3Drcstk"},
		{"after a lower-case percent-escape", "%2f" + upper, "%2f***6a"},
		{"two in a list", testAlias + "," + testAlias2, "***6a,***7a"},
		{"at the end of a word in another script", "別名" + testAlias, "別名***6a"},
		// Just outside the form: kept.
		{"25 characters", testAlias[:25], testAlias[:25]},
		{"27 characters", testAlias + "a", testAlias + "a"},
		{"a digit outside base32", "1" + testAlias[1:], "1" + testAlias[1:]},
		{"an 8 inside", testAlias[:10] + "8" + testAlias[11:], testAlias[:10] + "8" + testAlias[11:]},
		{"joined to a letter", "x" + testAlias, "x" + testAlias},
		{"mixed case, as a Go or metric name", "ServerTransactionsRejected", "ServerTransactionsRejected"},
		{"mixed case alias ID", "A" + testAlias[1:], "A" + testAlias[1:]},
		{"after a percent sign that escapes nothing", "%zz" + testAlias, "%zz" + testAlias},
		{"after a hex pair without a percent sign", "/3A" + testAlias, "/3A" + testAlias},
		{"a 128-bit hex ID", strings.Repeat("ab45", 8), strings.Repeat("ab45", 8)},
	}
	unkeyed, keyed := NewRedactor(nil), NewRedactor(testKey)
	want := hintOf(t, keyed.Identity("alias", aliasURI(testAlias)).Value.String())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unkeyed.Redact(tt.in); got != tt.want {
				t.Fatalf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
			if tt.in == tt.want {
				return
			}
			got := keyed.Redact(tt.in)
			if strings.Contains(strings.ToLower(got), testAlias) {
				t.Fatalf("keyed Redact(%q) = %q keeps the alias ID", tt.in, got)
			}
			if strings.Contains(tt.in, testAlias) || strings.Contains(tt.in, upper) {
				if h := hintOf(t, got); h != want {
					t.Fatalf("keyed Redact(%q) hint %q, want the alias's %q", tt.in, h, want)
				}
			}
		})
	}
}

// A mask's hint is no part of a word: the hint and the letters after it are
// never read as an alias ID (found by FuzzRedact), while "***" written in the
// input is text like any other.
func TestRedactReadsNoMaskHintAsAnAliasID(t *testing.T) {
	letters := "abcdefghijklmnopqrstuvwx" // 24, so that a 2-letter hint makes 26
	unkeyed := NewRedactor(nil)
	for _, tt := range []struct{ in, want string }{
		{testMSISDN[1:] + letters, "***01" + letters},
		{"***" + testAlias, "******6a"},
		{"*** " + testAlias, "*** ***6a"},
	} {
		if got := unkeyed.Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", tt.in, got, tt.want)
		}
	}
	in := "22222220a2222222a2222222a2 "
	got := NewRedactor(testKey).Redact(in)
	if want := NewRedactor(testKey).Redact("22222220") + in[8:]; got != want {
		t.Fatalf("keyed Redact(%q) = %q, want %q", in, got, want)
	}
}
