package ifc

import (
	"strings"
	"testing"
)

func TestCompileRefusesWhatGoReadsDifferentlyFromAPOSIXERE(t *testing.T) {
	tests := []struct {
		pattern, construct string
	}{
		// IEEE 1003.1 §9.3.5: a backslash in a bracket expression is
		// literal, so "[\.]com" matches "\com"; Go's parser reads an escape.
		{`[\.]com`, `a backslash inside a bracket expression`},
		{`[a\]]`, `a backslash inside a bracket expression`},
		{`[^\-]`, `a backslash inside a bracket expression`},
		{`[[:digit:]\\]`, `a backslash inside a bracket expression`},
		{`(a|[\d])`, `a backslash inside a bracket expression`},
		// §9.4.2: a backslash before an ordinary character is undefined in
		// an ERE; Go reads these as Perl or C escapes or refuses them with
		// a message that does not say why.
		{`\x41`, `the escape \x`},
		{`\x{41}`, `the escape \x`},
		{`a\d+`, `the escape \d`},
		{`\w`, `the escape \w`},
		{`\s`, `the escape \s`},
		{`\S`, `the escape \S`},
		{`\pL`, `the escape \p`},
		{`\p{Greek}`, `the escape \p`},
		{`\bconf`, `the escape \b`},
		{`\Aa\z`, `the escape \A`},
		{`\Q.\E`, `the escape \Q`},
		{`\n`, `the escape \n`},
		{`\t`, `the escape \t`},
		{`\101`, `the escape \1`},
		{`\012`, `the escape \0`},
		{`(a)\1`, `the escape \1`},
		// §9.3.5: Go has no collating symbols or equivalence classes and
		// reads "[[.a.]]" as the class [.[a] followed by "]".
		{`[[.a.]]`, `the collating symbol [. .]`},
		{`[[=a=]]`, `the equivalence class [= =]`},
		{`x[^[.-.]]`, `the collating symbol [. .]`},
		// §9.4.6 leaves "{" not followed by a digit undefined; glibc reads
		// "{,3}" as {0,3}, Go as the text "{,3}".
		{`a{,3}`, `the interval {,n}`},
		{`^x{,}$`, `the interval {,n}`},
		// Not a POSIX class name; Go reads it as the negated class.
		{`[[:^alpha:]]`, `the negated class [:^ :]`},
		// Only special characters may be escaped (§9.4.2): glibc and musl
		// read \< and \> as word boundaries, glibc \` and \' as the ends of
		// the value; Go reads all of these as the characters themselves.
		{`\<a`, `the escape \<`},
		{`a\>`, `the escape \>`},
		{"\\`a", "the escape \\`"},
		{`a\'`, `the escape \'`},
		{`a\-b`, `the escape \-`},
		{`user\@host`, `the escape \@`},
		{`a\/b`, `the escape \/`},
		{`tel\:`, `the escape \:`},
		{`\"x\"`, `the escape \"`},
		{"x\\\xc3\xa9", "a backslash before a character that is not special"},
		// A "]" first in the list, after an optional "^", is a member, so
		// the backslash after it is still inside the brackets.
		{`[]\.]`, `a backslash inside a bracket expression`},
		{`[^]\.]`, `a backslash inside a bracket expression`},
		{`[a[:^digit:]]`, `the negated class [:^ :]`},
	}
	for _, tc := range tests {
		for _, c := range []Condition{RequestURI(tc.pattern), SIPHeader{Header: tc.pattern}, SIPHeader{Header: "From", Content: tc.pattern}, SessionDescription{Line: "m", Content: tc.pattern}} {
			_, err := Compile([]FilterCriteria{criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}})})
			if err == nil || !strings.Contains(err.Error(), tc.construct) {
				t.Errorf("%q in %T: %v, want a refusal naming %s", tc.pattern, c, err, tc.construct)
			}
		}
	}
}

func TestCompileKeepsEscapedSpecialCharactersAndBracketsWithoutBackslashes(t *testing.T) {
	for pattern, value := range map[string]string{
		`conf\.example\.com`:         "sip:conf.example.com",
		`\+1555`:                     "tel:+15550100001",
		`\\`:                         `a\b`,
		`[.]com`:                     ".com",
		`[]a]`:                       "]",
		`[^]a]`:                      "b",
		`[[:digit:]]+`:               "42",
		`[a-z[]`:                     "[",
		`x\[\.a\.\]`:                 "x[.a.]",
		`\(\)\*\?\{\}\|\^\$\[\]\.\+`: "()*?{}|^$[].+",
		`a\{,3\}`:                    "a{,3}",
		`a{0,3}b`:                    "aab",
		`[{,]`:                       ",",
	} {
		budget := MaxSetInstructions
		p, err := compilePattern("Content", pattern, 0, &budget)
		if err != nil {
			t.Errorf("%q refused: %v", pattern, err)
			continue
		}
		if !p.re.MatchString(value) {
			t.Errorf("%q does not match %q", pattern, value)
		}
	}
}

func TestUnclosedBracketExpressionsAreStillRefusedAsInvalid(t *testing.T) {
	for _, pattern := range []string{`[a`, `x[`, `[[`, `[^]`, `[[:alpha:`, `[]`} {
		budget := MaxSetInstructions
		_, err := compilePattern("Content", pattern, 0, &budget)
		if err == nil || !strings.Contains(err.Error(), "is not a POSIX extended regular expression") {
			t.Errorf("%q: %v", pattern, err)
		}
	}
}

// Compile takes profiles of up to the provisioning API's 256 KiB, so the scan
// must stay linear: a "[:" with no ":]" after it is searched for once, not
// once per "[:". A quadratic scan would run for many minutes on this input
// and fail by the test timeout; a linear one takes milliseconds.
func TestTheDepartureScanIsLinear(t *testing.T) {
	for _, in := range []string{
		"[" + strings.Repeat("[:", 2<<20) + "a]",
		strings.Repeat("[[:", 1<<20),
		strings.Repeat("[[:alpha:]", 1<<19) + "]",
	} {
		if got := ereDeparture(in); got != "" {
			t.Fatalf("departure %q in a pattern without one", got)
		}
	}
}
