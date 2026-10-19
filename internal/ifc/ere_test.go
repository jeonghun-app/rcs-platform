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

func TestCompileKeepsEscapedPunctuationAndBracketsWithoutBackslashes(t *testing.T) {
	for pattern, value := range map[string]string{
		`conf\.example\.com`: "sip:conf.example.com",
		`\+1555`:             "tel:+15550100001",
		`a\-b\@c\/d\:e`:      "a-b@c/d:e",
		`\\`:                 `a\b`,
		`[.]com`:             ".com",
		`[]a]`:               "]",
		`[^]a]`:              "b",
		`[[:digit:]]+`:       "42",
		`[a-z[]`:             "[",
		`x\[\.a\.\]`:         "x[.a.]",
		`\(\)\*\?\{\}\|\^\$`: "()*?{}|^$",
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
