package ifc

import (
	"errors"
	"strings"
	"testing"
)

func TestAWholePatternMatchesTheWholeValueWithRegardToCase(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{`[a-z]+`, "abc", true},
		{`[a-z]+`, "Abc", false},
		{`abc`, "ABC", false},
		{`[[:lower:]]+`, "aBc", false},
		{`abc`, "xabc", false},
		{`abc`, "abcx", false},
		{`abc`, "abc\n", false},
		// Anchoring holds around an alternation, which "^a|b$" would not.
		{`a|b`, "ab", false},
		{`a|b`, "b", true},
		{`a|`, "", true},
		// Read as an ERE, not as Perl: (0+)?, which matches the empty value.
		{`0+?`, "", true},
		{`[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})?`, "my-bot.pub", true},
		{`[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})?`, "my-bot.pub.x", false},
	}
	for _, tc := range tests {
		w, err := CompileWholePattern("pattern", tc.pattern)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		if got, err := w.Match(tc.value); err != nil || got != tc.want {
			t.Errorf("%q against %q = %t, %v; want %t", tc.pattern, tc.value, got, err, tc.want)
		}
	}
}

func TestAWholePatternFollowsThePackagesPatternRules(t *testing.T) {
	for _, source := range []string{
		`[\.]com`,              // read differently from a POSIX ERE
		`(?i)abc`,              // Perl syntax
		`a{,3}`,                // an interval without its lower bound
		`[ab]{1000}[cd]{1000}`, // more than MaxPatternInstructions
		strings.Repeat("a", MaxPatternBytes+1),
	} {
		if _, err := CompileWholePattern("pattern", source); err == nil {
			t.Errorf("%.20q compiled", source)
		} else if !strings.HasPrefix(err.Error(), "pattern ") {
			t.Errorf("%.20q: the error %q does not name the pattern first", source, err)
		}
	}
}

func TestAWholePatternMatchOverTheWorkBudgetIsAnError(t *testing.T) {
	w, err := CompileWholePattern("pattern", `[ab]{100}c`)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", DefaultMaxWork/w.p.insts+1)
	got, err := w.Match(long)
	var le *LimitError
	if got || !errors.As(err, &le) || le.Limit != "MaxWork" {
		t.Fatalf("Match = %t, %v; want a *LimitError for MaxWork", got, err)
	}
	if _, err := w.Match(long[:len(long)/2]); err != nil {
		t.Fatalf("half the value: %v", err)
	}
}
