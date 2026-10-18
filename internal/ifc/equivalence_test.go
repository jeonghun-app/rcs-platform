package ifc

import (
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

// randomPattern builds an ERE from a small grammar that reaches the
// constructs whose reading differs between POSIX and Perl syntax or that
// stripping an outer ".*" could disturb: stacked quantifiers ("+?", "*?",
// "??", "{n}?", "**"), alternation at every level, anchors inside groups,
// bracket expressions and dots.
func randomPattern(r *rand.Rand, depth int) string {
	atoms := []string{"0", "a", "b", ".", "[ab]", "[^a]", "^", "$", ""}
	var b strings.Builder
	for n := r.IntN(4) + 1; n > 0; n-- {
		if depth > 0 && r.IntN(4) == 0 {
			b.WriteString("(" + randomPattern(r, depth-1) + ")")
		} else {
			b.WriteString(atoms[r.IntN(len(atoms))])
		}
		for q := r.IntN(3); q > 0; q-- {
			b.WriteString([]string{"*", "+", "?", "{1,2}", "{2}", "{0}"}[r.IntN(6)])
		}
		if r.IntN(6) == 0 {
			b.WriteString("|")
		}
	}
	return b.String()
}

// equivalenceValues are what evaluation can present: no newline, possibly
// empty, possibly invalid UTF-8.
var equivalenceValues = []string{"", "0", "00", "000", "a", "b", "ab", "ba", "a0b", "aab", "0a0", " ", "é", "\xff", "abba00"}

// TestPatternsMeanWhatPOSIXSaysWithAndWithoutAnOuterDotStar compiles 40 000
// generated patterns the way evaluation does and compares, on every value,
// with Go's POSIX compiler as the reference reading of Annex F:
//
//   - the pattern P itself;
//   - ".*" + P + ".*" as a string, whose meaning is the reference's for that
//     whole string (alternation may bind differently from P);
//   - ".*(" + P + ").*", which an unanchored search must treat exactly as P.
//
// The second and third go through the outer ".*" removal; the first through
// the plain path. All three must agree with the reference.
func TestPatternsMeanWhatPOSIXSaysWithAndWithoutAnOuterDotStar(t *testing.T) {
	r := rand.New(rand.NewPCG(61, 41))
	want := 40000
	if raceEnabled {
		want /= 10
	}
	checked, failures, skipped := 0, 0, 0
	for checked < want && failures < 10 {
		p := randomPattern(r, 2)
		if _, err := syntax.Parse(p, syntax.POSIX); err != nil {
			continue
		}
		checked++
		for _, src := range []string{p, ".*" + p + ".*", ".*(" + p + ").*"} {
			budget := MaxSetInstructions
			got, err := compilePattern("Content", src, 0, &budget)
			if err != nil {
				// Only the size limits may refuse an ERE; any other
				// refusal would leave an operator's pattern unusable.
				if !strings.Contains(err.Error(), "instructions") {
					t.Errorf("%q refused: %v", src, err)
					failures++
				}
				skipped++
				continue
			}
			ref := regexp.MustCompilePOSIX(src)
			for _, v := range equivalenceValues {
				if got.re.MatchString(v) != ref.MatchString(v) {
					t.Errorf("%q on %q: evaluation says %t, POSIX says %t", src, v, got.re.MatchString(v), ref.MatchString(v))
					failures++
				}
			}
		}
		// Wrapping in a group and padding never changes an unanchored match.
		budget := MaxSetInstructions
		plain, err1 := compilePattern("Content", p, 0, &budget)
		padded, err2 := compilePattern("Content", ".*("+p+").*", 0, &budget)
		if err1 == nil && err2 == nil {
			for _, v := range equivalenceValues {
				if plain.re.MatchString(v) != padded.re.MatchString(v) {
					t.Errorf("%q and .*(%s).* disagree on %q", p, p, v)
					failures++
				}
			}
		}
	}
	if checked < want {
		t.Fatalf("stopped after %d patterns", checked)
	}
	// The grammar keeps patterns small; if most were refused for size the
	// test would prove little.
	if skipped > checked/100 {
		t.Errorf("%d of %d patterns were over the size limits", skipped, checked)
	}
}

// TestCaseFoldingPatternsMeanWhatPOSIXSaysIgnoringCase checks the
// case-insensitive path (Request-URI, header names) on generated patterns:
// a value matches exactly when the reference matches it or its lower- or
// upper-case form for patterns written in lower case.
func TestCaseFoldingPatternsMeanWhatPOSIXSaysIgnoringCase(t *testing.T) {
	r := rand.New(rand.NewPCG(61, 7))
	for checked := 0; checked < 5000; {
		p := randomPattern(r, 2)
		if _, err := syntax.Parse(p, syntax.POSIX); err != nil {
			continue
		}
		checked++
		budget := MaxSetInstructions
		got, err := compilePattern("RequestURI", p, patternFoldCase, &budget)
		if err != nil {
			if !strings.Contains(err.Error(), "instructions") {
				t.Fatalf("%q refused: %v", p, err)
			}
			continue
		}
		ref := regexp.MustCompilePOSIX(p)
		for _, v := range equivalenceValues {
			// The grammar's letters are all lower case, so an upper-case
			// value matches exactly when its lower-case form does.
			if up := strings.ToUpper(v); got.re.MatchString(up) != ref.MatchString(strings.ToLower(up)) {
				t.Fatalf("%q on %q: evaluation says %t, POSIX on lower case says %t", p, up, got.re.MatchString(up), ref.MatchString(strings.ToLower(up)))
			}
		}
	}
}
