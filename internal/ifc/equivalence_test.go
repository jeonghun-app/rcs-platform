package ifc

import (
	"math/rand/v2"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
	"time"
)

// mixedAtoms reach the constructs whose reading differs between POSIX and
// Perl syntax, that stripping an outer ".*" could disturb, or that the
// parser rewrites into another shape: dots, anchors, bracket expressions,
// upper case and case pairs ("[Aa]", "[Tt][Ee][Ll]:", which the parser turns
// into folded literals), letters with more than two case variants ("k" also
// folds to the Kelvin sign), case-less punctuation, and alternatives sharing
// a prefix ("ab|aB", which the parser factors).
var mixedAtoms = []string{"0", "2", "a", "b", "A", "B", "k", "K", ".", "[ab]", "[^a]", "[Aa]", "[Bb]", "[Kk]",
	"[[:upper:]]", "[^[:lower:]]", "[^a-z]", "[Tt][Ee][Ll]:", ":", "-", ";", "/", "\\+", "(ab|aB)", "(A|a)",
	"(x-[Aa]|x-b)", "^", "$", ""}

// randomPattern builds an ERE from atoms with up to maxQuantifiers stacked
// quantifiers on each ("+?", "*?", "??", "{n}?", "**" with two), groups and
// alternation at every level.
func randomPattern(r *rand.Rand, atoms []string, depth, maxQuantifiers int) string {
	var b strings.Builder
	for n := r.IntN(4) + 1; n > 0; n-- {
		if depth > 0 && r.IntN(4) == 0 {
			b.WriteString("(" + randomPattern(r, atoms, depth-1, maxQuantifiers) + ")")
		} else {
			b.WriteString(atoms[r.IntN(len(atoms))])
		}
		for q := r.IntN(maxQuantifiers + 1); q > 0; q-- {
			b.WriteString([]string{"*", "+", "?", "{1,2}", "{2}", "{0}"}[r.IntN(6)])
		}
		if r.IntN(6) == 0 {
			b.WriteString("|")
		}
	}
	return b.String()
}

// equivalenceValues are compared with the reference: possibly empty,
// possibly invalid UTF-8, never with a newline, where Go's POSIX compiler
// reads line by line and evaluation reads as regexec does.
var equivalenceValues = []string{"", "0", "00", "000", "a", "b", "ab", "ba", "a0b", "aab", "0a0", " ", "é", "\xff", "abba00",
	"A", "AB", "aB", "Ab", "tel:", "TEL:", "Tel:x", "x-A", "x-b", "x-B", "kK", "\u212a", ";", "-:"}

// newlineValues hold newlines, on which a pattern and its padded form must
// still agree.
var newlineValues = []string{"\n", "a\nb", "\nab\n", "tel:\n", "a\n\nb"}

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
		p := randomPattern(r, mixedAtoms, 2, 2)
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
			for _, v := range append(equivalenceValues[:len(equivalenceValues):len(equivalenceValues)], newlineValues...) {
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

// TestCaseFoldingPatternsMeanWhatGoSaysIgnoringCase checks the
// case-insensitive path (Request-URI, header names). The reference is Go's
// own reading of the source with (?i), which folds before it merges
// alternatives, as REG_ICASE does; it reads Perl syntax, so the patterns have
// no stacked quantifier, where the two syntaxes differ. Values carry upper
// and lower case and the Kelvin sign.
func TestCaseFoldingPatternsMeanWhatGoSaysIgnoringCase(t *testing.T) {
	r := rand.New(rand.NewPCG(61, 7))
	want := 10000
	if raceEnabled {
		want /= 10
	}
	for checked := 0; checked < want; {
		p := randomPattern(r, mixedAtoms, 2, 1)
		// The reference applies only where Perl and POSIX syntax read the
		// pattern alike; an empty atom can still put two quantifiers side
		// by side ("K+?"), which they do not.
		ref, err := regexp.Compile("(?i:" + p + ")")
		posix, perr := syntax.Parse(p, posixFlags)
		perl, lerr := syntax.Parse(p, syntax.Perl)
		if err != nil || perr != nil || lerr != nil || !sameMeaning(posix, perl) {
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
		for _, v := range equivalenceValues {
			if got.re.MatchString(v) != ref.MatchString(v) {
				t.Fatalf("%q on %q: evaluation says %t, Go with (?i) says %t", p, v, got.re.MatchString(v), ref.MatchString(v))
			}
		}
	}
}

// TestCaseIdiomsAndFactoredAlternativesAreAccepted lists patterns whose tree
// changes shape when written out and parsed back. An ERE has no (?i), so
// "[Tt][Ee][Ll]:" is how operators ignore case; refusing it would refuse
// ordinary profiles.
func TestCaseIdiomsAndFactoredAlternativesAreAccepted(t *testing.T) {
	tests := []struct {
		pattern     string
		match, miss []string
	}{
		{"^[Tt][Ee][Ll]:", []string{"tel:+15550100001", "TEL:x", "tEl:"}, []string{"sip:tel:", "tel", "tex:"}},
		{"[Aa]|b", []string{"A", "xa", "b"}, []string{"", "B", "c"}},
		{"ab|aB", []string{"ab", "xaBy"}, []string{"AB", "a", "Ab"}},
		{"x-[Aa]|x-b", []string{"x-A", "x-a", "x-b"}, []string{"x-B", "x-", "X-a"}},
		{";ob|;oB", []string{";ob", ";oB"}, []string{";Ob", ";o"}},
		{"a|A|ab", []string{"a", "A", "ab"}, []string{"b", ""}},
		{"[Kk]", []string{"k", "K"}, []string{"x"}},
	}
	for _, tc := range tests {
		for _, mode := range []patternMode{0, patternFoldCase} {
			budget := MaxSetInstructions
			p, err := compilePattern("Content", tc.pattern, mode, &budget)
			if err != nil {
				t.Errorf("%q (mode %d) refused: %v", tc.pattern, mode, err)
				continue
			}
			for _, v := range tc.match {
				if !p.re.MatchString(v) {
					t.Errorf("%q (mode %d) does not match %q", tc.pattern, mode, v)
				}
			}
			if mode == 0 {
				for _, v := range tc.miss {
					if p.re.MatchString(v) {
						t.Errorf("%q matches %q", tc.pattern, v)
					}
				}
			}
		}
	}
}

// TestNewlinesAreReadAsPOSIXRegexecReadsThem pins what a pattern means on a
// value with a newline, which Go's POSIX flags alone would read line by
// line: "." and a negated bracket expression match a newline, and "^" and
// "$" match only at the ends of the value (IEEE 1003.1 regexec without
// REG_NEWLINE). Headers never hold a newline; a Request-URI or SDP line from
// an adapter might.
func TestNewlinesAreReadAsPOSIXRegexecReadsThem(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"a.b", "a\nb", true},
		{"^b", "a\nb", false},
		{"a$", "a\nb", false},
		{"^a.*b$", "a\nb", true},
		{"[^x]", "\n", true},
		{"a[^x]b", "a\nb", true},
		{"^$", "\n", false},
	}
	for _, tc := range tests {
		for _, src := range []string{tc.pattern, ".*" + tc.pattern + ".*", ".*(" + tc.pattern + ").*"} {
			budget := MaxSetInstructions
			p, err := compilePattern("Content", src, 0, &budget)
			if err != nil {
				t.Fatalf("%q: %v", src, err)
			}
			if got := p.re.MatchString(tc.value); got != tc.want {
				t.Errorf("%q on %q = %t, want %t", src, tc.value, got, tc.want)
			}
		}
	}
}

// A case-insensitive pattern still matches a letter that one of its
// alternatives names, however the parser merges the alternatives (POSIX
// REG_ICASE; musl agrees).
func TestCaseFoldedAlternativeOfALetterAndANegatedClassStillMatchesTheLetter(t *testing.T) {
	tp := func(c Condition) *TriggerPoint {
		return &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}}
	}
	for _, tc := range []struct{ pattern, uri string }{
		{"^(K|[^[:lower:]])$", "sip:u@K"},
		{"^(K|[^[:lower:]])$", "sip:u@k"},
		{"^([^a]|[[:upper:]])$", "sip:u@A"},
		{"^(A|[^a-z])$", "sip:u@a"},
	} {
		s := compile(t, criteria(0, tp(RequestURI(tc.pattern))))
		if !matches(t, s, req("INVITE", tc.uri), Context{}) {
			t.Errorf("RequestURI %q does not select %q", tc.pattern, tc.uri)
		}
	}
	s := compile(t, criteria(0, tp(SIPHeader{Header: "X|[^a-z]"})))
	if !matches(t, s, req("MESSAGE", impu, HeaderField{"X", "1"}), Context{}) {
		t.Errorf(`header name "X|[^a-z]" does not select header X`)
	}
}

// Bracket case pairs are the ERE idiom for "ignore case"; main accepts them.
func TestCasePairBracketsAreNotRefused(t *testing.T) {
	tp := func(c Condition) *TriggerPoint {
		return &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0}, Condition: c}}}
	}
	for _, c := range []Condition{
		SessionDescription{Line: "m", Content: "[Tt][Cc][Pp]/[Mm][Ss][Rr][Pp]"},
		RequestURI(`[Tt][Ee][Ll]:\+1`),
		SIPHeader{Header: "[Xx]-[0-9]"},
		SIPHeader{Header: "Subject", Content: "(A|a)2"},
	} {
		if _, err := Compile([]FilterCriteria{criteria(0, tp(c))}); err != nil {
			t.Errorf("%#v refused: %v", c, err)
		}
	}
	// And they select what they say.
	sdp := compile(t, criteria(0, tp(SessionDescription{Line: "m", Content: "[Tt][Cc][Pp]/[Mm][Ss][Rr][Pp]"})))
	if !matches(t, sdp, &sipRequest{method: "INVITE", uri: impu, sdp: []string{"m=message 9 tcp/MSRP *"}}, Context{}) ||
		matches(t, sdp, &sipRequest{method: "INVITE", uri: impu, sdp: []string{"m=message 9 TCP/TLS/MSRP *"}}, Context{}) {
		t.Error("[Tt][Cc][Pp]/[Mm][Ss][Rr][Pp] selects the wrong lines")
	}
}

// POSIX regcomp without REG_NEWLINE (musl agrees): "^"/"$" only at the ends of
// the value, "." and "[^…]" match a newline. Kills the DotNL, OneLine and
// ClassNL mutants.
func TestAnchorsAndNegatedClassesReadAValueWithANewlineAsOneString(t *testing.T) {
	for _, tc := range []struct {
		content, line string
		want          bool
	}{
		{"^b", "a=x\nb", false},
		{"x$", "a=x\nb", false},
		{"x[^y]b", "a=x\nb", true},
		{"x.b", "a=x\nb", true},
	} {
		s := compile(t, criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
			Condition: SessionDescription{Line: "a", Content: tc.content}}}}))
		r := &sipRequest{method: "INVITE", uri: impu, sdp: []string{tc.line}}
		if got := matches(t, s, r, Context{}); got != tc.want {
			t.Errorf("Content %q on %q: matched %t, want %t", tc.content, tc.line, got, tc.want)
		}
	}
}

// TestCompilingIsCheapForPatternsOfNegatedClasses compiles a set at the
// instruction budget built from negated classes, which Regexp.String took
// milliseconds each to write, and an oversized pattern of them, which must
// be refused before it is written out. The bound is generous: it separates
// linear work from the minutes the quadratic writer took, not this host's
// speed.
func TestCompilingIsCheapForPatternsOfNegatedClasses(t *testing.T) {
	big := strings.Repeat("[^0]", 1000)
	var cs []FilterCriteria
	for i := range 40 {
		cs = append(cs, criteria(i, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
			Condition: SIPHeader{Header: "Subject", Content: big}}}}))
	}
	start := time.Now()
	if _, err := Compile(cs); err != nil {
		t.Fatalf("set within the budget refused: %v", err)
	}
	oversized := criteria(0, &TriggerPoint{ConditionTypeCNF: true, SPTs: []SPT{{Groups: []int{0},
		Condition: SIPHeader{Header: "Subject", Content: strings.Repeat("[^0]", 4000)}}}})
	if _, err := Compile([]FilterCriteria{oversized}); err == nil {
		t.Fatal("oversized pattern accepted")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("compiling took %s", elapsed)
	}
}

// TestWriteTreeKeepsWhatPerlTreesMean covers the operators writeTree spells
// that a POSIX parse does not produce (line anchors, lazy repetition, empty
// classes) and refuses one it cannot spell, a word boundary.
func TestWriteTreeKeepsWhatPerlTreesMean(t *testing.T) {
	for _, src := range []string{`(?m:^a$)`, `a+?b`, `a{2,}?`, `[^\x00-\x{10FFFF}]`, `(?i:k)`, `\Aa\z`} {
		tree := mustParsePerl(t, src)
		var b strings.Builder
		if !writeTree(&b, tree) {
			t.Fatalf("%q not written", src)
		}
		if back := mustParsePerl(t, b.String()); !sameMeaning(back, tree) {
			t.Errorf("%q written as %q, which means something else", src, b.String())
		}
	}
	var b strings.Builder
	if writeTree(&b, mustParsePerl(t, `\ba`)) {
		t.Error(`\b written`)
	}
}

func mustParsePerl(t *testing.T, src string) *syntax.Regexp {
	t.Helper()
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	return re
}
