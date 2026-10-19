package ifc

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync/atomic"
	"unicode"
)

// Request is the view of a SIP request that service point triggers examine.
// The S-CSCF implements it over its SIP message type; the package stays free
// of a SIP dependency.
type Request interface {
	// Method is the request method, such as "INVITE".
	Method() string
	// RequestURI is the Request-URI as it appears in the request line.
	RequestURI() string
	// HeaderFields returns every header value of the request in order, one
	// entry per value: a header whose values form a comma-separated list
	// contributes one entry per element, because TS 29.228 Annex F matches
	// each value separately. Names are in their full form ("From", not
	// "f"), so that patterns need not list compact forms.
	HeaderFields() []HeaderField
	// SDPLines returns the lines of the request's session description, if
	// any, such as "m=message 9 TCP/MSRP *", without line endings.
	SDPLines() []string
}

// Limits on what evaluation examines. Matching a pattern costs about its
// program size times the length of the value it runs over, so a profile
// cannot make Compile hold an unbounded program, and a request cannot make an
// evaluation examine unbounded input or do unbounded work:
//
//   - A value longer than its limit, or beyond the bytes of its kind that one
//     evaluation examines, cannot be examined (lengths are counted before
//     white space is normalised); [Set.OversizedValues] counts it.
//   - Each match is charged against the evaluation's work budget
//     ([Limits.MaxWork]): one unit a byte of the value for a header name
//     that is a plain token, which is compared directly; four units a byte
//     for a pattern that is a plain literal (after a leading and trailing
//     ".*" are dropped), which is found with a substring search; and
//     instructions × bytes otherwise.
//     [Set.ExhaustedEvaluations] counts evaluations the budget could not
//     pay for.
//
// Either way the evaluation fails with a [*LimitError] rather than treating
// the condition as false: a false condition could let a padded request
// bypass an application server, or reach one it should not. The S-CSCF
// refuses such a request.
const (
	// MaxPatternInstructions bounds the compiled program of one pattern. A
	// pattern a person writes compiles to tens of instructions; counted
	// repetition ("{n}") is what multiplies the size.
	MaxPatternInstructions = 2000
	// MaxSetInstructions bounds the programs of one [Set] together, which is
	// what an S-CSCF holds for each registration.
	MaxSetInstructions = 50000
	// MaxHeaderLength bounds a header name or value that is matched.
	MaxHeaderLength = 8 << 10
	// MaxRequestURILength bounds the Request-URI that is matched.
	MaxRequestURILength = 2 << 10
	// MaxSDPLineLength bounds an SDP line that is matched.
	MaxSDPLineLength = 1 << 10
	// MaxHeaderBytes bounds the header names and values one evaluation
	// examines together, twice the 16 KiB of headers a SIP parser accepts
	// by default.
	MaxHeaderBytes = 32 << 10
	// MaxSDPBytes bounds the SDP lines one evaluation examines together;
	// an offer for MSRP chat or file transfer is well under 2 KiB.
	MaxSDPBytes = 16 << 10
	// DefaultMaxWork is the work budget of one evaluation, in units of one
	// instruction over one byte. The costliest patterns measured, short
	// counted repetitions such as "[ab]{100}c" over 3 KB values, ran at 12
	// to 27 ns a unit on a heavily loaded shared host (load average 56 to
	// 125), so spending the whole budget took up to about 25 ms of one core
	// there, and less on an idle one. 24 ordinary RCS criteria over a chat
	// INVITE or a REGISTER with a 2 KB Contact spend well under half of it;
	// an S-CSCF with larger profiles raises the budget with
	// [CompileWithLimits].
	DefaultMaxWork = 1_000_000
)

// ErrEvaluationLimit is wrapped by every [*LimitError].
var ErrEvaluationLimit = errors.New("ifc: request exceeds an evaluation limit")

// LimitError reports that an evaluation could not examine everything its
// criteria needed. Limit names the first limit reached, such as
// "MaxSDPBytes" or "MaxWork".
type LimitError struct {
	Limit string
}

func (e *LimitError) Error() string { return "ifc: request exceeds the evaluation limit " + e.Limit }

// Unwrap returns ErrEvaluationLimit.
func (e *LimitError) Unwrap() error { return ErrEvaluationLimit }

// Limits configures [CompileWithLimits]. Zero fields take the defaults.
type Limits struct {
	// MaxWork is the work budget of one evaluation; zero means
	// DefaultMaxWork.
	MaxWork int
}

// HeaderField is one header value of a [Request].
type HeaderField struct {
	Name  string
	Value string
}

// Context is what the S-CSCF knows about a request besides its content.
type Context struct {
	Case SessionCase
	// Unregistered says the served user is not registered, which selects
	// the criteria of the unregistered part of the profile. The
	// TerminatingUnregistered and OriginatingUnregistered cases imply it.
	Unregistered bool
	// RegistrationType is the kind of REGISTER being evaluated. When nil, a
	// Method "REGISTER" trigger matches every REGISTER, as TS 29.228 B.2.3
	// says for an S-CSCF without RegistrationType support.
	RegistrationType *RegistrationType
}

func (c Context) registered() bool {
	return !c.Unregistered && c.Case != TerminatingUnregistered && c.Case != OriginatingUnregistered
}

// Set is a compiled, priority-ordered list of filter criteria. Evaluation
// reads only the set's compiled form, which nothing changes after Compile, so
// one set can serve every request of a registration concurrently. The
// criteria that Match and Next return share their trigger points with the
// ones passed to Compile; treat them as read-only.
type Set struct {
	criteria  []compiledCriteria
	maxWork   int
	oversized atomic.Uint64
	exhausted atomic.Uint64
}

type compiledCriteria struct {
	fc      FilterCriteria
	trigger *compiledTrigger // nil: always matches
}

type compiledTrigger struct {
	cnf  bool
	spts []compiledSPT
	// members lists, for each distinct group number, the indexes of the
	// SPTs in it, so that evaluation is linear in the group memberships.
	members [][]int
}

type compiledSPT struct {
	negated bool
	kind    conditionKind
	// method or session case, for those kinds
	method  string
	regs    []RegistrationType
	session SessionCase
	// patterns: Request-URI; header name and value; SDP type and value. A
	// value pattern without a program matches any value.
	name, value pattern
}

type conditionKind uint8

const (
	kindRequestURI conditionKind = iota
	kindMethod
	kindHeader
	kindSessionCase
	kindSessionDescription
)

// Compile checks criteria (as Subscription.Marshal would), compiles their
// patterns and orders them by priority. It fails when two criteria share a
// priority, which TS 29.228 B.2.2 forbids and which would leave their order
// to chance, or when a pattern is not a POSIX extended regular expression.
// Errors name the criterion by priority and never quote a pattern, which may
// hold a subscriber identity.
func Compile(criteria []FilterCriteria) (*Set, error) {
	return CompileWithLimits(criteria, Limits{})
}

// CompileWithLimits is Compile with a work budget other than the default.
func CompileWithLimits(criteria []FilterCriteria, lim Limits) (*Set, error) {
	r := &reader{}
	for i := range criteria {
		r.validateCriteria(fmt.Sprintf("InitialFilterCriteria[%d]", i+1), &criteria[i])
	}
	if r.err != nil {
		return nil, r.err
	}
	s := &Set{criteria: make([]compiledCriteria, 0, len(criteria)), maxWork: lim.MaxWork}
	if s.maxWork <= 0 {
		s.maxWork = DefaultMaxWork
	}
	budget := MaxSetInstructions
	for _, fc := range criteria {
		c := compiledCriteria{fc: fc}
		if fc.TriggerPoint != nil {
			t, err := compileTrigger(fc.TriggerPoint, &budget)
			if err != nil {
				return nil, fmt.Errorf("ifc: filter criteria with priority %d: %w", fc.Priority, err)
			}
			c.trigger = t
		}
		s.criteria = append(s.criteria, c)
	}
	slices.SortFunc(s.criteria, func(a, b compiledCriteria) int { return cmp.Compare(a.fc.Priority, b.fc.Priority) })
	for i := 1; i < len(s.criteria); i++ {
		if s.criteria[i].fc.Priority == s.criteria[i-1].fc.Priority {
			return nil, fmt.Errorf("ifc: two filter criteria have priority %d", s.criteria[i].fc.Priority)
		}
	}
	return s, nil
}

func compileTrigger(tp *TriggerPoint, budget *int) (*compiledTrigger, error) {
	t := &compiledTrigger{cnf: tp.ConditionTypeCNF}
	byGroup := map[int][]int{}
	for i := range tp.SPTs {
		spt, err := compileSPT(&tp.SPTs[i], budget)
		if err != nil {
			return nil, fmt.Errorf("SPT %d: %w", i+1, err)
		}
		t.spts = append(t.spts, spt)
		for _, g := range tp.SPTs[i].Groups {
			if m := byGroup[g]; len(m) == 0 || m[len(m)-1] != i {
				byGroup[g] = append(m, i)
			}
		}
	}
	for _, g := range slices.Sorted(maps.Keys(byGroup)) {
		t.members = append(t.members, byGroup[g])
	}
	return t, nil
}

func compileSPT(spt *SPT, budget *int) (compiledSPT, error) {
	c := compiledSPT{negated: spt.ConditionNegated}
	var err error
	switch v := spt.Condition.(type) {
	case RequestURI:
		c.kind = kindRequestURI
		// Host names are case-insensitive (RFC 3261 §19.1.4).
		c.name, err = compilePattern("RequestURI", string(v), patternFoldCase, budget)
	case Method:
		c.kind, c.method, c.regs = kindMethod, string(v), slices.Clone(spt.RegistrationTypes)
	case SIPHeader:
		c.kind = kindHeader
		// Header names are case-insensitive (RFC 3261 §7.3.1), and a name
		// pattern must match the whole name: "Contact" must not select
		// Accept-Contact or Reject-Contact. Values are matched as written,
		// anywhere in the value, as Annex F's regexec semantics give.
		if c.name, err = compilePattern("Header", v.Header, patternFoldCase|patternWhole, budget); err == nil && matchesSomething(v.Content) {
			c.value, err = compilePattern("Content", v.Content, 0, budget)
		}
	case SessionCase:
		c.kind, c.session = kindSessionCase, v
	case SessionDescription:
		c.kind = kindSessionDescription
		if c.name, err = compilePattern("Line", v.Line, 0, budget); err == nil && matchesSomething(v.Content) {
			c.value, err = compilePattern("Content", v.Content, 0, budget)
		}
	}
	return c, err
}

// pattern is a compiled pattern and the size of its program, which is what
// a match is charged per byte.
type pattern struct {
	re    *regexp.Regexp
	insts int
	// token is set for a header name pattern that is a plain token, which
	// is compared with EqualFold at one unit a byte. linear is set for a
	// pattern whose whole match is a literal, which Go finds with a
	// substring search; that is charged literalCost a byte, about what such
	// a search costs against one instruction over one byte.
	token  string
	linear bool
}

const literalCost = 4

type patternMode uint8

const (
	patternFoldCase patternMode = 1 << iota // ignore case
	patternWhole                            // match the whole field
)

// posixFlags make Go's parser read a pattern as an ERE is read by POSIX
// regcomp without REG_NEWLINE, which is what TS 29.228 Annex F refers to:
// "." and a negated bracket expression match a newline too, and "^" and "$"
// match only at the ends of the value. Go's plain POSIX flags would read
// them line by line.
const posixFlags = syntax.POSIX | syntax.DotNL | syntax.ClassNL | syntax.OneLine

// compilePattern compiles a POSIX extended regular expression (TS 29.228
// Annex F). The pattern is parsed as an ERE, which refuses Perl extensions
// such as \d and (?i), and the parsed tree, not the source text, is what gets
// compiled: Go's matcher reads Perl syntax, in which some valid EREs mean
// something else. "0+?" is (0+)? in an ERE, which matches the empty value,
// but the lazy 0+? in Perl, which needs a 0 (#61).
//
// A case-insensitive pattern is parsed with FoldCase, so that the parser
// folds every literal and bracket expression before it merges them; folding
// text afterwards would fold the gaps of a negated class instead (the class
// [^a-z] that "K|[^[:lower:]]" merges into would lose k and K).
//
// The tree's size is checked first, and then the tree is written out by
// writeTree, which spells every node explicitly in time linear in the tree.
// The text is parsed back and compared with the tree by meaning
// ([sameMeaning]), so a pattern whose meaning could not be kept exactly is
// refused rather than compiled into something else.
func compilePattern(name, source string, mode patternMode, budget *int) (pattern, error) {
	flags := posixFlags
	if mode&patternFoldCase != 0 {
		flags |= syntax.FoldCase
	}
	tree, err := syntax.Parse(source, flags)
	if err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return pattern{}, fmt.Errorf("%s is not a POSIX extended regular expression: %s", name, se.Code)
		}
		return pattern{}, fmt.Errorf("%s is not a POSIX extended regular expression", name)
	}
	if mode&patternWhole == 0 {
		tree = withoutOuterDotStar(tree)
	}
	tooComplex := fmt.Errorf("%s compiles to more than %d instructions", name, MaxPatternInstructions)
	if estimateSize(tree) > 4*MaxPatternInstructions {
		return pattern{}, tooComplex
	}
	var b strings.Builder
	if !writeTree(&b, tree) {
		return pattern{}, fmt.Errorf("%s cannot be compiled without changing its meaning", name)
	}
	body := b.String()
	if back, err := syntax.Parse(body, syntax.Perl); err != nil || !sameMeaning(back, tree) {
		return pattern{}, fmt.Errorf("%s cannot be compiled without changing its meaning", name)
	}
	expr := body
	if mode&patternWhole != 0 {
		expr = `\A(?:` + body + `)\z`
	}
	perl, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return pattern{}, fmt.Errorf("%s cannot be compiled", name)
	}
	prog, err := syntax.Compile(perl.Simplify())
	if err != nil {
		return pattern{}, fmt.Errorf("%s cannot be compiled", name)
	}
	n := len(prog.Inst)
	if n > MaxPatternInstructions {
		return pattern{}, tooComplex
	}
	if n > *budget {
		return pattern{}, fmt.Errorf("the criteria compile to more than %d instructions together", MaxSetInstructions)
	}
	*budget -= n
	re, err := regexp.Compile(expr)
	if err != nil {
		return pattern{}, fmt.Errorf("%s cannot be compiled", name)
	}
	p := pattern{re: re, insts: n}
	if mode&patternWhole != 0 && mode&patternFoldCase != 0 && isPlainToken(source) {
		p.token = source
	}
	_, p.linear = re.LiteralPrefix()
	return p, nil
}

// writeTree writes re in Go's Perl syntax, spelling out what the POSIX parse
// decided so that nothing depends on flags inherited from the context: a
// folded literal in (?i:...), a class as its explicit ranges, "." and the
// anchors in their flag-independent forms, every quantified operand in a
// group and every alternative in a capture group. Captures do not change
// whether a pattern matches. It reports false for an operator the POSIX
// parse does not produce. Regexp.String would also do, but it scans the
// whole Unicode case table for every negated class, milliseconds each.
func writeTree(b *strings.Builder, re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`[^\x00-\x{10FFFF}]`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			b.WriteString(`(?i:`)
		} else {
			b.WriteString(`(?-i:`)
		}
		for _, r := range re.Rune {
			writeRune(b, r)
		}
		b.WriteString(`)`)
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			b.WriteString(`[^\x00-\x{10FFFF}]`)
			break
		}
		b.WriteString(`[`)
		for i := 0; i+1 < len(re.Rune); i += 2 {
			writeRune(b, re.Rune[i])
			if re.Rune[i+1] != re.Rune[i] {
				b.WriteString(`-`)
				writeRune(b, re.Rune[i+1])
			}
		}
		b.WriteString(`]`)
	case syntax.OpAnyChar:
		b.WriteString(`(?s:.)`)
	case syntax.OpAnyCharNotNL:
		b.WriteString(`(?-s:.)`)
	case syntax.OpBeginText:
		b.WriteString(`\A`)
	case syntax.OpEndText:
		b.WriteString(`\z`)
	case syntax.OpBeginLine:
		b.WriteString(`(?m:^)`)
	case syntax.OpEndLine:
		b.WriteString(`(?m:$)`)
	case syntax.OpCapture:
		b.WriteString(`(`)
		if !writeTree(b, re.Sub[0]) {
			return false
		}
		b.WriteString(`)`)
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		b.WriteString(`(?:`)
		if !writeTree(b, re.Sub[0]) {
			return false
		}
		b.WriteString(`)`)
		switch re.Op {
		case syntax.OpStar:
			b.WriteString(`*`)
		case syntax.OpPlus:
			b.WriteString(`+`)
		case syntax.OpQuest:
			b.WriteString(`?`)
		default:
			switch {
			case re.Max == re.Min:
				fmt.Fprintf(b, "{%d}", re.Min)
			case re.Max < 0:
				fmt.Fprintf(b, "{%d,}", re.Min)
			default:
				fmt.Fprintf(b, "{%d,%d}", re.Min, re.Max)
			}
		}
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteString(`?`)
		}
	case syntax.OpConcat:
		b.WriteString(`(?:`)
		for _, sub := range re.Sub {
			if !writeTree(b, sub) {
				return false
			}
		}
		b.WriteString(`)`)
	case syntax.OpAlternate:
		// Each alternative is a capture group so that parsing the text
		// back does not factor or merge the alternatives again, which it
		// would do differently from the first parse ("0.|00|0.0"); the
		// proof compares the trees without captures.
		b.WriteString(`(?:`)
		for i, sub := range re.Sub {
			if i > 0 {
				b.WriteString(`|`)
			}
			b.WriteString(`(`)
			if !writeTree(b, sub) {
				return false
			}
			b.WriteString(`)`)
		}
		b.WriteString(`)`)
	default:
		return false
	}
	return true
}

// writeRune writes r so that it reads as itself in a pattern and in a class.
func writeRune(b *strings.Builder, r rune) {
	if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
		b.WriteRune(r)
		return
	}
	fmt.Fprintf(b, `\x{%x}`, r)
}

// sameMeaning reports whether two trees match the same values. Writing a tree
// out and parsing it back often changes its shape without changing its
// meaning: "[Tt][Ee][Ll]:" parses to a case-folded literal "TEL" followed by
// ":", and comes back as one folded "TEL:"; "ab|aB" is factored into a
// class, a[Bb], and comes back as a folded literal. So the trees are compared
// by their structure without captures (writeTree adds some), and failing
// that by the programs they compile to, after folded literals have been
// spelt out as the classes of their case variants and the flag that has no
// effect on a class removed.
func sameMeaning(a, b *syntax.Regexp) bool {
	if a.Equal(b) || withoutCaptures(a).Equal(withoutCaptures(b)) {
		return true
	}
	pa, errA := syntax.Compile(withoutFolding(withoutCaptures(a)).Simplify())
	pb, errB := syntax.Compile(withoutFolding(withoutCaptures(b)).Simplify())
	return errA == nil && errB == nil && pa.String() == pb.String()
}

// withoutCaptures returns a copy of re with every capture group replaced by
// its content: captures decide what a match reports, not whether there is one.
func withoutCaptures(re *syntax.Regexp) *syntax.Regexp {
	if re.Op == syntax.OpCapture {
		return withoutCaptures(re.Sub[0])
	}
	c := *re
	c.Sub = make([]*syntax.Regexp, len(re.Sub))
	for i, sub := range re.Sub {
		c.Sub[i] = withoutCaptures(sub)
	}
	return &c
}

// withoutFolding returns a copy of re in which every case-folded literal is a
// sequence of plain literals and classes of all case variants
// (unicode.SimpleFold), and no class carries the FoldCase flag: classes list
// their runes, so the flag adds nothing to what they match.
func withoutFolding(re *syntax.Regexp) *syntax.Regexp {
	c := *re
	c.Sub = make([]*syntax.Regexp, len(re.Sub))
	for i, sub := range re.Sub {
		c.Sub[i] = withoutFolding(sub)
	}
	switch re.Op {
	case syntax.OpCharClass:
		c.Flags &^= syntax.FoldCase
		c.Rune = slices.Clone(re.Rune)
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase == 0 {
			c.Rune = slices.Clone(re.Rune)
			return &c
		}
		parts := make([]*syntax.Regexp, len(re.Rune))
		for i, r := range re.Rune {
			variants := []rune{r}
			for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
				variants = append(variants, f)
			}
			if len(variants) == 1 {
				parts[i] = &syntax.Regexp{Op: syntax.OpLiteral, Flags: re.Flags &^ syntax.FoldCase, Rune: variants}
				continue
			}
			slices.Sort(variants)
			ranges := make([]rune, 0, 2*len(variants))
			for _, v := range variants {
				ranges = append(ranges, v, v)
			}
			parts[i] = &syntax.Regexp{Op: syntax.OpCharClass, Rune: ranges}
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return &syntax.Regexp{Op: syntax.OpConcat, Sub: parts}
	}
	return &c
}

// isPlainToken reports whether s is a header name made only of token
// characters that are not ERE operators (RFC 3261 §25.1), so that the
// pattern means exactly that name.
func isPlainToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-!%_`'~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// matchesSomething reports whether a Content pattern restricts the value at
// all; an empty one, or ".*", is the same as no Content.
func matchesSomething(content string) bool {
	tree, err := syntax.Parse(content, posixFlags)
	if err != nil {
		return true // compilePattern reports the error
	}
	return withoutOuterDotStar(tree).Op != syntax.OpEmptyMatch
}

// withoutOuterDotStar drops a leading and a trailing ".*" from the tree of a
// pattern that is searched for anywhere in its field. Operators often write
// ".*X.*" for "contains X"; without the ".*", a literal X is found with a
// substring search instead of the full engine. Only the compiled form
// changes; the criteria keep the pattern as provisioned.
//
// The two match the same values, whatever "." matches: the search is
// unanchored and ".*" may match the empty string, so ".*P" matches a value
// exactly when P matches somewhere in it, with ".*" taking nothing or what
// precedes P; any anchor in P is checked at the same position either way.
// The same holds at the end. (The disagreement in #61 came from the plain
// path compiling the source as Perl, not from the removal.) Only the
// operands of the top-level concatenation are dropped, and only when they
// are exactly a star over a dot: ".*a|b" is an alternation and keeps its
// ".*", and ".*?", which an ERE reads as (.*)?, is left alone.
func withoutOuterDotStar(tree *syntax.Regexp) *syntax.Regexp {
	dotStar := func(re *syntax.Regexp) bool {
		return re.Op == syntax.OpStar && (re.Sub[0].Op == syntax.OpAnyChar || re.Sub[0].Op == syntax.OpAnyCharNotNL)
	}
	empty := &syntax.Regexp{Op: syntax.OpEmptyMatch, Flags: tree.Flags}
	if dotStar(tree) {
		return empty
	}
	if tree.Op != syntax.OpConcat {
		return tree
	}
	subs := tree.Sub
	for len(subs) > 0 && dotStar(subs[0]) {
		subs = subs[1:]
	}
	for len(subs) > 0 && dotStar(subs[len(subs)-1]) {
		subs = subs[:len(subs)-1]
	}
	switch len(subs) {
	case len(tree.Sub):
		return tree
	case 0:
		return empty
	case 1:
		return subs[0]
	}
	return &syntax.Regexp{Op: syntax.OpConcat, Flags: tree.Flags, Sub: subs}
}

// estimateSize is an upper bound on the instructions syntax.Compile emits for
// re, computed without expanding counted repetitions. It saturates, so it
// cannot overflow however the repetitions nest.
func estimateSize(re *syntax.Regexp) int {
	const ceiling = 1 << 24
	sum := func(subs []*syntax.Regexp) int {
		n := 1
		for _, sub := range subs {
			n = min(n+estimateSize(sub)+1, ceiling)
		}
		return n
	}
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune) + 1
	case syntax.OpConcat, syntax.OpAlternate:
		return sum(re.Sub)
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return min(estimateSize(re.Sub[0])+2, ceiling)
	case syntax.OpRepeat:
		copies := re.Max
		if copies < 0 {
			copies = re.Min + 1
		}
		return min((copies+1)*(estimateSize(re.Sub[0])+2), ceiling)
	}
	return 2
}

// Len returns the number of criteria in the set.
func (s *Set) Len() int { return len(s.criteria) }

// Match returns, in priority order, every criterion that applies to the
// request: the S-CSCF sends a third-party REGISTER to each of their servers
// (TS 24.229 §5.4.1.7).
//
// It fails with a [*LimitError] when the request is too large to evaluate.
func (s *Set) Match(req Request, ctx Context) ([]FilterCriteria, error) {
	in := newInput(req, ctx, s.maxWork)
	defer s.count(in)
	var out []FilterCriteria
	for i := range s.criteria {
		if s.criteria[i].matches(in) {
			out = append(out, s.criteria[i].fc)
		}
		if in.limit != "" {
			return nil, &LimitError{Limit: in.limit}
		}
	}
	return out, nil
}

// OversizedValues returns how many header values, Request-URIs and SDP lines
// evaluations of this set have left unexamined because they exceeded their
// own limit or their kind's per-evaluation limit. A rising count means
// requests that iFC may have misjudged, worth a metric.
func (s *Set) OversizedValues() uint64 { return s.oversized.Load() }

// ExhaustedEvaluations returns how many evaluations of this set ran out of
// work budget, so that some of their conditions were not examined. Like
// OversizedValues it is worth a metric.
func (s *Set) ExhaustedEvaluations() uint64 { return s.exhausted.Load() }

func (s *Set) count(in *input) {
	if in.oversized > 0 {
		s.oversized.Add(uint64(in.oversized))
	}
	if in.exhausted {
		s.exhausted.Add(1)
	}
}

// Next returns the first criterion, in priority order, whose priority is
// greater than after and that applies to the request; pass -1 to start. The
// S-CSCF calls it again with the priority it last used when the request
// returns from that application server, which may have changed the request
// (TS 24.229 §5.4.3.2).
//
// It fails with a [*LimitError] when the request is too large to evaluate;
// a criterion reached before the limit is returned, since the request
// satisfies it whatever the rest of the request holds.
func (s *Set) Next(req Request, ctx Context, after int) (FilterCriteria, bool, error) {
	in := newInput(req, ctx, s.maxWork)
	defer s.count(in)
	for i := range s.criteria {
		c := &s.criteria[i]
		if c.fc.Priority <= after {
			continue
		}
		matched := c.matches(in)
		if in.limit != "" {
			return FilterCriteria{}, false, &LimitError{Limit: in.limit}
		}
		if matched {
			return c.fc, true, nil
		}
	}
	return FilterCriteria{}, false, nil
}

func (c *compiledCriteria) matches(in *input) bool {
	switch c.fc.ProfilePart {
	case ProfilePartRegistered:
		if !in.ctx.registered() {
			return false
		}
	case ProfilePartUnregistered:
		if in.ctx.registered() {
			return false
		}
	}
	return c.trigger == nil || c.trigger.matches(in)
}

// matches evaluates the trigger in CNF or DNF (TS 29.228 Annex C). Each SPT
// is evaluated at most once, however many groups it belongs to.
func (t *compiledTrigger) matches(in *input) bool {
	results := make([]int8, len(t.spts)) // 0 not yet evaluated, 1 true, -1 false
	holds := func(i int) bool {
		if results[i] == 0 {
			results[i] = -1
			if t.spts[i].matches(in) != t.spts[i].negated {
				results[i] = 1
			}
		}
		return results[i] == 1
	}
	for _, members := range t.members {
		if t.cnf {
			// Each group is an OR; every group must hold.
			if !slices.ContainsFunc(members, holds) {
				return false
			}
		} else if !slices.ContainsFunc(members, func(i int) bool { return !holds(i) }) {
			// Each group is an AND; one group is enough.
			return true
		}
	}
	return t.cnf
}

func (c *compiledSPT) matches(in *input) bool {
	switch c.kind {
	case kindRequestURI:
		part, ok := in.uriPart()
		return ok && in.match(c.name, part)
	case kindMethod:
		if in.req.Method() != c.method {
			return false
		}
		if c.method == "REGISTER" && len(c.regs) > 0 && in.ctx.RegistrationType != nil {
			return slices.Contains(c.regs, *in.ctx.RegistrationType)
		}
		return true
	case kindHeader:
		for _, h := range in.headers() {
			if in.match(c.name, h.Name) && (c.value.re == nil || in.match(c.value, h.Value)) {
				return true
			}
		}
		return false
	case kindSessionCase:
		return in.ctx.Case == c.session
	case kindSessionDescription:
		for _, l := range in.sdp() {
			if in.match(c.name, l.Name) && (c.value.re == nil || in.match(c.value, l.Value)) {
				return true
			}
		}
		return false
	}
	return false
}

// input reads each part of the request once per evaluation, and only if a
// trigger needs it.
type input struct {
	req Request
	ctx Context
	// oversized counts the values left unexamined for their length.
	oversized int
	// work is what is left of the work budget; exhausted says a match
	// could not be paid for. limit names the first limit reached.
	work      int
	exhausted bool
	limit     string

	uri        string
	uriOK      bool
	uriDone    bool
	fields     []HeaderField
	fieldsDone bool
	lines      []HeaderField
	linesDone  bool
}

func newInput(req Request, ctx Context, work int) *input {
	return &input{req: req, ctx: ctx, work: work}
}

// match runs p over v if the budget can pay for it. An empty value still
// costs the program once.
func (in *input) match(p pattern, v string) bool {
	cost := max(len(v), 1)
	switch {
	case p.token != "":
	case p.linear:
		cost *= literalCost
	default:
		cost *= p.insts
	}
	if cost > in.work {
		in.work, in.exhausted = 0, true
		in.reached("MaxWork")
		return false
	}
	in.work -= cost
	if p.token != "" {
		return strings.EqualFold(v, p.token)
	}
	return p.re.MatchString(v)
}

// reached records a limit; the first one is reported.
func (in *input) reached(limit string) {
	if in.limit == "" {
		in.limit = limit
	}
}

func (in *input) uriPart() (string, bool) {
	if !in.uriDone {
		in.uriDone = true
		if uri := in.req.RequestURI(); len(uri) <= MaxRequestURILength {
			in.uri, in.uriOK = requestURIPart(uri), true
		} else {
			in.oversized++
			in.reached("MaxRequestURILength")
		}
	}
	return in.uri, in.uriOK
}

func (in *input) headers() []HeaderField {
	if !in.fieldsDone {
		total := 0
		for _, h := range in.req.HeaderFields() {
			n := len(h.Name) + len(h.Value)
			if limit := headerLimit(h, total+n); limit != "" {
				in.reached(limit)
				in.oversized++
				continue
			}
			total += n
			// Annex F matches names and values with white space at either
			// end removed and inner runs of it reduced to one space, which
			// is what collapse does.
			in.fields = append(in.fields, HeaderField{Name: collapse(h.Name), Value: collapse(h.Value)})
		}
		in.fieldsDone = true
	}
	return in.fields
}

func headerLimit(h HeaderField, total int) string {
	switch {
	case len(h.Name) > MaxHeaderLength || len(h.Value) > MaxHeaderLength:
		return "MaxHeaderLength"
	case total > MaxHeaderBytes:
		return "MaxHeaderBytes"
	}
	return ""
}

// sdp splits each SDP line into its type and value; lines without "=" are
// not SDP fields and are skipped.
func (in *input) sdp() []HeaderField {
	if !in.linesDone {
		total := 0
		for _, l := range in.req.SDPLines() {
			l = strings.TrimSuffix(l, "\r")
			if limit := sdpLimit(l, total+len(l)); limit != "" {
				in.reached(limit)
				in.oversized++
				continue
			}
			total += len(l)
			if typ, value, ok := strings.Cut(l, "="); ok {
				in.lines = append(in.lines, HeaderField{Name: typ, Value: value})
			}
		}
		in.linesDone = true
	}
	return in.lines
}

func sdpLimit(line string, total int) string {
	switch {
	case len(line) > MaxSDPLineLength:
		return "MaxSDPLineLength"
	case total > MaxSDPBytes:
		return "MaxSDPBytes"
	}
	return ""
}

// requestURIPart is the part of a Request-URI that a RequestURI pattern is
// matched against (TS 29.228 Annex F): the hostport of a SIP or SIPS URI and
// the telephone-subscriber of a tel URI. Other URIs are matched whole.
//
// In a SIP URI an unescaped "@" can only end the userinfo, and the hostport
// ends at the first ";" (parameters) or "?" (headers) after it (RFC 3261
// §25.1); the user part may itself contain ";" and "?", so the search starts
// after the "@".
func requestURIPart(uri string) string {
	scheme, rest, ok := strings.Cut(uri, ":")
	if !ok {
		return uri
	}
	switch strings.ToLower(scheme) {
	case "sip", "sips":
		if i := strings.IndexByte(rest, '@'); i >= 0 {
			rest = rest[i+1:]
		}
		if i := strings.IndexAny(rest, ";?"); i >= 0 {
			rest = rest[:i]
		}
		return rest
	case "tel":
		return rest
	}
	return uri
}
