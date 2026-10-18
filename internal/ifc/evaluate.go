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

// Limits on what evaluation examines. A pattern's cost is its program size
// times the length of the value it runs over, so both are bounded: a profile
// cannot make Compile hold an unbounded program, and a request cannot make one
// evaluation scan an unbounded value. A value longer than its limit (counted
// before white space is normalised) is not examined: the condition is false
// for it, so a negated condition holds, and [Set.OversizedValues] counts it.
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
)

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
	oversized atomic.Uint64
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
	// nil value pattern matches any value.
	name, value *regexp.Regexp
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
	r := &reader{}
	for i := range criteria {
		r.validateCriteria(fmt.Sprintf("InitialFilterCriteria[%d]", i+1), &criteria[i])
	}
	if r.err != nil {
		return nil, r.err
	}
	s := &Set{criteria: make([]compiledCriteria, 0, len(criteria))}
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
		if c.name, err = compilePattern("Header", v.Header, patternFoldCase|patternWhole, budget); err == nil && v.Content != "" {
			c.value, err = compilePattern("Content", v.Content, 0, budget)
		}
	case SessionCase:
		c.kind, c.session = kindSessionCase, v
	case SessionDescription:
		c.kind = kindSessionDescription
		if c.name, err = compilePattern("Line", v.Line, 0, budget); err == nil && v.Content != "" {
			c.value, err = compilePattern("Content", v.Content, 0, budget)
		}
	}
	return c, err
}

type patternMode uint8

const (
	patternFoldCase patternMode = 1 << iota // ignore case
	patternWhole                            // match the whole field
)

// compilePattern compiles a POSIX extended regular expression (TS 29.228
// Annex F). The pattern is first parsed with Go's POSIX syntax, which refuses
// the Perl extensions (\d, (?i), non-greedy repetition and so on) a pattern
// written for another HSS would not contain; it is then compiled with Go's
// engine, whose matching time is linear in the input. Only whether a pattern
// matches is used, so leftmost-longest and leftmost-first semantics give the
// same answers.
//
// The program size is estimated from the parse tree before anything is
// expanded, so a pattern such as "[ab]{1000}" repeated is refused without
// building its program, and then counted exactly against
// MaxPatternInstructions and the set's remaining budget.
func compilePattern(name, pattern string, mode patternMode, budget *int) (*regexp.Regexp, error) {
	if _, err := syntax.Parse(pattern, syntax.POSIX); err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return nil, fmt.Errorf("%s is not a POSIX extended regular expression: %s", name, se.Code)
		}
		return nil, fmt.Errorf("%s is not a POSIX extended regular expression", name)
	}
	expr := "(?:" + pattern + ")"
	if mode&patternFoldCase != 0 {
		expr = "(?i:" + pattern + ")"
	}
	if mode&patternWhole != 0 {
		expr = "^" + expr + "$"
	}
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be compiled", name)
	}
	tooComplex := fmt.Errorf("%s compiles to more than %d instructions", name, MaxPatternInstructions)
	if estimateSize(tree) > 4*MaxPatternInstructions {
		return nil, tooComplex
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil {
		return nil, fmt.Errorf("%s cannot be compiled", name)
	}
	n := len(prog.Inst)
	if n > MaxPatternInstructions {
		return nil, tooComplex
	}
	if n > *budget {
		return nil, fmt.Errorf("the criteria compile to more than %d instructions together", MaxSetInstructions)
	}
	*budget -= n
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be compiled", name)
	}
	return re, nil
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
func (s *Set) Match(req Request, ctx Context) []FilterCriteria {
	in := newInput(req, ctx)
	defer s.count(in)
	var out []FilterCriteria
	for i := range s.criteria {
		if s.criteria[i].matches(in) {
			out = append(out, s.criteria[i].fc)
		}
	}
	return out
}

// OversizedValues returns how many header values, Request-URIs and SDP lines
// evaluations of this set have left unexamined because they exceeded their
// limit. A rising count means requests that iFC may have misjudged, worth a
// metric.
func (s *Set) OversizedValues() uint64 { return s.oversized.Load() }

func (s *Set) count(in *input) {
	if in.oversized > 0 {
		s.oversized.Add(uint64(in.oversized))
	}
}

// Next returns the first criterion, in priority order, whose priority is
// greater than after and that applies to the request; pass -1 to start. The
// S-CSCF calls it again with the priority it last used when the request
// returns from that application server, which may have changed the request
// (TS 24.229 §5.4.3.2).
func (s *Set) Next(req Request, ctx Context, after int) (FilterCriteria, bool) {
	in := newInput(req, ctx)
	defer s.count(in)
	for i := range s.criteria {
		c := &s.criteria[i]
		if c.fc.Priority > after && c.matches(in) {
			return c.fc, true
		}
	}
	return FilterCriteria{}, false
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
		return ok && c.name.MatchString(part)
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
			if c.name.MatchString(h.Name) && (c.value == nil || c.value.MatchString(h.Value)) {
				return true
			}
		}
		return false
	case kindSessionCase:
		return in.ctx.Case == c.session
	case kindSessionDescription:
		for _, l := range in.sdp() {
			if c.name.MatchString(l.Name) && (c.value == nil || c.value.MatchString(l.Value)) {
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

	uri        string
	uriOK      bool
	uriDone    bool
	fields     []HeaderField
	fieldsDone bool
	lines      []HeaderField
	linesDone  bool
}

func newInput(req Request, ctx Context) *input { return &input{req: req, ctx: ctx} }

func (in *input) uriPart() (string, bool) {
	if !in.uriDone {
		in.uriDone = true
		if uri := in.req.RequestURI(); len(uri) <= MaxRequestURILength {
			in.uri, in.uriOK = requestURIPart(uri), true
		} else {
			in.oversized++
		}
	}
	return in.uri, in.uriOK
}

func (in *input) headers() []HeaderField {
	if !in.fieldsDone {
		// Annex F matches names and values with white space at either end
		// removed and inner runs of it reduced to one space, which is what
		// collapse does.
		for _, h := range in.req.HeaderFields() {
			if len(h.Name) > MaxHeaderLength || len(h.Value) > MaxHeaderLength {
				in.oversized++
				continue
			}
			in.fields = append(in.fields, HeaderField{Name: collapse(h.Name), Value: collapse(h.Value)})
		}
		in.fieldsDone = true
	}
	return in.fields
}

// sdp splits each SDP line into its type and value; lines without "=" are
// not SDP fields and are skipped.
func (in *input) sdp() []HeaderField {
	if !in.linesDone {
		for _, l := range in.req.SDPLines() {
			l = strings.TrimSuffix(l, "\r")
			if len(l) > MaxSDPLineLength {
				in.oversized++
				continue
			}
			if typ, value, ok := strings.Cut(l, "="); ok {
				in.lines = append(in.lines, HeaderField{Name: typ, Value: value})
			}
		}
		in.linesDone = true
	}
	return in.lines
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
