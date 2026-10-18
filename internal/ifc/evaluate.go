package ifc

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
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
	criteria []compiledCriteria
}

type compiledCriteria struct {
	fc      FilterCriteria
	trigger *compiledTrigger // nil: always matches
}

type compiledTrigger struct {
	cnf    bool
	spts   []compiledSPT
	groups []int // distinct group numbers, ascending
}

type compiledSPT struct {
	negated bool
	groups  []int
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
	for _, fc := range criteria {
		c := compiledCriteria{fc: fc}
		if fc.TriggerPoint != nil {
			t, err := compileTrigger(fc.TriggerPoint)
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

func compileTrigger(tp *TriggerPoint) (*compiledTrigger, error) {
	t := &compiledTrigger{cnf: tp.ConditionTypeCNF}
	for i := range tp.SPTs {
		spt, err := compileSPT(&tp.SPTs[i])
		if err != nil {
			return nil, fmt.Errorf("SPT %d: %w", i+1, err)
		}
		t.spts = append(t.spts, spt)
		t.groups = append(t.groups, spt.groups...)
	}
	slices.Sort(t.groups)
	t.groups = slices.Compact(t.groups)
	return t, nil
}

func compileSPT(spt *SPT) (compiledSPT, error) {
	c := compiledSPT{negated: spt.ConditionNegated, groups: slices.Clone(spt.Groups)}
	var err error
	switch v := spt.Condition.(type) {
	case RequestURI:
		c.kind = kindRequestURI
		// Host names are case-insensitive (RFC 3261 §19.1.4).
		c.name, err = compilePattern("RequestURI", string(v), true)
	case Method:
		c.kind, c.method, c.regs = kindMethod, string(v), slices.Clone(spt.RegistrationTypes)
	case SIPHeader:
		c.kind = kindHeader
		// Header names are case-insensitive (RFC 3261 §7.3.1); values are
		// matched as written.
		if c.name, err = compilePattern("Header", v.Header, true); err == nil && v.Content != "" {
			c.value, err = compilePattern("Content", v.Content, false)
		}
	case SessionCase:
		c.kind, c.session = kindSessionCase, v
	case SessionDescription:
		c.kind = kindSessionDescription
		if c.name, err = compilePattern("Line", v.Line, false); err == nil && v.Content != "" {
			c.value, err = compilePattern("Content", v.Content, false)
		}
	}
	return c, err
}

// compilePattern compiles a POSIX extended regular expression (TS 29.228
// Annex F). The pattern is first parsed with Go's POSIX syntax, which refuses
// the Perl extensions (\d, (?i), non-greedy repetition and so on) a pattern
// written for another HSS would not contain; it is then compiled with Go's
// engine, whose matching time is linear in the input. Only whether a pattern
// matches is used, so leftmost-longest and leftmost-first semantics give the
// same answers.
func compilePattern(name, pattern string, foldCase bool) (*regexp.Regexp, error) {
	if _, err := syntax.Parse(pattern, syntax.POSIX); err != nil {
		var se *syntax.Error
		if errors.As(err, &se) {
			return nil, fmt.Errorf("%s is not a POSIX extended regular expression: %s", name, se.Code)
		}
		return nil, fmt.Errorf("%s is not a POSIX extended regular expression", name)
	}
	prefix := "(?:"
	if foldCase {
		prefix = "(?i:"
	}
	re, err := regexp.Compile(prefix + pattern + ")")
	if err != nil {
		return nil, fmt.Errorf("%s cannot be compiled", name)
	}
	return re, nil
}

// Len returns the number of criteria in the set.
func (s *Set) Len() int { return len(s.criteria) }

// Match returns, in priority order, every criterion that applies to the
// request: the S-CSCF sends a third-party REGISTER to each of their servers
// (TS 24.229 §5.4.1.7).
func (s *Set) Match(req Request, ctx Context) []FilterCriteria {
	in := newInput(req, ctx)
	var out []FilterCriteria
	for i := range s.criteria {
		if s.criteria[i].matches(in) {
			out = append(out, s.criteria[i].fc)
		}
	}
	return out
}

// Next returns the first criterion, in priority order, whose priority is
// greater than after and that applies to the request; pass -1 to start. The
// S-CSCF calls it again with the priority it last used when the request
// returns from that application server, which may have changed the request
// (TS 24.229 §5.4.3.2).
func (s *Set) Next(req Request, ctx Context, after int) (FilterCriteria, bool) {
	in := newInput(req, ctx)
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
	for _, g := range t.groups {
		if t.cnf {
			// Each group is an OR; every group must hold.
			if !t.anyInGroup(g, holds) {
				return false
			}
		} else if t.allInGroup(g, holds) {
			// Each group is an AND; one group is enough.
			return true
		}
	}
	return t.cnf
}

func (t *compiledTrigger) anyInGroup(g int, holds func(int) bool) bool {
	for i := range t.spts {
		if slices.Contains(t.spts[i].groups, g) && holds(i) {
			return true
		}
	}
	return false
}

func (t *compiledTrigger) allInGroup(g int, holds func(int) bool) bool {
	for i := range t.spts {
		if slices.Contains(t.spts[i].groups, g) && !holds(i) {
			return false
		}
	}
	return true
}

func (c *compiledSPT) matches(in *input) bool {
	switch c.kind {
	case kindRequestURI:
		return c.name.MatchString(in.uriPart())
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

	uri        string
	uriDone    bool
	fields     []HeaderField
	fieldsDone bool
	lines      []HeaderField
	linesDone  bool
}

func newInput(req Request, ctx Context) *input { return &input{req: req, ctx: ctx} }

func (in *input) uriPart() string {
	if !in.uriDone {
		in.uri, in.uriDone = requestURIPart(in.req.RequestURI()), true
	}
	return in.uri
}

func (in *input) headers() []HeaderField {
	if !in.fieldsDone {
		// Annex F matches names and values with white space at either end
		// removed and inner runs of it reduced to one space, which is what
		// collapse does.
		for _, h := range in.req.HeaderFields() {
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
