package routing

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// maxPreferences bounds the Accept-Contact elements, and apart the
// Reject-Contact ones, a request may carry: RCS clients send one or two, and
// each costs a pass over every binding of the user.
const maxPreferences = 8

// errTooManyPreferences is a request with more than maxPreferences of
// either kind.
var errTooManyPreferences = errors.New("routing: too many caller preferences")

// preferences are a request's caller preferences (RFC 3841 §7.2): the
// Accept-Contact elements with require, which drop the bindings they do not
// match, and the Reject-Contact ones, which drop those they do. An
// Accept-Contact without require only orders the bindings in RFC 3841; here
// it is not used, and every binding left is tried by its q. A client that
// wants only the devices that registered a service asks with require and
// explicit on its feature tag; rcs-as's pager does not yet (#332), so its
// messages go to every binding of the user.
type preferences struct {
	requires []predicate
	rejects  []predicate
}

// predicate is one element's feature predicate, its values read once.
type predicate struct {
	explicit bool
	features []wanted
}

// wanted is a feature a predicate names, and the values it allows.
type wanted struct {
	name   string
	values []string
}

// preferencesOf reads req's caller preferences. An element that does not
// parse is left out, the others kept, unless it would require something,
// which is errBadPreference: leaving it out would send the request where
// the caller asked it not to go. More than maxPreferences of either kind is
// errTooManyPreferences.
func preferencesOf(req *sip.Request) (preferences, error) {
	accepts, err := elementsOf(&req.Header, "Accept-Contact")
	if err != nil {
		return preferences{}, err
	}
	rejects, err := elementsOf(&req.Header, "Reject-Contact")
	if err != nil {
		return preferences{}, err
	}
	var p preferences
	for _, a := range accepts {
		if a.Require() {
			p.requires = append(p.requires, predicateOf(a.Params, a.Explicit()))
		}
	}
	for _, r := range rejects {
		// A Reject-Contact drops a binding only if the binding has every
		// feature it names (§7.2.3).
		p.rejects = append(p.rejects, predicateOf(r.Params, true))
	}
	return p, nil
}

// errBadPreference is an element that does not parse and names require.
var errBadPreference = errors.New("routing: a caller preference that requires something does not parse")

// elementsOf parses the elements of the field name, which has the grammar
// of Accept-Contact (RFC 3841 §10), one by one: the ones that parse.
func elementsOf(h *sip.Header, name string) (sip.AcceptContacts, error) {
	var els []string
	for _, v := range h.Values(name) {
		var one sip.Header
		if one.Add(name, v) != nil {
			continue
		}
		vs, err := one.Elements(name)
		if err != nil {
			// A value that does not split, as one with an open quote, is
			// one element that does not parse.
			vs = []string{v}
		}
		els = append(els, vs...)
	}
	if len(els) > maxPreferences {
		return nil, errTooManyPreferences
	}
	var out sip.AcceptContacts
	for _, e := range els {
		as, err := parseAcceptContact(e)
		switch {
		case err == nil && len(as) == 1:
			out = append(out, as[0])
		case strings.Contains(strings.ToLower(e), "require"):
			return nil, errBadPreference
		}
	}
	return out, nil
}

func predicateOf(ps sip.Params, explicit bool) predicate {
	p := predicate{explicit: explicit}
	for _, q := range ps {
		name := strings.ToLower(q.Name)
		if name == "require" || name == "explicit" {
			continue
		}
		p.features = append(p.features, wanted{name: name, values: valuesOf(q)})
	}
	return p
}

// accepted are the bindings of cs that p accepts, and every binding that
// states no feature at all, which caller preferences do not apply to
// (§7.2.3). ops counts the values compared, which bounds the work a request
// makes (#322): each predicate value is looked up once per binding.
func (p preferences) accepted(cs []state.Contact, ops *int) []state.Contact {
	var out []state.Contact
	for _, c := range cs {
		f := featuresOf(c)
		if len(f) == 0 || p.keeps(f, ops) {
			out = append(out, c)
		}
	}
	return out
}

func (p preferences) keeps(f features, ops *int) bool {
	for _, a := range p.requires {
		if !a.matches(f, ops) {
			return false
		}
	}
	for _, r := range p.rejects {
		if r.matches(f, ops) {
			return false
		}
	}
	return true
}

// accepted are the bindings of cs that req's caller preferences accept, as
// preferences.accepted; with preferences that are refused, every binding.
func accepted(cs []state.Contact, req *sip.Request) []state.Contact {
	p, err := preferencesOf(req)
	if err != nil {
		return cs
	}
	var ops int
	return p.accepted(cs, &ops)
}

// features is the feature set of a binding (RFC 3840 §9), by lower-case
// name, each feature's values read once.
type features map[string]*stated

// stated are the values a binding states for one feature: its tokens and
// booleans by lower case, its strings with case, and its numbers sorted.
type stated struct {
	tokens  map[string]bool
	strings map[string]bool
	numbers []float64
}

// featuresOf is the feature set of a binding, from the feature tags its
// REGISTER's Contact carried.
func featuresOf(c state.Contact) features {
	f := features{}
	if len(c.FeatureTags) == 0 {
		return f
	}
	// The tags are stored as the Contact wrote them, so they parse as the
	// parameters of a preference.
	as, err := parseAcceptContact("*;" + strings.Join(c.FeatureTags, ";"))
	if err != nil || len(as) != 1 {
		return f
	}
	for _, p := range as[0].Params {
		s := &stated{tokens: map[string]bool{}, strings: map[string]bool{}}
		for _, v := range valuesOf(p) {
			switch {
			case strings.HasPrefix(v, "<"):
				s.strings[v] = true
			case strings.HasPrefix(v, "#"):
				if n, ok := number(strings.TrimPrefix(v[1:], "=")); ok {
					s.numbers = append(s.numbers, n)
				}
			default:
				s.tokens[strings.ToLower(v)] = true
			}
		}
		slices.Sort(s.numbers)
		f[strings.ToLower(p.Name)] = s
	}
	return f
}

// parseAcceptContact parses v, an Accept-Contact value.
func parseAcceptContact(v string) (sip.AcceptContacts, error) {
	var h sip.Header
	if err := h.Add("Accept-Contact", v); err != nil {
		return nil, err
	}
	return h.AcceptContact()
}

// matches reports whether a binding with features f matches the predicate
// (RFC 3841 §7.2.4): it has each feature the predicate names with a value
// the predicate allows. A feature the binding does not state matches unless
// explicit asks for the features to have been stated. It stops at the first
// feature that does not match.
func (p predicate) matches(f features, ops *int) bool {
	for _, w := range p.features {
		have, ok := f[w.name]
		switch {
		case !ok && p.explicit:
			return false
		case ok && !have.allows(w.values, ops):
			return false
		}
	}
	return true
}

// allows compares a predicate's values with a binding's (RFC 3840 §9): of
// the predicate's values the binding must have one, or, for one written with
// a leading !, have one that is not it (lacks). Tokens and booleans compare
// without case, a string in angle brackets whole and with case, numbers by
// value: a predicate's
// #>=n, #<=n, #=n or #a:b against a binding's #=n.
func (s *stated) allows(values []string, ops *int) bool {
	for _, v := range values {
		*ops++
		if neg, ok := strings.CutPrefix(v, "!"); ok {
			if s.lacks(neg) {
				return true
			}
			continue
		}
		if s.has(v) {
			return true
		}
	}
	return false
}

func (s *stated) has(v string) bool {
	switch {
	case strings.HasPrefix(v, "<"):
		return s.strings[v]
	case strings.HasPrefix(v, "#"):
		return s.number(v[1:])
	}
	return s.tokens[strings.ToLower(v)]
}

// lacks reports whether one of s's values is not v: the binding is a set of
// feature collections, one per value, and !v asks for a collection without
// v (RFC 3840 Appendix A, RFC 2533), so a binding with fthttp and geopush
// matches !fthttp.
func (s *stated) lacks(v string) bool {
	others := len(s.tokens) + len(s.strings) + len(s.numbers)
	switch {
	case strings.HasPrefix(v, "<"):
		if s.strings[v] {
			others--
		}
		return others > 0
	case strings.HasPrefix(v, "#"):
		return len(s.tokens)+len(s.strings) > 0 || s.numberNot(v[1:])
	}
	if s.tokens[strings.ToLower(v)] {
		others--
	}
	return others > 0
}

// numberNot reports whether one of s's numbers does not meet rel.
func (s *stated) numberNot(rel string) bool {
	ns := s.numbers
	if len(ns) == 0 {
		return false
	}
	lowest, highest := ns[0], ns[len(ns)-1]
	switch {
	case strings.HasPrefix(rel, ">="):
		n, ok := number(rel[2:])
		return !ok || lowest < n
	case strings.HasPrefix(rel, "<="):
		n, ok := number(rel[2:])
		return !ok || highest > n
	case strings.HasPrefix(rel, "="):
		n, ok := number(rel[1:])
		return !ok || lowest != n || highest != n
	}
	lo, hi, ok := strings.Cut(rel, ":")
	a, okA := number(lo)
	b, okB := number(hi)
	return !ok || !okA || !okB || lowest < a || highest > b
}

// number reports whether one of s's numbers meets rel, a predicate's
// numeric relation without its "#", by a search of the sorted numbers.
func (s *stated) number(rel string) bool {
	ns := s.numbers
	// first is the index of the first number at least n.
	first := func(n float64) int { i, _ := slices.BinarySearch(ns, n); return i }
	value := func(v string) (float64, bool) { return number(v) }
	switch {
	case strings.HasPrefix(rel, ">="):
		n, ok := value(rel[2:])
		return ok && len(ns) > 0 && ns[len(ns)-1] >= n
	case strings.HasPrefix(rel, "<="):
		n, ok := value(rel[2:])
		return ok && len(ns) > 0 && ns[0] <= n
	case strings.HasPrefix(rel, "="):
		n, ok := value(rel[1:])
		i := first(n)
		return ok && i < len(ns) && ns[i] == n
	}
	lo, hi, ok := strings.Cut(rel, ":")
	a, okA := value(lo)
	b, okB := value(hi)
	i := first(a)
	return ok && okA && okB && i < len(ns) && ns[i] <= b
}

// valuesOf are the values a feature parameter states: TRUE for a flag, the
// string of a string value, the elements of a value list.
func valuesOf(p sip.Param) []string {
	v := strings.TrimSpace(p.Value)
	switch {
	case !p.Quoted:
		return []string{boolean(v)}
	case strings.HasPrefix(v, "<"):
		return []string{v}
	}
	out := strings.Split(v, ",")
	for i := range out {
		// A quoted TRUE is the flag it writes out (RFC 3840 §9): a token,
		// compared without case.
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

// number reads an RFC 3840 number: a sign, digits, and a fraction, no
// exponent, no infinity.
func number(s string) (float64, bool) {
	unsigned := strings.TrimPrefix(strings.TrimPrefix(s, "+"), "-")
	rest := strings.TrimLeft(unsigned, "0123456789")
	if rest == unsigned {
		return 0, false // no digit before the fraction
	}
	if frac, ok := strings.CutPrefix(rest, "."); ok {
		rest = strings.TrimLeft(frac, "0123456789")
	}
	if rest != "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(s, 64)
	return n, err == nil
}

// boolean writes a flag (no value) as the TRUE it means.
func boolean(v string) string {
	if v == "" {
		return "TRUE"
	}
	return v
}
