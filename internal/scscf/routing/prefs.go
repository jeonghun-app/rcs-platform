package routing

import (
	"slices"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// accepted are the bindings of cs that req's caller preferences accept (RFC
// 3841 §7.2): those an Accept-Contact with require would not drop, less
// those a Reject-Contact matches, and every binding that states no feature
// at all, which the preferences do not apply to (§7.2.3). An Accept-Contact
// without require only orders the bindings in RFC 3841; here it is not
// used, and every binding left is tried by its q. A client that wants only
// the devices that registered a service asks with require and explicit on
// its feature tag; rcs-as's pager does not yet (#332), so its messages go
// to every binding of the user. A preference that does not parse is left
// out: the request is not refused for it.
func accepted(cs []state.Contact, req *sip.Request) []state.Contact {
	accepts, _ := req.Header.AcceptContact()
	rejects, _ := rejectContact(&req.Header)
	var out []state.Contact
	for _, c := range cs {
		f := featuresOf(c)
		ok := true
		for _, a := range accepts {
			if a.Require() && !matches(a.Params, f, a.Explicit()) {
				ok = false
			}
		}
		for _, r := range rejects {
			// A Reject-Contact drops a binding only if the binding has every
			// feature it names (§7.2.3).
			if matches(r.Params, f, true) {
				ok = false
			}
		}
		if ok || len(f) == 0 {
			out = append(out, c)
		}
	}
	return out
}

// rejectContact reads the Reject-Contact field, which has the grammar of
// Accept-Contact (RFC 3841 §10): parsed through a copy under that name.
func rejectContact(h *sip.Header) (sip.AcceptContacts, error) {
	var copied sip.Header
	for _, v := range h.Values("Reject-Contact") {
		if err := copied.Add("Accept-Contact", v); err != nil {
			return nil, err
		}
	}
	return copied.AcceptContact()
}

// featuresOf is the feature set of a binding (RFC 3840 §9), from the
// feature tags its REGISTER's Contact carried, by lower-case name.
func featuresOf(c state.Contact) map[string]sip.Param {
	f := map[string]sip.Param{}
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
		f[strings.ToLower(p.Name)] = p
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

// matches reports whether a binding with features f matches the feature
// predicate ps (RFC 3841 §7.2.4): it has each feature ps names with a value
// the predicate allows. A feature the binding does not state matches unless
// explicit asks for the features to have been stated.
func matches(ps sip.Params, f map[string]sip.Param, explicit bool) bool {
	for _, p := range ps {
		name := strings.ToLower(p.Name)
		if name == "require" || name == "explicit" {
			continue
		}
		have, ok := f[name]
		if !ok {
			if explicit {
				return false
			}
			continue
		}
		if !valueMatches(p, have) {
			return false
		}
	}
	return true
}

// valueMatches compares a predicate's value with a binding's (RFC 3840 §9,
// RFC 3841 §7.2.4): no value is TRUE; a quoted value is a string in angle
// brackets, whole, compared with case, or a list of values, of which the
// binding must have one, or, written with a leading !, lack it. Tokens and
// booleans compare without case, numbers by value: a predicate's #>=n,
// #<=n, #=n or #a:b against a binding's #=n or #n.
func valueMatches(want, have sip.Param) bool {
	haves := valuesOf(have)
	has := func(w string) bool {
		return slices.ContainsFunc(haves, func(h string) bool { return sameValue(w, h) })
	}
	for _, w := range valuesOf(want) {
		if neg, ok := strings.CutPrefix(w, "!"); ok {
			if !has(neg) {
				return true
			}
			continue
		}
		if has(w) {
			return true
		}
	}
	return false
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
		out[i] = strings.TrimSpace(out[i])
	}
	return out
}

// sameValue reports whether a binding's value h is what the predicate's
// value w asks for.
func sameValue(w, h string) bool {
	switch {
	case strings.HasPrefix(w, "<"):
		return w == h
	case strings.HasPrefix(w, "#"):
		return numberMatches(w[1:], h)
	}
	return strings.EqualFold(w, h)
}

// numberMatches reports whether a binding's numeric value h meets the
// relation rel of a predicate, "#" left out.
func numberMatches(rel, h string) bool {
	n, ok := number(strings.TrimPrefix(strings.TrimPrefix(h, "#"), "="))
	if !ok || !strings.HasPrefix(h, "#") {
		return false
	}
	at := func(s string, cmp func(a, b float64) bool) bool {
		m, ok := number(s)
		return ok && cmp(n, m)
	}
	switch {
	case strings.HasPrefix(rel, ">="):
		return at(rel[2:], func(a, b float64) bool { return a >= b })
	case strings.HasPrefix(rel, "<="):
		return at(rel[2:], func(a, b float64) bool { return a <= b })
	case strings.HasPrefix(rel, "="):
		return at(rel[1:], func(a, b float64) bool { return a == b })
	}
	lo, hi, ok := strings.Cut(rel, ":")
	return ok && at(lo, func(a, b float64) bool { return a >= b }) && at(hi, func(a, b float64) bool { return a <= b })
}

// number reads an RFC 3840 number: a sign, digits, and a fraction, no
// exponent, no infinity.
func number(s string) (float64, bool) {
	digits := strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(s, "+"), "-"), "0123456789")
	if digits == strings.TrimPrefix(strings.TrimPrefix(s, "+"), "-") {
		return 0, false // no digit before the fraction
	}
	if frac, ok := strings.CutPrefix(digits, "."); ok {
		digits = strings.TrimLeft(frac, "0123456789")
	}
	if digits != "" {
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
