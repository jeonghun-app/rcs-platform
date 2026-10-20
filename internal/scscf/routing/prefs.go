package routing

import (
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// accepted are the bindings of cs that req's caller preferences accept (RFC
// 3841 §7.2): those an Accept-Contact with require would not drop, less
// those a Reject-Contact matches. An Accept-Contact without require only
// orders the bindings in RFC 3841; here it is not used, and every binding
// left is tried by its q. RCS sets require (and explicit) on the feature
// tag of the service it asks for, so that a request reaches only the
// devices that registered it. A preference that does not parse is left
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
		if ok {
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

// valueMatches compares a predicate's value with a binding's (RFC 3840
// §9): no value is TRUE; a quoted value is a list of strings, compared with
// case, of which the binding must have one, or, written with a leading !,
// none; a token compares without case.
func valueMatches(want, have sip.Param) bool {
	if !want.Quoted {
		return strings.EqualFold(boolean(want.Value), boolean(have.Value))
	}
	haves := map[string]bool{}
	for _, v := range strings.Split(have.Value, ",") {
		haves[strings.TrimSpace(v)] = true
	}
	for _, v := range strings.Split(want.Value, ",") {
		v = strings.TrimSpace(v)
		if neg, ok := strings.CutPrefix(v, "!"); ok {
			if !haves[neg] {
				return true
			}
			continue
		}
		if haves[v] {
			return true
		}
	}
	return false
}

// boolean writes a flag (no value) as the TRUE it means.
func boolean(v string) string {
	if v == "" {
		return "TRUE"
	}
	return v
}
