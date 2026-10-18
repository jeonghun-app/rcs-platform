package sdp

import (
	"errors"
	"fmt"
	"strings"
)

// ErrNoAttribute is returned, wrapped with the attribute name, by the typed
// getters when the attribute is absent.
var ErrNoAttribute = errors.New("sdp: attribute not present")

// Attributes is an ordered list of a= lines.
//
// Names are matched case-insensitively. The attributes this package
// interprets are defined in ABNF with quoted literals, which RFC 5234 §2.3
// makes case-insensitive, and matching the same way for unknown names keeps
// the lookup rule uniform.
type Attributes []Attribute

// Get returns the value of the first attribute called name.
func (as Attributes) Get(name string) (value string, ok bool) {
	for _, a := range as {
		if strings.EqualFold(a.Name, name) {
			return a.Value, true
		}
	}
	return "", false
}

// Values returns the value of every attribute called name, in order.
func (as Attributes) Values(name string) []string {
	var vs []string
	for _, a := range as {
		if strings.EqualFold(a.Name, name) {
			vs = append(vs, a.Value)
		}
	}
	return vs
}

// Has reports whether an attribute called name is present.
func (as Attributes) Has(name string) bool {
	_, ok := as.Get(name)
	return ok
}

// Set makes name occur exactly once with value. The first occurrence is
// replaced where it stands, so the order of the other lines is untouched;
// later occurrences are removed. If name is absent it is appended.
func (as *Attributes) Set(name, value string) {
	as.replace(func(a Attribute) bool { return strings.EqualFold(a.Name, name) }, Attribute{Name: name, Value: value})
}

// Add appends an attribute, keeping any existing ones with the same name.
func (as *Attributes) Add(name, value string) {
	*as = append(*as, Attribute{Name: name, Value: value})
}

// Remove deletes every attribute called name.
func (as *Attributes) Remove(name string) {
	*as = as.filter(func(a Attribute) bool { return !strings.EqualFold(a.Name, name) })
}

// replace puts with in place of the first attribute matching match, drops
// the other matches, and appends with if nothing matched.
func (as *Attributes) replace(match func(Attribute) bool, with Attribute) {
	out := make(Attributes, 0, len(*as)+1)
	done := false
	for _, a := range *as {
		switch {
		case !match(a):
			out = append(out, a)
		case !done:
			out = append(out, with)
			done = true
		}
	}
	if !done {
		out = append(out, with)
	}
	*as = out
}

func (as Attributes) filter(keep func(Attribute) bool) Attributes {
	var out Attributes
	for _, a := range as {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

// single returns the value of an attribute that may occur at most once.
func (as Attributes) single(name string) (string, error) {
	vs := as.Values(name)
	switch len(vs) {
	case 0:
		return "", fmt.Errorf("%w: a=%s", ErrNoAttribute, name)
	case 1:
		return vs[0], nil
	default:
		return "", fmt.Errorf("sdp: a=%s: more than one line", name)
	}
}

// singleValue is single for an attribute that must carry a value.
func (as Attributes) singleValue(name string) (string, error) {
	v, err := as.single(name)
	if err == nil && v == "" {
		err = fmt.Errorf("sdp: a=%s: value missing", name)
	}
	return v, err
}
