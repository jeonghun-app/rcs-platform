package cpim

import (
	"slices"
	"strings"
)

// scope tracks the namespace bindings in force while walking the headers
// (RFC 3862 §3.4).
type scope struct {
	def      string
	prefixes map[string]string
}

func newScope() *scope {
	return &scope{def: CoreNamespace, prefixes: map[string]string{}}
}

func (s *scope) resolve(name string) (ns, local string, err error) {
	prefix, local, ok := strings.Cut(name, ".")
	if !ok {
		return s.def, name, nil
	}
	ns, ok = s.prefixes[prefix]
	if !ok {
		// §3.4: a prefix must be declared before it is used.
		return "", local, reject(ReasonNamespace, "namespace prefix used before its NS header")
	}
	return ns, local, nil
}

// declare applies an NS header value: [Name-prefix [SP]] "<" URI ">" (§4.6).
// The grammar has no space before "<" but every example has one, so a single
// space is accepted.
func (s *scope) declare(value string) error {
	prefix, uri, ok := strings.Cut(value, "<")
	if !ok || !strings.HasSuffix(uri, ">") {
		return reject(ReasonNamespace, "NS value is not [prefix] <URI>")
	}
	uri = uri[:len(uri)-1]
	prefix = strings.TrimSuffix(prefix, " ")
	if prefix != "" && !isName(prefix) {
		return reject(ReasonNamespace, "invalid namespace prefix")
	}
	// §3.4: a namespace is an absolute URI without a fragment.
	if !isAbsoluteURI(uri) || strings.ContainsRune(uri, '#') {
		return reject(ReasonNamespace, "namespace is not an absolute URI")
	}
	if prefix == "" {
		s.def = uri
	} else {
		s.prefixes[prefix] = uri
	}
	return nil
}

// prefixFor returns the prefix under which a header in ns can be appended, ""
// for the default namespace. When several prefixes are bound to ns the
// smallest is chosen so the result does not depend on map order.
func (s *scope) prefixFor(ns string) (string, bool) {
	if s.def == ns {
		return "", true
	}
	var found []string
	for p, u := range s.prefixes {
		if u == ns {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return "", false
	}
	return slices.Min(found), true
}
