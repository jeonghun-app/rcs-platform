package sip

import "strings"

// Param is one ";name=value" parameter of a header field or of a URI.
type Param struct {
	Name string
	// Value is empty for a flag such as lr. A header parameter value is stored
	// with the quotes and quoted-pairs of a quoted-string removed. A URI parameter
	// value is stored escaped, as written, because RFC 3261 §19.1.4 does not
	// treat an escaped reserved character as equal to the plain one.
	Value string
	// Quoted records that a header parameter value was, or has to be, written as
	// a quoted-string. URIs ignore it.
	Quoted bool
}

// Params is an ordered parameter list. Names are matched case-insensitively
// (RFC 3261 §7.3.1); the order and spelling of a parsed list are kept.
type Params []Param

func (ps Params) index(name string) int {
	for i := range ps {
		if strings.EqualFold(ps[i].Name, name) {
			return i
		}
	}
	return -1
}

// Get returns the value of the named parameter and whether it is present. A flag
// is present with an empty value.
func (ps Params) Get(name string) (string, bool) {
	if i := ps.index(name); i >= 0 {
		return ps[i].Value, true
	}
	return "", false
}

// Has reports whether the named parameter is present.
func (ps Params) Has(name string) bool { return ps.index(name) >= 0 }

// Set gives the named parameter a value, replacing it in place if present and
// appending it otherwise. The name must be a token; a parameter with any other
// name is written as invalidValue, so Header.Add refuses the value carrying it. The value is quoted when it is not a valid token or
// host, when it replaces a quoted value, and when the name is a feature tag:
// the RFC 3840 feature-param grammar always quotes their values.
func (ps *Params) Set(name, value string) {
	q := value == "" || !isAll(value, classGenValue) || strings.HasPrefix(name, "+")
	if i := ps.index(name); i >= 0 {
		q = q || (*ps)[i].Quoted
	}
	ps.put(Param{Name: name, Value: value, Quoted: q})
}

// SetQuoted is Set for a parameter whose grammar requires a quoted-string even
// when the value would pass as a token, such as the Reason text (RFC 3326 §2).
func (ps *Params) SetQuoted(name, value string) {
	ps.put(Param{Name: name, Value: value, Quoted: true})
}

// SetFlag adds the named parameter without a value, such as lr or rport.
func (ps *Params) SetFlag(name string) { ps.put(Param{Name: name}) }

// Del removes the named parameter.
func (ps *Params) Del(name string) {
	if i := ps.index(name); i >= 0 {
		*ps = append((*ps)[:i:i], (*ps)[i+1:]...)
	}
}

func (ps *Params) put(p Param) {
	if i := ps.index(p.Name); i >= 0 {
		(*ps)[i] = p
		return
	}
	*ps = append(*ps, p)
}

func (p Param) hasValue() bool { return p.Value != "" || p.Quoted }

// appendHeaderParams writes ps as header parameters. A value that cannot be
// written bare is quoted whatever its Quoted field says, so a list built in code
// always serializes to something that parses back.
func (ps Params) appendHeaderParams(b []byte) []byte {
	for _, p := range ps {
		b = append(b, ';')
		b = p.appendTo(b, classGenValue)
	}
	return b
}

func (p Param) appendTo(b []byte, bare uint16) []byte {
	if !isAll(p.Name, classToken) {
		return append(b, invalidValue...)
	}
	b = append(b, p.Name...)
	if !p.hasValue() {
		return b
	}
	b = append(b, '=')
	if p.Quoted || !isAll(p.Value, bare) {
		return appendQuoted(b, p.Value)
	}
	return append(b, p.Value...)
}

// parseParam reads "name [= value]" at s[i], allowing the whitespace RFC 3261
// §25.1 EQUAL permits around "=". The value is a token, a host or a
// quoted-string (gen-value).
func parseParam(s string, i int) (Param, int, error) {
	j := scanClass(s, i, classToken)
	if j == i {
		return Param{}, 0, syntaxError("empty or invalid parameter name")
	}
	p := Param{Name: s[i:j]}
	k := skipWS(s, j)
	if k >= len(s) || s[k] != '=' {
		return p, j, nil
	}
	k = skipWS(s, k+1)
	if k < len(s) && s[k] == '"' {
		v, next, ok := parseQuoted(s, k)
		if !ok {
			return Param{}, 0, syntaxError("invalid quoted parameter value")
		}
		p.Value, p.Quoted = v, true
		return p, next, nil
	}
	e := scanClass(s, k, classGenValue)
	if e == k {
		return Param{}, 0, syntaxError("empty or invalid parameter value")
	}
	p.Value = s[k:e]
	return p, e, nil
}

// maxParams bounds the parameters of one header element and the parameters and
// headers of one URI. Real IMS contacts carry about twenty.
const maxParams = 64

var errTooManyParams = syntaxError("too many parameters")

// parseParams reads a list of ";" parameters starting at s[i] and returns it with
// the index of the first byte that does not belong to it. A repeated name is an
// error: two tags or two branches leave a receiver to guess which one counts.
func parseParams(s string, i int) (Params, int, error) {
	var ps Params
	var seen nameSet
	for {
		k := skipWS(s, i)
		if k >= len(s) || s[k] != ';' {
			return ps, k, nil
		}
		p, next, err := parseParam(s, skipWS(s, k+1))
		if err != nil {
			return nil, 0, err
		}
		if len(ps) == maxParams {
			return nil, 0, errTooManyParams
		}
		if seen.add(lowerASCII(p.Name)) {
			return nil, 0, syntaxError("repeated parameter")
		}
		ps = append(ps, p)
		i = next
	}
}

// parseTrailingParams reads the parameters that end a header value and checks
// nothing follows them.
func parseTrailingParams(s string, i int) (Params, error) {
	ps, end, err := parseParams(s, i)
	if err != nil {
		return nil, err
	}
	if end != len(s) {
		return nil, syntaxError("unexpected characters after the value")
	}
	return ps, nil
}

// parseTokenParams parses `token *(SEMI generic-param)`, the shape of Event,
// Subscription-State, Reason and several other header fields.
func parseTokenParams(s string) (string, Params, error) {
	i := skipWS(s, 0)
	j := scanClass(s, i, classToken)
	if j == i {
		return "", nil, syntaxError("missing or invalid token")
	}
	ps, err := parseTrailingParams(s, j)
	if err != nil {
		return "", nil, err
	}
	return s[i:j], ps, nil
}

// nameSet finds repeated parameter names. Comparing every pair would let one
// 16 KiB field of near-identical names cost each accessor call millions of byte
// comparisons, so past a handful of names it switches to a map and the cost stays
// linear in the input.
type nameSet struct {
	small [8]string
	n     int
	m     map[string]struct{}
}

// add records key, already normalized by the caller, and reports whether it was
// there before.
func (s *nameSet) add(key string) bool {
	if s.m == nil {
		for _, k := range s.small[:s.n] {
			if k == key {
				return true
			}
		}
		if s.n < len(s.small) {
			s.small[s.n] = key
			s.n++
			return false
		}
		s.m = make(map[string]struct{}, 2*len(s.small))
		for _, k := range s.small {
			s.m[k] = struct{}{}
		}
	}
	if _, dup := s.m[key]; dup {
		return true
	}
	s.m[key] = struct{}{}
	return false
}
