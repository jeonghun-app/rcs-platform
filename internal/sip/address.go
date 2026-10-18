package sip

import (
	"math"
	"strings"
)

// Address is the value of From, To, Contact, Route and the other header fields
// built from a name-addr or addr-spec followed by header parameters (RFC 3261
// §20.10, §25.1).
type Address struct {
	// DisplayName is the display name with quotes and quoted-pairs resolved, or
	// a sequence of tokens joined by single spaces. Empty when absent.
	DisplayName string
	URI         URI
	// Params are the header parameters after the address, such as tag, expires
	// or a feature tag. Parameters of the URI itself are in URI.Params.
	Params Params
}

// ParseAddress parses one name-addr or addr-spec with its header parameters, the
// value of a From or To header field or one element of a Contact list.
func ParseAddress(s string) (Address, error) { return parseAddress(s, false) }

// parseAddress parses an address. nameAddrOnly refuses the bare addr-spec form,
// which Route, Record-Route, Path, Service-Route and P-Associated-URI do not
// allow.
func parseAddress(s string, nameAddrOnly bool) (Address, error) {
	var a Address
	i := skipWS(s, 0)
	if i == len(s) {
		return Address{}, syntaxError("empty address")
	}

	nameAddr := false
	if s[i] == '"' {
		name, next, ok := parseQuoted(s, i)
		if !ok {
			return Address{}, syntaxError("invalid quoted display name")
		}
		a.DisplayName = name
		i = skipWS(s, next)
		if i == len(s) || s[i] != '<' {
			return Address{}, syntaxError("display name not followed by <")
		}
		nameAddr = true
	} else {
		// An unquoted display name is a sequence of tokens (RFC 3261 §25.1). Anything
		// else before "<", such as the comma of RFC 4475 §3.1.2.15, makes this an
		// addr-spec, which then fails to parse as a URI.
		j := i
		for j < len(s) && (in(s[j], classToken) || isWS(s[j])) {
			j++
		}
		if j < len(s) && s[j] == '<' {
			a.DisplayName = strings.Join(strings.Fields(s[i:j]), " ")
			i = j
			nameAddr = true
		}
	}

	if nameAddr {
		// No whitespace is allowed just inside the angle brackets (LAQUOT and
		// RAQUOT, RFC 3261 §25.1; RFC 4475 §3.1.2.14); ParseURI refuses it.
		end := strings.IndexByte(s[i:], '>')
		if end < 0 {
			return Address{}, syntaxError("unterminated <")
		}
		u, err := ParseURI(s[i+1 : i+end])
		if err != nil {
			return Address{}, err
		}
		a.URI = u
		i += end + 1
	} else {
		if nameAddrOnly {
			return Address{}, syntaxError("address must be enclosed in <>")
		}
		// In an addr-spec the first ";" starts the header parameters, so a URI with
		// parameters, headers or a comma must use <> (RFC 3261 §20.10; RFC 4475
		// §3.1.2.13).
		end := i
		for end < len(s) && s[end] != ';' && !isWS(s[end]) {
			end++
		}
		text := s[i:end]
		if strings.ContainsAny(text, "?,") {
			return Address{}, syntaxError("URI with headers or comma must be enclosed in <>")
		}
		u, err := ParseURI(text)
		if err != nil {
			return Address{}, err
		}
		a.URI = u
		i = end
	}

	ps, err := parseTrailingParams(s, i)
	if err != nil {
		return Address{}, err
	}
	// A tag is a token (RFC 3261 §25.1 tag-param). Accepting a quoted one would
	// let "x y" into a dialog identifier and make tag="a" and tag=a the same
	// dialog for us but not for a stricter element.
	if i := ps.index("tag"); i >= 0 && (ps[i].Quoted || !isAll(ps[i].Value, classToken)) {
		return Address{}, syntaxError("invalid tag parameter")
	}
	a.Params = ps
	return a, nil
}

// Tag returns the tag parameter (RFC 3261 §19.3), or "".
func (a Address) Tag() string {
	t, _ := a.Params.Get("tag")
	return t
}

// String writes the address in name-addr form, with the display name quoted. The
// angle brackets are always written so that URI parameters cannot be mistaken
// for header parameters.
func (a Address) String() string { return string(a.appendTo(nil)) }

func (a Address) appendTo(b []byte) []byte {
	if a.DisplayName != "" {
		b = appendQuoted(b, a.DisplayName)
		b = append(b, ' ')
	}
	b = append(b, '<')
	b = a.URI.appendTo(b)
	b = append(b, '>')
	return a.Params.appendHeaderParams(b)
}

// Contact is one element of a Contact header field (RFC 3261 §20.10), or the "*"
// that removes every binding in a REGISTER (RFC 3261 §10.2.2).
type Contact struct {
	Star bool
	Address
}

// The contact parameters below are checked when read rather than when the Contact
// field is parsed. A registrar treats a malformed expires as 3600 and may treat
// an overlarge one as 2^32-1 (RFC 3261 §10.2; RFC 4475 §3.1.2.4), which it could
// not do if one bad parameter failed the whole Contact list. All of them are
// numbers, so a quoted value is malformed.

// Expires returns the expires parameter in seconds. present is false when there
// is none. err wraps ErrOutOfRange, with seconds set to 2^32-1, when the value is
// a number above 2^32-1, and ErrMalformed when it is not a number.
func (c Contact) Expires() (seconds uint32, present bool, err error) {
	p, ok := c.param("expires")
	if !ok {
		return 0, false, nil
	}
	n, err := deltaSeconds("Contact", p)
	return n, true, err
}

func (c Contact) param(name string) (Param, bool) {
	if i := c.Params.index(name); i >= 0 {
		return c.Params[i], true
	}
	return Param{}, false
}

// deltaSeconds reads an expires value for the accessors of the named header.
func deltaSeconds(header string, p Param) (uint32, error) {
	n, overlarge, ok := parseDeltaSeconds(p.Value)
	switch {
	case !ok || p.Quoted:
		return 0, headerError(header, "invalid expires value")
	case overlarge:
		return n, &ParseError{Header: header, Reason: "expires value above 2^32-1", Err: ErrOutOfRange}
	}
	return n, nil
}

// Q returns the q parameter in thousandths (q=0.5 is 500). Thousandths are exact,
// which a float is not, and a qvalue has at most three decimals (RFC 3261 §25.1).
// present is false when there is none; err wraps ErrMalformed when it is not a
// qvalue.
func (c Contact) Q() (thousandths int, present bool, err error) {
	p, ok := c.param("q")
	if !ok {
		return 0, false, nil
	}
	q, valid := parseQValue(p.Value)
	if !valid || p.Quoted {
		return 0, true, headerError("Contact", "invalid q parameter")
	}
	return q, true, nil
}

// Instance returns the +sip.instance parameter (RFC 5626 §4.1) without its
// quotes, for example "<urn:uuid:...>", and whether it is present.
func (c Contact) Instance() (string, bool) { return c.Params.Get("+sip.instance") }

// RegID returns the reg-id parameter (RFC 5626 §4.2). present is false when there
// is none; err wraps ErrMalformed when it is outside 1 to 2^31-1 (RFC 5626 §10).
func (c Contact) RegID() (id uint32, present bool, err error) {
	p, ok := c.param("reg-id")
	if !ok {
		return 0, false, nil
	}
	n, valid := parseDelta(p.Value)
	if !valid || p.Quoted || n == 0 || n >= 1<<31 {
		return 0, true, headerError("Contact", "invalid reg-id parameter")
	}
	return n, true, nil
}

// String writes the contact; see Address.String.
func (c Contact) String() string {
	if c.Star {
		return "*"
	}
	return c.Address.String()
}

// ParseContacts parses a Contact header field value.
func ParseContacts(s string) ([]Contact, error) {
	els, err := splitList(s)
	if err != nil {
		return nil, err
	}
	return parseContactElements(els)
}

func parseContactElements(els []string) ([]Contact, error) {
	out := make([]Contact, 0, len(els))
	for _, el := range els {
		if el == "*" {
			// STAR is the whole value or nothing (RFC 3261 §20.10).
			if len(els) != 1 {
				return nil, syntaxError("* combined with other contacts")
			}
			return []Contact{{Star: true}}, nil
		}
		a, err := parseAddress(el, false)
		if err != nil {
			return nil, err
		}
		out = append(out, Contact{Address: a})
	}
	return out, nil
}

// parseQValue parses a qvalue (RFC 3261 §25.1) into thousandths.
func parseQValue(s string) (int, bool) {
	if s == "" || s[0] != '0' && s[0] != '1' {
		return 0, false
	}
	whole := int(s[0]-'0') * 1000
	if len(s) == 1 {
		return whole, true
	}
	if s[1] != '.' || len(s) > 5 {
		return 0, false
	}
	frac := 0
	for i, scale := 2, 100; i < len(s); i, scale = i+1, scale/10 {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		frac += int(s[i]-'0') * scale
	}
	if whole == 1000 && frac != 0 {
		return 0, false
	}
	return whole + frac, true
}

// parseDelta parses delta-seconds (RFC 3261 §25.1), which is at most 2^32-1
// (RFC 3261 §20.19).
func parseDelta(s string) (uint32, bool) {
	n, overlarge, ok := parseDeltaSeconds(s)
	return n, ok && !overlarge
}

// parseDeltaSeconds parses delta-seconds and tells an overlarge value, returned
// as 2^32-1, apart from one that is not a number at all.
func parseDeltaSeconds(s string) (n uint32, overlarge, ok bool) {
	if !isDigits(s) {
		return 0, false, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v*10 + uint64(s[i]-'0')
		if v > math.MaxUint32 {
			return math.MaxUint32, true, true
		}
	}
	return uint32(v), false, true
}
