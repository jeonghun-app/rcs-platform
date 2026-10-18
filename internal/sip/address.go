package sip

import "strings"

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

// Expires returns the expires parameter in seconds and whether it is present.
func (c Contact) Expires() (uint32, bool) {
	v, ok := c.Params.Get("expires")
	if !ok {
		return 0, false
	}
	n, _ := parseDelta(v) // validated by parseContact
	return n, true
}

// Q returns the q parameter in thousandths (q=0.5 is 500) and whether it is
// present. Thousandths are exact, which a float is not, and qvalue has at most
// three decimals (RFC 3261 §20.10).
func (c Contact) Q() (int, bool) {
	v, ok := c.Params.Get("q")
	if !ok {
		return 0, false
	}
	q, _ := parseQValue(v)
	return q, true
}

// Instance returns the +sip.instance parameter (RFC 5626 §4.1) without its
// quotes, for example "<urn:uuid:...>", and whether it is present.
func (c Contact) Instance() (string, bool) { return c.Params.Get("+sip.instance") }

// RegID returns the reg-id parameter (RFC 5626 §4.2) and whether it is present.
func (c Contact) RegID() (uint32, bool) {
	v, ok := c.Params.Get("reg-id")
	if !ok {
		return 0, false
	}
	n, _ := parseDelta(v)
	return n, true
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
		if err := checkContactParams(a.Params); err != nil {
			return nil, err
		}
		out = append(out, Contact{Address: a})
	}
	return out, nil
}

// checkContactParams validates the parameters Contact gives a meaning to, so the
// accessors on Contact cannot meet a malformed value. An overlarge expires is
// refused rather than clamped (RFC 4475 §3.1.2.4).
func checkContactParams(ps Params) error {
	if v, ok := ps.Get("expires"); ok {
		if _, ok := parseDelta(v); !ok {
			return syntaxError("invalid expires parameter")
		}
	}
	if v, ok := ps.Get("q"); ok {
		if _, ok := parseQValue(v); !ok {
			return syntaxError("invalid q parameter")
		}
	}
	if v, ok := ps.Get("reg-id"); ok {
		// reg-id is 1 to 2^31-1 (the RFC 5626 grammar).
		if n, ok := parseDelta(v); !ok || n == 0 || n >= 1<<31 {
			return syntaxError("invalid reg-id parameter")
		}
	}
	return nil
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
	if !isDigits(s) {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		n = n*10 + uint64(s[i]-'0')
		if n > 1<<32-1 {
			return 0, false
		}
	}
	return uint32(n), true
}
