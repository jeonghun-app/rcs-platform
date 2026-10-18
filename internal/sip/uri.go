package sip

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// URI is a SIP or SIPS URI (RFC 3261 §19.1), a tel URI (RFC 3966) or any other
// absolute URI, such as a urn: or im: URI, which is kept as opaque text.
//
// Components are stored as written, escapes included, so a parsed URI writes back
// the way it arrived apart from the scheme, which is lower-cased. Equal applies the
// comparison rules; plain == on the fields is not URI equality.
type URI struct {
	// Scheme is lower case: "sip", "sips", "tel" or another scheme.
	Scheme string
	// User is the user part of a SIP URI, escaped, or the number of a tel URI
	// (global with a leading "+", or local).
	User string
	// Password is the password of a SIP URI, escaped. Empty when absent.
	Password string
	// Host is the host of a SIP URI: a domain name, an IPv4 address, or an IPv6
	// reference in brackets.
	Host string
	// Port is the port of a SIP URI, 0 when absent. RFC 3261 §19.1.4 treats an
	// absent port as different from an explicit 5060, so it is never filled in.
	Port int
	// Params are the URI parameters of a SIP or tel URI, escaped.
	Params Params
	// Headers are the header components of a SIP URI ("?name=value&..."), escaped.
	Headers Params
	// Opaque is everything after "scheme:" for a scheme other than sip, sips and
	// tel, exactly as written.
	Opaque string
}

// ParseURI parses a SIP, SIPS, tel or other absolute URI.
func ParseURI(s string) (URI, error) {
	colon := strings.IndexByte(s, ':')
	if colon <= 0 || !validScheme(s[:colon]) {
		return URI{}, syntaxError("URI has no valid scheme")
	}
	scheme := strings.ToLower(s[:colon])
	rest := s[colon+1:]
	switch scheme {
	case "sip", "sips":
		return parseSIPURI(scheme, rest)
	case "tel":
		return parseTelURI(rest)
	default:
		if rest == "" || !validEscaped(rest, classURIC) {
			return URI{}, syntaxError("invalid absolute URI")
		}
		return URI{Scheme: scheme, Opaque: rest}, nil
	}
}

func validScheme(s string) bool {
	if !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if c := s[i]; !isAlnum(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func parseSIPURI(scheme, rest string) (URI, error) {
	u := URI{Scheme: scheme}
	// "@" is never allowed unescaped after the userinfo (RFC 3261 §25.1), so the
	// first one ends it. The user part may contain ";" and "?", which is why the
	// userinfo has to be split off before parameters are looked for.
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		userinfo := rest[:at]
		rest = rest[at+1:]
		user, password, _ := strings.Cut(userinfo, ":")
		if user == "" || !validEscaped(user, classUser) || !validEscaped(password, classPassword) {
			return URI{}, syntaxError("invalid userinfo in URI")
		}
		u.User, u.Password = user, password
	}

	var end int
	if strings.HasPrefix(rest, "[") {
		end = strings.IndexByte(rest, ']') + 1
		if end == 0 {
			return URI{}, syntaxError("unterminated IPv6 reference in URI")
		}
	} else if end = strings.IndexAny(rest, ":;?"); end < 0 {
		end = len(rest)
	}
	u.Host, rest = rest[:end], rest[end:]
	if !validHost(u.Host) {
		return URI{}, syntaxError("invalid host in URI")
	}

	if strings.HasPrefix(rest, ":") {
		end = strings.IndexAny(rest, ";?")
		if end < 0 {
			end = len(rest)
		}
		port, ok := parsePort(rest[1:end])
		if !ok {
			return URI{}, syntaxError("invalid port in URI")
		}
		u.Port, rest = port, rest[end:]
	}

	var seen nameSet
	if strings.HasPrefix(rest, ";") {
		paramsEnd := strings.IndexByte(rest, '?')
		if paramsEnd < 0 {
			paramsEnd = len(rest)
		}
		u.Params = make(Params, 0, min(strings.Count(rest[:paramsEnd], ";"), maxParams))
	}
	for strings.HasPrefix(rest, ";") {
		rest = rest[1:]
		end = strings.IndexAny(rest, ";?")
		if end < 0 {
			end = len(rest)
		}
		name, value, hasValue := strings.Cut(rest[:end], "=")
		rest = rest[end:]
		if name == "" || !validEscaped(name, classParam) ||
			hasValue && (value == "" || !validEscaped(value, classParam)) {
			return URI{}, syntaxError("invalid URI parameter")
		}
		if len(u.Params) == maxParams {
			return URI{}, errTooManyParams
		}
		// The key is computed once per parameter: normalizing it again for every
		// pair let a crafted Contact cost a registrar milliseconds per read.
		if seen.add(uriParamKey(name)) {
			return URI{}, syntaxError("repeated URI parameter")
		}
		u.Params = append(u.Params, Param{Name: name, Value: value})
	}

	if strings.HasPrefix(rest, "?") {
		hs := rest[1:]
		u.Headers = make(Params, 0, min(strings.Count(hs, "&")+1, maxParams))
		for more := true; more; {
			var h string
			h, hs, more = strings.Cut(hs, "&")
			name, value, ok := strings.Cut(h, "=")
			if !ok || name == "" || !validEscaped(name, classURIHeader) || !validEscaped(value, classURIHeader) {
				return URI{}, syntaxError("invalid URI header")
			}
			if len(u.Headers) == maxParams {
				return URI{}, errTooManyParams
			}
			u.Headers = append(u.Headers, Param{Name: name, Value: value})
		}
		rest = ""
	}

	if rest != "" {
		return URI{}, syntaxError("unexpected characters in URI")
	}
	return u, nil
}

func parsePort(s string) (int, bool) {
	if !isDigits(s) || len(s) > 5 {
		return 0, false
	}
	n, _ := strconv.Atoi(s)
	// Port 0 cannot address anything, and accepting it would make an explicit
	// ":0" indistinguishable from an absent port.
	return n, n > 0 && n <= 65535
}

func parseTelURI(rest string) (URI, error) {
	number := rest
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		number, rest = rest[:i], rest[i:]
	} else {
		rest = ""
	}
	u := URI{Scheme: "tel", User: number}
	var seen nameSet
	global := strings.HasPrefix(number, "+")
	if global && !isGlobalNumberDigits(number) || !global && !isLocalNumberDigits(number) {
		return URI{}, syntaxError("invalid telephone number in tel URI")
	}
	for strings.HasPrefix(rest, ";") {
		rest = rest[1:]
		end := strings.IndexByte(rest, ';')
		if end < 0 {
			end = len(rest)
		}
		name, value, hasValue := strings.Cut(rest[:end], "=")
		rest = rest[end:]
		if !isAll(name, classTelPName) || hasValue && (value == "" || !validEscaped(value, classParam)) {
			return URI{}, syntaxError("invalid tel URI parameter")
		}
		if len(u.Params) == maxParams {
			return URI{}, errTooManyParams
		}
		if seen.add(lowerASCII(name)) {
			return URI{}, syntaxError("repeated tel URI parameter")
		}
		u.Params = append(u.Params, Param{Name: name, Value: value})
	}
	// A local number means nothing without its context (RFC 3966 §5.1.5).
	if !global && !u.Params.Has("phone-context") {
		return URI{}, syntaxError("local number in tel URI without phone-context")
	}
	return u, nil
}

// isGlobalNumberDigits checks global-number-digits (RFC 3966 §3): "+", then
// digits and visual separators with at least one digit.
func isGlobalNumberDigits(s string) bool {
	if len(s) < 2 || s[0] != '+' {
		return false
	}
	digit := false
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case '0' <= c && c <= '9':
			digit = true
		case !isVisualSeparator(c):
			return false
		}
	}
	return digit
}

// isLocalNumberDigits checks local-number-digits (RFC 3966 §3): hex digits, "*",
// "#" and visual separators, with at least one that is not a separator.
func isLocalNumberDigits(s string) bool {
	digit := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isHex(c) || c == '*' || c == '#':
			digit = true
		case !isVisualSeparator(c):
			return false
		}
	}
	return digit
}

func isVisualSeparator(c byte) bool { return c == '-' || c == '.' || c == '(' || c == ')' }

// validHost checks host (RFC 3261 §25.1): a hostname, an IPv4 address, or an
// IPv6 reference in brackets.
func validHost(h string) bool {
	if h == "" {
		return false
	}
	if h[0] == '[' {
		if len(h) < 2 || h[len(h)-1] != ']' {
			return false
		}
		a, err := netip.ParseAddr(h[1 : len(h)-1])
		return err == nil && a.Is6() && a.Zone() == ""
	}
	return isIPv4(h) || isHostname(h)
}

func isIPv4(s string) bool {
	for part := 0; part < 4; part++ {
		if part > 0 {
			if s == "" || s[0] != '.' {
				return false
			}
			s = s[1:]
		}
		n, v := 0, 0
		for n < len(s) && n < 4 && '0' <= s[n] && s[n] <= '9' {
			v = v*10 + int(s[n]-'0')
			n++
		}
		if n == 0 || n > 3 || v > 255 {
			return false
		}
		s = s[n:]
	}
	return s == ""
}

// isHostname checks hostname (RFC 3261 §25.1): dot-separated labels of letters,
// digits and inner hyphens, the last starting with a letter, with an optional
// trailing dot.
func isHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	// A domain name is at most 255 octets (RFC 1035 §2.3.4).
	if s == "" || len(s) > 255 {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			if !isAlnum(s[i]) && s[i] != '-' {
				return false
			}
			continue
		}
		label := s[start:i]
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if i == len(s) && !isAlpha(label[0]) {
			return false
		}
		start = i + 1
	}
	return true
}

// Param returns the value of a URI parameter. Unlike Params.Get it compares names
// with escapes normalized, so ";%6C%72" is found as "lr" (RFC 3261 §19.1.4).
func (u URI) Param(name string) (string, bool) {
	key := uriParamKey(name)
	for _, p := range u.Params {
		// Only a name with an escape needs normalizing, which allocates.
		if strings.IndexByte(p.Name, '%') < 0 && strings.EqualFold(p.Name, key) ||
			strings.IndexByte(p.Name, '%') >= 0 && uriParamKey(p.Name) == key {
			return p.Value, true
		}
	}
	return "", false
}

func uriParamKey(name string) string { return lowerASCII(normalizeEscapes(name)) }

// IsSIP reports whether u is a SIP or SIPS URI.
func (u URI) IsSIP() bool { return u.Scheme == "sip" || u.Scheme == "sips" }

// String returns the URI as text. Characters that a component cannot carry are
// escaped. A URI with a part that has no escaped form (an invalid scheme, host,
// port or tel number, an empty parameter name, too many parameters) is written as
// invalidValue, which Header.Add refuses; a zero URI is one of those.
func (u URI) String() string {
	return string(u.appendTo(nil))
}

// writable reports whether every part of u has a valid written form. Repeated
// parameter names are left to the caller.
func (u URI) writable() bool {
	if u.Scheme == "" || !validScheme(u.Scheme) || u.Scheme != lowerASCII(u.Scheme) ||
		len(u.Params) > maxParams || len(u.Headers) > maxParams {
		return false
	}
	for _, p := range u.Params {
		if p.Name == "" {
			return false
		}
	}
	switch u.Scheme {
	case "sip", "sips":
		for _, h := range u.Headers {
			if h.Name == "" {
				return false
			}
		}
		return (u.User != "" || u.Password == "") && validHost(u.Host) && u.Port >= 0 && u.Port <= 65535
	case "tel":
		global := strings.HasPrefix(u.User, "+")
		if global && !isGlobalNumberDigits(u.User) || !global && !isLocalNumberDigits(u.User) {
			return false
		}
		for _, p := range u.Params {
			if !isAll(p.Name, classTelPName) {
				return false
			}
		}
		return global || u.Params.Has("phone-context")
	default:
		return u.Opaque != ""
	}
}

func (u URI) appendTo(b []byte) []byte {
	if !u.writable() {
		return append(b, invalidValue...)
	}
	b = append(b, u.Scheme...)
	b = append(b, ':')
	switch u.Scheme {
	case "sip", "sips":
		if u.User != "" {
			b = appendEscaped(b, u.User, classUser)
			if u.Password != "" {
				b = append(b, ':')
				b = appendEscaped(b, u.Password, classPassword)
			}
			b = append(b, '@')
		}
		b = append(b, u.Host...)
		if u.Port > 0 {
			b = append(b, ':')
			b = strconv.AppendInt(b, int64(u.Port), 10)
		}
		b = appendURIParams(b, u.Params)
		for i, h := range u.Headers {
			if i == 0 {
				b = append(b, '?')
			} else {
				b = append(b, '&')
			}
			b = appendEscaped(b, h.Name, classURIHeader)
			b = append(b, '=')
			b = appendEscaped(b, h.Value, classURIHeader)
		}
	case "tel":
		b = append(b, u.User...)
		b = appendURIParams(b, u.Params)
	default:
		b = appendEscaped(b, u.Opaque, classURIC)
	}
	return b
}

func appendURIParams(b []byte, ps Params) []byte {
	for _, p := range ps {
		b = append(b, ';')
		b = appendEscaped(b, p.Name, classParam)
		if p.Value != "" {
			b = append(b, '=')
			b = appendEscaped(b, p.Value, classParam)
		}
	}
	return b
}

// uriParamsThatMustMatch are the SIP URI parameters that RFC 3261 §19.1.4 says
// make two URIs differ when only one of them has the parameter.
var uriParamsThatMustMatch = map[string]bool{
	"user": true, "ttl": true, "method": true, "maddr": true, "transport": true,
}

// Equal reports whether u and v identify the same resource under the comparison
// rules of RFC 3261 §19.1.4 for SIP and SIPS URIs and RFC 3966 §4 for tel URIs.
// Other schemes are equal when the scheme matches and the text is identical.
//
// The relation is not transitive, as §19.1.4 points out: a parameter present in
// only one URI is ignored unless it is one of user, ttl, method, maddr and
// transport.
func (u URI) Equal(v URI) bool {
	if u.Scheme != v.Scheme {
		return false
	}
	switch u.Scheme {
	case "sip", "sips":
		return sipEqual(u, v)
	case "tel":
		return telEqual(u, v)
	default:
		return u.Opaque == v.Opaque
	}
}

func sipEqual(u, v URI) bool {
	// Userinfo compares case-sensitively; everything else does not.
	if normalizeEscapes(u.User) != normalizeEscapes(v.User) ||
		normalizeEscapes(u.Password) != normalizeEscapes(v.Password) ||
		!hostEqual(u.Host, v.Host) || u.Port != v.Port {
		return false
	}
	up, vp := normalizedParams(u.Params), normalizedParams(v.Params)
	for _, p := range up {
		q, ok := findNormalized(vp, p.key)
		if !ok {
			if uriParamsThatMustMatch[p.key] {
				return false
			}
			continue
		}
		if p.value != q {
			return false
		}
	}
	for _, q := range vp {
		if _, ok := findNormalized(up, q.key); !ok && uriParamsThatMustMatch[q.key] {
			return false
		}
	}
	// Header components are never ignored: both URIs carry the same set.
	return slices.Equal(uriHeaderKeys(u.Headers), uriHeaderKeys(v.Headers))
}

// normalizedParam is a URI parameter reduced to what RFC 3261 §19.1.4 compares:
// escapes normalized and, since parameters compare case-insensitively, lower case.
type normalizedParam struct{ key, value string }

// normalizedParams normalizes each parameter once, so comparing two URIs costs
// about as much as parsing them instead of a normalization per pair.
func normalizedParams(ps Params) []normalizedParam {
	out := make([]normalizedParam, len(ps))
	for i, p := range ps {
		out[i] = normalizedParam{key: uriParamKey(p.Name), value: lowerASCII(normalizeEscapes(p.Value))}
	}
	return out
}

func findNormalized(ps []normalizedParam, key string) (string, bool) {
	for _, p := range ps {
		if p.key == key {
			return p.value, true
		}
	}
	return "", false
}

// uriHeaderKeys returns the header components normalized and sorted, so two sets
// compare equal whatever their order.
func uriHeaderKeys(hs Params) []normalizedParam {
	keys := make([]normalizedParam, len(hs))
	for i, h := range hs {
		keys[i] = normalizedParam{key: lowerASCII(normalizeEscapes(h.Name)), value: lowerASCII(normalizeEscapes(h.Value))}
	}
	slices.SortFunc(keys, func(a, b normalizedParam) int {
		if c := strings.Compare(a.key, b.key); c != 0 {
			return c
		}
		return strings.Compare(a.value, b.value)
	})
	return keys
}

func hostEqual(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	// Two spellings of one IPv6 address ("[::1]", "[0:0::1]") are the same host.
	if strings.HasPrefix(a, "[") && strings.HasPrefix(b, "[") {
		x, errX := netip.ParseAddr(strings.Trim(a, "[]"))
		y, errY := netip.ParseAddr(strings.Trim(b, "[]"))
		return errX == nil && errY == nil && x == y
	}
	return false
}

// telEqual applies RFC 3966 §4: the numbers match once visual separators are
// removed, and both URIs carry the same parameters in any order. A phone-context
// that is a global number compares without its visual separators too.
func telEqual(u, v URI) bool {
	if !strings.EqualFold(stripVisualSeparators(u.User), stripVisualSeparators(v.User)) ||
		len(u.Params) != len(v.Params) {
		return false
	}
	up, vp := normalizedTelParams(u.Params), normalizedTelParams(v.Params)
	for _, p := range up {
		if q, ok := findNormalized(vp, p.key); !ok || q != p.value {
			return false
		}
	}
	return true
}

func normalizedTelParams(ps Params) []normalizedParam {
	out := make([]normalizedParam, len(ps))
	for i, p := range ps {
		value := lowerASCII(normalizeEscapes(p.Value))
		if out[i].key = lowerASCII(p.Name); out[i].key == "phone-context" && strings.HasPrefix(value, "+") {
			value = stripVisualSeparators(value)
		}
		out[i].value = value
	}
	return out
}

func stripVisualSeparators(s string) string {
	if strings.IndexAny(s, "-.()") < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isVisualSeparator(s[i]) {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// IsGlobalNumber reports whether u names a telephone number in global form: a tel
// URI with a global number (RFC 3966 §5.1.4), or a SIP or SIPS URI marked
// user=phone whose user part is one (RFC 3261 §19.1.6).
func (u URI) IsGlobalNumber() bool {
	number, _, ok := u.telephoneSubscriber()
	return ok && isGlobalNumberDigits(number)
}

// E164 returns the number u names as "+" and digits only, the key under which a
// tel URI and the equivalent "sip:+...;user=phone" URI are the same public
// identity. It fails for local numbers, for numbers longer than the 15 digits
// E.164 allows, and for numbers with an extension or ISDN subaddress, which name
// something other than the subscriber's number.
func (u URI) E164() (string, bool) {
	number, params, ok := u.telephoneSubscriber()
	if !ok || !isGlobalNumberDigits(number) || params.Has("ext") || params.Has("isub") {
		return "", false
	}
	digits := stripVisualSeparators(number[1:])
	if len(digits) > 15 {
		return "", false
	}
	return "+" + digits, true
}

// telephoneSubscriber returns the number and parameters of a tel URI, or of the
// telephone-subscriber in the user part of a user=phone SIP URI.
func (u URI) telephoneSubscriber() (string, Params, bool) {
	switch u.Scheme {
	case "tel":
		return u.User, u.Params, true
	case "sip", "sips":
		if v, ok := u.Param("user"); !ok || !strings.EqualFold(normalizeEscapes(v), "phone") {
			return "", nil, false
		}
		number, rest, _ := strings.Cut(unescape(u.User), ";")
		var ps Params
		for rest != "" {
			var seg string
			seg, rest, _ = strings.Cut(rest, ";")
			name, value, _ := strings.Cut(seg, "=")
			ps = append(ps, Param{Name: name, Value: value})
		}
		return number, ps, true
	}
	return "", nil, false
}
