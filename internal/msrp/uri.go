package msrp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// URI is an MSRP or MSRPS URI (RFC 4975 §6, grammar in §9). It names one
// session at one MSRP node when SessionID is set, and the node itself
// otherwise.
type URI struct {
	// Secure is true for the msrps scheme, which requires TLS (§6).
	Secure bool
	// User is the optional userinfo part. It never takes part in comparison
	// (§6.1) and may not carry a password (§6).
	User string
	// Host is a host name, an IPv4 address or an IPv6 address without the
	// brackets.
	Host string
	// Port is the explicit port, or 0 when the URI has none.
	Port int
	// SessionID is compared case-sensitively (§6.1).
	SessionID string
	// Transport is the transport parameter; "tcp" for everything this
	// package speaks, TLS included (§6).
	Transport string
	// Params are the URI parameters after the transport, in order.
	Params []Param
}

// Param is one URI parameter: a token with an optional token value.
type Param struct {
	Name  string
	Value string
}

// ErrInvalidURI reports an MSRP URI that does not follow RFC 4975 §9.
var ErrInvalidURI = errors.New("msrp: invalid URI")

// uriError leaves the URI itself out of the message: it carries the
// session-id, which is a secret (ADR 0004), and often a client address, and
// errors tend to end up in logs.
func uriError(why string) error {
	return fmt.Errorf("%w: %s", ErrInvalidURI, why)
}

// ParseURI parses one MSRP URI.
func ParseURI(s string) (URI, error) {
	var u URI
	rest, ok := cutPrefixFold(s, "msrps://")
	if ok {
		u.Secure = true
	} else if rest, ok = cutPrefixFold(s, "msrp://"); !ok {
		return URI{}, uriError("scheme must be msrp or msrps")
	}

	// The authority ends at the session-id or at the mandatory transport.
	// ";" may appear in an RFC 3986 reg-name, but not in an MSRP authority,
	// because it starts the transport parameter here.
	end := strings.IndexAny(rest, "/;")
	if end < 0 {
		return URI{}, uriError("transport parameter missing")
	}
	if err := u.parseAuthority(rest[:end]); err != nil {
		return URI{}, uriError(err.Error())
	}
	rest = rest[end:]

	if strings.HasPrefix(rest, "/") {
		semi := strings.IndexByte(rest, ';')
		if semi < 0 {
			return URI{}, uriError("transport parameter missing")
		}
		u.SessionID = rest[1:semi]
		if !validSessionID(u.SessionID) {
			return URI{}, uriError("invalid session-id")
		}
		rest = rest[semi:]
	}

	params := strings.Split(rest[1:], ";")
	u.Transport = params[0]
	if u.Transport == "" || !isAlphanumeric(u.Transport) {
		return URI{}, uriError("invalid transport")
	}
	for _, p := range params[1:] {
		name, value, hasValue := strings.Cut(p, "=")
		if !isToken(name) || (hasValue && !isToken(value)) {
			return URI{}, uriError("invalid URI parameter")
		}
		u.Params = append(u.Params, Param{Name: name, Value: value})
	}
	return u, nil
}

func (u *URI) parseAuthority(a string) error {
	if at := strings.LastIndexByte(a, '@'); at >= 0 {
		u.User = a[:at]
		a = a[at+1:]
		if strings.ContainsRune(u.User, ':') {
			return errors.New("userinfo must not contain a password")
		}
		if !validRegName(u.User) {
			return errors.New("invalid userinfo")
		}
	}

	host, port := a, ""
	if strings.HasPrefix(a, "[") {
		closing := strings.IndexByte(a, ']')
		if closing < 0 {
			return errors.New("unterminated IPv6 literal")
		}
		host = a[1:closing]
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return errors.New("invalid IPv6 literal")
		}
		switch after := a[closing+1:]; {
		case after == "":
		case strings.HasPrefix(after, ":"):
			port = after[1:]
			if port == "" {
				return errors.New("empty port")
			}
		default:
			return errors.New("junk after IPv6 literal")
		}
	} else if colon := strings.LastIndexByte(a, ':'); colon >= 0 {
		host, port = a[:colon], a[colon+1:]
		if port == "" {
			return errors.New("empty port")
		}
	}
	if host == "" {
		return errors.New("empty host")
	}
	if !strings.HasPrefix(a, "[") && !validRegName(host) {
		return errors.New("invalid host")
	}
	u.Host = host
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || !isDigits(port) {
			return errors.New("invalid port")
		}
		u.Port = n
	}
	// §6: a numeric host must come with a port.
	if _, err := netip.ParseAddr(host); err == nil && u.Port == 0 {
		return errors.New("an IP address needs a port")
	}
	return nil
}

// String formats u in the form ParseURI accepts.
func (u URI) String() string {
	var b strings.Builder
	if u.Secure {
		b.WriteString("msrps://")
	} else {
		b.WriteString("msrp://")
	}
	if u.User != "" {
		b.WriteString(u.User)
		b.WriteByte('@')
	}
	if strings.IndexByte(u.Host, ':') >= 0 {
		b.WriteByte('[')
		b.WriteString(u.Host)
		b.WriteByte(']')
	} else {
		b.WriteString(u.Host)
	}
	if u.Port != 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(u.Port))
	}
	if u.SessionID != "" {
		b.WriteByte('/')
		b.WriteString(u.SessionID)
	}
	b.WriteByte(';')
	b.WriteString(u.Transport)
	for _, p := range u.Params {
		b.WriteByte(';')
		b.WriteString(p.Name)
		if p.Value != "" {
			b.WriteByte('=')
			b.WriteString(p.Value)
		}
	}
	return b.String()
}

// Equal compares u and v by the rules of RFC 4975 §6.1: the scheme and the
// transport case-insensitively, IP addresses by value, host names
// case-insensitively after percent-decoding, the port and the session-id
// exactly. Userinfo and URI parameters are ignored.
func (u URI) Equal(v URI) bool {
	return u.Secure == v.Secure &&
		u.Port == v.Port &&
		u.SessionID == v.SessionID &&
		strings.EqualFold(u.Transport, v.Transport) &&
		hostKey(u.Host) == hostKey(v.Host)
}

// Addr returns the host:port to dial for u. §6.2 needs no resolution step
// for the port because every URI exchanged in SDP carries one.
func (u URI) Addr() (string, error) {
	if u.Port == 0 {
		return "", uriError("no port to connect to")
	}
	return net.JoinHostPort(u.Host, strconv.Itoa(u.Port)), nil
}

// connKey identifies the connection u is reached over: the same scheme, host
// and port share a connection (§5.4).
func (u URI) connKey() string {
	scheme := "msrp"
	if u.Secure {
		scheme = "msrps"
	}
	return scheme + "|" + hostKey(u.Host) + "|" + strconv.Itoa(u.Port)
}

// valid reports whether u survives a round trip through String and
// ParseURI unchanged, so a message built from it is well formed on the wire.
func (u URI) valid() bool {
	s := u.String()
	p, err := ParseURI(s)
	return err == nil && p.String() == s
}

// hostKey normalises a host for comparison: IP addresses in canonical form,
// names lower-cased with percent-encoded unreserved characters decoded
// (§6.1 rule 2).
func hostKey(h string) string {
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap().String()
	}
	var b strings.Builder
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c == '%' && i+2 < len(h) {
			if v, err := strconv.ParseUint(h[i+1:i+3], 16, 8); err == nil && isUnreserved(byte(v)) {
				c = byte(v)
				i += 2
			}
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// validRegName accepts RFC 3986 reg-name characters (unreserved,
// pct-encoded, sub-delims) except ";", which ends an MSRP authority.
func validRegName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isUnreserved(c):
		case strings.IndexByte("!$&'()*+,=", c) >= 0:
		case c == '%':
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

// validSessionID follows the §9 session-id rule.
func validSessionID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isUnreserved(c) && c != '+' && c != '=' && c != '/' {
			return false
		}
	}
	return true
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

func isUnreserved(c byte) bool {
	return isAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || isDigit(c)
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isAlphanumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) {
			return false
		}
	}
	return true
}

// isToken follows the §9 token rule.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c == 0x21 || 0x23 <= c && c <= 0x27 || c == 0x2a || c == 0x2b ||
			c == 0x2d || c == 0x2e || isDigit(c) || 'A' <= c && c <= 'Z' ||
			0x5e <= c && c <= 0x7e
		if !ok {
			return false
		}
	}
	return true
}
