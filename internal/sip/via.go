package sip

import (
	"net/netip"
	"strconv"
	"strings"
)

// MagicCookie starts every branch parameter generated under RFC 3261, which is
// how an element tells such a branch from one of an RFC 2543 implementation
// (RFC 3261 §8.1.1.7).
const MagicCookie = "z9hG4bK"

// Via is one element of a Via header field (RFC 3261 §20.42). Only SIP/2.0 is
// accepted, so the protocol name and version are not stored.
type Via struct {
	// Transport is the transport as written, such as "UDP", "TCP" or "TLS".
	// Transport names compare case-insensitively.
	Transport string
	// Host is the sent-by host: a domain name, an IPv4 address or an IPv6
	// reference in brackets.
	Host string
	// Port is the sent-by port, 0 when absent.
	Port   int
	Params Params
}

// ParseVia parses a Via header field value, which may hold several elements.
func ParseVia(s string) ([]Via, error) {
	els, err := splitList(s)
	if err != nil {
		return nil, err
	}
	out := make([]Via, 0, len(els))
	for _, el := range els {
		v, err := parseViaElement(el)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// parseViaElement parses via-parm. The grammar allows whitespace around each "/"
// of sent-protocol and around the ":" of sent-by (SLASH and COLON, RFC 3261
// §25.1), which RFC 4475 §3.1.1.1 exercises.
func parseViaElement(s string) (Via, error) {
	var v Via
	i := skipWS(s, 0)
	var parts [3]string
	for n := range parts {
		if n > 0 {
			if i >= len(s) || s[i] != '/' {
				return Via{}, syntaxError("invalid sent-protocol in Via")
			}
			i = skipWS(s, i+1)
		}
		j := scanClass(s, i, classToken)
		if j == i {
			return Via{}, syntaxError("invalid sent-protocol in Via")
		}
		parts[n] = s[i:j]
		i = skipWS(s, j)
	}
	if !strings.EqualFold(parts[0], "SIP") || parts[1] != "2.0" {
		return Via{}, syntaxError("Via names a protocol other than SIP/2.0")
	}
	v.Transport = parts[2]
	if i == len(s) || !isWS(s[i-1]) {
		return Via{}, syntaxError("missing sent-by in Via")
	}

	var j int
	if s[i] == '[' {
		j = strings.IndexByte(s[i:], ']')
		if j < 0 {
			return Via{}, syntaxError("unterminated IPv6 reference in Via")
		}
		j += i + 1
	} else {
		j = i
		for j < len(s) && (isAlnum(s[j]) || s[j] == '.' || s[j] == '-') {
			j++
		}
	}
	v.Host = s[i:j]
	if !validHost(v.Host) {
		return Via{}, syntaxError("invalid sent-by host in Via")
	}
	i = skipWS(s, j)
	if i < len(s) && s[i] == ':' {
		i = skipWS(s, i+1)
		j = i
		for j < len(s) && '0' <= s[j] && s[j] <= '9' {
			j++
		}
		port, ok := parsePort(s[i:j])
		if !ok {
			return Via{}, syntaxError("invalid sent-by port in Via")
		}
		v.Port = port
		i = j
	}

	ps, err := parseTrailingParams(s, i)
	if err != nil {
		return Via{}, err
	}
	if err := checkViaParams(ps); err != nil {
		return Via{}, err
	}
	v.Params = ps
	return v, nil
}

// checkViaParams validates the parameters RFC 3261 §20.42 and RFC 3581 give a
// meaning to, so the accessors on Via cannot meet a malformed value.
func checkViaParams(ps Params) error {
	// None of these values may be quoted: their grammar is a token, a number or
	// an address.
	for _, p := range ps {
		switch lowerASCII(p.Name) {
		case "branch":
			if p.Quoted || !isAll(p.Value, classToken) {
				return syntaxError("invalid branch parameter in Via")
			}
		case "ttl":
			if n, valid := parseDelta(p.Value); p.Quoted || !valid || n > 255 || len(p.Value) > 3 {
				return syntaxError("invalid ttl parameter in Via")
			}
		case "maddr":
			if p.Quoted || !validHost(p.Value) {
				return syntaxError("invalid maddr parameter in Via")
			}
		case "received":
			if p.Quoted || !isIPv4(p.Value) && !isIPv6(p.Value) {
				return syntaxError("invalid received parameter in Via")
			}
		case "rport":
			// A request carries rport as a flag; the response gets the port filled in
			// (RFC 3581 §4).
			if _, valid := parsePort(p.Value); p.Quoted || p.Value != "" && !valid {
				return syntaxError("invalid rport parameter in Via")
			}
		}
	}
	return nil
}

// isIPv6 accepts an IPv6 address with or without brackets: received carries a bare
// IPv6address in RFC 3261 §20.42, but RFC 5118 §4.5 notes implementations that
// bracket it.
func isIPv6(s string) bool {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6() && a.Zone() == ""
}

// Branch returns the branch parameter, or "".
func (v Via) Branch() string {
	b, _ := v.Params.Get("branch")
	return b
}

// HasMagicCookie reports whether the branch was generated under RFC 3261, so the
// transaction can be matched on it alone (RFC 3261 §17.2.3).
func (v Via) HasMagicCookie() bool { return strings.HasPrefix(v.Branch(), MagicCookie) }

// Received returns the received parameter (RFC 3261 §18.2.1), or "".
func (v Via) Received() string {
	r, _ := v.Params.Get("received")
	return r
}

// RPort returns the rport parameter (RFC 3581). present reports the parameter at
// all; port is 0 when it is the flag a client sends.
func (v Via) RPort() (port int, present bool) {
	r, ok := v.Params.Get("rport")
	if !ok {
		return 0, false
	}
	port, _ = parsePort(r)
	return port, true
}

// MAddr returns the maddr parameter, or "".
func (v Via) MAddr() string {
	m, _ := v.Params.Get("maddr")
	return m
}

// TTL returns the ttl parameter and whether it is present.
func (v Via) TTL() (int, bool) {
	t, ok := v.Params.Get("ttl")
	if !ok {
		return 0, false
	}
	n, _ := strconv.Atoi(t)
	return n, true
}

// String writes the Via element in canonical form, or invalidValue if Transport
// is not a token, Host not a valid host or Port not a port.
func (v Via) String() string {
	if !isAll(v.Transport, classToken) || !validHost(v.Host) || v.Port < 0 || v.Port > 65535 {
		return invalidValue
	}
	b := make([]byte, 0, 64)
	b = append(b, "SIP/2.0/"...)
	b = append(b, v.Transport...)
	b = append(b, ' ')
	b = append(b, v.Host...)
	if v.Port > 0 {
		b = append(b, ':')
		b = strconv.AppendInt(b, int64(v.Port), 10)
	}
	return string(v.Params.appendHeaderParams(b))
}
