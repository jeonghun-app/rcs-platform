package pii

import (
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
)

// A client's IP address is personal data: with a time it points at one
// subscriber's line. Logs keep only the network it belongs to, enough to see
// which operator, region or NAT pool traffic came from; full addresses stay in
// memory, where flows need them.
const (
	// clientIPv4Bits keeps the /24 of an IPv4 address, the usual unit of
	// assignment below which an address picks out a customer.
	clientIPv4Bits = 24
	// clientIPv6Bits keeps the /48 of an IPv6 address, the size of one end
	// site's assignment (RFC 6177 §2); a /64 can still be one subscriber.
	clientIPv6Bits = 48
)

// ClientIP returns a log attribute holding the client address v truncated by
// [TruncateIP].
func ClientIP(key, v string) slog.Attr { return slog.String(key, TruncateIP(v)) }

// sixToFour is 2002::/16, whose addresses carry a whole IPv4 address in bits
// 16 to 47 (RFC 3056 §2): their /48 would log that address, so only the /16
// is kept.
var sixToFour = netip.MustParsePrefix("2002::/16")

// TruncateIP returns the network a client address belongs to, in prefix
// notation: 192.0.2.0/24 for an IPv4 address, 2001:db8:5::/48 for an IPv6 one,
// 2002::/16 for a 6to4 one. Every address is truncated, private, loopback and
// link-local ones included: a UE on an operator's APN often has an RFC 1918
// address, and the interface ID of a link-local or unique local IPv6 address
// can be the device's MAC address.
//
// v may be an address, address:port or [address]:port, with or without a
// zone; the port and zone are dropped, and an IPv4-mapped IPv6 address is
// truncated as the IPv4 address it carries. An IPv4 address may have leading
// zeros in its parts ("192.000.002.001"), as SIP's IPv4address allows
// (RFC 3261 §25.1). Anything else is masked whole, since it cannot be told
// apart from an identifier.
func TruncateIP(v string) string {
	ip, ok := parseIP(v)
	if !ok {
		return mark
	}
	if sixToFour.Contains(ip) {
		return sixToFour.String()
	}
	bits := clientIPv6Bits
	if ip.Is4() {
		bits = clientIPv4Bits
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return mark
	}
	return p.String()
}

// parseIP reads an address in any of the forms TruncateIP accepts, without
// its zone and unmapped.
func parseIP(v string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().WithZone("").Unmap(), true
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	if ip, err := netip.ParseAddr(bare); err == nil {
		return ip.WithZone("").Unmap(), true
	}
	// An IPv6 address ending in a dotted quad with leading zeros, which
	// netip refuses as it refuses them alone (::ffff:010.000.000.001).
	if i := strings.LastIndexByte(bare, ':'); i >= 0 && strings.Contains(bare[i:], ".") {
		if q, ok := parseDottedQuad(bare[i+1:]); ok {
			if ip, err := netip.ParseAddr(bare[:i+1] + q.String()); err == nil {
				return ip.WithZone("").Unmap(), true
			}
		}
	}
	host, port, found := strings.Cut(v, ":")
	if found && (port == "" || strings.Trim(port, "0123456789") != "") {
		return netip.Addr{}, false
	}
	return parseDottedQuad(host)
}

// parseDottedQuad reads four decimal parts of one to three digits, each 255
// at most, leading zeros allowed, as SIP's IPv4address (RFC 3261 §25.1);
// netip refuses leading zeros, which other parsers read as octal.
func parseDottedQuad(s string) (netip.Addr, bool) {
	var b [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 3 || strings.Trim(part, "0123456789") != "" {
			return netip.Addr{}, false
		}
		n := 0
		for _, c := range part {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// TruncateIPsIn returns s with each IP address in it written as
// [TruncateIP] writes it: an IPv6 address, bare or bracketed (its brackets
// kept and its port dropped), and a dotted-quad IPv4 address, with its port
// if it has one. It is for free text a service cannot structure, such as
// net/http's error lines ("TLS handshake error from 203.0.113.5:51234").
// An address is a token of its own: one inside a longer word or number
// (go1.2.3.4, 1.2.3.4.5) is not one. A network already as wide as a
// truncated one or wider, written with its length (10.0.0.0/8), is left as
// written, so that the function is idempotent and a configured network
// still reads as configured.
func TruncateIPsIn(s string) string {
	return truncateIPv4In(truncateIPv6In(s))
}

// truncateIPv6In truncates the IPv6 addresses of s: "[address]" with or
// without ":port", and a bare one, a token with two colons or more.
func truncateIPv6In(s string) string {
	t := newRewriter(s)
	for i := 0; i < len(s); {
		if s[i] == '[' {
			if end, ip, ok := bracketedAt(s, i); ok {
				// The brackets stay, so that the network reads as one
				// whatever sticks to it; the port goes.
				t.replace(i, end, "["+TruncateIP(ip)+"]")
				i = end
				continue
			}
			i++
			continue
		}
		// A token starts after a separator, or after a word's colon
		// (host:2001:db8::1); not after "/", where a prefix length or a
		// path goes on.
		start := i
		switch {
		case !tokenByte(s[i]) || i > 0 && (tokenByte(s[i-1]) || s[i-1] == '/'):
			i++
			continue
		case i > 0 && wordByte(s[i-1]):
			if s[i] != ':' {
				i++
				continue
			}
			start = i + 1
		}
		j := i
		for j < len(s) && tokenByte(s[j]) {
			j++
		}
		if j < len(s) && wordByte(s[j]) || j-start > maxAddressToken || strings.Count(s[start:j], ":") < 2 {
			i = j
			continue
		}
		// An IPv4 address with what follows it is the next pass's, and so
		// is a dotted quad at the end of one with a length after it, which
		// that pass truncated or keeps (::ffff:192.0.2.0/24).
		if n, ok := addressPrefix(s[start:j]); ok && strings.Contains(s[start:start+n], ":") &&
			!(strings.Contains(s[start:start+n], ".") && start+n < len(s) && s[start+n] == '/') {
			i = t.address(start, n)
			continue
		}
		i = j
	}
	return t.result()
}

// truncateIPv4In truncates the dotted-quad IPv4 addresses of s, each with
// its ":port" if it has one: four parts of digits and dots, not part of a
// longer word or of a longer dotted number.
func truncateIPv4In(s string) string {
	t := newRewriter(s)
	for i := 0; i < len(s); {
		if !digit(s[i]) || i > 0 && (wordByte(s[i-1]) || s[i-1] == '.') {
			i++
			continue
		}
		j := i
		for j < len(s) && (digit(s[j]) || s[j] == '.') {
			j++
		}
		run := strings.TrimRight(s[i:j], ".")
		end := i + len(run)
		// The dots after the run end a sentence only if no word follows.
		if j < len(s) && wordByte(s[j]) || end < j && j-end > 1 {
			i = j
			continue
		}
		if len(run) > maxAddressToken {
			i = j
			continue
		}
		if _, ok := parseDottedQuad(run); !ok {
			i = j
			continue
		}
		n := len(run)
		if end == j && end+1 < len(s) && s[end] == ':' {
			p := end + 1
			for p < len(s) && digit(s[p]) {
				p++
			}
			if p > end+1 && p-end <= 6 && (p == len(s) || !wordByte(s[p]) && s[p] != '.') {
				n = p - i
			}
		}
		i = t.address(i, n)
	}
	return t.result()
}

// A rewriter builds a copy of s with some of its spans replaced, in order.
type rewriter struct {
	s    string
	b    strings.Builder
	last int
}

func newRewriter(s string) *rewriter { return &rewriter{s: s} }

func (t *rewriter) replace(from, to int, with string) {
	t.b.WriteString(t.s[t.last:from])
	t.b.WriteString(with)
	t.last = to
}

// address truncates the address of n bytes at s[at:], with the length
// after it if one follows, and returns where it ends.
func (t *rewriter) address(at, n int) int {
	end, keep, ok := prefixLength(t.s, at+n, n)
	switch {
	case !ok:
		t.replace(at, at+n, TruncateIP(t.s[at:at+n]))
		return at + n
	case !keep:
		t.replace(at, end, TruncateIP(t.s[at:at+n]))
	}
	return end
}

func (t *rewriter) result() string {
	if t.last == 0 {
		return t.s
	}
	t.b.WriteString(t.s[t.last:])
	return t.b.String()
}

func digit(c byte) bool { return '0' <= c && c <= '9' }

// tokenByte reports whether c may be part of an IPv6 token: a hex digit, a
// colon or a dot.
func tokenByte(c byte) bool {
	return digit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' || c == ':' || c == '.'
}

// wordByte reports whether c continues a word: a letter, a digit or "_",
// or a byte of a non-ASCII character.
func wordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || digit(c) || c == '_' || c >= 0x80
}

// maxAddressToken bounds the tokens read as addresses: the longest IPv6
// address with an embedded IPv4 one and a zone fits, and so the scan stays
// linear in its input (docs/architecture.md §8).
const maxAddressToken = 64

// addressPrefix returns the length of the longest start of tok that is an
// address: tok itself, or tok without the dots and colons that end a
// sentence or a field after it, two at most.
func addressPrefix(tok string) (int, bool) {
	for n := len(tok); n > 0 && n >= len(tok)-2; n-- {
		if _, ok := parseIP(tok[:n]); ok {
			return n, true
		}
		if c := tok[n-1]; c != '.' && c != ':' {
			return 0, false
		}
	}
	return 0, false
}

// prefixLength reads "/len" at s[at:] after an address of n bytes before
// it. keep says the address is the network of that length and the length
// is no narrower than a truncated one, so it is left as written; end is
// where "/len" ends. ok is false when no length follows.
func prefixLength(s string, at, n int) (end int, keep, ok bool) {
	if at >= len(s) || s[at] != '/' {
		return 0, false, false
	}
	end = at + 1
	for end < len(s) && end-at <= 3 && digit(s[end]) {
		end++
	}
	// A dot after it ends a sentence, unless a digit follows it.
	if end == at+1 || end < len(s) && (wordByte(s[end]) || s[end] == '.' && end+1 < len(s) && digit(s[end+1])) {
		return 0, false, false
	}
	bits, _ := strconv.Atoi(s[at+1 : end])
	ip, okIP := parseIP(s[at-n : at])
	if !okIP || ip.Is4() && strings.Contains(s[at-n:at], ":") {
		// No address, or one with its port, which no network length
		// follows.
		return 0, false, false
	}
	limit := clientIPv6Bits
	if ip.Is4() {
		limit = clientIPv4Bits
	}
	p, err := ip.Prefix(bits)
	keep = err == nil && bits <= limit && p.Addr() == ip
	return end, keep, true
}

// bracketedAt reads "[address]" or "[address]:port" at s[at:], and returns
// where it ends and the address inside.
func bracketedAt(s string, at int) (end int, ip string, ok bool) {
	close := strings.IndexByte(s[at:min(len(s), at+maxAddressToken+2)], ']')
	if close < 2 {
		return 0, "", false
	}
	inside := s[at+1 : at+close]
	if _, ok := parseIP(inside); !ok {
		return 0, "", false
	}
	end = at + close + 1
	if end < len(s) && s[end] == ':' {
		p := end + 1
		for p < len(s) && p-end <= 5 && digit(s[p]) {
			p++
		}
		// A port, unless more of an address sticks to it.
		if p > end+1 && (p == len(s) || !tokenByte(s[p]) && !wordByte(s[p])) {
			end = p
		}
	}
	return end, inside, true
}
