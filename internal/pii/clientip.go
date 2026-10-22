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
// kept), and a dotted-quad IPv4 address, each without the port that follows
// it. It is for free text a service cannot structure, such as net/http's
// error lines ("TLS handshake error from 203.0.113.5:51234: EOF").
//
// An address is a token of its own: one inside a longer ASCII word or
// dotted number (go1.2.3.4, x192.0.2.7, 1.2.3.4.5) is not one; any other
// character, such as a space, punctuation, a run of dots, "/", or a
// character outside ASCII, may stand next to it. An IPv6 address may also
// follow a word's colon ("remote:2001:db8::1"). A network already as wide as
// a truncated one or wider, written with its length (10.0.0.0/8,
// 2001:db8::/32, and 2002::/16 for 6to4), is left as written, so that the
// function is idempotent and a configured network still reads as
// configured.
//
// Its one caller is the ErrorLog of an http.Server, whose lines bracket an
// IPv6 address that has a port. It is not built for unbracketed host:port
// text: an unbracketed IPv6 address with a port is read as one address when
// the port has at most four digits (2001:db8::1:443) and left whole
// otherwise (2001:db8::1:51234). A new caller that passes dial or parse
// errors, which may write that form, needs the case handled first. Also out
// of scope, as net/http never writes them: an address with percent-encoded
// delimiters (%5B2001:db8::1%5D, %3A), and the inet_aton forms
// (0xcb.0.113.5, 3405803781). The text after a bracketed address's port is
// read as a token of its own, so its network may start with digits that
// look like a port ("[::1]:0:1::" is written "[::/48]:1::/48").
//
// Some text that is no address reads as one and is rewritten: a four-part
// number such as a version or an OID part (1.2.3.4), an EUI-64
// (00:11:22:ff:fe:33:44:55), a hex word with "::" (dead::beef), a lone
// "::". That fails safe: the line says less, and nothing more leaks.
func TruncateIPsIn(s string) string {
	out, _ := truncateRounds(s, nil)
	return out
}

// maxRounds bounds the rounds of truncateRounds, so that TruncateIPsIn
// stays linear. A search of five million texts found none that needs more
// than three, the last of which only confirms the second
// (TestTruncateIPsInIsLinear's "three rounds"); one that is not stable
// within maxRounds fails FuzzTruncateIPsIn.
const maxRounds = 6

// truncateRounds truncates s in rounds of both passes, each reading the
// text the one before wrote, until a round changes nothing, and returns the
// result and whether it is stable, that is, truncated again it reads the
// same (#512): a network written next to text that was no address can make
// one, as "0.0.0.0/24::/48::" did. A round only replaces more text with
// networks, so nothing a round truncated comes back. each, when not nil,
// sees every round's output, for the tests.
func truncateRounds(s string, each func(string)) (out string, stable bool) {
	out = s
	for range maxRounds {
		next := truncateIPv4In(truncateIPv6In(out))
		if each != nil {
			each(next)
		}
		if next == out {
			return out, true
		}
		out = next
	}
	return out, false
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
		if !tokenByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && tokenByte(s[j]) {
			j++
		}
		// Part of a longer word, not an address of its own, unless one
		// colon parts it from the word ("2001:db8::1:x"), or it holds a
		// dotted quad, where an address ends ("::ffff:192.0.2.7:443x").
		if j < len(s) && wordByte(s[j]) && !(j-i >= 2 && s[j-1] == ':' && s[j-2] != ':') &&
			!(strings.Contains(s[i:j], ".") && strings.Contains(s[i:j], ":")) {
			i = j
			continue
		}
		// The token may start where it does, unless a word or a prefix
		// length's "/" comes before it; or after any of its colons
		// ("cafe:2001:db8::1"), within the last maxAddressToken bytes, the
		// longest an address can be, so that this stays linear.
		jt := i + len(strings.TrimRight(s[i:j], "."))
		var starts []int
		// Dots at a start part it from what is before them, as an ellipsis
		// does (".::1", ":.::1"), so the start after them is tried too.
		addStart := func(st int) {
			starts = append(starts, st)
			if lead := st + len(s[st:jt]) - len(strings.TrimLeft(s[st:jt], ".")); lead > st && lead < jt {
				starts = append(starts, lead)
			}
		}
		if prev := t.prevByte(i); !wordByte(prev) && !(prev == '/' && digit(t.prevByte(i-1))) {
			addStart(i)
		}
		w := max(i, jt-maxAddressToken-1)
		// A colon before the window whose dots reach into it starts
		// there, its dots trimmed (":" and 61 dots and "0::1", #520): the
		// dots are scanned once, so this stays linear.
		if d := w; d > i && s[d] == '.' {
			for d > i && s[d-1] == '.' {
				d--
			}
			if d > i && s[d-1] == ':' {
				addStart(d)
			}
		}
		for k := w; k < jt; k++ {
			if s[k] == ':' && k+1 < jt {
				addStart(k + 1)
			}
		}
		// The first start that holds an IPv6 address is taken.
		next, at, n, portEnd := j, -1, 0, -1
		for _, st := range starts {
			tok := s[st:jt]
			if st >= jt || len(tok) > maxAddressToken {
				continue
			}
			m, ok := addressPrefix(tok)
			pe := -1
			if !ok {
				// An address with a dotted quad ends at it; after it,
				// ":port" can be nothing else (::ffff:192.0.2.7:443), and
				// anything else is text.
				if q := quadEnd(tok); q > 0 && q < len(tok) && parseOK(tok[:q]) {
					m, ok = q, true
					if p, isPort := portAt(s, st+q); isPort {
						pe = p
					}
				}
			}
			// An IPv4 address with what follows it is the next pass's, and
			// so is an IPv6 one that says no more than its dotted quad
			// (::a.b.c.d, ::ffff:a.b.c.d) with a length after it, which
			// that pass truncated or keeps (::192.0.2.0/24).
			if !ok || strings.Count(tok[:m], ":") < 2 ||
				st+m+1 < len(s) && s[st+m] == '/' && digit(s[st+m+1]) && onlyIPv4(tok[:m]) {
				continue
			}
			at, n, portEnd = st, m, pe
			break
		}
		switch {
		case at < 0:
		case portEnd >= 0:
			t.replace(at, portEnd, TruncateIP(s[at:at+n]))
			next = portEnd
		case at > starts[0]:
			// After a hex word's colon ("cafe:2001:db8::1"), the word and
			// the network could read as one address from an earlier start
			// when the line is read again; then that address is the one
			// truncated, so that the line reads the same each time.
			end := at + n
			if e, _, ok := prefixLength(s, end, n); ok {
				end = e
			}
			// Until no earlier start reads as one address with the network
			// written so far; each step starts earlier, so this ends.
			network, from := TruncateIP(s[at:at+n]), at
			for moved := true; moved; {
				moved = false
				k := strings.IndexByte(network, '/')
				for _, st0 := range starts {
					if k <= 0 || st0 >= from {
						break
					}
					if combo := s[st0:from] + network[:k]; parseOK(combo) {
						network, from, moved = TruncateIP(combo), st0, true
						break
					}
				}
			}
			if from < at {
				t.replace(from, end, network)
				next = end
			} else {
				next = t.address(at, n)
			}
		default:
			next = t.address(at, n)
		}
		i = next
	}
	return t.result()
}

// truncateIPv4In truncates the dotted-quad IPv4 addresses of s, each with
// its ":port" if it has one: four parts of digits and dots, not part of a
// longer word or of a longer dotted number.
func truncateIPv4In(s string) string {
	t := newRewriter(s)
	for i := 0; i < len(s); {
		if !digit(s[i]) {
			i++
			continue
		}
		// A digit after a word, or after a dot after a word or a number,
		// continues it (go1.2.3.4, x.1.2.3.4, 1.2.3.4.5); after other
		// dots, such as an ellipsis, it starts a token.
		if prev := t.prevByte(i); wordByte(prev) || prev == '.' && i >= 2 && wordByte(s[i-2]) {
			for i < len(s) && (digit(s[i]) || s[i] == '.') {
				i++
			}
			continue
		}
		j := i
		for j < len(s) && (digit(s[j]) || s[j] == '.') {
			j++
		}
		// Dots after the run end a sentence or trail off, unless a word
		// follows them.
		run := strings.TrimRight(s[i:j], ".")
		end := i + len(run)
		if j < len(s) && wordByte(s[j]) || len(run) > maxAddressToken {
			i = j
			continue
		}
		if _, ok := parseDottedQuad(run); !ok {
			i = j
			continue
		}
		// After trimmed dots, s[end] is a dot, and no port follows.
		n := len(run)
		if p, ok := portAt(s, end); ok {
			n = p - i
		}
		i = t.address(i, n)
	}
	return t.result()
}

// quadEnd returns where the dotted quad of an IPv6 token ends: the four
// parts after the last colon before its first dot, or 0 if it has none.
func quadEnd(tok string) int {
	d := strings.IndexByte(tok, '.')
	if d < 0 {
		return 0
	}
	q := strings.LastIndexByte(tok[:d], ':') + 1
	for parts := 0; parts < 4; parts++ {
		if parts > 0 {
			if q >= len(tok) || tok[q] != '.' {
				return 0
			}
			q++
		}
		start := q
		for q < len(tok) && digit(tok[q]) {
			q++
		}
		if q == start {
			return 0
		}
	}
	// A fifth part makes a longer dotted number, no address.
	if q+1 < len(tok) && tok[q] == '.' && digit(tok[q+1]) {
		return 0
	}
	return q
}

// onlyIPv4 reports whether v is an IPv6 address with a dotted quad whose
// other bits say nothing: IPv4-compatible (::a.b.c.d) or IPv4-mapped.
func onlyIPv4(v string) bool {
	if !strings.Contains(v, ".") {
		return false
	}
	ip, ok := parseIP(v)
	if !ok {
		return false
	}
	if ip.Is4() {
		return true // mapped, which parseIP unmaps
	}
	b := ip.As16()
	return [12]byte(b[:12]) == [12]byte{}
}

// parseOK reports whether s is an address TruncateIP reads.
func parseOK(s string) bool {
	_, ok := parseIP(s)
	return ok
}

// portAt reads ":port" at s[at:], one to five digits, and returns where it
// ends. net/http writes ": " after the address and port it names, so a
// port ends at whatever is not a digit, nor a dot and a digit, which would
// make a decimal number of it.
func portAt(s string, at int) (int, bool) {
	if at >= len(s) || s[at] != ':' {
		return 0, false
	}
	p := at + 1
	for p < len(s) && p-at <= 5 && digit(s[p]) {
		p++
	}
	if p == at+1 || p < len(s) && (digit(s[p]) || s[p] == '.' && p+1 < len(s) && digit(s[p+1])) {
		return 0, false
	}
	return p, true
}

// A rewriter builds a copy of s with some of its spans replaced, in order.
type rewriter struct {
	s    string
	b    strings.Builder
	last int
	// lastOut is the last byte of the last replacement, which stands
	// before s[last] in the copy.
	lastOut byte
}

func newRewriter(s string) *rewriter { return &rewriter{s: s} }

func (t *rewriter) replace(from, to int, with string) {
	t.b.WriteString(t.s[t.last:from])
	t.b.WriteString(with)
	t.last = to
	if with != "" {
		t.lastOut = with[len(with)-1]
	}
}

// prevByte is the byte before s[i] in the copy, or 0 at its start: so that
// the copy, read again, has its tokens start where they did (idempotence).
// For i at most t.last, it is the byte before s[i] in s, or the last byte
// of the replacement that ends at i.
func (t *rewriter) prevByte(i int) byte {
	switch {
	case i <= 0:
		return 0
	case i == t.last && t.lastOut != 0:
		return t.lastOut
	}
	return t.s[i-1]
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

// wordByte reports whether c continues an ASCII word: a letter, a digit or
// "_". Any other byte, of a character outside ASCII too, is a separator:
// text in a script without spaces, such as "来自203.0.113.9。", still
// separates an address from its words.
func wordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || digit(c) || c == '_'
}

// maxAddressToken bounds the tokens read as addresses: the longest IPv6
// address with an embedded IPv4 one and a zone fits, and so the scan stays
// linear in its input (docs/architecture.md §8).
const maxAddressToken = 64

// addressPrefix returns the length of the start of tok that is an address:
// tok itself, or tok without the one colon that ends a field after it
// ("2001:db8::1: EOF"), never one of a "::". The dots after it are trimmed
// already.
func addressPrefix(tok string) (int, bool) {
	if _, ok := parseIP(tok); ok {
		return len(tok), true
	}
	if n := len(tok) - 1; n > 0 && tok[n] == ':' && tok[n-1] != ':' {
		if _, ok := parseIP(tok[:n]); ok {
			return n, true
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
	// A dot and a digit after it make a netmask's first part
	// (203.0.113.5/255.255.255.0), which is no length.
	if end == at+1 || end < len(s) && (digit(s[end]) || s[end] == '.' && end+1 < len(s) && digit(s[end+1])) {
		return 0, false, false
	}
	bits, _ := strconv.Atoi(s[at+1 : end])
	ip, okIP := parseIP(s[at-n : at])
	if !okIP || ip.Is4() && strings.Contains(s[at-n:at], ":") && !strings.Contains(s[at-n:at], "::") {
		// No address, or an IPv4 one with its port, which no network
		// length follows.
		return 0, false, false
	}
	limit := clientIPv6Bits
	switch {
	case ip.Is4():
		limit = clientIPv4Bits
	case sixToFour.Contains(ip):
		// Its bits 16 to 47 are a whole IPv4 address.
		limit = sixToFour.Bits()
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
	if p, ok := portAt(s, end); ok {
		end = p
	}
	return end, inside, true
}
