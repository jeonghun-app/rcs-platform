package pii

import (
	"log/slog"
	"net/netip"
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
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")); err == nil {
		return ip.WithZone("").Unmap(), true
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
