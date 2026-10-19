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

// TruncateIP returns the network a client address belongs to, in prefix
// notation: 192.0.2.0/24 for an IPv4 address, 2001:db8:5::/48 for an IPv6 one.
// v may be an address, address:port or [address]:port, with or without a
// zone; the port and zone are dropped, and an IPv4-mapped IPv6 address is
// truncated as the IPv4 address it carries. Anything else is masked whole,
// since it cannot be told apart from an identifier.
func TruncateIP(v string) string {
	ip, ok := parseIP(v)
	if !ok {
		return mark
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
	return netip.Addr{}, false
}
