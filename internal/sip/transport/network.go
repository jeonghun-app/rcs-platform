package transport

import "strings"

// Network is a SIP transport as a Via header field names it (RFC 3261 §20.42).
type Network string

// The transports this package implements.
const (
	UDP Network = "UDP"
	TCP Network = "TCP"
	TLS Network = "TLS"
)

// Reliable reports whether the transport delivers in order and without loss,
// which decides whether a transaction retransmits (RFC 3261 §17.1.1.2,
// §17.1.2.2, §17.2.1).
func (n Network) Reliable() bool { return n == TCP || n == TLS }

// DefaultPort is the port a sent-by without one implies (RFC 3261 §18.2.2,
// §19.1.2).
func (n Network) DefaultPort() int {
	if n == TLS {
		return 5061
	}
	return 5060
}

// parseNetwork maps a Via transport, which compares case-insensitively, to a
// Network this package can use.
func parseNetwork(s string) (Network, bool) {
	switch n := Network(strings.ToUpper(s)); n {
	case UDP, TCP, TLS:
		return n, true
	}
	return "", false
}
