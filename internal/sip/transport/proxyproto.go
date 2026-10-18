package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// The PROXY protocol is specified in HAProxy's proxy-protocol.txt; clause numbers
// below refer to that document. Only version 2, the binary form the AWS NLB sends,
// is accepted.

// proxySignature starts every version 2 header (proxy-protocol.txt §2.2). It
// cannot begin a SIP message, so a client that skips the load balancer is
// refused on its first bytes.
var proxySignature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyFixedLen = 16
	// maxProxyPayload bounds the address block and TLVs. The NLB sends 12 or 36
	// address bytes plus a VPC endpoint TLV of a few dozen; the format allows up
	// to 65535, which a peer could otherwise make every connection buffer.
	maxProxyPayload = 1024

	proxyVersion2   = 0x2
	proxyFamilyINET = 0x1
	proxyFamily6    = 0x2
	proxyStream     = 0x1
	proxyINETLen    = 4 + 4 + 2 + 2
	proxyINET6Len   = 16 + 16 + 2 + 2
	proxyTLVHdrLen  = 1 + 2
)

// ProxyCommand is the command of a PROXY protocol v2 header (proxy-protocol.txt
// §2.2, low nibble of the 13th byte).
type ProxyCommand uint8

const (
	// ProxyLocal marks a connection the load balancer made itself, such as a
	// health check. Its address block carries no client and is ignored.
	ProxyLocal ProxyCommand = 0x0
	// ProxyProxy marks a relayed client connection.
	ProxyProxy ProxyCommand = 0x1
)

// ErrProxyHeader means the bytes at the start of a connection are not a valid
// PROXY protocol v2 header this package accepts.
var ErrProxyHeader = errors.New("transport: invalid PROXY protocol v2 header")

// ProxyHeader is a parsed PROXY protocol v2 header.
type ProxyHeader struct {
	Command ProxyCommand
	// Source is the client address and Destination the address the client
	// connected to. Both are zero for ProxyLocal. IPv4-mapped IPv6 addresses are
	// unmapped, so the same client has the same address whichever family the load
	// balancer used.
	Source, Destination netip.AddrPort
}

// ReadProxyHeader reads exactly one PROXY protocol v2 header from r and nothing
// after it, so what follows (a TLS ClientHello or the first SIP message) is still
// unread. An error from r is returned as it is; a malformed header yields an error
// wrapping ErrProxyHeader.
func ReadProxyHeader(r io.Reader) (ProxyHeader, error) {
	buf := make([]byte, proxyFixedLen, proxyFixedLen+64)
	if _, err := io.ReadFull(r, buf); err != nil {
		return ProxyHeader{}, err
	}
	if !bytes.Equal(buf[:len(proxySignature)], proxySignature) {
		return ProxyHeader{}, proxyError("missing signature")
	}
	n := int(binary.BigEndian.Uint16(buf[14:16]))
	if n > maxProxyPayload {
		return ProxyHeader{}, proxyError("header too long")
	}
	buf = append(buf, make([]byte, n)...)
	if _, err := io.ReadFull(r, buf[proxyFixedLen:]); err != nil {
		return ProxyHeader{}, err
	}
	return ParseProxyHeader(buf)
}

// ParseProxyHeader parses b, which must be exactly one PROXY protocol v2 header.
//
// It accepts what a SIP stream listener can use: version 2, a LOCAL command, or a
// PROXY command for TCP over IPv4 or IPv6. A PROXY header for UDP, a UNIX socket
// or an unspecified family is refused rather than falling back to the socket
// address (which §2.2 permits), because that address is the load balancer and
// would give every client the same identity. TLVs must exactly fill the declared
// length; their contents are not interpreted.
func ParseProxyHeader(b []byte) (ProxyHeader, error) {
	if len(b) < proxyFixedLen || !bytes.Equal(b[:len(proxySignature)], proxySignature) {
		return ProxyHeader{}, proxyError("missing signature")
	}
	if n := int(binary.BigEndian.Uint16(b[14:16])); n > maxProxyPayload || len(b) != proxyFixedLen+n {
		return ProxyHeader{}, proxyError("length does not match")
	}
	if b[12]>>4 != proxyVersion2 {
		return ProxyHeader{}, proxyError("unsupported version")
	}
	payload := b[proxyFixedLen:]
	switch ProxyCommand(b[12] & 0x0f) {
	case ProxyLocal:
		// §2.2: the receiver uses the real endpoints and discards the address
		// block, whatever family it claims.
		return ProxyHeader{Command: ProxyLocal}, nil
	case ProxyProxy:
	default:
		return ProxyHeader{}, proxyError("unsupported command")
	}
	if b[13]&0x0f != proxyStream {
		return ProxyHeader{}, proxyError("not a stream connection")
	}
	h := ProxyHeader{Command: ProxyProxy}
	var addrLen int
	switch b[13] >> 4 {
	case proxyFamilyINET:
		addrLen = proxyINETLen
		if len(payload) < addrLen {
			return ProxyHeader{}, proxyError("address block too short")
		}
		src := netip.AddrFrom4([4]byte(payload[0:4]))
		dst := netip.AddrFrom4([4]byte(payload[4:8]))
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[8:10]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[10:12]))
	case proxyFamily6:
		addrLen = proxyINET6Len
		if len(payload) < addrLen {
			return ProxyHeader{}, proxyError("address block too short")
		}
		src := netip.AddrFrom16([16]byte(payload[0:16])).Unmap()
		dst := netip.AddrFrom16([16]byte(payload[16:32])).Unmap()
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[32:34]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[34:36]))
	default:
		return ProxyHeader{}, proxyError("unsupported address family")
	}
	// A client address that no client can have would become a flow identity and a
	// received parameter; refuse it instead.
	if a := h.Source.Addr(); h.Source.Port() == 0 || a.IsUnspecified() || a.IsMulticast() {
		return ProxyHeader{}, proxyError("invalid source address")
	}
	if err := checkTLVs(payload[addrLen:]); err != nil {
		return ProxyHeader{}, err
	}
	return h, nil
}

// checkTLVs checks that the type-length-value records after the address block
// fill it exactly (proxy-protocol.txt §2.2.1).
func checkTLVs(b []byte) error {
	for len(b) > 0 {
		if len(b) < proxyTLVHdrLen {
			return proxyError("truncated TLV")
		}
		n := proxyTLVHdrLen + int(binary.BigEndian.Uint16(b[1:3]))
		if n > len(b) {
			return proxyError("truncated TLV")
		}
		b = b[n:]
	}
	return nil
}

func proxyError(reason string) error {
	return fmt.Errorf("%w: %s", ErrProxyHeader, reason)
}
