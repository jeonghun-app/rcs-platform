// Package proxyproto reads the PROXY protocol version 2 header that the AWS
// NLB puts in front of every connection it forwards to a target group with
// proxy protocol enabled (ADR 0003).
//
// Fargate tasks are IP targets, and on TLS listeners the NLB does not
// preserve the client's source address for those, so without the header a
// service sees every client as the load balancer. Per-source limits and
// anything else keyed on the client address depend on it. A listener that
// requires the header refuses a connection without one, so a target group
// with proxy protocol switched off fails loudly instead of quietly giving
// every client one address.
//
// The protocol is specified in HAProxy's proxy-protocol.txt; clause numbers
// in this package refer to that document. Only version 2, the binary form
// the NLB sends, is accepted.
//
// This is the platform's one PROXY parser: msrp-relay uses it, and the SIP
// transport (#35) is to use it rather than a copy of its own. Its rules are
// strict on purpose and must stay so: no fallback to the socket address for
// UNSPEC, UDP or UNIX headers, no unusable source address, a bounded
// payload.
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// signature starts every version 2 header (proxy-protocol.txt §2.2). It
// cannot begin an MSRP or SIP message, so a client that skips the load
// balancer is refused on its first bytes.
var signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

// SignatureLen is the length of the signature that starts every version 2
// header.
const SignatureLen = 12

// HasSignature reports whether b starts with the version 2 signature: a
// listener that also takes connections without a header looks at a
// connection's first SignatureLen bytes to tell the two apart.
func HasSignature(b []byte) bool { return bytes.HasPrefix(b, signature) }

const (
	fixedLen = 16
	// MaxPayload bounds the address block and TLVs. The NLB sends 12 or 36
	// address bytes plus a VPC endpoint TLV of a few dozen; the format allows
	// up to 65535, which a peer could otherwise make every connection
	// buffer.
	MaxPayload = 1024

	version2   = 0x2
	familyINET = 0x1
	family6    = 0x2
	stream     = 0x1
	inetLen    = 4 + 4 + 2 + 2
	inet6Len   = 16 + 16 + 2 + 2
	tlvHdrLen  = 1 + 2
)

// Command is the command of a version 2 header (proxy-protocol.txt §2.2, low
// nibble of the 13th byte).
type Command uint8

const (
	// Local marks a connection the load balancer made itself, such as a
	// health check. Its address block carries no client and is ignored.
	Local Command = 0x0
	// Proxy marks a relayed client connection.
	Proxy Command = 0x1
)

// ErrInvalid means the bytes at the start of a connection are not a valid
// PROXY protocol v2 header this package accepts.
var ErrInvalid = errors.New("proxyproto: invalid PROXY protocol v2 header")

// Header is a parsed version 2 header.
type Header struct {
	Command Command
	// Source is the client address and Destination the address the client
	// connected to. Both are zero for Local. IPv4-mapped IPv6 addresses are
	// unmapped, so the same client has the same address whichever family
	// the load balancer used.
	Source, Destination netip.AddrPort
}

// Read reads exactly one version 2 header from r and nothing after it, so
// what follows (the first MSRP request, say) is still unread. An error from
// r is returned as it is; a malformed header yields an error wrapping
// ErrInvalid.
func Read(r io.Reader) (Header, error) {
	buf := make([]byte, fixedLen, fixedLen+64)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Header{}, err
	}
	if !bytes.Equal(buf[:len(signature)], signature) {
		return Header{}, invalid("missing signature")
	}
	n := int(binary.BigEndian.Uint16(buf[14:16]))
	if n > MaxPayload {
		return Header{}, invalid("header too long")
	}
	buf = append(buf, make([]byte, n)...)
	if _, err := io.ReadFull(r, buf[fixedLen:]); err != nil {
		return Header{}, err
	}
	return Parse(buf)
}

// Parse parses b, which must be exactly one version 2 header.
//
// It accepts what a stream listener can use: a LOCAL command, or a PROXY
// command for TCP over IPv4 or IPv6. A PROXY header for UDP, a UNIX socket
// or an unspecified family is refused rather than falling back to the
// socket address (which §2.2 permits), because that address is the load
// balancer and would give every client the same identity. TLVs must
// exactly fill the declared length; their contents are not interpreted.
func Parse(b []byte) (Header, error) {
	if len(b) < fixedLen || !bytes.Equal(b[:len(signature)], signature) {
		return Header{}, invalid("missing signature")
	}
	if n := int(binary.BigEndian.Uint16(b[14:16])); n > MaxPayload || len(b) != fixedLen+n {
		return Header{}, invalid("length does not match")
	}
	if b[12]>>4 != version2 {
		return Header{}, invalid("unsupported version")
	}
	payload := b[fixedLen:]
	switch Command(b[12] & 0x0f) {
	case Local:
		// §2.2: the receiver uses the real endpoints and discards the
		// address block, whatever family it claims.
		return Header{Command: Local}, nil
	case Proxy:
	default:
		return Header{}, invalid("unsupported command")
	}
	if b[13]&0x0f != stream {
		return Header{}, invalid("not a stream connection")
	}
	h := Header{Command: Proxy}
	var addrLen int
	switch b[13] >> 4 {
	case familyINET:
		addrLen = inetLen
		if len(payload) < addrLen {
			return Header{}, invalid("address block too short")
		}
		src := netip.AddrFrom4([4]byte(payload[0:4]))
		dst := netip.AddrFrom4([4]byte(payload[4:8]))
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[8:10]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[10:12]))
	case family6:
		addrLen = inet6Len
		if len(payload) < addrLen {
			return Header{}, invalid("address block too short")
		}
		src := netip.AddrFrom16([16]byte(payload[0:16])).Unmap()
		dst := netip.AddrFrom16([16]byte(payload[16:32])).Unmap()
		h.Source = netip.AddrPortFrom(src, binary.BigEndian.Uint16(payload[32:34]))
		h.Destination = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(payload[34:36]))
	default:
		return Header{}, invalid("unsupported address family")
	}
	// A client address no client can have would become the key of
	// per-source limits; refuse it instead.
	if a := h.Source.Addr(); h.Source.Port() == 0 || a.IsUnspecified() || a.IsMulticast() {
		return Header{}, invalid("invalid source address")
	}
	if err := checkTLVs(payload[addrLen:]); err != nil {
		return Header{}, err
	}
	return h, nil
}

// checkTLVs checks that the type-length-value records after the address
// block fill it exactly (proxy-protocol.txt §2.2.1).
func checkTLVs(b []byte) error {
	for len(b) > 0 {
		if len(b) < tlvHdrLen {
			return invalid("truncated TLV")
		}
		n := tlvHdrLen + int(binary.BigEndian.Uint16(b[1:3]))
		if n > len(b) {
			return invalid("truncated TLV")
		}
		b = b[n:]
	}
	return nil
}

// Marshal encodes h the way the NLB does: a Local header without an
// address block, a Proxy header for TCP over IPv4 when both addresses are
// IPv4 and over IPv6 otherwise (IPv4 addresses then mapped). It is what tests and local tools put in
// front of a connection to a listener that requires the header.
func (h Header) Marshal() []byte {
	b := append([]byte(nil), signature...)
	if h.Command != Proxy {
		return append(b, version2<<4|byte(Local), 0x00, 0, 0)
	}
	src, dst := h.Source.Addr(), h.Destination.Addr()
	if src.Is4() && dst.Is4() {
		b = append(b, version2<<4|byte(Proxy), familyINET<<4|stream)
		b = binary.BigEndian.AppendUint16(b, inetLen)
		s, d := src.As4(), dst.As4()
		b = append(append(b, s[:]...), d[:]...)
	} else {
		b = append(b, version2<<4|byte(Proxy), family6<<4|stream)
		b = binary.BigEndian.AppendUint16(b, inet6Len)
		s, d := as16(src), as16(dst)
		b = append(append(b, s[:]...), d[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, h.Source.Port())
	return binary.BigEndian.AppendUint16(b, h.Destination.Port())
}

// as16 is netip.Addr.As16 with the zero Addr as all zeros, which Parse
// refuses as a source, rather than a panic.
func as16(a netip.Addr) [16]byte {
	if !a.IsValid() {
		return [16]byte{}
	}
	return a.As16()
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, reason)
}
