package diameter

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
	"unicode/utf8"
)

// AVPFlags are the flag bits of an AVP header (RFC 6733 §4.1).
type AVPFlags uint8

// AVP flag bits. The low five bits are reserved; a receiver ignores them.
const (
	// FlagVendor says a Vendor-ID field follows the AVP length. Encoding sets
	// it whenever AVP.VendorID is not zero.
	FlagVendor AVPFlags = 0x80
	// FlagMandatory says a receiver that does not understand the AVP must
	// reject the message (§4.1).
	FlagMandatory AVPFlags = 0x40
	// FlagProtected is reserved for end-to-end security, which nothing
	// defines; senders leave it clear (§4.1).
	FlagProtected AVPFlags = 0x20
)

const (
	avpHeaderLen       = 8
	avpVendorHeaderLen = 12
	// maxAVPLength is the largest value of the 24-bit AVP Length field.
	maxAVPLength = 1<<24 - 1
)

// AVP is one attribute-value pair. Data is the payload without padding. A
// Grouped AVP keeps its children encoded in Data, so an AVP received from a
// peer can be copied into Failed-AVP or into an answer byte for byte; use
// [AVP.Grouped] to read the children.
type AVP struct {
	Code     uint32
	Flags    AVPFlags
	VendorID uint32
	Data     []byte
}

// NewAVP returns an AVP carrying data, which is usually produced by one of
// the encoders in this file ([Unsigned32], [Address], [Grouped], ...). The V
// flag follows vendorID, so callers pass only FlagMandatory (or nothing).
func NewAVP(code uint32, flags AVPFlags, vendorID uint32, data []byte) *AVP {
	if vendorID != 0 {
		flags |= FlagVendor
	}
	return &AVP{Code: code, Flags: flags, VendorID: vendorID, Data: data}
}

// Mandatory reports whether the M bit is set.
func (a *AVP) Mandatory() bool { return a.Flags&FlagMandatory != 0 }

func (a *AVP) hasVendor() bool { return a.Flags&FlagVendor != 0 || a.VendorID != 0 }

// encodedLen is the AVP's length on the wire including padding.
func (a *AVP) encodedLen() int {
	return pad4(a.headerLen() + len(a.Data))
}

func (a *AVP) headerLen() int {
	if a.hasVendor() {
		return avpVendorHeaderLen
	}
	return avpHeaderLen
}

// appendTo appends the encoded AVP and its padding. Lengths are not checked
// here: [Message.Encode] rejects a message whose AVPs do not fit the 24-bit
// length fields, which also covers every AVP nested inside them.
func (a *AVP) appendTo(b []byte) []byte {
	flags := a.Flags
	if a.hasVendor() {
		flags |= FlagVendor
	}
	length := a.headerLen() + len(a.Data)
	b = binary.BigEndian.AppendUint32(b, a.Code)
	b = append(b, byte(flags), byte(length>>16), byte(length>>8), byte(length))
	if a.hasVendor() {
		b = binary.BigEndian.AppendUint32(b, a.VendorID)
	}
	b = append(b, a.Data...)
	for i := length; i%4 != 0; i++ {
		b = append(b, 0)
	}
	return b
}

func pad4(n int) int { return (n + 3) &^ 3 }

// Errors returned by the AVP accessors. A decoded message has already been
// checked against its dictionary, so these matter mainly for AVPs the
// dictionary does not describe.
var (
	ErrAVPLength              = errors.New("diameter: AVP payload has the wrong length for its type")
	ErrInvalidUTF8            = errors.New("diameter: UTF8String is not valid UTF-8")
	ErrInvalidIdentity        = errors.New("diameter: invalid DiameterIdentity")
	ErrInvalidURI             = errors.New("diameter: invalid DiameterURI")
	ErrUnsupportedAddressType = errors.New("diameter: Address family is neither IPv4 nor IPv6")
)

// Unsigned32 encodes an Unsigned32 payload (RFC 6733 §4.2).
func Unsigned32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// Unsigned64 encodes an Unsigned64 payload (RFC 6733 §4.2).
func Unsigned64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// Integer32 encodes an Integer32 payload (RFC 6733 §4.2).
func Integer32(v int32) []byte { return Unsigned32(uint32(v)) }

// Integer64 encodes an Integer64 payload (RFC 6733 §4.2).
func Integer64(v int64) []byte { return Unsigned64(uint64(v)) }

// Enumerated encodes an Enumerated payload, which is an Integer32 on the wire
// (RFC 6733 §4.3.1).
func Enumerated(v int32) []byte { return Integer32(v) }

// Address family numbers used by the Address type (RFC 6733 §4.3.1, IANA
// address family numbers).
const (
	addressFamilyIPv4 = 1
	addressFamilyIPv6 = 2
)

// Address encodes an Address payload (RFC 6733 §4.3.1): the address family
// followed by the address. An IPv4-mapped IPv6 address is sent as IPv6, as
// given. The zero netip.Addr encodes as an empty payload, which every receiver
// rejects; callers validate addresses before building messages.
func Address(addr netip.Addr) []byte {
	switch {
	case addr.Is4():
		a := addr.As4()
		return append([]byte{0, addressFamilyIPv4}, a[:]...)
	case addr.Is6():
		a := addr.As16()
		return append([]byte{0, addressFamilyIPv6}, a[:]...)
	}
	return nil
}

// ntpUnixOffset is the number of seconds from the NTP epoch (1900-01-01) to
// the Unix epoch.
const ntpUnixOffset = 2208988800

// Time encodes a Time payload: seconds since 1900-01-01 UTC as the 32-bit NTP
// timestamp (RFC 6733 §4.3.1). The value wraps in February 2036; decoding
// follows the RFC 4330 §3 rule (a clear top bit means the era after 2036), so
// times from 1968 to 2104 round-trip. Sub-second precision is dropped.
func Time(t time.Time) []byte {
	return Unsigned32(uint32(t.Unix() + ntpUnixOffset))
}

// Grouped encodes the children of a Grouped AVP (RFC 6733 §4.4).
func Grouped(children ...*AVP) []byte {
	var b []byte
	for _, c := range children {
		b = c.appendTo(b)
	}
	return b
}

// NewGrouped returns a Grouped AVP holding children.
func NewGrouped(code uint32, flags AVPFlags, vendorID uint32, children ...*AVP) *AVP {
	return NewAVP(code, flags, vendorID, Grouped(children...))
}

// Unsigned32 decodes an Unsigned32 payload.
func (a *AVP) Unsigned32() (uint32, error) {
	if len(a.Data) != 4 {
		return 0, ErrAVPLength
	}
	return binary.BigEndian.Uint32(a.Data), nil
}

// Unsigned64 decodes an Unsigned64 payload.
func (a *AVP) Unsigned64() (uint64, error) {
	if len(a.Data) != 8 {
		return 0, ErrAVPLength
	}
	return binary.BigEndian.Uint64(a.Data), nil
}

// Integer32 decodes an Integer32 payload.
func (a *AVP) Integer32() (int32, error) {
	v, err := a.Unsigned32()
	return int32(v), err
}

// Integer64 decodes an Integer64 payload.
func (a *AVP) Integer64() (int64, error) {
	v, err := a.Unsigned64()
	return int64(v), err
}

// Enumerated decodes an Enumerated payload.
func (a *AVP) Enumerated() (int32, error) { return a.Integer32() }

// OctetString returns the payload. The slice aliases the AVP.
func (a *AVP) OctetString() []byte { return a.Data }

// UTF8String decodes a UTF8String payload (RFC 6733 §4.3.1).
func (a *AVP) UTF8String() (string, error) {
	if !utf8.Valid(a.Data) {
		return "", ErrInvalidUTF8
	}
	return string(a.Data), nil
}

// DiameterIdentity decodes a DiameterIdentity payload: the FQDN or realm of a
// Diameter node (RFC 6733 §4.3.1).
func (a *AVP) DiameterIdentity() (string, error) {
	if !validIdentity(a.Data) {
		return "", ErrInvalidIdentity
	}
	return string(a.Data), nil
}

// validIdentity accepts the characters of a DNS host name plus underscore,
// which some deployments use in service names. Anything else (spaces,
// control characters, non-ASCII) cannot be a FQDN and is rejected rather
// than passed on into peer tables and logs.
func validIdentity(b []byte) bool {
	if len(b) == 0 || len(b) > 255 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// DiameterURI decodes a DiameterURI payload (RFC 6733 §4.3.1). Only the
// scheme and the character set are checked; nothing in this package routes by
// URI (redirect agents are out of scope).
func (a *AVP) DiameterURI() (string, error) {
	if !validURI(a.Data) {
		return "", ErrInvalidURI
	}
	return string(a.Data), nil
}

func validURI(b []byte) bool {
	var rest []byte
	switch {
	case hasPrefixFold(b, "aaa://"):
		rest = b[len("aaa://"):]
	case hasPrefixFold(b, "aaas://"):
		rest = b[len("aaas://"):]
	default:
		return false
	}
	if len(rest) == 0 {
		return false
	}
	for _, c := range rest {
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// Address decodes an Address payload. Only IPv4 and IPv6 are understood;
// other families decode with [ErrUnsupportedAddressType].
func (a *AVP) Address() (netip.Addr, error) {
	if len(a.Data) < 2 {
		return netip.Addr{}, ErrAVPLength
	}
	family := binary.BigEndian.Uint16(a.Data)
	addr := a.Data[2:]
	switch family {
	case addressFamilyIPv4:
		if len(addr) != 4 {
			return netip.Addr{}, ErrAVPLength
		}
		return netip.AddrFrom4([4]byte(addr)), nil
	case addressFamilyIPv6:
		if len(addr) != 16 {
			return netip.Addr{}, ErrAVPLength
		}
		return netip.AddrFrom16([16]byte(addr)), nil
	}
	return netip.Addr{}, ErrUnsupportedAddressType
}

// Time decodes a Time payload; see [Time] for the era rule.
func (a *AVP) Time() (time.Time, error) {
	v, err := a.Unsigned32()
	if err != nil {
		return time.Time{}, err
	}
	secs := int64(v) - ntpUnixOffset
	if v&0x80000000 == 0 {
		secs += 1 << 32
	}
	return time.Unix(secs, 0).UTC(), nil
}

// Grouped decodes the children of a Grouped AVP, one level deep. Children of
// a decoded message were validated, to the dictionary's depth limit, when the
// message was decoded.
func (a *AVP) Grouped() ([]*AVP, error) {
	var out []*AVP
	b := a.Data
	for len(b) > 0 {
		c, n, fault := splitAVP(b)
		if fault != nil {
			return nil, ErrAVPLength
		}
		out = append(out, c)
		b = b[n:]
	}
	return out, nil
}

// splitAVP reads one AVP from the front of b and returns it with the number
// of bytes it occupies including padding. The last AVP of a message or group
// must carry its padding too: a length that would need bytes past the end is
// a fault, never a short read. The returned AVP's Data aliases b.
func splitAVP(b []byte) (*AVP, int, *avpLengthFault) {
	if len(b) < avpHeaderLen {
		return nil, 0, &avpLengthFault{header: b}
	}
	a := &AVP{
		Code:  binary.BigEndian.Uint32(b),
		Flags: AVPFlags(b[4]),
	}
	length := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
	hdr := avpHeaderLen
	if a.Flags&FlagVendor != 0 {
		hdr = avpVendorHeaderLen
		if len(b) < hdr {
			return nil, 0, &avpLengthFault{avp: a}
		}
		a.VendorID = binary.BigEndian.Uint32(b[8:])
	}
	if length < hdr || pad4(length) > len(b) {
		return nil, 0, &avpLengthFault{avp: a}
	}
	a.Data = b[hdr:length:length]
	return a, pad4(length), nil
}

// avpLengthFault describes an AVP whose length is unusable. It keeps what
// could be read of the header so the answer's Failed-AVP can identify the AVP
// (RFC 6733 §7.1.5, DIAMETER_INVALID_AVP_LENGTH).
type avpLengthFault struct {
	avp    *AVP   // nil when not even the code and flags could be read
	header []byte // when avp is nil, the bytes that were available
}
