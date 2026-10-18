package diameter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Default decoding limits.
const (
	// DefaultMaxMessageSize leaves room for a Cx Server-Assignment-Answer
	// carrying a large service profile (User-Data) while bounding the memory
	// one connection can make the node allocate per message.
	DefaultMaxMessageSize = 256 << 10
	// DefaultMaxDepth is the Grouped nesting depth accepted. Cx and Sh AVPs
	// nest only a few levels; the limit bounds recursion on hostile input.
	DefaultMaxDepth = 8
)

// Limits bounds what the decoder accepts. Zero fields take the defaults.
type Limits struct {
	MaxMessageSize int
	MaxDepth       int
}

func (l Limits) withDefaults() Limits {
	if l.MaxMessageSize <= 0 || l.MaxMessageSize > maxMessageLength {
		l.MaxMessageSize = DefaultMaxMessageSize
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	return l
}

// ReadMessage reads and decodes one message from a stream.
//
// The header's length is checked before the body is read, so a peer cannot
// make the node allocate more than the size limit. An error other than
// [*Error] (I/O, [ErrInvalidHeader], [ErrMessageTooLarge]) means the stream
// has lost its framing and the connection must be closed. An [*Error] comes
// with the partially decoded message, as for [DecodeMessage], and the stream
// can continue.
func ReadMessage(r io.Reader, dict *Dictionary, lim Limits) (*Message, error) {
	lim = lim.withDefaults()
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length < HeaderLen {
		return nil, ErrInvalidHeader
	}
	if length > lim.MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	b := make([]byte, length)
	copy(b, hdr[:])
	if _, err := io.ReadFull(r, b[HeaderLen:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return DecodeMessage(b, dict, lim)
}

// DecodeMessage decodes one complete message.
//
// When b holds a full header but the message is malformed, DecodeMessage
// returns the message decoded so far (header, and the AVPs before the fault)
// together with an [*Error] carrying the result code RFC 6733 §7.1 assigns to
// the fault, so the caller can answer a request. The AVPs of a decoded message
// alias b. A nil dictionary knows no AVP, so every AVP with the M bit is
// unsupported.
func DecodeMessage(b []byte, dict *Dictionary, lim Limits) (*Message, error) {
	lim = lim.withDefaults()
	if len(b) < HeaderLen {
		return nil, ErrInvalidHeader
	}
	if len(b) > lim.MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	m := &Message{
		version:       b[0],
		Flags:         CommandFlags(b[4]),
		Code:          uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
		ApplicationID: binary.BigEndian.Uint32(b[8:]),
		HopByHop:      binary.BigEndian.Uint32(b[12:]),
		EndToEnd:      binary.BigEndian.Uint32(b[16:]),
	}
	if m.version != Version {
		return m, &Error{ResultCode: ResultUnsupportedVersion, Message: "unsupported version"}
	}
	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length != len(b) || length%4 != 0 {
		return m, &Error{ResultCode: ResultInvalidMessageLength, Message: "invalid message length"}
	}
	// The E bit marks an answer that reports a protocol error; on a request
	// it is an invalid combination (§3, §7.1.3).
	if m.IsRequest() && m.Flags&FlagError != 0 {
		return m, &Error{ResultCode: ResultInvalidHdrBits, Message: "E bit set on a request"}
	}
	d := decoder{dict: dict, maxDepth: lim.MaxDepth}
	avps, err := d.avps(b[HeaderLen:], 1)
	m.AVPs = avps
	if err != nil {
		return m, err
	}
	return m, nil
}

type decoder struct {
	dict     *Dictionary
	maxDepth int
}

// avps decodes a sequence of AVPs at the given nesting depth (1 for the
// message's own AVPs). It stops at the first fault.
func (d decoder) avps(b []byte, depth int) ([]*AVP, *Error) {
	var out []*AVP
	for len(b) > 0 {
		a, n, fault := splitAVP(b)
		if fault != nil {
			return out, d.lengthFault(fault)
		}
		if derr := d.validate(a, depth); derr != nil {
			return out, derr
		}
		out = append(out, a)
		b = b[n:]
	}
	return out, nil
}

// lengthFault builds DIAMETER_INVALID_AVP_LENGTH for an AVP whose length is
// unusable. The Failed-AVP repeats the header that could be read (zero-filled
// to a full header) with a zero payload of the minimal size for the AVP's
// type (RFC 6733 §7.1.5).
func (d decoder) lengthFault(e *avpLengthFault) *Error {
	a := e.avp
	if a == nil {
		var hdr [avpHeaderLen]byte
		copy(hdr[:], e.header)
		a = &AVP{Code: binary.BigEndian.Uint32(hdr[:]), Flags: AVPFlags(hdr[4]) &^ FlagVendor}
	}
	minLen := 0
	if def, ok := d.lookup(a); ok {
		minLen = def.Type.minPayload()
	}
	failed := &AVP{Code: a.Code, Flags: a.Flags, VendorID: a.VendorID, Data: make([]byte, minLen)}
	return &Error{ResultCode: ResultInvalidAVPLength, FailedAVP: failed, Message: "invalid AVP length"}
}

func (d decoder) lookup(a *AVP) (AVPDef, bool) {
	if d.dict == nil {
		return AVPDef{}, false
	}
	return d.dict.Lookup(a.Code, a.VendorID)
}

// validate checks one AVP against its definition. Unknown AVPs without the M
// bit are kept as opaque data: a receiver ignores what it does not need
// (RFC 6733 §4.1).
func (d decoder) validate(a *AVP, depth int) *Error {
	def, ok := d.lookup(a)
	if !ok {
		if a.Mandatory() {
			return &Error{ResultCode: ResultAVPUnsupported, FailedAVP: a,
				Message: fmt.Sprintf("unsupported AVP %d (vendor %d)", a.Code, a.VendorID)}
		}
		return nil
	}
	if n := fixedLength(def.Type); n >= 0 && len(a.Data) != n {
		return &Error{ResultCode: ResultInvalidAVPLength, FailedAVP: a, Message: "invalid " + def.Name + " length"}
	}
	switch def.Type {
	case TypeUTF8String:
		if !utf8.Valid(a.Data) {
			return invalidAVP(a, def.Name)
		}
	case TypeDiameterIdentity:
		if !validIdentity(a.Data) {
			return invalidAVP(a, def.Name)
		}
	case TypeDiameterURI:
		if !validURI(a.Data) {
			return invalidAVP(a, def.Name)
		}
	case TypeAddress:
		if !validAddressLength(a.Data) {
			return &Error{ResultCode: ResultInvalidAVPLength, FailedAVP: a, Message: "invalid " + def.Name + " length"}
		}
	case TypeGrouped:
		return d.grouped(a, def, depth)
	}
	return nil
}

// grouped validates the children of a Grouped AVP. Failed-AVP is the
// exception: it carries AVPs this node may not understand (that is often why
// they failed), so its contents are not checked.
func (d decoder) grouped(a *AVP, def AVPDef, depth int) *Error {
	if (a.Code == AVPFailedAVP && a.VendorID == 0) || len(a.Data) == 0 {
		return nil
	}
	if depth >= d.maxDepth {
		return &Error{ResultCode: ResultUnableToComply, FailedAVP: a, Message: def.Name + " nested too deeply"}
	}
	if _, err := d.avps(a.Data, depth+1); err != nil {
		// Report the inner fault inside the AVP that contains it, so the
		// peer can locate it (RFC 6733 §7.5).
		err.FailedAVP = &AVP{Code: a.Code, Flags: a.Flags, VendorID: a.VendorID, Data: Grouped(err.FailedAVP)}
		return err
	}
	return nil
}

// fixedLength is the payload length a type requires, or -1 if it varies.
func fixedLength(t DataType) int {
	switch t {
	case TypeInteger32, TypeUnsigned32, TypeTime, TypeEnumerated:
		return 4
	case TypeInteger64, TypeUnsigned64:
		return 8
	}
	return -1
}

// validAddressLength checks that IPv4 and IPv6 addresses have their full
// length. Other address families are allowed with any length: RFC 6733
// §4.3.1 permits them and this node merely cannot interpret them.
func validAddressLength(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	switch binary.BigEndian.Uint16(b) {
	case addressFamilyIPv4:
		return len(b) == 2+4
	case addressFamilyIPv6:
		return len(b) == 2+16
	}
	return true
}
