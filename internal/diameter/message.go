package diameter

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CommandFlags are the flag bits of the message header (RFC 6733 §3).
type CommandFlags uint8

// Command flag bits. The low four bits are reserved; a receiver ignores them.
const (
	FlagRequest    CommandFlags = 0x80
	FlagProxiable  CommandFlags = 0x40
	FlagError      CommandFlags = 0x20
	FlagRetransmit CommandFlags = 0x10
)

const (
	// Version is the only protocol version (RFC 6733 §3).
	Version = 1
	// HeaderLen is the length of the fixed message header.
	HeaderLen = 20
	// maxMessageLength is the largest value of the 24-bit Message Length field.
	maxMessageLength = 1<<24 - 1
)

// Message is a Diameter request or answer. AVPs keep the order they had on the
// wire, which matters for the AVPs whose position the command ABNF fixes
// (Session-Id first, RFC 6733 §8.8).
type Message struct {
	Flags         CommandFlags
	Code          uint32 // 24 bits on the wire
	ApplicationID uint32
	HopByHop      uint32
	EndToEnd      uint32
	AVPs          []*AVP

	// version is kept only so that a decoded message with an unsupported
	// version can be answered; encoding always writes Version.
	version uint8
}

// IsRequest reports whether the R bit is set.
func (m *Message) IsRequest() bool { return m.Flags&FlagRequest != 0 }

// Add appends AVPs.
func (m *Message) Add(avps ...*AVP) { m.AVPs = append(m.AVPs, avps...) }

// Find returns the first top-level AVP with the code and vendor, or nil.
func (m *Message) Find(code, vendorID uint32) *AVP {
	for _, a := range m.AVPs {
		if a.Code == code && a.VendorID == vendorID {
			return a
		}
	}
	return nil
}

// FindAll returns every top-level AVP with the code and vendor.
func (m *Message) FindAll(code, vendorID uint32) []*AVP {
	var out []*AVP
	for _, a := range m.AVPs {
		if a.Code == code && a.VendorID == vendorID {
			out = append(out, a)
		}
	}
	return out
}

// SessionID returns the Session-Id, if the message has one.
func (m *Message) SessionID() (string, bool) {
	a := m.Find(AVPSessionID, 0)
	if a == nil {
		return "", false
	}
	s, err := a.UTF8String()
	return s, err == nil
}

// ResultCode returns the Result-Code of an answer. Answers that report their
// outcome in Experimental-Result instead (common in Cx) return false; read
// that AVP directly.
func (m *Message) ResultCode() (uint32, bool) {
	a := m.Find(AVPResultCode, 0)
	if a == nil {
		return 0, false
	}
	v, err := a.Unsigned32()
	return v, err == nil
}

// ErrMessageTooLong is returned by [Message.Encode] for a message that does
// not fit the 24-bit length field.
var ErrMessageTooLong = errors.New("diameter: message exceeds the maximum length")

// Encode returns the wire form of the message.
func (m *Message) Encode() ([]byte, error) {
	if m.Code > 0xffffff {
		return nil, fmt.Errorf("diameter: command code %d does not fit 24 bits", m.Code)
	}
	length := HeaderLen
	for _, a := range m.AVPs {
		if a.headerLen()+len(a.Data) > maxAVPLength {
			return nil, ErrMessageTooLong
		}
		length += a.encodedLen()
	}
	if length > maxMessageLength {
		return nil, ErrMessageTooLong
	}
	b := make([]byte, 0, length)
	b = append(b, Version, byte(length>>16), byte(length>>8), byte(length))
	b = append(b, byte(m.Flags), byte(m.Code>>16), byte(m.Code>>8), byte(m.Code))
	b = binary.BigEndian.AppendUint32(b, m.ApplicationID)
	b = binary.BigEndian.AppendUint32(b, m.HopByHop)
	b = binary.BigEndian.AppendUint32(b, m.EndToEnd)
	for _, a := range m.AVPs {
		b = a.appendTo(b)
	}
	return b, nil
}
