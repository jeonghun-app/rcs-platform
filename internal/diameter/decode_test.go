package diameter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// rawMessage builds a message header with a correct length around raw AVP
// bytes, so tests can put malformed AVPs on the wire.
func rawMessage(flags CommandFlags, body ...[]byte) []byte {
	b := make([]byte, HeaderLen)
	for _, p := range body {
		b = append(b, p...)
	}
	b[0] = Version
	b[1], b[2], b[3] = byte(len(b)>>16), byte(len(b)>>8), byte(len(b))
	b[4] = byte(flags)
	b[5], b[6], b[7] = 0, 1, 44 // command 300
	binary.BigEndian.PutUint32(b[8:], 16777216)
	binary.BigEndian.PutUint32(b[12:], 0x01020304)
	binary.BigEndian.PutUint32(b[16:], 0x05060708)
	return b
}

// rawAVP builds AVP bytes with an explicit length field and no automatic
// padding.
func rawAVP(code uint32, flags AVPFlags, length int, rest ...byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, code)
	b = append(b, byte(flags), byte(length>>16), byte(length>>8), byte(length))
	return append(b, rest...)
}

func encodeAVPs(avps ...*AVP) []byte { return Grouped(avps...) }

func TestMalformedMessagesAreRejectedWithTheirResultCode(t *testing.T) {
	sessionID := NewAVP(AVPSessionID, FlagMandatory, 0, []byte("scscf-1.rcs.test;1;2"))
	deep := NewAVP(codeU32, 0, testVendor, Unsigned32(1))
	for range DefaultMaxDepth {
		deep = NewGrouped(codeGroup, 0, testVendor, deep)
	}
	tests := []struct {
		name       string
		msg        []byte
		resultCode uint32
		failedCode uint32 // 0: no Failed-AVP expected
	}{
		{"unsupported version", func() []byte { b := rawMessage(FlagRequest); b[0] = 2; return b }(), ResultUnsupportedVersion, 0},
		{"length field larger than the message", func() []byte { b := rawMessage(FlagRequest); b[3] += 4; return b }(), ResultInvalidMessageLength, 0},
		{"length not a multiple of four", func() []byte {
			b := rawMessage(FlagRequest, []byte{1, 2})
			return b
		}(), ResultInvalidMessageLength, 0},
		{"E bit on a request", rawMessage(FlagRequest | FlagError), ResultInvalidHdrBits, 0},
		{"AVP length below the header size", rawMessage(FlagRequest, rawAVP(AVPOriginHost, FlagMandatory, 7, 0, 0, 0, 0)), ResultInvalidAVPLength, AVPOriginHost},
		{"AVP length past the end", rawMessage(FlagRequest, rawAVP(AVPOriginHost, FlagMandatory, 40, 'a', 'b', 'c', 'd')), ResultInvalidAVPLength, AVPOriginHost},
		{"vendor flag without room for the vendor id", rawMessage(FlagRequest, rawAVP(codeU32, FlagVendor, 8)), ResultInvalidAVPLength, codeU32},
		{"vendor AVP length below the vendor header size", rawMessage(FlagRequest, rawAVP(codeU32, FlagVendor, 10, 0, 0, 0x28, 0xaf)), ResultInvalidAVPLength, codeU32},
		{"trailing bytes shorter than an AVP header", rawMessage(FlagRequest, encodeAVPs(sessionID), []byte{0, 0, 1, 8}), ResultInvalidAVPLength, AVPOriginHost},
		{"last AVP without its padding leaves the message length unaligned", func() []byte {
			b := rawMessage(FlagRequest, rawAVP(AVPProductName, 0, 9, 'x', 0, 0, 0))
			// Drop the padding and fix the message length: the AVP now ends
			// exactly at its length but its padded length runs past the end.
			b = b[:len(b)-3]
			b[3] = byte(len(b))
			return b
		}(), ResultInvalidMessageLength, 0},
		{"Unsigned32 with three bytes", rawMessage(FlagRequest, rawAVP(AVPResultCode, FlagMandatory, 11, 0, 0, 1, 0)), ResultInvalidAVPLength, AVPResultCode},
		{"Unsigned64 with four bytes", rawMessage(FlagRequest, encodeAVPs(NewAVP(codeU64, 0, testVendor, Unsigned32(1)))), ResultInvalidAVPLength, codeU64},
		{"Address IPv4 with three address bytes", rawMessage(FlagRequest, rawAVP(AVPHostIPAddress, FlagMandatory, 13, 0, 1, 192, 0, 2, 0, 0, 0)), ResultInvalidAVPLength, AVPHostIPAddress},
		{"Address with only part of the family", rawMessage(FlagRequest, rawAVP(AVPHostIPAddress, FlagMandatory, 9, 0, 0, 0, 0)), ResultInvalidAVPLength, AVPHostIPAddress},
		{"UTF8String not valid UTF-8", rawMessage(FlagRequest, encodeAVPs(NewAVP(AVPSessionID, FlagMandatory, 0, []byte{0xc3, 0x28}))), ResultInvalidAVPValue, AVPSessionID},
		{"DiameterIdentity with a space", rawMessage(FlagRequest, encodeAVPs(NewAVP(AVPOriginHost, FlagMandatory, 0, []byte("bad host")))), ResultInvalidAVPValue, AVPOriginHost},
		{"DiameterURI with a foreign scheme", rawMessage(FlagRequest, encodeAVPs(NewAVP(AVPRedirectHost, FlagMandatory, 0, []byte("sip:hss")))), ResultInvalidAVPValue, AVPRedirectHost},
		{"unknown AVP with the M bit", rawMessage(FlagRequest, encodeAVPs(NewAVP(4242, FlagMandatory, 0, []byte("x")))), ResultAVPUnsupported, 4242},
		{"unknown vendor AVP with the M bit", rawMessage(FlagRequest, encodeAVPs(NewAVP(codeU32, FlagMandatory, 99, Unsigned32(1)))), ResultAVPUnsupported, codeU32},
		{"fault inside a Grouped AVP", rawMessage(FlagRequest, encodeAVPs(
			NewGrouped(codeGroup, FlagMandatory, testVendor, NewAVP(codeU32, 0, testVendor, []byte{1})))), ResultInvalidAVPLength, codeGroup},
		{"Grouped nested deeper than the limit", rawMessage(FlagRequest, encodeAVPs(deep)), ResultUnableToComply, codeGroup},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := DecodeMessage(tt.msg, testDictionary(t), Limits{})
			var derr *Error
			if !errors.As(err, &derr) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if derr.ResultCode != tt.resultCode {
				t.Fatalf("result code = %d, want %d (%v)", derr.ResultCode, tt.resultCode, derr)
			}
			if m == nil || m.HopByHop != 0x01020304 || m.EndToEnd != 0x05060708 {
				t.Fatalf("the header must survive a decode error so the request can be answered: %+v", m)
			}
			switch {
			case tt.failedCode == 0 && derr.FailedAVP != nil:
				t.Fatalf("unexpected Failed-AVP %+v", derr.FailedAVP)
			case tt.failedCode != 0 && (derr.FailedAVP == nil || derr.FailedAVP.Code != tt.failedCode):
				t.Fatalf("Failed-AVP = %+v, want code %d", derr.FailedAVP, tt.failedCode)
			}
		})
	}
}

func TestLengthFaultReportsTheHeaderWithAMinimalZeroPayload(t *testing.T) {
	b := rawMessage(FlagRequest, rawAVP(AVPResultCode, FlagMandatory, 3, 0, 0, 0, 0))
	_, err := DecodeMessage(b, nil, Limits{})
	var derr *Error
	if !errors.As(err, &derr) || derr.ResultCode != ResultInvalidAVPLength {
		t.Fatalf("err = %v", err)
	}
	// With no dictionary the type is unknown, so the payload is empty.
	if derr.FailedAVP.Code != AVPResultCode || len(derr.FailedAVP.Data) != 0 {
		t.Fatalf("Failed-AVP = %+v", derr.FailedAVP)
	}

	d, _ := NewDictionary()
	_, err = DecodeMessage(b, d, Limits{})
	errors.As(err, &derr)
	if !bytes.Equal(derr.FailedAVP.Data, []byte{0, 0, 0, 0}) || !derr.FailedAVP.Mandatory() {
		t.Fatalf("Failed-AVP = %+v, want M bit and four zero bytes for an Unsigned32", derr.FailedAVP)
	}
}

func TestTruncatedAVPHeaderIsZeroFilledInFailedAVP(t *testing.T) {
	b := rawMessage(FlagRequest, []byte{0, 0, 1, 8})
	_, err := DecodeMessage(b, nil, Limits{})
	var derr *Error
	if !errors.As(err, &derr) || derr.ResultCode != ResultInvalidAVPLength {
		t.Fatalf("err = %v", err)
	}
	if derr.FailedAVP.Code != AVPOriginHost || derr.FailedAVP.Flags != 0 {
		t.Fatalf("Failed-AVP = %+v, want code %d with zero flags", derr.FailedAVP, AVPOriginHost)
	}
}

func TestFaultInsideGroupedIsReportedInsideItsParent(t *testing.T) {
	bad := NewAVP(codeU32, FlagMandatory, testVendor, []byte{1, 2})
	b := rawMessage(FlagRequest, encodeAVPs(NewGrouped(codeGroup, FlagMandatory, testVendor, bad)))
	_, err := DecodeMessage(b, testDictionary(t), Limits{})
	var derr *Error
	if !errors.As(err, &derr) {
		t.Fatalf("err = %v", err)
	}
	children, gerr := derr.FailedAVP.Grouped()
	if gerr != nil || len(children) != 1 || children[0].Code != codeU32 || !bytes.Equal(children[0].Data, []byte{1, 2}) {
		t.Fatalf("Failed-AVP children = %+v, %v; want the offending child as received", children, gerr)
	}
}

func TestDecodeErrorKeepsTheAVPsBeforeTheFault(t *testing.T) {
	sid := NewAVP(AVPSessionID, FlagMandatory, 0, []byte("scscf-1.rcs.test;1;2"))
	b := rawMessage(FlagRequest, encodeAVPs(sid, NewAVP(4242, FlagMandatory, 0, nil)))
	m, err := DecodeMessage(b, testDictionary(t), Limits{})
	if err == nil {
		t.Fatal("unknown M-bit AVP accepted")
	}
	if got, ok := m.SessionID(); !ok || got != "scscf-1.rcs.test;1;2" {
		t.Fatalf("SessionID() = %q, %v; the answer must be able to copy it", got, ok)
	}
}

func TestUnknownAVPWithoutTheMBitIsKeptAsOpaqueData(t *testing.T) {
	b := rawMessage(FlagRequest, encodeAVPs(NewAVP(4242, 0, 0, []byte("opaque"))))
	m, err := DecodeMessage(b, testDictionary(t), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if a := m.Find(4242, 0); a == nil || string(a.Data) != "opaque" {
		t.Fatalf("AVP 4242 = %+v", a)
	}
}

func TestFailedAVPContentsAreNotValidated(t *testing.T) {
	// A peer reports our unsupported AVP back to us inside Failed-AVP; the
	// answer must still decode.
	inner := NewAVP(4242, FlagMandatory, 0, []byte("x"))
	b := rawMessage(0, encodeAVPs(NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(ResultAVPUnsupported)),
		NewGrouped(AVPFailedAVP, FlagMandatory, 0, inner)))
	d, _ := NewDictionary()
	if _, err := DecodeMessage(b, d, Limits{}); err != nil {
		t.Fatalf("answer with Failed-AVP rejected: %v", err)
	}
}

func TestEmptyGroupedAtTheDepthLimitIsAccepted(t *testing.T) {
	g := NewGrouped(codeGroup, 0, testVendor)
	for range DefaultMaxDepth - 1 {
		g = NewGrouped(codeGroup, 0, testVendor, g)
	}
	if _, err := DecodeMessage(rawMessage(FlagRequest, encodeAVPs(g)), testDictionary(t), Limits{}); err != nil {
		t.Fatalf("depth %d rejected: %v", DefaultMaxDepth, err)
	}
}

func TestAddressOfAnotherFamilyIsAcceptedAsOpaque(t *testing.T) {
	a := NewAVP(AVPHostIPAddress, FlagMandatory, 0, []byte{0, 8, 'x'})
	d, _ := NewDictionary()
	if _, err := DecodeMessage(rawMessage(FlagRequest, encodeAVPs(a)), d, Limits{}); err != nil {
		t.Fatalf("family 8 rejected: %v", err)
	}
}

func TestMessagesShorterThanAHeaderCannotBeFramed(t *testing.T) {
	if _, err := DecodeMessage(make([]byte, HeaderLen-1), nil, Limits{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("err = %v, want ErrInvalidHeader", err)
	}
	b := rawMessage(FlagRequest)
	b[3] = 12
	if _, err := ReadMessage(bytes.NewReader(b), nil, Limits{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("ReadMessage with length 12: %v, want ErrInvalidHeader", err)
	}
}

func TestMessageOverTheSizeLimitIsRefused(t *testing.T) {
	b := rawMessage(FlagRequest, encodeAVPs(NewAVP(AVPProductName, 0, 0, make([]byte, 100))))
	if _, err := DecodeMessage(b, nil, Limits{MaxMessageSize: 64}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("DecodeMessage: %v, want ErrMessageTooLarge", err)
	}
	if _, err := ReadMessage(bytes.NewReader(b), nil, Limits{MaxMessageSize: 64}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("ReadMessage: %v, want ErrMessageTooLarge", err)
	}
}

// headerOnlyReader fails the test if more than the header is read.
type headerOnlyReader struct {
	t *testing.T
	b []byte
}

func (r *headerOnlyReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		r.t.Fatal("body read although the header announced an oversized message")
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func TestReadMessageChecksTheLengthBeforeReadingTheBody(t *testing.T) {
	hdr := rawMessage(FlagRequest)
	hdr[1], hdr[2], hdr[3] = 0xff, 0xff, 0xfc
	if _, err := ReadMessage(&headerOnlyReader{t: t, b: hdr}, nil, Limits{}); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestReadMessageReportsATruncatedBody(t *testing.T) {
	b := rawMessage(FlagRequest, encodeAVPs(NewAVP(AVPProductName, 0, 0, []byte("abcd"))))
	if _, err := ReadMessage(bytes.NewReader(b[:len(b)-2]), nil, Limits{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadMessage(bytes.NewReader(b[:HeaderLen]), nil, Limits{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	if _, err := ReadMessage(bytes.NewReader(nil), nil, Limits{}); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF on a clean end of stream", err)
	}
}

func TestReadMessageReadsConsecutiveMessages(t *testing.T) {
	var stream []byte
	for i := range 3 {
		m := &Message{Flags: FlagRequest, Code: CodeDeviceWatchdog, HopByHop: uint32(i)}
		m.Add(NewAVP(AVPOriginHost, FlagMandatory, 0, []byte("hss.rcs.test")))
		b, _ := m.Encode()
		stream = append(stream, b...)
	}
	r := bytes.NewReader(stream)
	d, _ := NewDictionary()
	for i := range 3 {
		m, err := ReadMessage(r, d, Limits{})
		if err != nil || m.HopByHop != uint32(i) {
			t.Fatalf("message %d: %+v, %v", i, m, err)
		}
	}
}

func TestLimitsDefaultWhenUnsetOrOutOfRange(t *testing.T) {
	l := Limits{MaxMessageSize: maxMessageLength + 1}.withDefaults()
	if l.MaxMessageSize != DefaultMaxMessageSize || l.MaxDepth != DefaultMaxDepth {
		t.Fatalf("withDefaults() = %+v", l)
	}
}
