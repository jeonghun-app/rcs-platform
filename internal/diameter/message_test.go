package diameter

import (
	"bytes"
	"errors"
	"testing"
)

func TestHeaderFieldsRoundTrip(t *testing.T) {
	m := &Message{
		Flags:         FlagRequest | FlagProxiable | FlagRetransmit,
		Code:          0xabcdef,
		ApplicationID: 16777217,
		HopByHop:      0xdeadbeef,
		EndToEnd:      0x12345678,
	}
	m.Add(NewAVP(AVPOriginHost, FlagMandatory, 0, []byte("as.rcs.test")))
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != Version || int(b[1])<<16|int(b[2])<<8|int(b[3]) != len(b) {
		t.Fatalf("version/length = % x for %d bytes", b[:4], len(b))
	}
	d, _ := NewDictionary()
	got, err := DecodeMessage(b, d, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != m.Flags || got.Code != m.Code || got.ApplicationID != m.ApplicationID ||
		got.HopByHop != m.HopByHop || got.EndToEnd != m.EndToEnd {
		t.Fatalf("header = %+v, want %+v", got, m)
	}
}

func TestEncodeRefusesACommandCodeWiderThan24Bits(t *testing.T) {
	if _, err := (&Message{Code: 1 << 24}).Encode(); err == nil {
		t.Fatal("command code 2^24 encoded")
	}
}

func TestEncodeRefusesAnAVPLargerThanItsLengthField(t *testing.T) {
	m := &Message{AVPs: []*AVP{NewAVP(AVPClass, 0, 0, make([]byte, maxAVPLength))}}
	if _, err := m.Encode(); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("err = %v, want ErrMessageTooLong", err)
	}
}

func TestEncodeRefusesAMessageLargerThanItsLengthField(t *testing.T) {
	big := make([]byte, maxAVPLength/2)
	m := &Message{AVPs: []*AVP{NewAVP(AVPClass, 0, 0, big), NewAVP(AVPClass, 0, 0, big), NewAVP(AVPClass, 0, 0, big)}}
	if _, err := m.Encode(); !errors.Is(err, ErrMessageTooLong) {
		t.Fatalf("err = %v, want ErrMessageTooLong", err)
	}
}

func TestFindReturnsTheFirstMatchAndFindAllEveryMatch(t *testing.T) {
	m := &Message{}
	m.Add(
		NewAVP(AVPRouteRecord, FlagMandatory, 0, []byte("a.test")),
		NewAVP(codeU32, 0, testVendor, Unsigned32(1)),
		NewAVP(AVPRouteRecord, FlagMandatory, 0, []byte("b.test")),
	)
	if a := m.Find(AVPRouteRecord, 0); a == nil || string(a.Data) != "a.test" {
		t.Fatalf("Find = %+v", a)
	}
	if all := m.FindAll(AVPRouteRecord, 0); len(all) != 2 || string(all[1].Data) != "b.test" {
		t.Fatalf("FindAll = %+v", all)
	}
	if m.Find(codeU32, 0) != nil {
		t.Fatal("Find matched a vendor AVP without its vendor")
	}
	if m.Find(codeU32, testVendor) == nil {
		t.Fatal("Find missed the vendor AVP")
	}
}

func TestSessionIDAndResultCodeAreReadWhenPresent(t *testing.T) {
	m := &Message{}
	if _, ok := m.SessionID(); ok {
		t.Fatal("SessionID on an empty message")
	}
	if _, ok := m.ResultCode(); ok {
		t.Fatal("ResultCode on an empty message")
	}
	m.Add(NewAVP(AVPSessionID, FlagMandatory, 0, []byte("h.test;1;2")), NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(5012)))
	if s, ok := m.SessionID(); !ok || s != "h.test;1;2" {
		t.Fatalf("SessionID = %q, %v", s, ok)
	}
	if rc, ok := m.ResultCode(); !ok || rc != 5012 {
		t.Fatalf("ResultCode = %d, %v", rc, ok)
	}
}

func TestDecodedAVPsMayBeCopiedVerbatimIntoAnotherMessage(t *testing.T) {
	proxy := NewGrouped(AVPProxyInfo, FlagMandatory, 0,
		NewAVP(AVPProxyHost, FlagMandatory, 0, []byte("dra.rcs.test")),
		NewAVP(AVPProxyState, FlagMandatory, 0, []byte{1, 2, 3}))
	b, _ := (&Message{Flags: FlagRequest, AVPs: []*AVP{proxy}}).Encode()
	d, _ := NewDictionary()
	m, err := DecodeMessage(b, d, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := (&Message{Flags: FlagRequest, AVPs: m.AVPs}).Encode()
	if !bytes.Equal(b, b2) {
		t.Fatalf("re-encoded % x, want % x", b2, b)
	}
}

func TestProtocolErrorClassIsThe3xxxRange(t *testing.T) {
	for code, want := range map[uint32]bool{
		ResultSuccess: false, 2999: false, ResultCommandUnsupported: true, ResultUnknownPeer: true,
		3999: true, ResultAuthenticationRejected: false, ResultMissingAVP: false,
	} {
		if got := IsProtocolError(code); got != want {
			t.Errorf("IsProtocolError(%d) = %v", code, got)
		}
	}
}

func TestErrorTextNamesTheResultCode(t *testing.T) {
	if got := (&Error{ResultCode: 5005}).Error(); got != "diameter: result 5005" {
		t.Errorf("Error() = %q", got)
	}
	if got := (&Error{ResultCode: 5005, Message: "missing Origin-Host"}).Error(); got != "diameter: result 5005: missing Origin-Host" {
		t.Errorf("Error() = %q", got)
	}
}
