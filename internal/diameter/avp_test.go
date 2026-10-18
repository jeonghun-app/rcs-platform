package diameter

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Test AVP codes outside the base range, one per data type, so every type
// can be exercised through the dictionary-driven decoder.
const (
	testVendor = 10415
	codeU32    = 9001
	codeU64    = 9002
	codeI32    = 9003
	codeI64    = 9004
	codeOctets = 9005
	codeUTF8   = 9006
	codeIdent  = 9007
	codeURI    = 9008
	codeAddr   = 9009
	codeTime   = 9010
	codeEnum   = 9011
	codeGroup  = 9012
)

var testDefs = []AVPDef{
	{"Test-Unsigned32", codeU32, testVendor, TypeUnsigned32},
	{"Test-Unsigned64", codeU64, testVendor, TypeUnsigned64},
	{"Test-Integer32", codeI32, testVendor, TypeInteger32},
	{"Test-Integer64", codeI64, testVendor, TypeInteger64},
	{"Test-OctetString", codeOctets, testVendor, TypeOctetString},
	{"Test-UTF8String", codeUTF8, testVendor, TypeUTF8String},
	{"Test-Identity", codeIdent, testVendor, TypeDiameterIdentity},
	{"Test-URI", codeURI, testVendor, TypeDiameterURI},
	{"Test-Address", codeAddr, testVendor, TypeAddress},
	{"Test-Time", codeTime, testVendor, TypeTime},
	{"Test-Enumerated", codeEnum, testVendor, TypeEnumerated},
	{"Test-Grouped", codeGroup, testVendor, TypeGrouped},
}

func testDictionary(t testing.TB) *Dictionary {
	t.Helper()
	d, err := NewDictionary(testDefs...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// roundTrip encodes a message holding a, decodes it and returns the AVP.
func roundTrip(t *testing.T, a *AVP) *AVP {
	t.Helper()
	m := &Message{Flags: FlagRequest, Code: 300, ApplicationID: 16777216, AVPs: []*AVP{a}}
	b, err := m.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := DecodeMessage(b, testDictionary(t), Limits{})
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if len(got.AVPs) != 1 {
		t.Fatalf("decoded %d AVPs, want 1", len(got.AVPs))
	}
	out := got.AVPs[0]
	if out.Code != a.Code || out.VendorID != a.VendorID || out.Flags != a.Flags || !bytes.Equal(out.Data, a.Data) {
		t.Fatalf("round trip changed the AVP: got %+v, want %+v", out, a)
	}
	return out
}

func TestEveryDataTypeRoundTripsThroughEncodeAndDecode(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::1")
	when := time.Date(2026, 10, 18, 12, 30, 45, 0, time.UTC)
	child := NewAVP(codeU32, FlagMandatory, testVendor, Unsigned32(7))

	tests := []struct {
		name  string
		avp   *AVP
		check func(t *testing.T, a *AVP)
	}{
		{"Unsigned32", NewAVP(codeU32, FlagMandatory, testVendor, Unsigned32(4294967295)), func(t *testing.T, a *AVP) {
			if v, err := a.Unsigned32(); err != nil || v != 4294967295 {
				t.Errorf("Unsigned32() = %d, %v", v, err)
			}
		}},
		{"Unsigned64", NewAVP(codeU64, FlagMandatory, testVendor, Unsigned64(1<<63+5)), func(t *testing.T, a *AVP) {
			if v, err := a.Unsigned64(); err != nil || v != 1<<63+5 {
				t.Errorf("Unsigned64() = %d, %v", v, err)
			}
		}},
		{"Integer32", NewAVP(codeI32, FlagMandatory, testVendor, Integer32(-42)), func(t *testing.T, a *AVP) {
			if v, err := a.Integer32(); err != nil || v != -42 {
				t.Errorf("Integer32() = %d, %v", v, err)
			}
		}},
		{"Integer64", NewAVP(codeI64, FlagMandatory, testVendor, Integer64(-1<<40)), func(t *testing.T, a *AVP) {
			if v, err := a.Integer64(); err != nil || v != -1<<40 {
				t.Errorf("Integer64() = %d, %v", v, err)
			}
		}},
		{"OctetString", NewAVP(codeOctets, 0, testVendor, []byte{0, 1, 2, 0xff, 0xfe}), func(t *testing.T, a *AVP) {
			if !bytes.Equal(a.OctetString(), []byte{0, 1, 2, 0xff, 0xfe}) {
				t.Errorf("OctetString() = %x", a.OctetString())
			}
		}},
		{"UTF8String", NewAVP(codeUTF8, 0, testVendor, []byte("가나다 abc")), func(t *testing.T, a *AVP) {
			if v, err := a.UTF8String(); err != nil || v != "가나다 abc" {
				t.Errorf("UTF8String() = %q, %v", v, err)
			}
		}},
		{"DiameterIdentity", NewAVP(codeIdent, 0, testVendor, []byte("scscf-1a.rcs.test")), func(t *testing.T, a *AVP) {
			if v, err := a.DiameterIdentity(); err != nil || v != "scscf-1a.rcs.test" {
				t.Errorf("DiameterIdentity() = %q, %v", v, err)
			}
		}},
		{"DiameterURI", NewAVP(codeURI, 0, testVendor, []byte("aaa://hss.rcs.test:3868;transport=tcp")), func(t *testing.T, a *AVP) {
			if v, err := a.DiameterURI(); err != nil || v != "aaa://hss.rcs.test:3868;transport=tcp" {
				t.Errorf("DiameterURI() = %q, %v", v, err)
			}
		}},
		{"Address IPv4", NewAVP(codeAddr, 0, testVendor, Address(v4)), func(t *testing.T, a *AVP) {
			if v, err := a.Address(); err != nil || v != v4 {
				t.Errorf("Address() = %v, %v", v, err)
			}
		}},
		{"Address IPv6", NewAVP(codeAddr, 0, testVendor, Address(v6)), func(t *testing.T, a *AVP) {
			if v, err := a.Address(); err != nil || v != v6 {
				t.Errorf("Address() = %v, %v", v, err)
			}
		}},
		{"Time", NewAVP(codeTime, 0, testVendor, Time(when)), func(t *testing.T, a *AVP) {
			if v, err := a.Time(); err != nil || !v.Equal(when) {
				t.Errorf("Time() = %v, %v", v, err)
			}
		}},
		{"Enumerated", NewAVP(codeEnum, 0, testVendor, Enumerated(2)), func(t *testing.T, a *AVP) {
			if v, err := a.Enumerated(); err != nil || v != 2 {
				t.Errorf("Enumerated() = %d, %v", v, err)
			}
		}},
		{"Grouped", NewGrouped(codeGroup, FlagMandatory, testVendor, child, NewAVP(codeUTF8, 0, testVendor, []byte("x"))), func(t *testing.T, a *AVP) {
			children, err := a.Grouped()
			if err != nil || len(children) != 2 {
				t.Fatalf("Grouped() = %d children, %v", len(children), err)
			}
			if v, _ := children[0].Unsigned32(); v != 7 || children[1].Code != codeUTF8 {
				t.Errorf("children = %+v, %+v", children[0], children[1])
			}
		}},
		{"empty Grouped", NewGrouped(codeGroup, 0, testVendor), func(t *testing.T, a *AVP) {
			if children, err := a.Grouped(); err != nil || len(children) != 0 {
				t.Errorf("Grouped() = %v, %v", children, err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, roundTrip(t, tt.avp))
		})
	}
}

func TestBaseAVPWithoutVendorHasAnEightByteHeader(t *testing.T) {
	a := NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(ResultSuccess))
	got := a.appendTo(nil)
	want := []byte{0, 0, 1, 12, 0x40, 0, 0, 12, 0, 0, 0x07, 0xd1}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded % x, want % x", got, want)
	}
}

func TestVendorFlagFollowsTheVendorID(t *testing.T) {
	a := NewAVP(codeU32, FlagMandatory, testVendor, Unsigned32(1))
	if a.Flags != FlagVendor|FlagMandatory {
		t.Fatalf("flags = %#x, want V and M", a.Flags)
	}
	got := a.appendTo(nil)
	if len(got) != 16 || got[7] != 16 {
		t.Fatalf("vendor AVP encoded as % x, want a 12-byte header and length 16", got)
	}
}

func TestPaddingIsWrittenButNotCountedInTheAVPLength(t *testing.T) {
	a := NewAVP(AVPProductName, 0, 0, []byte("abcde"))
	got := a.appendTo(nil)
	if len(got) != 16 {
		t.Fatalf("encoded length %d, want 16 (13 padded to 16)", len(got))
	}
	if got[7] != 13 {
		t.Fatalf("AVP Length = %d, want 13", got[7])
	}
	if !bytes.Equal(got[13:], []byte{0, 0, 0}) {
		t.Fatalf("padding = % x, want zeros", got[13:])
	}
}

func TestTimeFollowsTheNTPEraRuleAcross2036(t *testing.T) {
	tests := []struct {
		name string
		when time.Time
		wire uint32
	}{
		{"Unix epoch", time.Unix(0, 0).UTC(), 2208988800},
		{"last second of era 0", time.Date(2036, 2, 7, 6, 28, 15, 0, time.UTC), 0xffffffff},
		{"first second of era 1", time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC), 0},
		// Unix 4102444800 + 2208988800 NTP offset - 2^32.
		{"late in era 1", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), 2016466304},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAVP(AVPEventTimestamp, 0, 0, Time(tt.when))
			if v, _ := a.Unsigned32(); v != tt.wire {
				t.Fatalf("wire value = %d, want %d", v, tt.wire)
			}
			got, err := a.Time()
			if err != nil || !got.Equal(tt.when) {
				t.Fatalf("Time() = %v, %v; want %v", got, err, tt.when)
			}
		})
	}
}

func TestTimeDropsSubSecondPrecision(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 999_000_000, time.UTC)
	got, err := NewAVP(AVPEventTimestamp, 0, 0, Time(when)).Time()
	if err != nil || !got.Equal(when.Truncate(time.Second)) {
		t.Fatalf("Time() = %v, %v", got, err)
	}
}

func TestAccessorsRejectPayloadsOfTheWrongShape(t *testing.T) {
	short := &AVP{Data: []byte{1, 2, 3}}
	if _, err := short.Unsigned32(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Unsigned32 on 3 bytes: %v", err)
	}
	if _, err := short.Integer32(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Integer32 on 3 bytes: %v", err)
	}
	if _, err := short.Enumerated(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Enumerated on 3 bytes: %v", err)
	}
	if _, err := short.Unsigned64(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Unsigned64 on 3 bytes: %v", err)
	}
	if _, err := short.Integer64(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Integer64 on 3 bytes: %v", err)
	}
	if _, err := short.Time(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Time on 3 bytes: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0xff, 0xfe}}).UTF8String(); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("UTF8String on invalid UTF-8: %v", err)
	}
	if _, err := (&AVP{Data: []byte("host name")}).DiameterIdentity(); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("DiameterIdentity with a space: %v", err)
	}
	if _, err := (&AVP{Data: []byte("http://hss")}).DiameterURI(); !errors.Is(err, ErrInvalidURI) {
		t.Errorf("DiameterURI with http scheme: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0, 3, 1, 2}}).Address(); !errors.Is(err, ErrUnsupportedAddressType) {
		t.Errorf("Address with family 3: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0}}).Address(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Address with 1 byte: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0, 1, 10, 0, 0}}).Address(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("IPv4 Address with 3 address bytes: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0, 2, 1, 2, 3, 4}}).Address(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("IPv6 Address with 4 address bytes: %v", err)
	}
	if _, err := (&AVP{Data: []byte{0, 0, 0, 1, 0, 0, 0, 4}}).Grouped(); !errors.Is(err, ErrAVPLength) {
		t.Errorf("Grouped with a child shorter than its header: %v", err)
	}
}

func TestZeroAddressEncodesAsAnEmptyPayload(t *testing.T) {
	if b := Address(netip.Addr{}); len(b) != 0 {
		t.Fatalf("Address(zero) = % x, want empty", b)
	}
}

func TestDiameterIdentityAcceptsHostNameCharactersOnly(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"hss.rcs.test", true},
		{"scscf-0a1b2c.rcs.local", true},
		{"ims.mnc001.mcc001.3gppnetwork.org", true},
		{"_diameter._tcp.rcs.test", true},
		{"", false},
		{"host name", false},
		{"host\x00", false},
		{"hôst.test", false},
		{string(bytes.Repeat([]byte("a"), 256)), false},
	}
	for _, tt := range tests {
		if got := validIdentity([]byte(tt.in)); got != tt.want {
			t.Errorf("validIdentity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDiameterURIRequiresTheAAASchemes(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"aaa://hss.rcs.test", true},
		{"AAA://hss.rcs.test:3868", true},
		{"aaas://hss.rcs.test:5658;transport=tcp", true},
		{"aaa://", false},
		{"aaa:/hss", false},
		{"http://hss.rcs.test", false},
		{"aaa://hss rcs", false},
		{"aaa://hss\x7f", false},
		{"aa", false},
	}
	for _, tt := range tests {
		if got := validURI([]byte(tt.in)); got != tt.want {
			t.Errorf("validURI(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
