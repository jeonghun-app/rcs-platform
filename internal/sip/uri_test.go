package sip

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseURIReadsEveryComponent(t *testing.T) {
	tests := []struct {
		in   string
		want URI
	}{
		{"sip:alice@example.com", URI{Scheme: "sip", User: "alice", Host: "example.com"}},
		{"SIPS:alice:secret@example.com:5061", URI{Scheme: "sips", User: "alice", Password: "secret", Host: "example.com", Port: 5061}},
		{"sip:example.com;lr", URI{Scheme: "sip", Host: "example.com", Params: Params{{Name: "lr"}}}},
		{"sip:192.0.2.1:5060;transport=tcp", URI{Scheme: "sip", Host: "192.0.2.1", Port: 5060, Params: Params{{Name: "transport", Value: "tcp"}}}},
		{"sip:[2001:db8::1]:5070;maddr=[2001:db8::2]", URI{Scheme: "sip", Host: "[2001:db8::1]", Port: 5070, Params: Params{{Name: "maddr", Value: "[2001:db8::2]"}}}},
		{"sip:alice@example.com?subject=project%20x&priority=urgent", URI{Scheme: "sip", User: "alice", Host: "example.com",
			Headers: Params{{Name: "subject", Value: "project%20x"}, {Name: "priority", Value: "urgent"}}}},
		{"sip:+15550100001@ims.example.net;user=phone", URI{Scheme: "sip", User: "+15550100001", Host: "ims.example.net", Params: Params{{Name: "user", Value: "phone"}}}},
		// The user part may hold ";" and "?" (RFC 3261 §25.1 user-unreserved).
		{"sip:user;par=u%40example.net@example.com", URI{Scheme: "sip", User: "user;par=u%40example.net", Host: "example.com"}},
		{"sip:example.com.", URI{Scheme: "sip", Host: "example.com."}},
		{"sip:h?x=", URI{Scheme: "sip", Host: "h", Headers: Params{{Name: "x"}}}},
		{"tel:+1-555-010-0001", URI{Scheme: "tel", User: "+1-555-010-0001"}},
		{"tel:7042;phone-context=example.com", URI{Scheme: "tel", User: "7042", Params: Params{{Name: "phone-context", Value: "example.com"}}}},
		{"tel:+15550100001;ext=12", URI{Scheme: "tel", User: "+15550100001", Params: Params{{Name: "ext", Value: "12"}}}},
		{"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", URI{Scheme: "urn", Opaque: "uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6"}},
		{"urn:service:sos", URI{Scheme: "urn", Opaque: "service:sos"}},
		{"im:alice@example.com", URI{Scheme: "im", Opaque: "alice@example.com"}},
	}
	for _, tt := range tests {
		got, err := ParseURI(tt.in)
		if err != nil {
			t.Errorf("ParseURI(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseURI(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestMalformedURIsAreRejected(t *testing.T) {
	for _, in := range []string{
		"",
		"sip",
		":alice@example.com",
		"1sip:alice@example.com",
		"s p:x",
		"sip:",
		"sip:@example.com",
		"sip:al ice@example.com",
		"sip:alice@",
		"sip:alice@exa_mple.com",
		"sip:alice@-example.com",
		"sip:alice@example-.com",
		"sip:alice@example.123",
		"sip:alice@1.2.3.256",
		"sip:alice@1.2.3",
		"sip:alice@1.2.3.4.5",
		"sip:alice@example..com",
		"sip:alice@[2001:db8::1",
		"sip:alice@[192.0.2.1]",
		"sip:alice@[fe80::1%25eth0]",
		"sip:alice@[2001:db8::1]x",
		"sip:alice@example.com:",
		"sip:alice@example.com:0",
		"sip:alice@example.com:65536",
		"sip:alice@example.com:123456",
		"sip:alice@example.com:50a",
		"sip:alice@example.com;",
		"sip:alice@example.com;;lr",
		"sip:alice@example.com;x=",
		"sip:alice@example.com;x=a=b",
		"sip:alice@example.com;lr;LR",
		"sip:alice@example.com;lr;%6C%72",
		"sip:alice@example.com;x=<y>",
		"sip:alice@example.com?",
		"sip:alice@example.com?x",
		"sip:alice@example.com?=x",
		"sip:alice@example.com?a=b&",
		"sip:%zz@example.com",
		"sip:alice%2@example.com",
		"sip:alice:pa:ss@example.com",
		"sip:alice@exa%41mple.com",
		"tel:",
		"tel:+",
		"tel:+--",
		"tel:+1555x",
		"tel:7042",
		"tel:7042;phone-context=example.com;phone-context=example.net",
		"tel:+15550100001;",
		"tel:+15550100001;ext=",
		"tel:+15550100001;e_xt=1",
		"urn:",
		"urn:a b",
		"urn:<x>",
	} {
		_, err := ParseURI(in)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseURI(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestURIStringRoundTripsParsedURIs(t *testing.T) {
	for _, in := range []string{
		"sip:alice@example.com",
		"sips:alice:secret@example.com:5061;transport=tls",
		"sip:[2001:db8::1]:5070;lr;maddr=[2001:db8::2]",
		"sip:%61lice@example.com;n%61me=v%61lue%25%34%31?h=a%20b&g=",
		"sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*:&it+has=1,weird!*pas$wo~d_too.(doesn't-it)@example.com",
		"tel:+1-555-010-0001;ext=12",
		"tel:*7042#;phone-context=example.com",
		"urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
	} {
		u, err := ParseURI(in)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", in, err)
		}
		if got := u.String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
	}
}

func TestURIStringEscapesWhatAComponentCannotCarry(t *testing.T) {
	u := URI{
		Scheme:  "sip",
		User:    "a b>c",
		Host:    "example.com",
		Params:  Params{{Name: "x", Value: "1;2"}},
		Headers: Params{{Name: "Subject", Value: "a&b"}},
	}
	want := "sip:a%20b%3Ec@example.com;x=1%3B2?Subject=a%26b"
	if got := u.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if _, err := ParseURI(want); err != nil {
		t.Fatalf("escaped URI does not parse: %v", err)
	}
	if got := (URI{}).String(); got != "" {
		t.Errorf("zero URI String() = %q", got)
	}
}

// The examples of RFC 3261 §19.1.4.
func TestURIEqualFollowsRFC3261Section19_1_4(t *testing.T) {
	tests := []struct {
		a, b  string
		equal bool
	}{
		{"sip:%61lice@atlanta.com;transport=TCP", "sip:alice@AtLanTa.CoM;Transport=tcp", true},
		{"sip:carol@chicago.com", "sip:carol@chicago.com;newparam=5", true},
		{"sip:carol@chicago.com", "sip:carol@chicago.com;security=on", true},
		{"sip:carol@chicago.com;newparam=5", "sip:carol@chicago.com;security=on", true},
		{"sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com", "sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com", true},
		{"sip:alice@atlanta.com?subject=project%20x&priority=urgent", "sip:alice@atlanta.com?priority=urgent&subject=project%20x", true},
		{"SIP:ALICE@AtLanTa.CoM;Transport=udp", "sip:alice@AtLanTa.CoM;Transport=UDP", false},
		{"sip:bob@biloxi.com", "sip:bob@biloxi.com:5060", false},
		{"sip:bob@biloxi.com", "sip:bob@biloxi.com;transport=udp", false},
		{"sip:bob@biloxi.com", "sip:bob@biloxi.com:6000;transport=tcp", false},
		{"sip:carol@chicago.com", "sip:carol@chicago.com?Subject=next%20meeting", false},
		{"sip:bob@phone21.boxesbybob.com", "sip:bob@192.0.2.4", false},
		// Equality is not transitive: both equal the URI without the parameter.
		{"sip:carol@chicago.com;security=on", "sip:carol@chicago.com;security=off", false},
	}
	for _, tt := range tests {
		a, err := ParseURI(tt.a)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", tt.a, err)
		}
		b, err := ParseURI(tt.b)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", tt.b, err)
		}
		if got := a.Equal(b); got != tt.equal {
			t.Errorf("%q.Equal(%q) = %v, want %v", tt.a, tt.b, got, tt.equal)
		}
		if got := b.Equal(a); got != tt.equal {
			t.Errorf("%q.Equal(%q) = %v, want %v", tt.b, tt.a, got, tt.equal)
		}
	}
}

func TestURIEqualHandlesSchemesEscapesAndAddresses(t *testing.T) {
	tests := []struct {
		a, b  string
		equal bool
	}{
		{"sip:alice@example.com", "sips:alice@example.com", false},
		{"sip:alice@example.com", "sip:Alice@example.com", false},
		{"sip:alice:a@example.com", "sip:alice:b@example.com", false},
		// An escaped reserved character is not the character itself.
		{"sip:a%3Bb@example.com", "sip:a;b@example.com", false},
		{"sip:a%3bb@example.com", "sip:a%3Bb@example.com", true},
		{"sip:[2001:db8::1]", "sip:[2001:db8:0:0::1]", true},
		{"sip:[2001:db8::1]", "sip:[2001:db8::2]", false},
		{"sip:example.com;maddr=192.0.2.1", "sip:example.com", false},
		{"sip:example.com;%6C%72", "sip:example.com;lr", true},
		{"sip:example.com;lr", "sip:example.com;lr=on", false},
		{"sip:example.com?a=1", "sip:example.com?b=1", false},
		{"sip:example.com?A=x", "sip:example.com?a=X", true},
		{"tel:+1-555-010-0001", "tel:+15550100001", true},
		{"tel:+15550100001", "tel:+15550100002", false},
		{"tel:+15550100001;ext=1", "tel:+15550100001", false},
		{"tel:+15550100001;ext=1", "tel:+15550100001;EXT=1", true},
		{"tel:+15550100001;ext=1", "tel:+15550100001;isub=1", false},
		{"tel:7042;phone-context=Example.com", "tel:7042;phone-context=example.com", true},
		{"urn:uuid:abc", "urn:uuid:abc", true},
		{"urn:uuid:abc", "urn:uuid:abd", false},
		{"tel:+15550100001", "sip:+15550100001@example.com;user=phone", false},
	}
	for _, tt := range tests {
		a, err := ParseURI(tt.a)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", tt.a, err)
		}
		b, err := ParseURI(tt.b)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", tt.b, err)
		}
		if got := a.Equal(b); got != tt.equal {
			t.Errorf("%q.Equal(%q) = %v, want %v", tt.a, tt.b, got, tt.equal)
		}
	}
}

func TestTelAndUserPhoneURIsShareAnE164Key(t *testing.T) {
	tests := []struct {
		in     string
		global bool
		key    string
	}{
		{"tel:+15550100001", true, "+15550100001"},
		{"tel:+1-555-010-0001", true, "+15550100001"},
		{"tel:+1.555.(010).0001", true, "+15550100001"},
		{"sip:+15550100001@ims.example.net;user=phone", true, "+15550100001"},
		{"sips:+1-555-010-0001@ims.example.net;user=PHONE", true, "+15550100001"},
		{"sip:%2B15550100001@ims.example.net;user=phone", true, "+15550100001"},
		{"sip:+15550100001;npdi@ims.example.net;user=phone", true, "+15550100001"},
		// An extension or subaddress names something other than the number.
		{"tel:+15550100001;ext=12", true, ""},
		{"sip:+15550100001;isub=12@ims.example.net;user=phone", true, ""},
		// Without user=phone the user part is just a user name.
		{"sip:+15550100001@ims.example.net", false, ""},
		{"tel:7042;phone-context=example.com", false, ""},
		{"sip:alice@ims.example.net;user=phone", false, ""},
		// E.164 allows at most 15 digits.
		{"tel:+1-555-010-0001-23456", true, ""},
		{"urn:service:sos", false, ""},
	}
	for _, tt := range tests {
		u, err := ParseURI(tt.in)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", tt.in, err)
		}
		if got := u.IsGlobalNumber(); got != tt.global {
			t.Errorf("%q IsGlobalNumber() = %v, want %v", tt.in, got, tt.global)
		}
		key, ok := u.E164()
		if key != tt.key || ok != (tt.key != "") {
			t.Errorf("%q E164() = %q, %v, want %q", tt.in, key, ok, tt.key)
		}
	}
}

func TestURIParamComparesEscapedNames(t *testing.T) {
	u, err := ParseURI("sip:example.com;%6C%72;Transport=TCP")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Param("lr"); !ok {
		t.Error(`Param("lr") not found`)
	}
	if v, ok := u.Param("transport"); !ok || v != "TCP" {
		t.Errorf(`Param("transport") = %q, %v`, v, ok)
	}
	if _, ok := u.Param("maddr"); ok {
		t.Error(`Param("maddr") found`)
	}
	if !u.IsSIP() {
		t.Error("IsSIP() = false")
	}
}
