package sip

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseViaReadsEveryElement(t *testing.T) {
	tests := []struct {
		in   string
		want Vias
	}{
		{"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds", Vias{{Transport: "UDP", Host: "192.0.2.1", Port: 5060,
			Params: Params{{Name: "branch", Value: "z9hG4bK776asdhds"}}}}},
		// RFC 4475 §3.1.1.1 puts whitespace around every separator.
		{"SIP  /  2.0  / TCP   spindle.example.com   ;  branch  =   z9hG4bK9ikj8  ,  sip / 2.0 / UDP [2001:db8::9] : 5070 ; rport ; received = 2001:db8::1",
			Vias{
				{Transport: "TCP", Host: "spindle.example.com", Params: Params{{Name: "branch", Value: "z9hG4bK9ikj8"}}},
				{Transport: "UDP", Host: "[2001:db8::9]", Port: 5070, Params: Params{{Name: "rport"}, {Name: "received", Value: "2001:db8::1"}}},
			}},
		{"SIP/2.0/UNKNOWN t1.example.com;branch=z9hG4bKasdf;ttl=255;maddr=224.0.1.75;rport=5061;received=192.0.2.9;x-extra=\"q\"",
			Vias{{Transport: "UNKNOWN", Host: "t1.example.com", Params: Params{
				{Name: "branch", Value: "z9hG4bKasdf"}, {Name: "ttl", Value: "255"}, {Name: "maddr", Value: "224.0.1.75"},
				{Name: "rport", Value: "5061"}, {Name: "received", Value: "192.0.2.9"}, {Name: "x-extra", Value: "q", Quoted: true}}}}},
		{"SIP/2.0/TLS client.example.com;received=[2001:db8::1]", Vias{{Transport: "TLS", Host: "client.example.com",
			Params: Params{{Name: "received", Value: "[2001:db8::1]"}}}}},
	}
	for _, tt := range tests {
		got, err := ParseVia(tt.in)
		if err != nil {
			t.Errorf("ParseVia(%q): %v", tt.in, err)
			continue
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseVia(%q) = %#v, want %#v", tt.in, got, tt.want)
		}
	}
}

func TestMalformedViasAreRejected(t *testing.T) {
	for _, in := range []string{
		"",
		"SIP/2.0/UDP",
		"SIP/2.0/UDP ",
		"SIP/2.0 UDP host.example.com",
		"SIP/2.0/ host.example.com",
		"SIP/2.0/UDPhost.example.com",
		"HTTP/1.1/TCP host.example.com",
		"SIP/3.0/UDP host.example.com",
		"SIP/2.0/UDP host_1.example.com",
		"SIP/2.0/UDP [2001:db8::1",
		"SIP/2.0/UDP host.example.com:",
		"SIP/2.0/UDP host.example.com:0",
		"SIP/2.0/UDP host.example.com:70000",
		"SIP/2.0/UDP 192.0.2.15;;,;,,",
		"SIP/2.0/UDP host.example.com;branch",
		"SIP/2.0/UDP host.example.com;branch=\"z9hG4bK1\"",
		"SIP/2.0/UDP host.example.com;branch=1;branch=2",
		"SIP/2.0/UDP host.example.com;ttl=256",
		"SIP/2.0/UDP host.example.com;ttl=0001",
		"SIP/2.0/UDP host.example.com;maddr=bad_host",
		"SIP/2.0/UDP host.example.com;received=host.example.com",
		"SIP/2.0/UDP host.example.com;received=1.2.3.999",
		"SIP/2.0/UDP host.example.com;received=\"192.0.2.1\"",
		"SIP/2.0/UDP host.example.com;maddr=\"h2.example.com\"",
		"SIP/2.0/UDP host.example.com;ttl=\"1\"",
		"SIP/2.0/UDP host.example.com;rport=0",
		"SIP/2.0/UDP host.example.com;rport=x",
		"SIP/2.0/UDP host.example.com;rport=\"5060\"",
		"SIP/2.0/UDP host.example.com junk",
	} {
		if _, err := ParseVia(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseVia(%q) error = %v, want ErrMalformed", in, err)
		}
	}
}

func TestViaAccessorsReadTheParameters(t *testing.T) {
	vs, err := ParseVia("SIP/2.0/UDP client.example.com;branch=z9hG4bKnashds8;rport=5070;received=192.0.2.4;maddr=192.0.2.200;ttl=16")
	if err != nil {
		t.Fatal(err)
	}
	v := vs[0]
	if v.Branch() != "z9hG4bKnashds8" || !v.HasMagicCookie() || v.Received() != "192.0.2.4" || v.MAddr() != "192.0.2.200" {
		t.Errorf("accessors: %q %v %q %q", v.Branch(), v.HasMagicCookie(), v.Received(), v.MAddr())
	}
	if p, ok := v.RPort(); !ok || p != 5070 {
		t.Errorf("RPort() = %d, %v", p, ok)
	}
	if ttl, ok := v.TTL(); !ok || ttl != 16 {
		t.Errorf("TTL() = %d, %v", ttl, ok)
	}

	flag, _ := ParseVia("SIP/2.0/UDP client.example.com;branch=1;rport")
	if p, ok := flag[0].RPort(); !ok || p != 0 {
		t.Errorf("rport flag: RPort() = %d, %v", p, ok)
	}
	if flag[0].HasMagicCookie() {
		t.Error("an RFC 2543 branch has the magic cookie")
	}
	var bare Via
	if _, ok := bare.RPort(); ok {
		t.Error("RPort() present on an empty Via")
	}
	if _, ok := bare.TTL(); ok {
		t.Error("TTL() present on an empty Via")
	}
	if bare.Branch() != "" || bare.Received() != "" || bare.MAddr() != "" {
		t.Error("empty Via has parameters")
	}
}

func TestViaStringRoundTrips(t *testing.T) {
	v := Via{Transport: "TCP", Host: "[2001:db8::1]", Port: 5061, Params: Params{{Name: "branch", Value: MagicCookie + "abc"}, {Name: "rport"}}}
	s := v.String()
	if s != "SIP/2.0/TCP [2001:db8::1]:5061;branch=z9hG4bKabc;rport" {
		t.Errorf("String() = %q", s)
	}
	got, err := ParseVia(s)
	if err != nil || !reflect.DeepEqual(got, Vias{v}) {
		t.Errorf("round trip = %#v, %v", got, err)
	}
}

func TestHeaderViaReadsEveryFieldTopFirst(t *testing.T) {
	var h Header
	mustAdd(t, &h, "Via", "SIP/2.0/UDP a.example.com;branch=z9hG4bK1, SIP/2.0/UDP b.example.com;branch=z9hG4bK2")
	mustAdd(t, &h, "v", "SIP/2.0/UDP c.example.com;branch=z9hG4bK3")
	vs, err := h.Via()
	if err != nil || len(vs) != 3 || vs[0].Host != "a.example.com" || vs[2].Host != "c.example.com" {
		t.Fatalf("Via() = %#v, %v", vs, err)
	}
	mustAdd(t, &h, "Via", "SIP/2.0/UDP")
	if _, err := h.Via(); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed Via: %v", err)
	}
}
