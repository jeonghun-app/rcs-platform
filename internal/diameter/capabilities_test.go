package diameter

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

func TestPeerRulesMatchHostPatternRealmAndNetwork(t *testing.T) {
	vpc := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}
	inVPC := netip.MustParseAddr("10.0.3.7")
	outside := netip.MustParseAddr("192.0.2.1")
	tests := []struct {
		name  string
		rule  PeerRule
		host  string
		realm string
		src   netip.Addr
		want  bool
	}{
		{"exact host", PeerRule{Host: "icscf.rcs.test"}, "icscf.rcs.test", "rcs.test", inVPC, true},
		{"exact host ignores case", PeerRule{Host: "ICSCF.rcs.test"}, "icscf.RCS.test", "rcs.test", inVPC, true},
		{"other host", PeerRule{Host: "icscf.rcs.test"}, "scscf.rcs.test", "rcs.test", inVPC, false},
		{"pattern matches a task identity", PeerRule{HostPattern: "scscf-*.rcs.local"}, "scscf-0a1b2c3d.rcs.local", "rcs.local", inVPC, true},
		{"pattern ignores case", PeerRule{HostPattern: "SCSCF-*.rcs.local"}, "scscf-AB.rcs.LOCAL", "rcs.local", inVPC, true},
		{"pattern star does not cross a dot", PeerRule{HostPattern: "scscf-*.rcs.local"}, "scscf-x.evil.rcs.local", "rcs.local", inVPC, false},
		{"pattern needs the same label count", PeerRule{HostPattern: "*.rcs.local"}, "rcs.local", "rcs.local", inVPC, false},
		{"pattern prefix must match", PeerRule{HostPattern: "scscf-*.rcs.local"}, "icscf-1.rcs.local", "rcs.local", inVPC, false},
		{"pattern with a star in the middle", PeerRule{HostPattern: "s*f-1.rcs.local"}, "scscf-1.rcs.local", "rcs.local", inVPC, true},
		{"pattern star matches nothing", PeerRule{HostPattern: "scscf*.rcs.local"}, "scscf.rcs.local", "rcs.local", inVPC, true},
		{"pattern with two stars backtracks", PeerRule{HostPattern: "*a*b.test"}, "xaxxab.test", "test", inVPC, true},
		{"pattern with trailing literal unmatched", PeerRule{HostPattern: "*a*b.test"}, "xaxxa.test", "test", inVPC, false},
		{"realm only", PeerRule{Realm: "rcs.local"}, "anything.rcs.local", "rcs.local", inVPC, true},
		{"realm mismatch", PeerRule{Realm: "rcs.local"}, "x.rcs.local", "other.local", inVPC, false},
		{"realm and network accept a VPC peer", PeerRule{Realm: "rcs.local", Networks: vpc}, "scscf-9.rcs.local", "rcs.local", inVPC, true},
		{"realm and network refuse an outside peer", PeerRule{Realm: "rcs.local", Networks: vpc}, "scscf-9.rcs.local", "rcs.local", outside, false},
		{"network refuses an unknown source", PeerRule{Realm: "rcs.local", Networks: vpc}, "scscf-9.rcs.local", "rcs.local", netip.Addr{}, false},
		{"every field must match", PeerRule{HostPattern: "scscf-*.rcs.local", Realm: "rcs.local"}, "scscf-1.rcs.local", "other", inVPC, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rule.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := tt.rule.matches(tt.host, tt.realm, tt.src); got != tt.want {
				t.Fatalf("matches(%q, %q, %v) = %v, want %v", tt.host, tt.realm, tt.src, got, tt.want)
			}
		})
	}
}

func TestPeerRuleMustNameAnIdentity(t *testing.T) {
	bad := []PeerRule{
		{},
		{Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{HostPattern: "scscf-*.rcs local"},
		{Realm: "rcs.local", Networks: []netip.Prefix{{}}},
	}
	for _, r := range bad {
		if err := r.validate(); err == nil {
			t.Errorf("rule %+v accepted", r)
		}
	}
}

func TestCommonApplicationsAreTheLocalOnesTheRemoteAdvertises(t *testing.T) {
	local := []Application{{ID: 16777216, VendorID: 10415}, {ID: 16777217, VendorID: 10415}, {ID: 4}}
	tests := []struct {
		name   string
		remote []uint32
		want   []uint32
	}{
		{"one in common", []uint32{16777216, 99}, []uint32{16777216}},
		{"none in common", []uint32{99}, nil},
		{"relay accepts everything", []uint32{AppRelay}, []uint32{16777216, 16777217, 4}},
		{"duplicates collapse", []uint32{4, 4}, []uint32{4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commonApplications(local, tt.remote); !slices.Equal(got, tt.want) {
				t.Fatalf("commonApplications = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOnlyNoInbandSecurityIsAcceptable(t *testing.T) {
	if !securityAcceptable(nil) {
		t.Error("absent Inband-Security-Id means NO_INBAND_SECURITY")
	}
	if !securityAcceptable([]uint32{InbandSecurityTLS, InbandSecurityNone}) {
		t.Error("an offer including NO_INBAND_SECURITY is acceptable")
	}
	if securityAcceptable([]uint32{InbandSecurityTLS}) {
		t.Error("TLS only is not acceptable")
	}
}

func TestParseCapabilitiesReadsApplicationsFromBothForms(t *testing.T) {
	d, _ := NewDictionary()
	m := testCER("scscf-1.rcs.test", "rcs.test",
		NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(4)),
		NewGrouped(AVPVendorSpecificApplicationID, FlagMandatory, 0,
			NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(10415)),
			NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(16777216))),
		NewAVP(AVPInbandSecurityID, FlagMandatory, 0, Unsigned32(InbandSecurityNone)),
	)
	caps, err := parseCapabilities(m, d)
	if err != nil {
		t.Fatal(err)
	}
	if caps.host != "scscf-1.rcs.test" || caps.realm != "rcs.test" || caps.originStateID != 7 {
		t.Fatalf("caps = %+v", caps)
	}
	if !slices.Equal(caps.authApps, []uint32{4, 16777216}) || !slices.Equal(caps.inbandSecurity, []uint32{0}) {
		t.Fatalf("applications %v, security %v", caps.authApps, caps.inbandSecurity)
	}
}

func TestParseCapabilitiesRefusesBadValues(t *testing.T) {
	d, _ := NewDictionary()
	tests := []struct {
		name string
		avp  *AVP
	}{
		{"short Auth-Application-Id", NewAVP(AVPAuthApplicationID, FlagMandatory, 0, []byte{1})},
		{"short Inband-Security-Id", NewAVP(AVPInbandSecurityID, FlagMandatory, 0, []byte{1})},
		{"broken Vendor-Specific-Application-Id", NewAVP(AVPVendorSpecificApplicationID, FlagMandatory, 0, []byte{0, 0, 1, 2, 0, 0, 0, 3})},
		{"short Auth-Application-Id inside Vendor-Specific-Application-Id", NewGrouped(AVPVendorSpecificApplicationID, FlagMandatory, 0,
			NewAVP(AVPAuthApplicationID, FlagMandatory, 0, []byte{1}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCapabilities(testCER("h.test", "test", tt.avp), d)
			if err == nil || err.ResultCode != ResultInvalidAVPValue {
				t.Fatalf("err = %v, want DIAMETER_INVALID_AVP_VALUE", err)
			}
		})
	}
	m := testCER("h.test", "test")
	m.Find(AVPOriginHost, 0).Data = []byte("bad host")
	if _, err := parseCapabilities(m, d); err == nil || err.ResultCode != ResultInvalidAVPValue {
		t.Fatalf("invalid Origin-Host: %v", err)
	}
	m = testCER("h.test", "test")
	m.Find(AVPOriginRealm, 0).Data = nil
	if _, err := parseCapabilities(m, d); err == nil || err.ResultCode != ResultInvalidAVPValue {
		t.Fatalf("empty Origin-Realm: %v", err)
	}
}

func TestParseCapabilitiesReportsTheFirstMissingRequiredAVP(t *testing.T) {
	d, _ := NewDictionary()
	for _, code := range []uint32{AVPOriginHost, AVPOriginRealm, AVPHostIPAddress, AVPVendorID, AVPProductName} {
		m := testCER("h.test", "test")
		m.AVPs = slices.DeleteFunc(m.AVPs, func(a *AVP) bool { return a.Code == code })
		_, err := parseCapabilities(m, d)
		if err == nil || err.ResultCode != ResultMissingAVP || err.FailedAVP.Code != code {
			t.Errorf("without AVP %d: %v", code, err)
		}
	}
}

func TestAddrOfReadsTCPAndTextualAddresses(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 3868}
	if got := addrOf(tcp); got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("addrOf(TCP) = %v, want the unmapped IPv4 address", got)
	}
	if got := addrOf(&net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1}); got != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("addrOf(UDP) = %v", got)
	}
	if got := addrOf(pipeAddr{}); got.IsValid() {
		t.Errorf("addrOf(pipe) = %v, want none", got)
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }
