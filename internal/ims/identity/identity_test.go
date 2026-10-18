package identity

import (
	"strings"
	"testing"
)

// Test identities: MCC 001 / MNC 01 and the fictional +1 555 0100 range
// (.github/allowed-test-identifiers.txt).
const (
	domain = "ims.mnc001.mcc001.3gppnetwork.org"
	imsi1  = "001010000000001"
	impi1  = imsi1 + "@" + domain
	impu1  = "sip:+15550100001@" + domain
	tel1   = "tel:+15550100001"
)

func TestPrivateIdentitiesAreNAIs(t *testing.T) {
	for impi, want := range map[string]bool{
		impi1:                               true,
		"alice@example.org":                 true,
		"a.b+c@sub.example.org":             true,
		"no-realm":                          false,
		"@example.org":                      false,
		"a@":                                false,
		"a@b@example.org":                   false,
		"a b@example.org":                   false,
		"a/b@example.org":                   false,
		"a%2Fb@example.org":                 false,
		"a@-bad.example.org":                false,
		"a@exa_mple.org":                    false,
		"a@example..org":                    false,
		strings.Repeat("a", 250) + "@x.org": false,
		"a\x00@example.org":                 false,
	} {
		if got := ValidIMPI(impi) == nil; got != want {
			t.Errorf("ValidIMPI(%q) = %t, want %t", impi, got, want)
		}
	}
}

func TestIMSIsAreSixToFifteenDigits(t *testing.T) {
	for imsi, want := range map[string]bool{
		imsi1: true, "001010": true, "00101": false, imsi1 + "1": false, "00101000000000a": false, "": false,
	} {
		if got := ValidIMSI(imsi) == nil; got != want {
			t.Errorf("ValidIMSI(%q) = %t, want %t", imsi, got, want)
		}
	}
}

func TestPublicIdentitiesHaveOneCanonicalForm(t *testing.T) {
	for in, want := range map[string]string{
		impu1: impu1,
		"SIP:+15550100001@IMS.mnc001.mcc001.3gppnetwork.org": impu1,
		"sip:%2B15550100001@" + domain:                       impu1,
		impu1 + ";user=phone":                                impu1,
		"sips:alice@example.org":                             "sips:alice@example.org",
		"sip:alice;a=b@example.org":                          "sip:alice;a=b@example.org",
		tel1:                                                 tel1,
		"tel:+1-555-0100-001":                                tel1,
		"tel:+1(555)0100.001;phone-context=x":                tel1,
		"TEL:+15550100001":                                   tel1,
		"sip:example.org":                                    "",
		"sip:alice:secret@example.org":                       "",
		"sip:alice@example.org:5060":                         "",
		"sip:alice@example.org?subject=x":                    "",
		"sip:%40@example.org":                                "",
		"sip:%zz@example.org":                                "",
		"sip:%2@example.org":                                 "",
		"sip:%0A@example.org":                                "",
		"tel:5550100":                                        "",
		"tel:+":                                              "",
		"tel:+" + strings.Repeat("1", 16):                    "",
		"tel:+1555x":                                         "",
		"mailto:alice@example.org":                           "",
		"+15550100001":                                       "",
		"sip:" + strings.Repeat("a", 260) + "@x":             "",
	} {
		got, ok := CanonicalIMPU(in)
		if ok != (want != "") || got != want {
			t.Errorf("CanonicalIMPU(%q) = %q, %t; want %q", in, got, ok, want)
		}
	}
}

// FuzzCanonicalIMPU checks that the canonical form is a fixed point: what
// the HSS stores matches itself when it comes back in a Cx request.
func FuzzCanonicalIMPU(f *testing.F) {
	for _, s := range []string{impu1, tel1, "sip:%2B1@X.ORG;user=phone", "tel:+1-2(3).4", "sips:a;b@c", "sip:%41@b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := CanonicalIMPU(s)
		if !ok {
			return
		}
		again, ok := CanonicalIMPU(c)
		if !ok || again != c {
			t.Fatalf("CanonicalIMPU(%q) = %q, which canonicalises to %q, %t", s, c, again, ok)
		}
	})
}

func TestDomainNamesAreLDHLabels(t *testing.T) {
	for name, want := range map[string]bool{
		domain: true, "a": true, "a-b.c": true, "": false, "-a.b": false, "a-.b": false, "a..b": false,
		"a_b.c": false, strings.Repeat("a", 64) + ".b": false, strings.Repeat("a.", 127) + "a": false,
	} {
		if got := IsDomainName(name); got != want {
			t.Errorf("IsDomainName(%q) = %t, want %t", name, got, want)
		}
	}
}
