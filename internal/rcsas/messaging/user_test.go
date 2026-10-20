package messaging

import (
	"strings"
	"testing"
)

func TestAUserIsNamedInOneForm(t *testing.T) {
	const (
		domain   = "ims.mnc001.mcc001.3gppnetwork.org"
		alice    = "tel:+15550100001"
		bob      = "tel:+15550100002"
		aliceSIP = "sip:+15550100001@" + domain + ";user=phone"
	)
	for in, want := range map[string]string{
		"tel:+1-555-010-0001": alice,
		"tel:+15550100001":    alice,
		aliceSIP:              alice,
		"sip:+1-555-010-0001@IMS.example.net;user=phone": alice,
		// The home domain's SIP form of a number is that number
		// (architecture §4), elsewhere only with user=phone.
		"sip:+15550100001@" + domain:                        alice,
		"sip:+1-555-010-0001@" + strings.ToUpper(domain):    alice,
		"sip:+15550100001@other.example.net":                "sip:+15550100001@other.example.net",
		"sip:+15550100001@" + domain + ";user=ip":           "sip:+15550100001@" + domain,
		"sip:+15550100001;ext=11@" + domain:                 "sip:+15550100001;ext=11@" + domain,
		"sip:Bob@EXAMPLE.net":                               "sip:Bob@example.net",
		"sip:Bob@example.net;user=phone":                    "sip:Bob@example.net",
		"sip:%42ob@example.net":                             "sip:Bob@example.net",
		"sips:+15550100002@" + domain + ";user=phone;lr":    bob,
		"sip:+15550100002;ext=11@" + domain + ";user=phone": "sip:+15550100002;ext=11@" + domain,
	} {
		if got, ok := UserOf(in, domain); !ok || got != want {
			t.Errorf("UserOf(%q) = %q, %t, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "not a URI", "tel:5550100", "sip:example.net", "http://example.net/"} {
		if got, ok := UserOf(in, domain); ok {
			t.Errorf("UserOf(%q) = %q, want none", in, got)
		}
	}
}
