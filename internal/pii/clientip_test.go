package pii

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestClientIPsAreTruncatedToTheirNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.77":              "192.0.2.0/24",
		"198.51.100.200:5060":     "198.51.100.0/24",
		"2001:db8:5:6:7::8":       "2001:db8:5::/48",
		"[2001:db8:5:6::8]:5061":  "2001:db8:5::/48",
		"[2001:db8:ffff::1]":      "2001:db8:ffff::/48",
		"fe80::1%eth0":            "fe80::/48",
		"[fe80::1%25eth0]:443":    "fe80::/48",
		"::ffff:203.0.113.9":      "203.0.113.0/24",
		"[::ffff:203.0.113.9]:80": "203.0.113.0/24",
		"10.1.2.3":                "10.1.2.0/24",
		"":                        "***",
		"host.example.com:5060":   "***",
		"192.0.2.300":             "***",
		// Every address is a client's as far as a log can tell: private,
		// loopback and link-local ones are truncated too (#36).
		"[fe80::211:22ff:fe33:4455]": "fe80::/48",
		"127.0.0.1":                  "127.0.0.0/24",
		// Leading zeros, which SIP's IPv4address accepts (RFC 3261 §25.1).
		"192.000.002.001":      "192.0.2.0/24",
		"010.020.030.040:5060": "10.20.30.0/24",
		"1.2.3.0004":           "***",
		"1.2.3":                "***",
		// A 6to4 address carries a whole IPv4 address in bits 16 to 47
		// (RFC 3056 §2), so it keeps only its /16.
		"2002:c000:201::1":         "2002::/16",
		"[2002:cb00:7109:1::5]:80": "2002::/16",
	} {
		if got := TruncateIP(in); got != want {
			t.Errorf("TruncateIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientIPAttributeNeverCarriesTheFullAddress(t *testing.T) {
	var buf bytes.Buffer
	untimedJSONLogger(&buf).Info("connection", ClientIP("source", "192.0.2.77:40001"), ClientIP("v6", "[2001:db8:5:6:7::8]:5061"))
	out := buf.String()
	if strings.Contains(out, `"time"`) {
		t.Fatalf("the line has a timestamp whose digits could match a secret:\n%s", out)
	}
	for _, leak := range []string{"192.0.2.77", "40001", ":6:7::8", "5061"} {
		if strings.Contains(out, leak) {
			t.Errorf("log line has %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"source":"192.0.2.0/24"`) || !strings.Contains(out, `"v6":"2001:db8:5::/48"`) {
		t.Errorf("log line lacks the networks: %s", out)
	}
}

// FuzzTruncateIP checks that whatever the input, the result is the mask or a
// /24 or /48 prefix that contains the address the input names, so no more of
// the address than its network is ever logged.
func FuzzTruncateIP(f *testing.F) {
	for _, s := range []string{"192.0.2.77", "[2001:db8::1]:5060", "fe80::1%eth0", "::ffff:1.2.3.4", "1.2.3.4:5", "x", "", "001.02.3.255:0", "2002:c000:201::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := TruncateIP(s)
		if out == mark {
			return
		}
		p, err := netip.ParsePrefix(out)
		if err != nil || p != p.Masked() {
			t.Fatalf("TruncateIP(%q) = %q, not a masked prefix", s, out)
		}
		ip, ok := parseIP(s)
		if !ok || !p.Contains(ip) {
			t.Fatalf("TruncateIP(%q) = %q, which does not contain the address", s, out)
		}
		switch {
		case sixToFour.Contains(ip):
			if p != sixToFour {
				t.Fatalf("TruncateIP(%q) = %q keeps part of the IPv4 address in a 6to4 address", s, out)
			}
		case ip.Is4() && p.Bits() != clientIPv4Bits, ip.Is6() && p.Bits() != clientIPv6Bits:
			t.Fatalf("TruncateIP(%q) = %q, not a /24 or /48", s, out)
		}
	})
}
