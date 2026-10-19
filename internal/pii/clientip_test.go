package pii

import (
	"bytes"
	"log/slog"
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
	} {
		if got := TruncateIP(in); got != want {
			t.Errorf("TruncateIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientIPAttributeNeverCarriesTheFullAddress(t *testing.T) {
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("connection", ClientIP("source", "192.0.2.77:40001"), ClientIP("v6", "[2001:db8:5:6:7::8]:5061"))
	out := buf.String()
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
	for _, s := range []string{"192.0.2.77", "[2001:db8::1]:5060", "fe80::1%eth0", "::ffff:1.2.3.4", "1.2.3.4:5", "x", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := TruncateIP(s)
		if out == mark {
			return
		}
		p, err := netip.ParsePrefix(out)
		if err != nil || (p.Bits() != clientIPv4Bits && p.Bits() != clientIPv6Bits) || p != p.Masked() {
			t.Fatalf("TruncateIP(%q) = %q, not a masked /24 or /48", s, out)
		}
		ip, ok := parseIP(s)
		if !ok || !p.Contains(ip) {
			t.Fatalf("TruncateIP(%q) = %q, which does not contain the address", s, out)
		}
	})
}
