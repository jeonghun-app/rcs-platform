package pii

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
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
		"::ffff:203.000.113.009":  "203.0.113.0/24",
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

// Free text, such as net/http's error lines, keeps only the networks of
// the addresses in it, and everything else as it was (#36).
func TestTheAddressesInFreeTextAreTruncated(t *testing.T) {
	for in, want := range map[string]string{
		"http: TLS handshake error from 203.0.113.5:51234: EOF":                  "http: TLS handshake error from 203.0.113.0/24: EOF",
		"http2: server: error reading preface from client [2001:db8:5:6::8]:443": "http2: server: error reading preface from client [2001:db8:5::/48]",
		"peer 2001:db8:5:6:7::8 closed":                                          "peer 2001:db8:5::/48 closed",
		"from ::ffff:203.0.113.9 and 192.000.002.001.":                           "from 203.0.113.0/24 and 192.0.2.0/24.",
		"6to4 2002:c000:201::1":                                                  "6to4 2002::/16",
		"two: 192.0.2.7, 198.51.100.8:5060;":                                     "two: 192.0.2.0/24, 198.51.100.0/24;",
		"peer 203.0.113.250 closed":                                              "peer 203.0.113.0/24 closed",
		"host:192.0.2.7 and host:2001:db8:5:6::8":                                "host:192.0.2.0/24 and host:2001:db8:5::/48",
		// What is not an address stays.
		"go1.26.10 at 2026-10-21T12:42:25.4376791Z, version 1.2.3, 1.2.3.4.5": "go1.26.10 at 2026-10-21T12:42:25.4376791Z, version 1.2.3, 1.2.3.4.5",
		"mac aa:bb:cc:dd:ee:ff, ratio 3:2, time 12:42:25, 192.0.2.300":        "mac aa:bb:cc:dd:ee:ff, ratio 3:2, time 12:42:25, 192.0.2.300",
		"id x192.0.2.7 and 192.0.2.7x":                                        "id x192.0.2.7 and 192.0.2.7x",
		// A network as wide as a truncated one, or wider, is not an
		// address of anyone's, and stays as written; a narrower one is
		// truncated.
		"RELAY_CORE_NETWORKS 10.0.0.0/8 and 2001:db8::/32": "RELAY_CORE_NETWORKS 10.0.0.0/8 and 2001:db8::/32",
		"host 192.0.2.7/32 and 2001:db8:5:6::8/128":        "host 192.0.2.0/24 and 2001:db8:5::/48",
		"": "",
		// net/http writes ": <err>" right after the peer's address and
		// port: the port goes all the same (#389 reviews).
		"http: TLS handshake error from [2001:db8:5:6::8]:51234: EOF":       "http: TLS handshake error from [2001:db8:5::/48]: EOF",
		"http: panic serving [2001:db8:5:6::8]:51234: boom":                 "http: panic serving [2001:db8:5::/48]: boom",
		"read tcp [2001:db8::1]:8443->[2001:db8:5:6::8]:51234: i/o timeout": "read tcp [2001:db8::/48]->[2001:db8:5::/48]: i/o timeout",
		"read tcp 10.0.1.5:8443->203.0.113.9:51234: i/o timeout":            "read tcp 10.0.1.0/24->203.0.113.0/24: i/o timeout",
		"from 203.0.113.5:51234.":                                           "from 203.0.113.0/24.",
		"from 203.0.113.5:51234x":                                           "from 203.0.113.0/24x",
		// Ellipses, characters outside ASCII and other separators.
		"from 203.0.113.9...":                    "from 203.0.113.0/24...",
		"conn...203.0.113.9":                     "conn...203.0.113.0/24",
		"from 203.0.113.9.. x":                   "from 203.0.113.0/24.. x",
		"peer 2001:db8:5:6::8...":                "peer 2001:db8:5::/48...",
		"nbsp\u00a0203.0.113.9":                  "nbsp\u00a0203.0.113.0/24",
		"来自203.0.113.9。":                         "来自203.0.113.0/24。",
		"：203.0.113.9":                           "：203.0.113.0/24",
		"“203.0.113.9”":                          "“203.0.113.0/24”",
		"udp/2001:db8:5:6::8 and ip/203.0.113.9": "udp/2001:db8:5::/48 and ip/203.0.113.0/24",
		" :2001:db8:5:6::8 =:2001:db8:5:6::9":    " :2001:db8:5::/48 =:2001:db8:5::/48",
		// After a word's colon, whatever letter ends the word.
		"remote:2001:db8:5:6::8 node:2001:db8:5:6::8":    "remote:2001:db8:5::/48 node:2001:db8:5::/48",
		"ipv6:2001:db8:5:6::8 cafe:2001:db8:5:6:7:8:9:a": "ipv6:2001:db8:5::/48 cafe:2001:db8::/48",
		// A 6to4 network keeps only its /16, which holds no IPv4 address.
		"from 2002:cb00:7109::/48 x": "from 2002::/16 x",
		"2002:cb00:7108::/47":        "2002::/16",
		"2002::/16":                  "2002::/16",
		// A network length with host bits under it does not keep the
		// address (#389 QA), and a port of five digits goes whole.
		"inet 203.0.113.5/24 brd":   "inet 203.0.113.0/24 brd",
		"[2001:db8:5:6::8]:51234 x": "[2001:db8:5::/48] x",
		"203.0.113.5:51234 x":       "203.0.113.0/24 x",
		// A length is read up to the first character that is no digit.
		"203.0.113.5/24x":           "203.0.113.0/24x",
		"203.0.113.5/255.255.255.0": "203.0.113.0/24/255.255.255.0/24",
		"::ffff:cb00:7105/96":       "203.0.113.0/24",
	} {
		if got := TruncateIPsIn(in); got != want {
			t.Errorf("TruncateIPsIn(%q)\n = %q\nwant %q", in, got, want)
		}
	}
}

// TruncateIPsIn reads its input in linear time whatever the input
// (docs/architecture.md §8), for the runs that would make a naive scanner
// try every start or every end: 64 times the input costs at most 512
// times the allocations, and, outside the race detector, at most 8 times
// the CPU time of 64 reads of the small one, the best of five, in one of
// three attempts (the method of reginfo's linearity test, #317).
func TestTruncateIPsInIsLinear(t *testing.T) {
	cpu := func() time.Duration {
		var ru syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
			t.Fatal(err)
		}
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	read := func(text string, n int) time.Duration {
		start := cpu()
		for range n {
			_ = TruncateIPsIn(text)
		}
		return cpu() - start
	}
	for name, unit := range map[string]string{
		"dots":         ".",
		"colons":       ":",
		"brackets":     "[",
		"open v6":      "[::1",
		"quads":        "1.2.3.4:",
		"dotted digit": "1.",
		"hex colons":   "a:",
		"long token":   "a:b:c::4 " + strings.Repeat(".", 64),
		"mixed":        "[1.2.3.4]:5 ::ffff:1.2.3.4/24 ",
	} {
		t.Run(name, func(t *testing.T) {
			small := strings.Repeat(unit, max(1, 1024/len(unit)))
			large := strings.Repeat(small, 64)
			a := testing.AllocsPerRun(3, func() { _ = TruncateIPsIn(small) })
			b := testing.AllocsPerRun(3, func() { _ = TruncateIPsIn(large) })
			if b > 512*max(a, 1) {
				t.Fatalf("64× the input made %v allocations against %v: not linear", b, a)
			}
			if raceEnabled {
				return
			}
			var ratios []string
			for range 3 {
				s, l := time.Duration(1<<62), time.Duration(1<<62)
				for range 5 {
					s = min(s, read(small, 64))
					l = min(l, read(large, 1))
				}
				if l <= 8*s {
					return
				}
				ratios = append(ratios, fmt.Sprintf("%v against %v (%.1f×)", l, s, float64(l)/float64(s)))
			}
			t.Fatalf("64× the input once took, against 64 of the small, three times over: %s: not linear", strings.Join(ratios, "; "))
		})
	}
}

// QA's test on #389: the ports go in the line shapes net/http writes.
func TestPortsAreDroppedInNetHTTPsLineShape(t *testing.T) {
	for in, want := range map[string]string{
		"http: TLS handshake error from 203.0.113.5:51234: EOF":                         "http: TLS handshake error from 203.0.113.0/24: EOF",
		"http: TLS handshake error from [2001:db8:5:6::8]:51234: EOF":                   "http: TLS handshake error from [2001:db8:5::/48]: EOF",
		"http2: server: error reading preface from client [2001:db8:5:6::8]:51234: EOF": "http2: server: error reading preface from client [2001:db8:5::/48]: EOF",
		"read tcp [2001:db8::1]:443->[2001:db8:5:6::8]:51234: i/o timeout":              "read tcp [2001:db8::/48]->[2001:db8:5::/48]: i/o timeout",
	} {
		if got := TruncateIPsIn(in); got != want {
			t.Errorf("TruncateIPsIn(%q)\n = %q\nwant %q", in, got, want)
		}
	}
}
