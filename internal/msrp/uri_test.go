package msrp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseURIReadsEveryPartOfTheGrammar(t *testing.T) {
	tests := []struct {
		in   string
		want URI
	}{
		{"msrp://client.example.com:2855/k3l2m1n0;tcp", URI{Host: "client.example.com", Port: 2855, SessionID: "k3l2m1n0", Transport: "tcp"}},
		{"msrps://relay.example.net:2856/a+b=c/d;tcp", URI{Secure: true, Host: "relay.example.net", Port: 2856, SessionID: "a+b=c/d", Transport: "tcp"}},
		{"msrp://192.0.2.10:2855/s1;tcp", URI{Host: "192.0.2.10", Port: 2855, SessionID: "s1", Transport: "tcp"}},
		{"msrp://[2001:db8::7]:2855/s1;tcp", URI{Host: "2001:db8::7", Port: 2855, SessionID: "s1", Transport: "tcp"}},
		{"msrp://bob@as.example.org:9000/x;tcp", URI{User: "bob", Host: "as.example.org", Port: 9000, SessionID: "x", Transport: "tcp"}},
		{"msrp://relay.example.net;tcp", URI{Host: "relay.example.net", Transport: "tcp"}},
		{"msrp://relay.example.net:2855;tcp;foo=bar;baz", URI{Host: "relay.example.net", Port: 2855, Transport: "tcp",
			Params: []Param{{Name: "foo", Value: "bar"}, {Name: "baz"}}}},
		{"MSRP://relay.example.net:2855/s;TCP", URI{Host: "relay.example.net", Port: 2855, SessionID: "s", Transport: "TCP"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseURI(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != tt.want.String() || got.User != tt.want.User || got.Secure != tt.want.Secure ||
				got.Host != tt.want.Host || got.Port != tt.want.Port || got.SessionID != tt.want.SessionID ||
				got.Transport != tt.want.Transport || len(got.Params) != len(tt.want.Params) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseURIRejectsWhatTheGrammarDoesNotAllow(t *testing.T) {
	for _, in := range []string{
		"",
		"sip:alice@example.com",
		"msrp:relay.example.net:2855/s;tcp",
		"msrp://relay.example.net:2855/s",           // transport is mandatory
		"msrp://relay.example.net:2855/s;",          // empty transport
		"msrp://relay.example.net:2855/s;t-cp",      // transport is alphanumeric
		"msrp://192.0.2.10/s;tcp",                   // an IP address needs a port (§6)
		"msrp://[2001:db8::7]/s;tcp",                // so does an IPv6 one
		"msrp://bob:secret@relay.example.net:1;tcp", // no passwords (§6)
		"msrp://relay.example.net:0/s;tcp",
		"msrp://relay.example.net:65536/s;tcp",
		"msrp://relay.example.net:+80/s;tcp",
		"msrp://relay.example.net:/s;tcp",
		"msrp://:2855/s;tcp",
		"msrp://relay.example.net:2855/;tcp",
		"msrp://relay.example.net:2855/s?x;tcp",
		"msrp://relay.example.net:2855/s;tcp;a=b=c",
		"msrp://relay.example.net:2855/s;tcp;=b",
		"msrp://rel ay.example.net:2855/s;tcp",
		"msrp://relay%zz.example.net:2855/s;tcp",
		"msrp://[2001:db8::7:2855/s;tcp",
		"msrp://[192.0.2.1]:2855/s;tcp",
		"msrp://[2001:db8::7]x/s;tcp",
		"msrp://[2001:db8::7]:/s;tcp",
		"msrp://[fe80::1%25eth0]:2855/s;tcp",
		"msrp://2001:db8::7:2855/s;tcp",
	} {
		if _, err := ParseURI(in); !errors.Is(err, ErrInvalidURI) {
			t.Errorf("ParseURI(%q) = %v, want ErrInvalidURI", in, err)
		}
	}
}

func TestURIStringRoundTrips(t *testing.T) {
	for _, in := range []string{
		"msrp://client.example.com:2855/k3l2m1n0;tcp",
		"msrps://bob@[2001:db8::7]:2856/a+b=c/d;tcp;x=y;z",
		"msrp://relay.example.net;tcp",
	} {
		if got := mustURI(t, in).String(); got != in {
			t.Errorf("String() = %q, want %q", got, in)
		}
	}
}

func TestURIComparisonFollowsSection6_1(t *testing.T) {
	tests := []struct {
		a, b  string
		equal bool
	}{
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "MSRP://relay.example.net:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://RELAY.Example.NET:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://r%65lay.example.net:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855/abc;TCP", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://alice@relay.example.net:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855/abc;tcp;x=1", true},
		{"msrp://[2001:db8::7]:2855/abc;tcp", "msrp://[2001:DB8:0:0:0:0:0:7]:2855/abc;tcp", true},
		{"msrp://192.0.2.1:2855/abc;tcp", "msrp://[::ffff:192.0.2.1]:2855/abc;tcp", true},
		{"msrp://relay.example.net:2855/abc;tcp", "msrps://relay.example.net:2855/abc;tcp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855/ABC;tcp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855;tcp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net/abc;tcp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2856/abc;tcp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.net:2855/abc;sctp", false},
		{"msrp://relay.example.net:2855/abc;tcp", "msrp://relay.example.org:2855/abc;tcp", false},
		{"msrp://r%2Elay.example.net:2855/abc;tcp", "msrp://r.lay.example.net:2855/abc;tcp", true},
		{"msrp://r%21lay.example.net:2855/abc;tcp", "msrp://r!lay.example.net:2855/abc;tcp", false},
	}
	for _, tt := range tests {
		a, b := mustURI(t, tt.a), mustURI(t, tt.b)
		if a.Equal(b) != tt.equal || b.Equal(a) != tt.equal {
			t.Errorf("%s vs %s: Equal = %v, want %v", tt.a, tt.b, a.Equal(b), tt.equal)
		}
	}
}

func TestURIAddrNeedsAPort(t *testing.T) {
	if addr, err := mustURI(t, "msrp://[2001:db8::7]:2855/s;tcp").Addr(); err != nil || addr != "[2001:db8::7]:2855" {
		t.Fatalf("Addr() = %q, %v", addr, err)
	}
	if _, err := mustURI(t, "msrp://relay.example.net/s;tcp").Addr(); !errors.Is(err, ErrInvalidURI) {
		t.Fatalf("Addr() without a port = %v, want ErrInvalidURI", err)
	}
}

func TestURIsOnOneHostShareAConnectionKey(t *testing.T) {
	a := mustURI(t, "msrp://AS.example.org:9000/one;tcp")
	b := mustURI(t, "msrp://as.example.org:9000/two;tcp")
	c := mustURI(t, "msrps://as.example.org:9000/two;tcp")
	if a.connKey() != b.connKey() {
		t.Error("sessions on one host and port must share a connection (§5.4)")
	}
	if a.connKey() == c.connKey() {
		t.Error("msrp and msrps must not share a connection")
	}
}

func TestURIErrorsDoNotRevealTheSessionID(t *testing.T) {
	// The session-id is the secret that binds a connection (ADR 0004) and
	// errors are likely to be logged.
	for _, in := range []string{"msrp://192.0.2.1/s3cr3tsess10n;tcp", "msrp://relay.example.net:2855/s3cr3tsess10n"} {
		_, err := ParseURI(in)
		if err == nil || strings.Contains(err.Error(), "s3cr3tsess10n") || strings.Contains(err.Error(), "192.0.2.1") {
			t.Errorf("ParseURI(%q) error = %v", in, err)
		}
	}
	_, err := mustURI(t, "msrp://relay.example.net/s3cr3tsess10n;tcp").Addr()
	if err == nil || strings.Contains(err.Error(), "s3cr3tsess10n") {
		t.Errorf("Addr error = %v", err)
	}
}
