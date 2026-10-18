package diameter

import (
	"bytes"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

func fuzzSeeds() [][]byte {
	var seeds [][]byte
	add := func(m *Message) {
		b, err := m.Encode()
		if err != nil {
			panic(err)
		}
		seeds = append(seeds, b)
	}
	add(testCER("scscf-1.rcs.test", "rcs.test",
		NewGrouped(AVPVendorSpecificApplicationID, FlagMandatory, 0,
			NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(10415)),
			NewAVP(AVPAuthApplicationID, FlagMandatory, 0, Unsigned32(16777216)))))
	add(&Message{Flags: FlagRequest, Code: CodeDeviceWatchdog, AVPs: []*AVP{
		NewAVP(AVPOriginHost, FlagMandatory, 0, []byte("hss.rcs.test")),
		NewAVP(AVPOriginRealm, FlagMandatory, 0, []byte("rcs.test")),
	}})
	add(&Message{Code: 300, ApplicationID: 16777216, Flags: FlagError, AVPs: []*AVP{
		NewAVP(AVPSessionID, FlagMandatory, 0, []byte("scscf-1.rcs.test;1;2;x")),
		NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(ResultMissingAVP)),
		NewGrouped(AVPFailedAVP, FlagMandatory, 0, NewAVP(AVPUserName, FlagMandatory, 0, nil)),
		NewGrouped(AVPProxyInfo, FlagMandatory, 0,
			NewAVP(AVPProxyHost, FlagMandatory, 0, []byte("dra.rcs.test")),
			NewAVP(AVPProxyState, FlagMandatory, 0, []byte{9})),
		NewAVP(AVPEventTimestamp, 0, 0, Time(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))),
		NewAVP(AVPHostIPAddress, FlagMandatory, 0, Address(netip.MustParseAddr("2001:db8::7"))),
		NewAVP(AVPRedirectHost, FlagMandatory, 0, []byte("aaa://hss.rcs.test")),
		NewAVP(codeI64, 0, testVendor, Integer64(-1)),
		NewGrouped(codeGroup, 0, testVendor, NewGrouped(codeGroup, 0, testVendor, NewAVP(codeOctets, 0, testVendor, []byte("z")))),
	}})
	seeds = append(seeds, rawMessage(FlagRequest, rawAVP(AVPOriginHost, FlagMandatory, 7, 0, 0, 0, 0)))
	return seeds
}

// FuzzDecodeMessage checks that no input makes the decoder panic, read out of
// bounds or allocate past the limit, and that whatever it accepts it can
// encode again into a message it accepts the same way.
func FuzzDecodeMessage(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	dict := testDictionary(f)
	lim := Limits{MaxMessageSize: 4096, MaxDepth: 4}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ReadMessage(bytes.NewReader(b), dict, lim)
		var derr *Error
		if err != nil {
			if errors.As(err, &derr) && m == nil {
				t.Fatalf("decode error %v without the message header", derr)
			}
			if derr != nil && derr.FailedAVP != nil {
				// Failed-AVP must itself be encodable for the error answer.
				if _, eerr := (&Message{AVPs: []*AVP{NewGrouped(AVPFailedAVP, FlagMandatory, 0, derr.FailedAVP)}}).Encode(); eerr != nil {
					t.Fatalf("Failed-AVP cannot be encoded: %v", eerr)
				}
			}
			return
		}
		for _, a := range m.AVPs {
			exercise(a, 0)
		}
		out, err := m.Encode()
		if err != nil {
			t.Fatalf("accepted message does not encode: %v", err)
		}
		m2, err := DecodeMessage(out, dict, lim)
		if err != nil {
			t.Fatalf("re-encoded message rejected: %v", err)
		}
		out2, _ := m2.Encode()
		if !bytes.Equal(out, out2) {
			t.Fatalf("encoding is not stable:\n% x\n% x", out, out2)
		}
	})
}

// exercise calls every accessor; none may panic on any payload.
func exercise(a *AVP, depth int) {
	_, _ = a.Unsigned32()
	_, _ = a.Unsigned64()
	_, _ = a.Integer32()
	_, _ = a.Integer64()
	_, _ = a.Enumerated()
	_, _ = a.UTF8String()
	_, _ = a.DiameterIdentity()
	_, _ = a.DiameterURI()
	_, _ = a.Address()
	_, _ = a.Time()
	_ = a.OctetString()
	if depth < 8 {
		if children, err := a.Grouped(); err == nil {
			for _, c := range children {
				exercise(c, depth+1)
			}
		}
	}
}

// FuzzMatchHostPattern checks the peer pattern matcher against a regular
// expression in which `*` is any run of non-dot characters.
func FuzzMatchHostPattern(f *testing.F) {
	f.Add("scscf-*.rcs.local", "scscf-1a.rcs.local")
	f.Add("*a*b.test", "xaxxab.test")
	f.Add("**", "")
	f.Add("S*.x", "s.X")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		if len(pattern) > 64 || len(host) > 64 || !ascii(pattern) || !ascii(host) {
			return
		}
		parts := strings.Split(pattern, "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		want := regexp.MustCompile("(?i)^" + strings.Join(parts, "[^.]*") + "$").MatchString(host)
		if got := matchHostPattern(pattern, host); got != want {
			t.Fatalf("matchHostPattern(%q, %q) = %v, want %v", pattern, host, got, want)
		}
	})
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
