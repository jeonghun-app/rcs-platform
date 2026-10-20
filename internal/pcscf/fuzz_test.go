package pcscf

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// quotedString and networkProvidedParam are an independent reading of a
// P-Access-Network-Info value (RFC 7315 §5.4): its quoted strings, and the
// network-provided parameter outside them.
var (
	quotedString         = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	networkProvidedParam = regexp.MustCompile(`(?i);[ \t]*network-provided[ \t]*(?:=|;|$)`)
)

// FuzzStripNetworkHeaders checks what a client's header goes through on
// arrival, whatever it holds: no header only the network may set is left,
// under any spelling of its name, and a P-Access-Network-Info value stays if
// and only if it does not claim network-provided (review of #188).
func FuzzStripNetworkHeaders(f *testing.F) {
	for _, seed := range []struct{ name, value, pani string }{
		{"P-Asserted-Identity", "<sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org>", "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=001010000000001"},
		{"p-charging-vector", "icid-value=1", "3GPP-E-UTRAN-FDD; network-provided"},
		{"Path", "<sip:forged@10.0.9.9;lr>", "3GPP-E-UTRAN-FDD;Network-Provided;utran-cell-id-3gpp=001010000000001"},
		{"P-Profile-Key", "<sip:x@h>", `IEEE-802.11; i-wlan-node-id="a;network-provided;b"`},
		{"Feature-Caps", "*;+g.3gpp.icsi-ref", `IEEE-802.11; i-wlan-node-id="a\";network-provided;b"`},
		{"Route", "<sip:pcscf.rcs.example.net;lr>", `x; network-provided = "1"`},
		{"P-Preferred-Identity", "<tel:+15550100001>", `"unterminated; network-provided`},
	} {
		f.Add(seed.name, seed.value, seed.pani)
	}
	f.Fuzz(func(t *testing.T, name, value, pani string) {
		var h sip.Header
		if h.Add(name, value) != nil || h.Add("P-Access-Network-Info", pani) != nil {
			return
		}
		for _, n := range networkOnlyHeaders {
			if h.Add(n, value) != nil || h.Add(strings.ToLower(n), value) != nil {
				return
			}
		}
		els, err := h.Elements("P-Access-Network-Info")
		stripNetworkHeaders(&h)
		for _, n := range networkOnlyHeaders {
			if v := h.Values(n); len(v) != 0 {
				t.Fatalf("%s left: %q", n, v)
			}
		}
		left := h.Values("P-Access-Network-Info")
		if err != nil {
			if len(left) != 0 {
				t.Fatalf("an unreadable P-Access-Network-Info was kept: %q", left)
			}
			return
		}
		var want []string
		for _, el := range els {
			if networkProvided(el) {
				continue
			}
			want = append(want, el)
			if unquoted := quotedString.ReplaceAllString(el, `""`); !strings.Contains(unquoted, `"`) && networkProvidedParam.MatchString(unquoted) {
				t.Fatalf("%q claims network-provided and was kept", el)
			}
		}
		if strings.Join(left, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("P-Access-Network-Info %q, want %q", left, want)
		}
	})
}

// FuzzRouteICID checks the icid a core-facing Record-Route value carries,
// which a client's copy of the route brings back and so is the client's to
// write (review of #221): recordRoute writes an icid only if routeICID reads
// it back unchanged, and whatever value the client puts in its place,
// routeICID returns only an icid recordRoute would write, or none.
func FuzzRouteICID(f *testing.F) {
	for _, seed := range []struct{ icid, raw string }{
		{"fedcba9876543210fedcba9876543210", "fedcba9876543210fedcba9876543210"},
		{`a b;c=d\"e`, "a%20b%3Bc"},
		{"%41é", "%2541%C3%A9"},
		{"", "%"},
		{strings.Repeat("x", maxICID+1), "%01"},
		{"\x7f", "%ZZ"},
		{"\xff", "%FF"},
	} {
		f.Add(seed.icid, seed.raw)
	}
	p := &pcscf{cfg: Config{CoreHost: netip.MustParseAddr("10.0.2.9"), PublicHost: "pcscf.rcs.example.net"}, corePort: 5070, dialogKey: []byte("fuzz key")}
	f.Fuzz(func(t *testing.T, icid, raw string) {
		written := p.recordRoute("FLOW-A", false, icid, "call-1")[0]
		back, err := sip.ParseAddress(written.String())
		if err != nil {
			t.Fatalf("the Record-Route %s does not parse: %v", written, err)
		}
		got, ok := routeICID(back.URI)
		if validICID(icid) != ok || ok && got != icid {
			t.Fatalf("icid %q written as %s, read back %q, %v", icid, written, got, ok)
		}
		if !p.inDialogWith(back.URI, "call-1") {
			t.Fatalf("the route %s fails its own MAC", written)
		}
		u, err := sip.ParseURI("sip:FLOW-A@10.0.2.9:5070;transport=tcp;lr;icid=" + raw)
		if err != nil {
			return
		}
		if got, ok := routeICID(u); ok {
			if !validICID(got) {
				t.Fatalf("%q read as %q, which recordRoute would not write", raw, got)
			}
			again, ok := routeICID(p.recordRoute("FLOW-A", false, got, "call-1")[0].URI)
			if !ok || again != got {
				t.Fatalf("%q read as %q, written again and read as %q, %v", raw, got, again, ok)
			}
		}
	})
}
