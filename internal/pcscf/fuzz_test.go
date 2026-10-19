package pcscf

import (
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
