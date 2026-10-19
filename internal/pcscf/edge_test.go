package pcscf

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Every header only the network may set is removed from a client's request,
// however it is written and however often it appears; the headers a client
// may set stay (TS 24.229 §5.2, ADR 0007 §7).
func TestClientRequestsLoseTheHeadersOnlyTheNetworkMaySet(t *testing.T) {
	for _, name := range []string{
		"P-Asserted-Identity", "P-Served-User", "P-Asserted-Service", "P-Charging-Vector",
		"P-Charging-Function-Addresses", "P-Visited-Network-ID", "P-Associated-URI", "P-Called-Party-ID",
	} {
		t.Run(name, func(t *testing.T) {
			var h sip.Header
			for _, f := range []struct{ name, value string }{
				{"P-Preferred-Identity", "<sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org>"},
				{name, "<sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org>"},
				{"P-Access-Network-Info", "3GPP-E-UTRAN-FDD"},
				{lowerCase(name), "<sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org>"},
				{"Route", "<sip:" + publicHost + ";lr>"},
			} {
				if err := h.Add(f.name, f.value); err != nil {
					t.Fatal(err)
				}
			}
			stripNetworkHeaders(&h)
			if v := h.Values(name); len(v) != 0 {
				t.Fatalf("%s left: %q", name, v)
			}
			for _, kept := range []string{"P-Preferred-Identity", "P-Access-Network-Info", "Route"} {
				if h.Get(kept) == "" {
					t.Errorf("%s was removed as well", kept)
				}
			}
		})
	}
}

func lowerCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// pcscf names itself by its public name and its task address, each on the
// public port and on the two default ports, and by the core listener at its
// task address.
func TestSelfListsThePublicNameAndTheTaskAddress(t *testing.T) {
	cfg := Config{PublicHost: publicHost, PublicPort: 5061, CoreHost: netip.MustParseAddr("10.0.2.9")}
	var got []string
	for _, u := range selfURIs(cfg, 5070) {
		got = append(got, u.String())
	}
	want := []string{
		"sip:" + publicHost + ":5061", "sip:" + publicHost + ":5060",
		"sip:10.0.2.9:5061", "sip:10.0.2.9:5060", "sip:10.0.2.9:5070",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Self = %q, want %q", got, want)
	}
	cfg.CoreHost = netip.MustParseAddr("fd00::9")
	if got := selfURIs(cfg, 5070); got[len(got)-1].Host != "[fd00::9]" {
		t.Fatalf("IPv6 host %q", got[len(got)-1].Host)
	}
}
