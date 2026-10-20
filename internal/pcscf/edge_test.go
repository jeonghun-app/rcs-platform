package pcscf

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Every header only the network may set is removed from a client's request,
// however it is written and however often it appears; the headers a client
// may set stay (TS 24.229 §5.2, ADR 0007 §7).
func TestClientRequestsLoseTheHeadersOnlyTheNetworkMaySet(t *testing.T) {
	for _, name := range []string{
		"P-Asserted-Identity", "P-Served-User", "P-Asserted-Service", "P-Charging-Vector",
		"P-Charging-Function-Addresses", "P-Visited-Network-ID", "P-Associated-URI", "P-Called-Party-ID",
		"P-Media-Authorization", "Feature-Caps", "P-Private-Network-Indication", "P-Profile-Key",
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

// A client may say how it is attached in P-Access-Network-Info, but not that
// the network vouches for it: a value with network-provided is removed (TS
// 24.229 §5.2.1).
func TestAClientsNetworkProvidedAccessInfoIsRemoved(t *testing.T) {
	for _, tt := range []struct {
		values []string
		want   string
	}{
		{[]string{"3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=001010000000001"}, "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=001010000000001"},
		{[]string{"3GPP-E-UTRAN-FDD; network-provided"}, ""},
		{[]string{"3GPP-E-UTRAN-FDD;Network-Provided;utran-cell-id-3gpp=001010000000001"}, ""},
		{[]string{"IEEE-802.11; i-wlan-node-id=\"a;network-provided;b\""}, "IEEE-802.11; i-wlan-node-id=\"a;network-provided;b\""},
		{[]string{"IEEE-802.11; i-wlan-node-id=\"a\\\";network-provided;b\""}, "IEEE-802.11; i-wlan-node-id=\"a\\\";network-provided;b\""},
		{[]string{"3GPP-E-UTRAN-FDD; network-provided, IEEE-802.11"}, "IEEE-802.11"},
		{[]string{"3GPP-E-UTRAN-FDD", "IEEE-802.11; network-provided"}, "3GPP-E-UTRAN-FDD"},
	} {
		var h sip.Header
		for _, v := range tt.values {
			if err := h.Add("P-Access-Network-Info", v); err != nil {
				t.Fatal(err)
			}
		}
		stripNetworkHeaders(&h)
		if got := strings.Join(h.Values("P-Access-Network-Info"), ", "); got != tt.want {
			t.Errorf("%q gave %q, want %q", tt.values, got, tt.want)
		}
	}
}

// Every message from a client, response or request, loses those headers on
// arrival, before any route could forward them; the core's keep theirs.
func TestEveryClientMessageIsStrippedOnArrival(t *testing.T) {
	res := "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP 10.0.2.9:5070;branch=z9hG4bK-1\r\nFrom: <sip:a@h>;tag=1\r\nTo: <sip:b@h>;tag=2\r\n" +
		"Call-ID: c\r\nCSeq: 1 INVITE\r\nP-Asserted-Identity: <" + "sip:+15550100003@ims.mnc001.mcc001.3gppnetwork.org" + ">\r\nP-Charging-Vector: icid-value=1\r\nContent-Length: 0\r\n\r\n"
	req := "MESSAGE sip:b@h SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.10:1;branch=z9hG4bK-2\r\nMax-Forwards: 70\r\nFrom: <sip:a@h>;tag=1\r\nTo: <sip:b@h>\r\n" +
		"Call-ID: c\r\nCSeq: 1 MESSAGE\r\nP-Asserted-Identity: <sip:a@h>\r\nContent-Length: 0\r\n\r\n"
	for _, text := range []string{res, req} {
		for _, tt := range []struct {
			listener string
			stripped bool
		}{{clientListener, true}, {clientUDPListener, true}, {coreListener, false}, {"", false}} {
			m, err := sip.ParseMessage([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			fromClientMessage(transport.Inbound{Message: m, Source: transport.Source{Listener: tt.listener}})
			if has := m.Headers().Has("P-Asserted-Identity"); has == tt.stripped {
				t.Errorf("listener %q: P-Asserted-Identity left %v", tt.listener, has)
			}
		}
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

// pcscf names itself by its public name, the NLB's public addresses and its
// task address, each on the public port and on the two default ports, and by
// the core listener at its task address.
func TestSelfListsThePublicNameTheNLBAndTheTaskAddress(t *testing.T) {
	cfg := Config{PublicHost: publicHost, PublicPort: 5061, CoreHost: netip.MustParseAddr("10.0.2.9"),
		PublicAddrs: []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}}
	var got []string
	for _, u := range selfURIs(cfg, 5070) {
		got = append(got, u.String())
	}
	want := []string{
		"sip:" + publicHost + ":5061", "sip:" + publicHost + ":5060",
		"sip:203.0.113.10:5061", "sip:203.0.113.10:5060",
		"sip:[2001:db8::10]:5061", "sip:[2001:db8::10]:5060",
		"sip:10.0.2.9:5061", "sip:10.0.2.9:5060", "sip:10.0.2.9:5070",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Self = %q, want %q", got, want)
	}
}
