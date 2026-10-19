package transport

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// FuzzStampReceived checks that the Via rewrite on every inbound request keeps
// the request valid, keeps every Via, and makes the response route back to the
// source whenever the client asked for rport.
func FuzzStampReceived(f *testing.F) {
	for _, via := range []string{
		"Via: SIP/2.0/UDP client.example.com;rport;branch=z9hG4bK1",
		"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK1;received=203.0.113.9",
		"v: SIP/2.0/TLS [2001:db8::10]:5061;branch=z9hG4bK1, SIP/2.0/UDP b.example.com;branch=z9hG4bK2",
		"Via: SIP / 2.0 / UDP   spaced.example.com ; rport ; branch = z9hG4bK3\r\nVia: SIP/2.0/UDP c.example.com;branch=z9hG4bK4",
	} {
		f.Add([]byte(rawRequest("OPTIONS", via)), []byte{192, 0, 2, 10}, uint16(40000))
	}
	f.Add([]byte(rawRequest("INVITE", "Via: SIP/2.0/UDP x.example.com;rport=1;branch=z9hG4bK5")),
		[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}, uint16(1))
	f.Fuzz(func(t *testing.T, data, ip []byte, port uint16) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || port == 0 {
			return
		}
		src := netip.AddrPortFrom(addr.Unmap(), port)
		m, err := sip.ParseMessage(data)
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok || req.Validate() != nil {
			return
		}
		before, _ := req.Header.Via()
		if err := stampReceived(req, src); err != nil {
			t.Fatalf("stampReceived failed on a valid request: %v", err)
		}
		if err := req.Validate(); err != nil {
			t.Fatalf("stamped request no longer validates: %v", err)
		}
		after, _ := req.Header.Via()
		if len(after) != len(before) {
			t.Fatalf("%d Vias became %d", len(before), len(after))
		}
		for i := 1; i < len(after); i++ {
			if after[i].String() != before[i].String() {
				t.Fatalf("Via %d changed: %s -> %s", i, before[i], after[i])
			}
		}
		top := after[0]
		if top.Branch() != before[0].Branch() || !strings.EqualFold(top.Host, before[0].Host) || top.Port != before[0].Port {
			t.Fatalf("top Via identity changed: %s -> %s", before[0], top)
		}
		if _, rport := top.RPort(); rport {
			if _, ok := parseNetwork(top.Transport); ok {
				if _, to, err := responseTarget(top, true); err != nil || to != src {
					t.Fatalf("response for an rport request goes to %v (%v), not the source %v", to, err, src)
				}
			}
		}
		// What is forwarded must parse back to the same Vias.
		b, err := req.Bytes()
		if err != nil {
			t.Fatalf("stamped request does not serialize: %v", err)
		}
		again, err := sip.ParseMessage(b)
		if err != nil {
			t.Fatalf("stamped request does not parse: %v", err)
		}
		vias, err := again.Headers().Via()
		if err != nil || len(vias) != len(after) || vias[0].String() != top.String() {
			t.Fatalf("reparsed Vias differ: %v", err)
		}
	})
}
