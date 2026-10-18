package transport

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// rawRequest builds a request in wire form; the Via lines are given whole.
func rawRequest(method string, vias ...string) string {
	lines := []string{method + " sip:bob@example.com SIP/2.0"}
	lines = append(lines, vias...)
	lines = append(lines,
		"Max-Forwards: 70",
		"To: <sip:bob@example.com>",
		"From: <sip:alice@example.com>;tag=a1",
		"Call-ID: c1@example.com",
		"CSeq: 1 "+method,
		"Content-Length: 0",
	)
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

func parseRequest(t *testing.T, s string) *sip.Request {
	t.Helper()
	m, err := sip.ParseMessage([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return m.(*sip.Request)
}

func TestReceivedAndRPortAreStampedOnTheTopVia(t *testing.T) {
	src4 := netip.MustParseAddrPort("192.0.2.10:40000")
	src6 := netip.MustParseAddrPort("[2001:db8::10]:40000")
	tests := []struct {
		name string
		via  []string
		src  netip.AddrPort
		want []string // every Via value after stamping, top first
	}{
		{"sent-by is the source: nothing added",
			[]string{"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1"}, src4,
			[]string{"SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1"}},
		{"sent-by is a host name: received added (RFC 3261 §18.2.1)",
			[]string{"Via: SIP/2.0/UDP client.example.com;branch=z9hG4bK1"}, src4,
			[]string{"SIP/2.0/UDP client.example.com;branch=z9hG4bK1;received=192.0.2.10"}},
		{"sent-by is another address: received added",
			[]string{"Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK1"}, src4,
			[]string{"SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK1;received=192.0.2.10"}},
		{"rport asks for received even when equal (RFC 3581 §4)",
			[]string{"Via: SIP/2.0/UDP 192.0.2.10:5060;rport;branch=z9hG4bK1"}, src4,
			[]string{"SIP/2.0/UDP 192.0.2.10:5060;rport=40000;branch=z9hG4bK1;received=192.0.2.10"}},
		{"a forged received is overwritten",
			[]string{"Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1;received=203.0.113.9"}, src4,
			[]string{"SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1;received=192.0.2.10"}},
		{"a client-supplied rport value is overwritten",
			[]string{"Via: SIP/2.0/UDP host.example.com;rport=9;branch=z9hG4bK1"}, src4,
			[]string{"SIP/2.0/UDP host.example.com;rport=40000;branch=z9hG4bK1;received=192.0.2.10"}},
		{"IPv6 sent-by equal to the source",
			[]string{"Via: SIP/2.0/TCP [2001:db8::10]:5060;branch=z9hG4bK1"}, src6,
			[]string{"SIP/2.0/TCP [2001:db8::10]:5060;branch=z9hG4bK1"}},
		{"IPv6 received is written bare (RFC 3261 §20.42)",
			[]string{"Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK1"}, src6,
			[]string{"SIP/2.0/TCP client.example.com;branch=z9hG4bK1;received=2001:db8::10"}},
		{"elements below the top in the same line are kept",
			[]string{"Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK1, SIP/2.0/UDP b.example.com;branch=z9hG4bK2"}, src4,
			[]string{"SIP/2.0/UDP a.example.com;branch=z9hG4bK1;received=192.0.2.10, SIP/2.0/UDP b.example.com;branch=z9hG4bK2"}},
		{"lines below the top keep their order",
			[]string{"v: SIP/2.0/UDP a.example.com;branch=z9hG4bK1", "Via: SIP/2.0/UDP b.example.com;branch=z9hG4bK2",
				"Via: SIP/2.0/UDP c.example.com;branch=z9hG4bK3"}, src4,
			[]string{"SIP/2.0/UDP a.example.com;branch=z9hG4bK1;received=192.0.2.10",
				"SIP/2.0/UDP b.example.com;branch=z9hG4bK2", "SIP/2.0/UDP c.example.com;branch=z9hG4bK3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := parseRequest(t, rawRequest("OPTIONS", tt.via...))
			if err := stampReceived(req, tt.src); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Values("Via"); strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("Via =\n%q\nwant\n%q", got, tt.want)
			}
			if err := req.Validate(); err != nil {
				t.Fatalf("stamped request no longer validates: %v", err)
			}
		})
	}
}

func TestStampingKeepsTheViaFieldsInPlace(t *testing.T) {
	req := parseRequest(t, rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK1", "Via: SIP/2.0/UDP b.example.com;branch=z9hG4bK2"))
	if err := stampReceived(req, netip.MustParseAddrPort("192.0.2.10:1")); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range req.Header.Fields() {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "Via,Via,Max-Forwards,To,From,Call-ID,CSeq,Content-Length" {
		t.Fatalf("field order = %s", got)
	}
}

func TestSetSentByRewritesTheTopViaOnlyWhenItDiffers(t *testing.T) {
	req := parseRequest(t, rawRequest("MESSAGE", "Via: SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK1"))
	if err := setSentBy(req, TCP, "pcscf.example.com", 5060); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Via"); got != "SIP/2.0/TCP pcscf.example.com:5060;branch=z9hG4bK1" {
		t.Fatalf("Via = %q", got)
	}
	before, _ := req.Bytes()
	if err := setSentBy(req, TCP, "PCSCF.example.com", 5060); err != nil {
		t.Fatal(err)
	}
	if after, _ := req.Bytes(); string(after) != string(before) {
		t.Fatalf("an equal sent-by rewrote the request:\n%s\n%s", before, after)
	}
}

func TestSetSentByNeedsAVia(t *testing.T) {
	req := &sip.Request{Method: "OPTIONS"}
	if err := setSentBy(req, UDP, "a.example.com", 5060); err == nil {
		t.Fatal("accepted a request without Via")
	}
}

func TestResponseTargetFollowsReceivedAndRPort(t *testing.T) {
	tests := []struct {
		via      string
		useRPort bool
		network  Network
		want     string
	}{
		{"SIP/2.0/UDP 192.0.2.10:5070;branch=z9hG4bK1", true, UDP, "192.0.2.10:5070"},
		{"SIP/2.0/UDP 192.0.2.10;branch=z9hG4bK1", true, UDP, "192.0.2.10:5060"},
		{"SIP/2.0/TLS 192.0.2.10;branch=z9hG4bK1", false, TLS, "192.0.2.10:5061"},
		{"SIP/2.0/UDP host.example.com:5070;branch=z9hG4bK1;received=192.0.2.10", true, UDP, "192.0.2.10:5070"},
		{"SIP/2.0/UDP host.example.com:5070;rport=40000;branch=z9hG4bK1;received=192.0.2.10", true, UDP, "192.0.2.10:40000"},
		// Over a reliable transport a new connection goes to the sent-by port
		// (RFC 3261 §18.2.2); rport named the closed connection's source port.
		{"SIP/2.0/TCP host.example.com:5070;rport=40000;branch=z9hG4bK1;received=192.0.2.10", false, TCP, "192.0.2.10:5070"},
		{"SIP/2.0/udp [2001:db8::10]:5070;branch=z9hG4bK1", true, UDP, "[2001:db8::10]:5070"},
		{"SIP/2.0/UDP host.example.com;branch=z9hG4bK1;received=2001:db8::10;rport=1", true, UDP, "[2001:db8::10]:1"},
		// maddr is never followed: it would make the server a reflector.
		{"SIP/2.0/UDP 192.0.2.10;maddr=239.255.255.1;branch=z9hG4bK1", true, UDP, "192.0.2.10:5060"},
	}
	for _, tt := range tests {
		vias, err := sip.ParseVia(tt.via)
		if err != nil {
			t.Fatal(err)
		}
		n, addr, err := responseTarget(vias[0], tt.useRPort)
		if err != nil || n != tt.network || addr.String() != tt.want {
			t.Errorf("responseTarget(%q) = %s %v, %v; want %s %s", tt.via, n, addr, err, tt.network, tt.want)
		}
	}
}

func TestUnroutableResponsesAreRefused(t *testing.T) {
	for _, via := range []string{
		"SIP/2.0/SCTP 192.0.2.10;branch=z9hG4bK1",
		"SIP/2.0/UDP host.example.com;branch=z9hG4bK1",
	} {
		vias, err := sip.ParseVia(via)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := responseTarget(vias[0], true); !errors.Is(err, ErrUnroutable) {
			t.Errorf("responseTarget(%q) = %v, want ErrUnroutable", via, err)
		}
	}
}

func TestNetworkNamesFollowTheViaTransport(t *testing.T) {
	for in, want := range map[string]Network{"udp": UDP, "Tcp": TCP, "TLS": TLS} {
		if n, ok := parseNetwork(in); !ok || n != want {
			t.Errorf("parseNetwork(%q) = %q, %v", in, n, ok)
		}
	}
	for _, in := range []string{"SCTP", "WS", "WSS", ""} {
		if _, ok := parseNetwork(in); ok {
			t.Errorf("parseNetwork(%q) accepted", in)
		}
	}
	if UDP.Reliable() || !TCP.Reliable() || !TLS.Reliable() {
		t.Error("reliability is wrong")
	}
	if UDP.DefaultPort() != 5060 || TCP.DefaultPort() != 5060 || TLS.DefaultPort() != 5061 {
		t.Error("default ports are wrong")
	}
}

func TestStampingKeepsTheBytesOfTheOtherVias(t *testing.T) {
	req := parseRequest(t, rawRequest("OPTIONS", "Via: SIP/2.0/UDP a.example.com;branch=z9hG4bK1",
		"v:  SIP/2.0/UDP   b.example.com ;branch=z9hG4bK2"))
	if err := stampReceived(req, netip.MustParseAddrPort("192.0.2.10:1")); err != nil {
		t.Fatal(err)
	}
	b, _ := req.Bytes()
	if !strings.Contains(string(b), "\r\nv:  SIP/2.0/UDP   b.example.com ;branch=z9hG4bK2\r\n") {
		t.Fatalf("the second Via was rewritten:\n%s", b)
	}
}
