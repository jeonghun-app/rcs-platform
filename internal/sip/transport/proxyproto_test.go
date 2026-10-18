package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// proxyHeader encodes a PROXY protocol v2 header for tests. verCmd and famProto
// are the 13th and 14th bytes; addrs is the address block and tlvs follows it.
func proxyHeader(verCmd, famProto byte, addrs, tlvs []byte) []byte {
	b := append([]byte{}, proxySignature...)
	b = append(b, verCmd, famProto)
	b = binary.BigEndian.AppendUint16(b, uint16(len(addrs)+len(tlvs)))
	b = append(b, addrs...)
	return append(b, tlvs...)
}

// inetBlock encodes an address block, in the IPv6 form if either address is
// IPv6.
func inetBlock(src, dst netip.AddrPort) []byte {
	var b []byte
	if src.Addr().Is4() && dst.Addr().Is4() {
		s, d := src.Addr().As4(), dst.Addr().As4()
		b = append(append(b, s[:]...), d[:]...)
	} else {
		s, d := src.Addr().As16(), dst.Addr().As16()
		b = append(append(b, s[:]...), d[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	return binary.BigEndian.AppendUint16(b, dst.Port())
}

// proxyHeaderFor encodes the header the NLB sends for a TCP client.
func proxyHeaderFor(src, dst netip.AddrPort, tlvs []byte) []byte {
	fam := byte(0x11)
	if !src.Addr().Is4() || !dst.Addr().Is4() {
		fam = 0x21
	}
	return proxyHeader(0x21, fam, inetBlock(src, dst), tlvs)
}

// awsTLV is a PP2_TYPE_AWS record like the one the NLB adds for a VPC endpoint.
var awsTLV = []byte{0xEA, 0x00, 0x05, 0x01, 'v', 'p', 'c', 'e'}

func TestProxyHeaderGivesTheClientAddress(t *testing.T) {
	client4 := netip.MustParseAddrPort("192.0.2.10:40000")
	lb4 := netip.MustParseAddrPort("198.51.100.1:5060")
	client6 := netip.MustParseAddrPort("[2001:db8::10]:40001")
	lb6 := netip.MustParseAddrPort("[2001:db8::1]:5061")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(netip.MustParseAddr("::ffff:192.0.2.11").As16()), 40002)
	tests := []struct {
		name     string
		in       []byte
		src, dst netip.AddrPort
	}{
		{"IPv4", proxyHeaderFor(client4, lb4, nil), client4, lb4},
		{"IPv6", proxyHeaderFor(client6, lb6, nil), client6, lb6},
		{"IPv4-mapped IPv6 is unmapped", proxyHeader(0x21, 0x21, inetBlock(mapped, lb6), nil),
			netip.MustParseAddrPort("192.0.2.11:40002"), lb6},
		{"TLVs are skipped", proxyHeaderFor(client4, lb4, awsTLV), client4, lb4},
		{"an empty TLV is allowed", proxyHeaderFor(client4, lb4, []byte{0x04, 0, 0}), client4, lb4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ParseProxyHeader(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if h.Command != ProxyProxy || h.Source != tt.src || h.Destination != tt.dst {
				t.Fatalf("got %+v, want PROXY %v -> %v", h, tt.src, tt.dst)
			}
		})
	}
}

func TestProxyLocalHeaderIgnoresTheAddressBlock(t *testing.T) {
	// A health check: the NLB sends LOCAL, with UNSPEC or with a stale address
	// block, and both must be accepted without an address.
	for _, in := range [][]byte{
		proxyHeader(0x20, 0x00, nil, nil),
		proxyHeader(0x20, 0x11, inetBlock(netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.2:2")), nil),
		proxyHeader(0x20, 0x31, make([]byte, 7), nil),
	} {
		h, err := ParseProxyHeader(in)
		if err != nil {
			t.Fatalf("%x: %v", in, err)
		}
		if h != (ProxyHeader{Command: ProxyLocal}) {
			t.Fatalf("got %+v, want a bare LOCAL", h)
		}
	}
}

func TestInvalidProxyHeadersAreRejected(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.1:5060")
	good := proxyHeaderFor(src, dst, nil)
	corrupt := func(i int, v byte) []byte {
		b := append([]byte{}, good...)
		b[i] = v
		return b
	}
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"a SIP message", []byte("REGISTER sip:example.com SIP/2.0\r\n\r\n")},
		{"version 1 text header", []byte("PROXY TCP4 192.0.2.10 198.51.100.1 40000 5060\r\n")},
		{"bad signature", corrupt(5, 'x')},
		{"version 1 in the binary form", corrupt(12, 0x11)},
		{"unknown command", corrupt(12, 0x22)},
		{"datagram protocol", corrupt(13, 0x12)},
		{"unspecified protocol", corrupt(13, 0x10)},
		{"unspecified family with PROXY", proxyHeader(0x21, 0x01, nil, nil)},
		{"UNIX family", proxyHeader(0x21, 0x31, make([]byte, 216), nil)},
		{"short IPv4 block", proxyHeader(0x21, 0x11, make([]byte, 11), nil)},
		{"short IPv6 block", proxyHeader(0x21, 0x21, make([]byte, 35), nil)},
		{"truncated TLV header", proxyHeaderFor(src, dst, []byte{0xEA, 0x00})},
		{"TLV longer than the header", proxyHeaderFor(src, dst, []byte{0xEA, 0x00, 0x09, 1})},
		{"declared length too long", good[:len(good)-1]},
		{"declared length too short", append(append([]byte{}, good...), 0)},
		{"over the size limit", proxyHeader(0x21, 0x11, inetBlock(src, dst), make([]byte, maxProxyPayload))},
		{"source port 0", proxyHeaderFor(netip.MustParseAddrPort("192.0.2.10:0"), dst, nil)},
		{"unspecified source", proxyHeaderFor(netip.MustParseAddrPort("0.0.0.0:40000"), dst, nil)},
		{"multicast source", proxyHeaderFor(netip.MustParseAddrPort("[ff02::1]:40000"), netip.MustParseAddrPort("[2001:db8::1]:5060"), nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseProxyHeader(tt.in); !errors.Is(err, ErrProxyHeader) {
				t.Fatalf("ParseProxyHeader = %v, want ErrProxyHeader", err)
			}
		})
	}
}

func TestReadProxyHeaderLeavesTheFollowingBytesUnread(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.1:5060")
	rest := []byte("\x16\x03\x01 a TLS ClientHello")
	r := bytes.NewReader(append(proxyHeaderFor(src, dst, awsTLV), rest...))
	h, err := ReadProxyHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	if h.Source != src {
		t.Fatalf("Source = %v, want %v", h.Source, src)
	}
	if left, _ := io.ReadAll(r); !bytes.Equal(left, rest) {
		t.Fatalf("left %q unread, want %q", left, rest)
	}
}

func TestReadProxyHeaderReportsAShortStream(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.1:5060")
	full := proxyHeaderFor(src, dst, nil)
	for _, n := range []int{0, 10, len(full) - 1} {
		if _, err := ReadProxyHeader(bytes.NewReader(full[:n])); err == nil {
			t.Fatalf("%d bytes: accepted a truncated header", n)
		}
	}
}

func TestReadProxyHeaderRefusesAnOverlongHeaderBeforeReadingIt(t *testing.T) {
	b := proxyHeader(0x21, 0x11, nil, nil)
	binary.BigEndian.PutUint16(b[14:], 0xffff)
	if _, err := ReadProxyHeader(bytes.NewReader(b)); !errors.Is(err, ErrProxyHeader) {
		t.Fatalf("ReadProxyHeader = %v, want ErrProxyHeader", err)
	}
}

func FuzzParseProxyHeader(f *testing.F) {
	src := netip.MustParseAddrPort("192.0.2.10:40000")
	dst := netip.MustParseAddrPort("198.51.100.1:5060")
	f.Add(proxyHeaderFor(src, dst, nil))
	f.Add(proxyHeaderFor(src, dst, awsTLV))
	f.Add(proxyHeaderFor(netip.MustParseAddrPort("[2001:db8::10]:1"), netip.MustParseAddrPort("[2001:db8::1]:2"), nil))
	f.Add(proxyHeader(0x20, 0x00, nil, nil))
	f.Add(proxyHeader(0x21, 0x31, make([]byte, 216), nil))
	f.Add([]byte("PROXY TCP4 192.0.2.10 198.51.100.1 40000 5060\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseProxyHeader(data)
		// ReadProxyHeader must agree with ParseProxyHeader on a whole header and
		// consume exactly that header.
		r := bytes.NewReader(append(append([]byte{}, data...), "next"...))
		h2, err2 := ReadProxyHeader(r)
		if err != nil {
			if err2 == nil && r.Len() == len("next") {
				t.Fatalf("ReadProxyHeader accepted what ParseProxyHeader refused: %v", err)
			}
			return
		}
		if err2 != nil || h2 != h || r.Len() != len("next") {
			t.Fatalf("ReadProxyHeader = %+v, %v with %d left; ParseProxyHeader = %+v", h2, err2, r.Len(), h)
		}
		if h.Command == ProxyLocal {
			if h != (ProxyHeader{Command: ProxyLocal}) {
				t.Fatalf("LOCAL header carries addresses: %+v", h)
			}
			return
		}
		if !h.Source.IsValid() || h.Source.Port() == 0 || h.Source.Addr().Is4In6() {
			t.Fatalf("accepted an unusable source %v", h.Source)
		}
		// Encoding what was parsed, without TLVs, must parse to the same header.
		again, err := ParseProxyHeader(proxyHeaderFor(h.Source, h.Destination, nil))
		if err != nil || again != h {
			t.Fatalf("re-encoded header = %+v, %v; want %+v", again, err, h)
		}
	})
}
