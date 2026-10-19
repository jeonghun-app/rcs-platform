package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"testing"
)

// raw encodes a header for tests. verCmd and famProto are the 13th and 14th
// bytes; addrs is the address block and tlvs follows it.
func raw(verCmd, famProto byte, addrs, tlvs []byte) []byte {
	b := append([]byte{}, signature...)
	b = append(b, verCmd, famProto)
	b = binary.BigEndian.AppendUint16(b, uint16(len(addrs)+len(tlvs)))
	b = append(b, addrs...)
	return append(b, tlvs...)
}

// withTLVs is the header the NLB sends for a TCP client, followed by tlvs.
func withTLVs(src, dst netip.AddrPort, tlvs []byte) []byte {
	b := Header{Command: Proxy, Source: src, Destination: dst}.Marshal()
	binary.BigEndian.PutUint16(b[14:16], binary.BigEndian.Uint16(b[14:16])+uint16(len(tlvs)))
	return append(b, tlvs...)
}

// awsTLV is a PP2_TYPE_AWS record like the one the NLB adds for a VPC
// endpoint.
var awsTLV = []byte{0xEA, 0x00, 0x05, 0x01, 'v', 'p', 'c', 'e'}

var (
	client4 = netip.MustParseAddrPort("192.0.2.10:40000")
	lb4     = netip.MustParseAddrPort("198.51.100.1:2855")
)

func TestHeaderGivesTheClientAddress(t *testing.T) {
	client6 := netip.MustParseAddrPort("[2001:db8::10]:40001")
	lb6 := netip.MustParseAddrPort("[2001:db8::1]:2856")
	mapped := netip.AddrPortFrom(netip.AddrFrom16(netip.MustParseAddr("::ffff:192.0.2.11").As16()), 40002)
	s, d := mapped.Addr().As16(), lb6.Addr().As16()
	mappedBlock := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(append(s[:], d[:]...), mapped.Port()), lb6.Port())
	tests := []struct {
		name     string
		in       []byte
		src, dst netip.AddrPort
	}{
		{"IPv4", withTLVs(client4, lb4, nil), client4, lb4},
		{"IPv6", withTLVs(client6, lb6, nil), client6, lb6},
		{"IPv4-mapped IPv6 is unmapped", raw(0x21, 0x21, mappedBlock, nil), netip.MustParseAddrPort("192.0.2.11:40002"), lb6},
		{"TLVs are skipped", withTLVs(client4, lb4, awsTLV), client4, lb4},
		{"an empty TLV is allowed", withTLVs(client4, lb4, []byte{0x04, 0, 0}), client4, lb4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := Parse(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if h.Command != Proxy || h.Source != tt.src || h.Destination != tt.dst {
				t.Fatalf("got %+v, want PROXY %v -> %v", h, tt.src, tt.dst)
			}
		})
	}
}

func TestLocalHeaderIgnoresTheAddressBlock(t *testing.T) {
	// A health check: the NLB sends LOCAL, with UNSPEC or with a stale
	// address block, and both must be accepted without an address.
	for _, in := range [][]byte{
		Header{Command: Local}.Marshal(),
		raw(0x20, 0x11, withTLVs(client4, lb4, nil)[fixedLen:], nil),
		raw(0x20, 0x31, make([]byte, 7), nil),
	} {
		h, err := Parse(in)
		if err != nil {
			t.Fatalf("%x: %v", in, err)
		}
		if h != (Header{Command: Local}) {
			t.Fatalf("got %+v, want a bare LOCAL", h)
		}
	}
}

func TestInvalidHeadersAreRejected(t *testing.T) {
	good := withTLVs(client4, lb4, nil)
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
		{"an MSRP request", []byte("MSRP a786hjs2 SEND\r\nTo-Path: msrp://relay.example.net:2855/s;tcp\r\n")},
		{"version 1 text header", []byte("PROXY TCP4 192.0.2.10 198.51.100.1 40000 2855\r\n")},
		{"bad signature", corrupt(5, 'x')},
		{"version 1 in the binary form", corrupt(12, 0x11)},
		{"unknown command", corrupt(12, 0x22)},
		{"datagram protocol", corrupt(13, 0x12)},
		{"unspecified protocol", corrupt(13, 0x10)},
		{"unspecified family with PROXY", raw(0x21, 0x01, nil, nil)},
		{"UNIX family", raw(0x21, 0x31, make([]byte, 216), nil)},
		{"short IPv4 block", raw(0x21, 0x11, make([]byte, 11), nil)},
		{"short IPv6 block", raw(0x21, 0x21, make([]byte, 35), nil)},
		{"truncated TLV header", withTLVs(client4, lb4, []byte{0xEA, 0x00})},
		{"TLV longer than the header", withTLVs(client4, lb4, []byte{0xEA, 0x00, 0x09, 1})},
		{"declared length too long", good[:len(good)-1]},
		{"declared length too short", append(append([]byte{}, good...), 0)},
		{"over the size limit", withTLVs(client4, lb4, make([]byte, MaxPayload))},
		{"source port 0", withTLVs(netip.MustParseAddrPort("192.0.2.10:0"), lb4, nil)},
		{"unspecified source", withTLVs(netip.MustParseAddrPort("0.0.0.0:40000"), lb4, nil)},
		{"multicast source", withTLVs(netip.MustParseAddrPort("[ff02::1]:40000"), netip.MustParseAddrPort("[2001:db8::1]:2855"), nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.in); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestReadLeavesTheFollowingBytesUnread(t *testing.T) {
	rest := []byte("MSRP a786hjs2 SEND\r\n")
	r := bytes.NewReader(append(withTLVs(client4, lb4, awsTLV), rest...))
	h, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	if h.Source != client4 {
		t.Fatalf("Source = %v, want %v", h.Source, client4)
	}
	if left, _ := io.ReadAll(r); !bytes.Equal(left, rest) {
		t.Fatalf("left %q unread, want %q", left, rest)
	}
}

func TestReadReportsAShortStream(t *testing.T) {
	full := withTLVs(client4, lb4, nil)
	for _, n := range []int{0, 10, len(full) - 1} {
		if _, err := Read(bytes.NewReader(full[:n])); err == nil {
			t.Fatalf("%d bytes: accepted a truncated header", n)
		}
	}
}

func TestReadRefusesAnOverlongHeaderBeforeReadingIt(t *testing.T) {
	b := raw(0x21, 0x11, nil, nil)
	binary.BigEndian.PutUint16(b[14:], 0xffff)
	if _, err := Read(bytes.NewReader(b)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read = %v, want ErrInvalid", err)
	}
}

func TestReadRefusesBytesThatAreNotAHeaderAfterSixteen(t *testing.T) {
	// A client that skips the load balancer is refused on its first request
	// line rather than read further.
	r := bytes.NewReader([]byte("MSRP a786hjs2 SEND\r\nTo-Path: msrp://x:1/s;tcp\r\n"))
	if _, err := Read(r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read = %v, want ErrInvalid", err)
	}
	if r.Len() != len("MSRP a786hjs2 SEND\r\nTo-Path: msrp://x:1/s;tcp\r\n")-fixedLen {
		t.Fatalf("Read consumed %d bytes past the fixed part", len("MSRP a786hjs2 SEND\r\nTo-Path: msrp://x:1/s;tcp\r\n")-fixedLen-r.Len())
	}
}

func TestMarshalRoundTrips(t *testing.T) {
	for _, h := range []Header{
		{Command: Local},
		{Command: Proxy, Source: client4, Destination: lb4},
		{Command: Proxy, Source: netip.MustParseAddrPort("[2001:db8::10]:1"), Destination: netip.MustParseAddrPort("[2001:db8::1]:2")},
		// Mixed families travel as IPv6, and the IPv4 side comes back
		// unmapped.
		{Command: Proxy, Source: client4, Destination: netip.MustParseAddrPort("[2001:db8::1]:2")},
	} {
		got, err := Parse(h.Marshal())
		if err != nil || got != h {
			t.Fatalf("Parse(%+v.Marshal()) = %+v, %v", h, got, err)
		}
	}
}

func TestMarshalOfAProxyHeaderWithoutAddressesIsRefusedNotAPanic(t *testing.T) {
	if _, err := Parse(Header{Command: Proxy}.Marshal()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Parse = %v, want ErrInvalid", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(withTLVs(client4, lb4, nil))
	f.Add(withTLVs(client4, lb4, awsTLV))
	f.Add(withTLVs(netip.MustParseAddrPort("[2001:db8::10]:1"), netip.MustParseAddrPort("[2001:db8::1]:2"), nil))
	f.Add(Header{Command: Local}.Marshal())
	f.Add(raw(0x21, 0x31, make([]byte, 216), nil))
	f.Add([]byte("PROXY TCP4 192.0.2.10 198.51.100.1 40000 2855\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Parse(data)
		// Read must agree with Parse on a whole header and consume exactly
		// that header.
		r := bytes.NewReader(append(append([]byte{}, data...), "next"...))
		h2, err2 := Read(r)
		if err != nil {
			if err2 == nil && r.Len() == len("next") {
				t.Fatalf("Read accepted what Parse refused: %v", err)
			}
			return
		}
		if err2 != nil || h2 != h || r.Len() != len("next") {
			t.Fatalf("Read = %+v, %v with %d left; Parse = %+v", h2, err2, r.Len(), h)
		}
		if h.Command == Local {
			if h != (Header{Command: Local}) {
				t.Fatalf("LOCAL header carries addresses: %+v", h)
			}
			return
		}
		if !h.Source.IsValid() || h.Source.Port() == 0 || h.Source.Addr().Is4In6() {
			t.Fatalf("accepted an unusable source %v", h.Source)
		}
		// Encoding what was parsed, without TLVs, must parse to the same
		// header.
		again, err := Parse(h.Marshal())
		if err != nil || again != h {
			t.Fatalf("re-encoded header = %+v, %v; want %+v", again, err, h)
		}
	})
}
