package proxy

import (
	"context"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// FuzzForwarding runs what the proxy does to a request it forwards, short of
// sending it, on arbitrary requests: validation, Route preprocessing, the
// branch copy with Record-Route and Via, the strict-router fix-up, and the
// CANCEL built from the result. Whatever comes in, what goes out must be a
// valid request that serializes and parses back, with one less Max-Forwards,
// the proxy's Via on top of every received one, and no Route naming the proxy
// on top.
func FuzzForwarding(f *testing.F) {
	for _, extra := range [][]string{
		nil,
		{"Route: <sip:proxy.example.net;lr>, <sip:next.example.net;lr>"},
		{"Route: <sip:proxy.example.net;lr>", "Route: <sip:strict.example.net>", "Route: <sip:last.example.net;lr>"},
		{"Route: <sip:p1.example.com;lr>", "Route: <sip:caller@u1.example.com>"},
		{"Max-Forwards: 1", "Proxy-Require: foo"},
		{"Via: SIP/2.0/TCP invalid;branch=z9hG4bKx.00112233aabbccdd", "Via: SIP/2.0/UDP 192.0.2.10"},
	} {
		lines := []string{
			"INVITE sip:bob@example.com SIP/2.0",
			"Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup",
			"Max-Forwards: 70",
			"To: <sip:bob@example.com>",
			"From: <sip:alice@example.com>;tag=a1",
			"Call-ID: c1",
			"CSeq: 1 INVITE",
		}
		lines = append(lines, extra...)
		f.Add([]byte(strings.Join(lines, "\r\n") + "\r\nContent-Length: 0\r\n\r\n"))
	}
	// An escaped NUL the parser accepts and Header.Add refuses (RFC 4475
	// §3.1.1.2): the CANCEL must copy it, not write it again.
	f.Add([]byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.10;branch=z9hG4bKn\r\n" +
		"From: \"a\\\x00b\" <sip:alice@example.com>;tag=a1\r\nTo: <sip:bob@example.com>\r\nCall-ID: c\r\n" +
		"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("BYE sip:proxy.example.net;lr SIP/2.0\r\nVia: SIP/2.0/UDP a.example.com;branch=z9hG4bK1\r\n" +
		"To: <sip:b@example.com>;tag=1\r\nFrom: <sip:a@example.com>;tag=2\r\nCall-ID: c\r\nCSeq: 2 BYE\r\n" +
		"Route: <sip:x.example.com;lr>, <sip:y@example.com>\r\nContent-Length: 0\r\n\r\n"))

	// The seed is fixed, so a failing input fails the same way every run.
	p, err := New(&fakeNet{}, Config{Self: []sip.URI{selfURI}, Rand: rand.NewChaCha8([32]byte{2}), Resolver: fakeResolver{}})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(p.Close)
	dec := Decision{RecordRoute: []sip.Address{mustAddr("<sip:proxy.example.net;lr>")}}

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := sip.ParseMessage(data)
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok || req.Validate() != nil {
			return
		}
		if p.validate(req, p.loopHash(req)) != nil {
			return
		}
		in, err := p.preprocess(req, transport.Source{})
		if err != nil {
			return
		}
		if routes, err := in.Message.Header.Route(); err == nil && len(routes) > 0 && p.isSelf(routes[0].URI) {
			t.Fatal("a Route naming the proxy is left on top")
		}
		fwd, dst, err := p.buildBranch(context.Background(), in, &dec, Target{URI: in.Message.URI}, true, MaxBreadth)
		if err != nil {
			return
		}
		if err := addVia(fwd, dst, "z9hG4bKfuzz.0"); err != nil {
			t.Fatalf("adding the Via: %v", err)
		}
		if err := fwd.Validate(); err != nil {
			t.Fatalf("the forwarded request does not validate: %v", err)
		}
		b, err := fwd.Bytes()
		if err != nil {
			t.Fatalf("the forwarded request does not serialize: %v", err)
		}
		back, err := sip.ParseMessage(b)
		if err != nil {
			t.Fatalf("the forwarded request does not parse back: %v\n%s", err, b)
		}
		out := back.(*sip.Request)
		inVias, _ := req.Header.Via()
		outVias, err := out.Header.Via()
		if err != nil || len(outVias) != len(inVias)+1 || outVias[0].Branch() != "z9hG4bKfuzz.0" {
			t.Fatalf("Via %v became %v", req.Header.Values("Via"), out.Header.Values("Via"))
		}
		want := 70
		if req.Header.Has("Max-Forwards") {
			n, _ := req.Header.MaxForwards()
			want = n - 1
		}
		if n, err := out.Header.MaxForwards(); err != nil || n != want {
			t.Fatalf("Max-Forwards = %d (%v), want %d", n, err, want)
		}
		if req.Method == "INVITE" {
			if _, err := buildCancel(fwd); err != nil {
				t.Fatalf("no CANCEL for the forwarded INVITE: %v", err)
			}
		}
	})
}
