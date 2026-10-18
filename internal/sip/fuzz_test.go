package sip

import (
	"bufio"
	"bytes"
	"reflect"
	"strings"
	"testing"
)

var fuzzMessageSeeds = []string{
	basicInvite,
	invalidBase,
	lines("SIP/2.0 200 OK", "v: SIP/2.0/UDP a.example.com;branch=z9hG4bK1;received=192.0.2.1", "t: <sip:b@example.com>;tag=2",
		"f: <sip:a@example.com>;tag=1", "i: x@y", "CSeq: 1 REGISTER", "m: <sip:a@192.0.2.1:5060;ob>;expires=600;+sip.instance=\"<urn:uuid:1>\"",
		"Service-Route: <sip:orig@scscf.example.com;lr>", "P-Associated-URI: <sip:+15550100001@example.com>, <tel:+15550100001>", "l: 0"),
	lines("MESSAGE sip:+15550100002@example.com;user=phone SIP/2.0", "Via: SIP/2.0/TLS [2001:db8::1]:5061;branch=z9hG4bKx;rport",
		"Subject: folded", " value", "Content-Type: message/cpim") + "body",
	lines("SIP/2.0 401 Unauthorized", "WWW-Authenticate: Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=AKAv1-MD5", "Content-Length: 0"),
	"\r\n\r\n" + lines("OPTIONS sip:a@example.com SIP/2.0", "Content-Length: 1") + "x",
	lines("OPTIONS sip:a@example.com SIP/2.0", "X: \"q\\\"\"", "Y: <a,b>, c"),
	// Control characters: refused raw, allowed as quoted-pairs.
	lines("OPTIONS sip:a@example.com SIP/2.0", "X: a\x00b\x1b[31m", "l: 0"),
	lines("OPTIONS sip:a@example.com SIP/2.0", "To: \"\\\x00\\\x7f\" <sip:b@example.com>", "l: 0"),
	lines("SIP/2.0 200 \xff", "l: 0"),
}

// equalMessages compares two parsed messages field by field, ignoring
// Content-Length, which the serializer may add or rewrite.
func equalMessages(a, b Message) bool {
	strip := func(m Message) ([]HeaderField, Message) {
		var out []HeaderField
		for _, f := range m.Headers().Fields() {
			if headerKey(f.Name) != "content-length" {
				out = append(out, f)
			}
		}
		switch m := m.(type) {
		case *Request:
			return out, &Request{Method: m.Method, URI: m.URI, Body: m.Body}
		case *Response:
			return out, &Response{StatusCode: m.StatusCode, Reason: m.Reason, Body: m.Body}
		}
		return nil, nil
	}
	fa, ma := strip(a)
	fb, mb := strip(b)
	return reflect.DeepEqual(fa, fb) && reflect.DeepEqual(ma, mb)
}

// checkReparse asserts that a parsed message serializes, that the result parses
// to the same message, and that serializing that again changes nothing.
func checkReparse(t *testing.T, m Message) {
	t.Helper()
	b1, err := m.Bytes()
	if err != nil {
		t.Fatalf("parsed message does not serialize: %v", err)
	}
	m2, err := ParseMessage(b1)
	if err != nil {
		t.Fatalf("serialized message does not parse: %v\n%q", err, b1)
	}
	if !equalMessages(m, m2) {
		t.Fatalf("reparsed message differs:\n%q", b1)
	}
	b2, err := m2.Bytes()
	if err != nil || !bytes.Equal(b1, b2) {
		t.Fatalf("serialization is not stable:\n%q\n%q", b1, b2)
	}
	if (m.Validate() == nil) != (m2.Validate() == nil) {
		t.Fatalf("Validate disagrees after a round trip: %v / %v", m.Validate(), m2.Validate())
	}
}

func FuzzParseMessage(f *testing.F) {
	for _, s := range fuzzMessageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseMessage(data)
		if err != nil {
			return
		}
		checkReparse(t, m)
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte(basicInvite + "\r\n\r\n" + basicInvite))
	for _, s := range fuzzMessageSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bufio.NewReaderSize(bytes.NewReader(data), 16), Limits{MaxHeaderBytes: 4096, MaxBodyBytes: 4096})
		for i := 0; i < 8; i++ {
			m, err := r.ReadMessage()
			if err != nil {
				return
			}
			checkReparse(t, m)
		}
	})
}

func FuzzParseURI(f *testing.F) {
	for _, s := range []string{
		"sip:alice@example.com", "sips:a:b@[2001:db8::1]:5061;transport=tls;lr?h=v&x=",
		"sip:%61lice@example.com;n%61me=v%61lue%25%34%31", "tel:+1-555-010-0001;ext=1",
		"tel:*7042#;phone-context=example.com", "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
		"sip:+15550100001;npdi@example.com;user=phone", "SIP:host.example.com.:5060",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseURI(s)
		if err != nil {
			return
		}
		s2 := u.String()
		u2, err := ParseURI(s2)
		if err != nil {
			t.Fatalf("String() %q of %q does not parse: %v", s2, s, err)
		}
		if !reflect.DeepEqual(u, u2) {
			t.Fatalf("round trip of %q via %q: %#v != %#v", s, s2, u, u2)
		}
		if s3 := u2.String(); s3 != s2 {
			t.Fatalf("String() is not stable: %q then %q", s2, s3)
		}
		if !u.Equal(u2) || !u2.Equal(u) {
			t.Fatalf("%q is not equal to itself", s)
		}
		k1, ok1 := u.E164()
		k2, ok2 := u2.E164()
		if k1 != k2 || ok1 != ok2 || u.IsGlobalNumber() != u2.IsGlobalNumber() || ok1 && !u.IsGlobalNumber() {
			t.Fatalf("telephone number of %q changed across a round trip", s)
		}
	})
}

// FuzzHeaderValues checks every typed header parser: whatever one accepts, its
// canonical form must parse back to the same value, so a value read from one
// message and written into another means the same thing.
func FuzzHeaderValues(f *testing.F) {
	for _, s := range []string{
		`"A \"b\"" <sip:a@example.com;lr>;tag=1;x="y z"`, "sip:a@example.com;tag=1", "*",
		"SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK1;rport;received=192.0.2.1",
		"1 INVITE", `multipart/mixed;boundary="a b"`, "icid-value=abc;orig-ioi=x", `"net 1";x=1, other`,
		`*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session";require`,
		"reg;id=1", "terminated;reason=timeout;retry-after=5", "1800;refresher=uac", `Q.850;cause=16;text="x"`,
		`Digest realm="r", nonce="n", qop="auth,auth-int", algorithm=MD5, stale=false`,
	} {
		f.Add(s)
	}
	type roundTrip struct {
		name string
		get  func(h *Header) (any, error)
		put  func(v any) []string
	}
	join := func(ss []string) []string { return []string{strings.Join(ss, ", ")} }
	trips := []roundTrip{
		{"From", func(h *Header) (any, error) { return h.From() }, func(v any) []string { return []string{v.(Address).String()} }},
		{"Contact", func(h *Header) (any, error) { return h.Contact() }, func(v any) []string {
			var out []string
			for _, c := range v.([]Contact) {
				out = append(out, c.String())
			}
			return join(out)
		}},
		{"Route", func(h *Header) (any, error) { return h.Route() }, func(v any) []string {
			var out []string
			for _, a := range v.([]Address) {
				out = append(out, a.String())
			}
			return join(out)
		}},
		{"Via", func(h *Header) (any, error) { return h.Via() }, func(v any) []string {
			var out []string
			for _, x := range v.([]Via) {
				out = append(out, x.String())
			}
			return join(out)
		}},
		{"CSeq", func(h *Header) (any, error) { return h.CSeq() }, func(v any) []string { return []string{v.(CSeq).String()} }},
		{"Content-Type", func(h *Header) (any, error) { return h.ContentType() }, func(v any) []string { return []string{v.(MediaType).String()} }},
		{"P-Charging-Vector", func(h *Header) (any, error) { return h.PChargingVector() }, func(v any) []string { return []string{v.(ChargingVector).String()} }},
		{"P-Visited-Network-ID", func(h *Header) (any, error) { return h.PVisitedNetworkID() }, func(v any) []string {
			var out []string
			for _, x := range v.([]VisitedNetwork) {
				out = append(out, x.String())
			}
			return join(out)
		}},
		{"Accept-Contact", func(h *Header) (any, error) { return h.AcceptContact() }, func(v any) []string {
			var out []string
			for _, x := range v.([]AcceptContact) {
				out = append(out, x.String())
			}
			return join(out)
		}},
		{"Event", func(h *Header) (any, error) { return h.Event() }, func(v any) []string { return []string{v.(Event).String()} }},
		{"Subscription-State", func(h *Header) (any, error) { return h.SubscriptionState() }, func(v any) []string { return []string{v.(SubscriptionState).String()} }},
		{"Session-Expires", func(h *Header) (any, error) { return h.SessionExpires() }, func(v any) []string { return []string{v.(SessionExpires).String()} }},
		{"Min-SE", func(h *Header) (any, error) { return h.MinSE() }, func(v any) []string { return []string{v.(MinSE).String()} }},
		{"Reason", func(h *Header) (any, error) { return h.Reason() }, func(v any) []string {
			var out []string
			for _, x := range v.([]Reason) {
				out = append(out, x.String())
			}
			return join(out)
		}},
		{"WWW-Authenticate", func(h *Header) (any, error) { return h.WWWAuthenticate() }, func(v any) []string {
			var out []string
			for _, x := range v.([]Challenge) {
				out = append(out, x.String())
			}
			return out
		}},
		{"Authorization", func(h *Header) (any, error) { return h.Authorization() }, func(v any) []string {
			var out []string
			for _, x := range v.([]Credentials) {
				out = append(out, x.String())
			}
			return out
		}},
	}
	f.Fuzz(func(t *testing.T, value string) {
		for _, rt := range trips {
			var h Header
			if h.Add(rt.name, value) != nil {
				return
			}
			v, err := rt.get(&h)
			if err != nil {
				continue
			}
			var again Header
			for _, s := range rt.put(v) {
				if err := again.Add(rt.name, s); err != nil {
					t.Fatalf("%s: canonical form %q cannot be added: %v", rt.name, s, err)
				}
			}
			v2, err := rt.get(&again)
			if err != nil {
				t.Fatalf("%s: canonical form %q of %q does not parse: %v", rt.name, again.Get(rt.name), value, err)
			}
			if !reflect.DeepEqual(v, v2) {
				t.Fatalf("%s: %q round-trips via %q to a different value:\n%#v\n%#v", rt.name, value, again.Get(rt.name), v, v2)
			}
		}
	})
}
