package sip

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func mustBytes(t *testing.T, m Message) []byte {
	t.Helper()
	b, err := m.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return b
}

func TestUnmodifiedMessagesSerializeByteIdentically(t *testing.T) {
	for _, in := range []string{
		basicInvite,
		lines(
			"REGISTER sip:ims.example.net SIP/2.0",
			"v  :  SIP / 2.0 / TCP  client.example.com ;branch = z9hG4bK1",
			"MaX-fOrWaRdS: 0070",
			"t: <sip:+15550100001@ims.example.net>",
			"f: <sip:+15550100001@ims.example.net>;tag=a1",
			"i: reg.1@client.example.com",
			"CSeq:   1",
			"  REGISTER",
			"m: <sip:client.example.com;transport=tcp>;+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000000000001>\";reg-id=1",
			"NewHeader: unusual ;; ,, value",
			"l: 0",
		),
		lines("SIP/2.0 100 ", "Content-Length: 000"),
	} {
		m := mustParse(t, in)
		if got := mustBytes(t, m); string(got) != in {
			t.Errorf("serialization differs:\n got %q\nwant %q", got, in)
		}
	}
}

func TestSerializerRecomputesContentLength(t *testing.T) {
	m := mustParse(t, basicInvite).(*Request)
	m.Body = []byte("hello, world")
	got := string(mustBytes(t, m))
	if !strings.Contains(got, "\r\nContent-Length: 12\r\n\r\nhello, world") {
		t.Errorf("Content-Length not updated:\n%s", got)
	}

	// A datagram without Content-Length gains one.
	d := mustParse(t, "MESSAGE sip:bob@example.com SIP/2.0\r\nSubject: x\r\n\r\nabc").(*Request)
	if got := string(mustBytes(t, d)); got != "MESSAGE sip:bob@example.com SIP/2.0\r\nSubject: x\r\nContent-Length: 3\r\n\r\nabc" {
		t.Errorf("got %q", got)
	}

	// A compact Content-Length keeps its name when it has to be rewritten.
	c := mustParse(t, lines("MESSAGE sip:bob@example.com SIP/2.0", "l: 0")).(*Request)
	c.Body = []byte("ab")
	if got := string(mustBytes(t, c)); !strings.Contains(got, "\r\nl: 2\r\n") {
		t.Errorf("got %q", got)
	}

	// A built request with two stale Content-Length fields gets one right one.
	var r Request
	r.Method = "MESSAGE"
	r.URI = URI{Scheme: "sip", Host: "example.com"}
	mustAdd(t, &r.Header, "Content-Length", "99")
	mustAdd(t, &r.Header, "Content-Length", "98")
	r.Body = []byte("x")
	if got := string(mustBytes(t, &r)); got != "MESSAGE sip:example.com SIP/2.0\r\nContent-Length: 1\r\n\r\nx" {
		t.Errorf("got %q", got)
	}
}

func TestBuiltMessagesUseCanonicalForms(t *testing.T) {
	var r Request
	r.Method = "OPTIONS"
	r.URI = URI{Scheme: "sip", User: "bob", Host: "example.com"}
	via := Via{Transport: "UDP", Host: "192.0.2.1", Port: 5060, Params: Params{{Name: "branch", Value: "z9hG4bK1"}, {Name: "rport"}}}
	mustAdd(t, &r.Header, "v", via.String())
	mustAdd(t, &r.Header, "max-forwards", "70")
	from := Address{DisplayName: "Alice", URI: URI{Scheme: "sip", User: "alice", Host: "example.com"}, Params: Params{{Name: "tag", Value: "1"}}}
	mustAdd(t, &r.Header, "f", from.String())
	want := "OPTIONS sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: \"Alice\" <sip:alice@example.com>;tag=1\r\n" +
		"Content-Length: 0\r\n\r\n"
	if got := string(mustBytes(t, &r)); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestReplacingAFieldDropsItsRawBytes(t *testing.T) {
	m := mustParse(t, basicInvite)
	if err := m.Headers().Set("max-forwards", "69"); err != nil {
		t.Fatal(err)
	}
	got := string(mustBytes(t, m))
	want := strings.Replace(basicInvite, "Max-Forwards: 70", "Max-Forwards: 69", 1)
	if got != want {
		t.Errorf("got %q", got)
	}
}

func TestSerializationRefusesCorruptStartLines(t *testing.T) {
	good := URI{Scheme: "sip", Host: "example.com"}
	for _, r := range []*Request{
		{Method: "", URI: good},
		{Method: "IN VITE", URI: good},
		{Method: "INVITE"},
		{Method: "INVITE", URI: URI{Scheme: "sip", Host: "example.com\r\nVia: x"}},
		{Method: "INVITE", URI: URI{Scheme: "sip", Host: "exa mple.com"}},
	} {
		if _, err := r.Bytes(); err == nil {
			t.Errorf("Bytes() of %q %q succeeded", r.Method, r.URI.Host)
		}
		var buf bytes.Buffer
		if _, err := r.WriteTo(&buf); err == nil || buf.Len() != 0 {
			t.Errorf("WriteTo() of %q wrote %d bytes, err %v", r.Method, buf.Len(), err)
		}
	}
	for _, r := range []*Response{
		{StatusCode: 99, Reason: "x"},
		{StatusCode: 700, Reason: "x"},
		{StatusCode: 200, Reason: "OK\r\nVia: x"},
	} {
		if _, err := r.Bytes(); err == nil {
			t.Errorf("Bytes() of %d %q succeeded", r.StatusCode, r.Reason)
		}
		if _, err := r.WriteTo(&bytes.Buffer{}); err == nil {
			t.Errorf("WriteTo() of %d %q succeeded", r.StatusCode, r.Reason)
		}
	}
}

func TestWriteToWritesTheSerializedMessage(t *testing.T) {
	m := mustParse(t, basicInvite)
	var buf bytes.Buffer
	n, err := m.WriteTo(&buf)
	if err != nil || n != int64(len(basicInvite)) || buf.String() != basicInvite {
		t.Errorf("WriteTo = %d, %v, %q", n, err, buf.String())
	}
	res := &Response{StatusCode: 200, Reason: "OK"}
	buf.Reset()
	if _, err := res.WriteTo(&buf); err != nil || buf.String() != "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n" {
		t.Errorf("response WriteTo = %v, %q", err, buf.String())
	}
}

func TestCloneDoesNotShareState(t *testing.T) {
	req := mustParse(t, basicInvite).(*Request)
	req.URI.Params = Params{{Name: "lr"}}
	c := req.Clone()
	c.URI.Params[0].Name = "transport"
	c.Body[0] = 'J'
	if err := c.Header.Set("To", "<sip:carol@example.com>"); err != nil {
		t.Fatal(err)
	}
	if req.URI.Params[0].Name != "lr" || string(req.Body) != "hello" || !strings.Contains(req.Header.Get("To"), "bob") {
		t.Error("modifying the clone changed the original request")
	}

	res := &Response{StatusCode: 200, Reason: "OK", Body: []byte("x")}
	rc := res.Clone()
	rc.Body[0] = 'y'
	if string(res.Body) != "x" {
		t.Error("modifying the clone changed the original response")
	}
	if (&Request{}).Clone().Body != nil {
		t.Error("clone of a nil body is not nil")
	}
}

func TestValidateAcceptsAWellFormedRequestAndResponse(t *testing.T) {
	req := mustParse(t, basicInvite)
	if err := req.Validate(); err != nil {
		t.Errorf("request: %v", err)
	}
	// RFC 3261 §16.3 step 3: a request without Max-Forwards passes.
	noMF := mustParse(t, strings.Replace(basicInvite, "Max-Forwards: 70\r\n", "", 1))
	if err := noMF.Validate(); err != nil {
		t.Errorf("request without Max-Forwards: %v", err)
	}
	res := mustParse(t, lines(
		"SIP/2.0 200 OK",
		"Via: SIP/2.0/TCP client.example.com:5060;branch=z9hG4bK74bf9",
		"From: Alice <sip:alice@example.com>;tag=9fxced76sl",
		"To: Bob <sip:bob@example.com>;tag=8321234356",
		"Call-ID: a84b4c76e66710@client.example.com",
		"CSeq: 1 INVITE",
		"Content-Length: 0",
	))
	if err := res.Validate(); err != nil {
		t.Errorf("response: %v", err)
	}
}

func TestValidateRejectsMissingDuplicateAndMalformedFields(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     error
		header   string
	}{
		{"no Via", "Via: SIP/2.0/TCP client.example.com:5060;branch=z9hG4bK74bf9\r\n", "", ErrMissingHeader, "Via"},
		{"bad Via", "SIP/2.0/TCP client", "SIP/1.0/TCP client", ErrMalformed, "Via"},
		{"no From", "From: Alice <sip:alice@example.com>;tag=9fxced76sl\r\n", "", ErrMissingHeader, "From"},
		{"two Froms", "From: Alice", "From: Mallory <sip:m@example.com>;tag=1\r\nFrom: Alice", ErrMalformed, "From"},
		{"no To", "To: Bob <sip:bob@example.com>\r\n", "", ErrMissingHeader, "To"},
		{"bad Call-ID", "Call-ID: a84b4c76e66710@client.example.com", "Call-ID: a b", ErrMalformed, "Call-ID"},
		{"Call-ID with two @", "Call-ID: a84b4c76e66710@client.example.com", "Call-ID: a@b@c", ErrMalformed, "Call-ID"},
		{"no CSeq", "CSeq: 1 INVITE\r\n", "", ErrMissingHeader, "CSeq"},
		{"CSeq method mismatch", "CSeq: 1 INVITE", "CSeq: 1 OPTIONS", ErrMalformed, "CSeq"},
		{"CSeq method case", "CSeq: 1 INVITE", "CSeq: 1 invite", ErrMalformed, "CSeq"},
		{"bad Max-Forwards", "Max-Forwards: 70", "Max-Forwards: 256", ErrMalformed, "Max-Forwards"},
	}
	for _, tt := range tests {
		m := mustParse(t, strings.Replace(basicInvite, tt.old, tt.new, 1))
		err := m.Validate()
		var pe *ParseError
		if !errors.Is(err, tt.want) || !errors.As(err, &pe) || pe.Header != tt.header {
			t.Errorf("%s: Validate() = %v, want %v in %s", tt.name, err, tt.want, tt.header)
		}
	}
	// A Request-URI built in code with header components is caught too.
	req := mustParse(t, basicInvite).(*Request)
	req.URI.Headers = Params{{Name: "Subject", Value: "x"}}
	if err := req.Validate(); !errors.Is(err, ErrMalformed) {
		t.Errorf("Request-URI with headers: %v", err)
	}
	if err := (&Response{StatusCode: 200}).Validate(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("empty response: %v", err)
	}
}
