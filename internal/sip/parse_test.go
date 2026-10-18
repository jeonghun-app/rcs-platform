package sip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

const basicInvite = "INVITE sip:bob@example.com SIP/2.0\r\n" +
	"Via: SIP/2.0/TCP client.example.com:5060;branch=z9hG4bK74bf9\r\n" +
	"Max-Forwards: 70\r\n" +
	"From: Alice <sip:alice@example.com>;tag=9fxced76sl\r\n" +
	"To: Bob <sip:bob@example.com>\r\n" +
	"Call-ID: a84b4c76e66710@client.example.com\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Contact: <sip:alice@client.example.com;transport=tcp>\r\n" +
	"Content-Type: text/plain\r\n" +
	"Content-Length: 5\r\n" +
	"\r\n" +
	"hello"

func mustParse(t *testing.T, s string) Message {
	t.Helper()
	m, err := ParseMessage([]byte(s))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	return m
}

func TestParseRequestReadsStartLineHeadersAndBody(t *testing.T) {
	req, ok := mustParse(t, basicInvite).(*Request)
	if !ok {
		t.Fatal("not a request")
	}
	if req.Method != "INVITE" || req.URI.String() != "sip:bob@example.com" || string(req.Body) != "hello" {
		t.Errorf("got %q %q body %q", req.Method, req.URI.String(), req.Body)
	}
	if req.Header.Len() != 9 || req.Header.Get("cseq") != "1 INVITE" {
		t.Errorf("headers = %q", req.Header.Fields())
	}
	if err := req.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseResponseReadsStatusLine(t *testing.T) {
	tests := []struct {
		line   string
		code   int
		reason string
	}{
		{"SIP/2.0 200 OK", 200, "OK"},
		{"sip/2.0 486 Busy Here", 486, "Busy Here"},
		{"SIP/2.0 699 ", 699, ""},
		{"SIP/2.0 180 Ringing\tnow", 180, "Ringing\tnow"},
	}
	for _, tt := range tests {
		res, ok := mustParse(t, lines(tt.line, "Content-Length: 0")).(*Response)
		if !ok {
			t.Fatalf("%q: not a response", tt.line)
		}
		if res.StatusCode != tt.code || res.Reason != tt.reason {
			t.Errorf("%q: got %d %q", tt.line, res.StatusCode, res.Reason)
		}
	}
}

func TestMalformedStartLinesAreRejected(t *testing.T) {
	for _, line := range []string{
		"",
		"INVITE",
		" INVITE sip:a@example.com SIP/2.0",
		"INVITE sip:a@example.com",
		"INVITE sip:a@example.com SIP/2.0 ",
		"INVITE  sip:a@example.com SIP/2.0",
		"INV(ITE sip:a@example.com SIP/2.0",
		"INVITE sip:a@example.com HTTP/1.1",
		"INVITE sip:a@example.com SIP/",
		"INVITE <sip:a@example.com> SIP/2.0",
		"INVITE sip:a@example.com?Subject=x SIP/2.0",
		"SIP/2.0 200",
		"SIP/2.0 20 OK",
		"SIP/2.0 2000 OK",
		"SIP/2.0 099 Low",
		"SIP/2.0 700 High",
		"SIP/2.0 2x0 OK",
		"SIP/2.0  200 OK",
		"SIP/2.0 200 O\x00K",
		"HTTP/1.1 200 OK",
	} {
		_, err := ParseMessage([]byte(lines(line, "Content-Length: 0")))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: error = %v, want ErrMalformed", line, err)
		}
	}
}

func TestOtherSIPVersionsAreUnsupportedRatherThanMalformed(t *testing.T) {
	for _, line := range []string{"OPTIONS sip:a@example.com SIP/7.0", "SIP/3.0 200 OK"} {
		_, err := ParseMessage([]byte(lines(line, "Content-Length: 0")))
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%q: error = %v, want ErrUnsupportedVersion", line, err)
		}
	}
}

func TestFoldedHeaderLinesAreUnfolded(t *testing.T) {
	m := mustParse(t, lines(
		"OPTIONS sip:example.com SIP/2.0",
		"Subject: first  ",
		"   second",
		"\tthird",
		"Via  :  SIP/2.0/UDP a.example.com;branch=z9hG4bK1",
		"Empty:",
	))
	h := m.Headers()
	if got := h.Get("Subject"); got != "first second third" {
		t.Errorf("Subject = %q", got)
	}
	if got := h.Get("Via"); got != "SIP/2.0/UDP a.example.com;branch=z9hG4bK1" {
		t.Errorf("Via = %q", got)
	}
	if got := h.Fields()[1].Name; got != "Via" {
		t.Errorf("name = %q", got)
	}
	if !h.Has("Empty") || h.Get("Empty") != "" {
		t.Errorf("empty field lost")
	}
}

func TestMalformedHeaderLinesAreRejected(t *testing.T) {
	for _, hl := range []string{
		"No colon here",
		": empty name",
		"Bad Name: x",
		"Bad\x01Name: x",
		"Folded\r\n : name",
		"Subject: bare\nLF",
		"Subject: bare\rCR",
	} {
		_, err := ParseMessage([]byte(lines("OPTIONS sip:example.com SIP/2.0", hl)))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: error = %v, want ErrMalformed", hl, err)
		}
	}
	// A continuation line directly after the start line has nothing to continue.
	_, err := ParseMessage([]byte(lines("OPTIONS sip:example.com SIP/2.0", " Subject: x")))
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("continuation of the start line: error = %v", err)
	}
}

func TestDatagramBodyFollowsContentLength(t *testing.T) {
	head := "MESSAGE sip:bob@example.com SIP/2.0\r\nSubject: x\r\n"
	tests := []struct {
		name, in, body string
	}{
		// RFC 3261 §18.3: without Content-Length the body runs to the end of the datagram.
		{"absent", head + "\r\nabc", "abc"},
		{"exact", head + "Content-Length: 3\r\n\r\nabc", "abc"},
		// Octets beyond Content-Length are discarded (RFC 3261 §18.3).
		{"shorter", head + "l: 2\r\n\r\nabc", "ab"},
		{"zero", head + "Content-Length: 0\r\n\r\nabc", ""},
		{"leading zeros", head + "Content-Length: 003\r\n\r\nabc", "abc"},
	}
	for _, tt := range tests {
		m, err := ParseMessage([]byte(tt.in))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got := string(m.(*Request).Body); got != tt.body {
			t.Errorf("%s: body = %q, want %q", tt.name, got, tt.body)
		}
	}
}

func TestParsedBodyDoesNotAliasTheInput(t *testing.T) {
	buf := []byte(basicInvite)
	m, err := ParseMessage(buf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range buf {
		buf[i] = 'x'
	}
	if string(m.(*Request).Body) != "hello" || m.Headers().Get("To") != "Bob <sip:bob@example.com>" {
		t.Error("the message changed with the input buffer")
	}
}

func TestBadContentLengthsAreRejected(t *testing.T) {
	head := "MESSAGE sip:bob@example.com SIP/2.0\r\n"
	for _, tt := range []struct {
		name, in string
		want     error
	}{
		{"negative", head + "Content-Length: -1\r\n\r\n", ErrMalformed},
		{"signed", head + "Content-Length: +1\r\n\r\nx", ErrMalformed},
		{"empty", head + "Content-Length:\r\n\r\n", ErrMalformed},
		{"list", head + "Content-Length: 1, 1\r\n\r\nx", ErrMalformed},
		{"twice", head + "Content-Length: 1\r\nl: 1\r\n\r\nx", ErrMalformed},
		{"beyond datagram", head + "Content-Length: 10\r\n\r\nshort", ErrMalformed},
		{"overlarge", head + "Content-Length: 99999999999999999999999\r\n\r\n", ErrBodyTooLarge},
	} {
		_, err := ParseMessage([]byte(tt.in))
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestLimitsHaveTypedErrors(t *testing.T) {
	big := "MESSAGE sip:bob@example.com SIP/2.0\r\nSubject: " + strings.Repeat("a", 200) + "\r\n\r\n"
	lim := Limits{MaxHeaderBytes: 100, MaxHeaders: 2, MaxBodyBytes: 4}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"header bytes", big, ErrHeaderTooLarge},
		{"header bytes, unterminated", big[:len(big)-4], ErrHeaderTooLarge},
		{"header count", lines("OPTIONS sip:a@example.com SIP/2.0", "A: 1", "B: 2", "C: 3"), ErrTooManyHeaders},
		{"body by Content-Length", lines("OPTIONS sip:a@example.com SIP/2.0", "l: 5") + "12345", ErrBodyTooLarge},
		{"body of the datagram", lines("OPTIONS sip:a@example.com SIP/2.0") + "12345", ErrBodyTooLarge},
	}
	for _, tt := range tests {
		_, err := ParseDatagram([]byte(tt.in), lim)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
		r := NewReader(bufio.NewReader(strings.NewReader(tt.in)), lim)
		if _, err := r.ReadMessage(); tt.name != "body of the datagram" && !errors.Is(err, tt.want) {
			t.Errorf("%s (stream): error = %v, want %v", tt.name, err, tt.want)
		}
	}
	// Exactly at the limits is fine.
	exact := lines("OPTIONS sip:a@example.com SIP/2.0", "l: 4") + "1234"
	headLen := strings.Index(exact, "\r\n\r\n") + 2
	if _, err := ParseDatagram([]byte(exact), Limits{MaxHeaderBytes: headLen, MaxHeaders: 1, MaxBodyBytes: 4}); err != nil {
		t.Errorf("message at the limits: %v", err)
	}
	if _, err := ParseDatagram([]byte(exact), Limits{MaxHeaderBytes: headLen - 1}); !errors.Is(err, ErrHeaderTooLarge) {
		t.Errorf("one byte over: %v", err)
	}
}

func TestDefaultLimitsApplyToZeroFields(t *testing.T) {
	got := Limits{MaxHeaders: 5}.withDefaults()
	want := Limits{MaxHeaderBytes: 16 << 10, MaxHeaders: 5, MaxBodyBytes: 1 << 20}
	if got != want {
		t.Errorf("withDefaults() = %+v", got)
	}
	many := "OPTIONS sip:a@example.com SIP/2.0\r\n" + strings.Repeat("A: 1\r\n", 129) + "\r\n"
	if _, err := ParseMessage([]byte(many)); !errors.Is(err, ErrTooManyHeaders) {
		t.Errorf("129 headers: %v", err)
	}
}

func TestDatagramOfOnlyCRLFIsAKeepAlive(t *testing.T) {
	for _, in := range []string{"", "\r\n", "\r\n\r\n"} {
		if _, err := ParseMessage([]byte(in)); !errors.Is(err, ErrKeepAlive) {
			t.Errorf("%q: error = %v, want ErrKeepAlive", in, err)
		}
	}
	m, err := ParseMessage([]byte("\r\n\r\n" + basicInvite))
	if err != nil || m.(*Request).Method != "INVITE" {
		t.Errorf("leading CRLFs before a message: %v", err)
	}
	if _, err := ParseMessage([]byte("OPTIONS sip:a@example.com SIP/2.0\r\nA: 1\r\n")); !errors.Is(err, ErrMalformed) {
		t.Errorf("unterminated header section: %v", err)
	}
}

func TestReaderReadsBackToBackMessagesAndSkipsKeepAlives(t *testing.T) {
	second := strings.Replace(basicInvite, "CSeq: 1 INVITE", "CSeq: 2 INVITE", 1)
	stream := "\r\n\r\n" + basicInvite + "\r\n\r\n\r\n" + second + "\r\n\r\n"
	pings := 0
	r := NewReader(bufio.NewReader(strings.NewReader(stream)), Limits{})
	r.OnKeepAlive = func() { pings++ }
	for _, want := range []string{"1 INVITE", "2 INVITE"} {
		m, err := r.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if got := m.Headers().Get("CSeq"); got != want || string(m.(*Request).Body) != "hello" {
			t.Errorf("CSeq = %q body %q", got, m.(*Request).Body)
		}
	}
	if _, err := r.ReadMessage(); err != io.EOF {
		t.Errorf("end of stream: %v, want io.EOF", err)
	}
	// One ping before the first message, one after the first (the third CRLF is
	// half of nothing), one at the end.
	if pings != 3 {
		t.Errorf("OnKeepAlive called %d times, want 3", pings)
	}
}

func TestReaderHandlesSmallReadsAndLongLines(t *testing.T) {
	long := lines("MESSAGE sip:bob@example.com SIP/2.0", "Subject: "+strings.Repeat("s", 9000), "Content-Length: 3") + "abc"
	// A 16-byte buffer forces ReadSlice to report ErrBufferFull for most lines.
	br := bufio.NewReaderSize(iotest.OneByteReader(strings.NewReader(long)), 16)
	m, err := NewReader(br, Limits{}).ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Headers().Get("Subject")) != 9000 || string(m.(*Request).Body) != "abc" {
		t.Error("message read in small pieces differs")
	}
}

func TestReaderRequiresContentLength(t *testing.T) {
	r := NewReader(bufio.NewReader(strings.NewReader(lines("OPTIONS sip:a@example.com SIP/2.0", "Subject: x"))), Limits{})
	if _, err := r.ReadMessage(); !errors.Is(err, ErrMissingContentLength) {
		t.Errorf("error = %v, want ErrMissingContentLength", err)
	}
}

func TestReaderReportsTruncatedStreams(t *testing.T) {
	for _, in := range []string{
		"\r",
		"OPTIONS sip:a@example.com SIP/2.0\r\nContent-Le",
		basicInvite[:len(basicInvite)-2],
	} {
		r := NewReader(bufio.NewReader(strings.NewReader(in)), Limits{})
		if _, err := r.ReadMessage(); err != io.ErrUnexpectedEOF {
			t.Errorf("%q: error = %v, want io.ErrUnexpectedEOF", in, err)
		}
	}
}

func TestReaderRejectsBareLFAtOnce(t *testing.T) {
	r := NewReader(bufio.NewReader(strings.NewReader("OPTIONS sip:a@example.com SIP/2.0\nVia: x\n\n")), Limits{})
	if _, err := r.ReadMessage(); !errors.Is(err, ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

func TestReaderPassesOnTransportErrors(t *testing.T) {
	boom := errors.New("connection reset")
	for _, in := range []string{"", "\r\n", "OPTIONS sip:a@example.com SIP/2.0\r\n", lines("OPTIONS sip:a@example.com SIP/2.0", "l: 9") + "ab"} {
		src := io.MultiReader(strings.NewReader(in), iotest.ErrReader(boom))
		r := NewReader(bufio.NewReader(src), Limits{})
		if _, err := r.ReadMessage(); !errors.Is(err, boom) {
			t.Errorf("%q: error = %v, want the transport error", in, err)
		}
	}
}

func TestStreamAndDatagramParsesAgree(t *testing.T) {
	d, err := ParseMessage([]byte(basicInvite))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewReader(bufio.NewReader(strings.NewReader(basicInvite)), Limits{}).ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	db, _ := d.Bytes()
	sb, _ := s.Bytes()
	if !bytes.Equal(db, sb) {
		t.Errorf("stream and datagram parses differ:\n%s\n%s", db, sb)
	}
}
