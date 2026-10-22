package msrp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

const (
	toURI   = "msrp://as.example.org:9000/as9ses;tcp"
	fromURI = "msrp://client.example.com:2855/cl1ses;tcp"
)

func readOne(t *testing.T, in string) *Message {
	t.Helper()
	m, err := NewReader(strings.NewReader(in), 0).ReadMessage(DefaultMaxMessageSize)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	return m
}

func TestReadMessageParsesASendWithABody(t *testing.T) {
	m := readOne(t, wire(
		"MSRP t1x9q2 SEND",
		"To-Path: "+toURI,
		"From-Path: "+fromURI,
		"Message-ID: m77aa1",
		"Byte-Range: 1-11/11",
		"Success-Report: yes",
		"Failure-Report: partial",
		"X-Trace: one two",
		"Content-Disposition: render",
		"Content-Type: text/plain;charset=UTF-8",
		"",
		"hello there",
		"-------t1x9q2$",
	))
	if m.Method != MethodSend || m.TransactionID != "t1x9q2" || m.MessageID != "m77aa1" {
		t.Fatalf("start line or Message-ID wrong: %+v", m)
	}
	if len(m.ToPath) != 1 || m.ToPath[0].String() != toURI || m.FromPath[0].String() != fromURI {
		t.Fatalf("paths wrong: %v %v", m.ToPath, m.FromPath)
	}
	if *m.ByteRange != (ByteRange{Start: 1, End: 11, Total: 11}) {
		t.Fatalf("Byte-Range = %v", m.ByteRange)
	}
	if !m.WantsSuccessReport() || m.FailureMode() != ReportPartial {
		t.Fatalf("report headers = %v %v", m.SuccessReport, m.FailureReport)
	}
	if m.ContentType != "text/plain;charset=UTF-8" || m.MediaType() != "text/plain" {
		t.Fatalf("Content-Type = %q", m.ContentType)
	}
	if v, ok := m.Get("x-trace"); !ok || v != "one two" {
		t.Fatalf("extension header = %q, %v", v, ok)
	}
	if v, _ := m.Get("Content-Disposition"); v != "render" {
		t.Fatalf("Content-Disposition = %q", v)
	}
	if string(m.Body.Bytes()) != "hello there" || m.Continuation != FlagEnd {
		t.Fatalf("body %q flag %q", m.Body, m.Continuation)
	}
}

func TestReadMessageParsesABodilessSend(t *testing.T) {
	m := readOne(t, wire(
		"MSRP b0dy1ess SEND",
		"To-Path: "+toURI,
		"From-Path: "+fromURI,
		"Message-ID: k33pal1ve",
		"Byte-Range: 1-0/0",
		"-------b0dy1ess$",
	))
	if m.HasBody() || m.Body.Len() != 0 || m.Continuation != FlagEnd {
		t.Fatalf("bodiless SEND read as %+v", m)
	}
}

func TestReadMessageKeepsAnEmptyBodyApartFromNoBody(t *testing.T) {
	m := readOne(t, wire(
		"MSRP e1mpty SEND",
		"To-Path: "+toURI,
		"From-Path: "+fromURI,
		"Message-ID: msg1",
		"Content-Type: text/plain",
		"",
		"",
		"-------e1mpty$",
	))
	if !m.HasBody() || m.Body.Len() != 0 {
		t.Fatalf("empty body read as %+v", m)
	}
}

func TestReadMessageParsesResponses(t *testing.T) {
	for _, tt := range []struct {
		start   string
		code    int
		comment string
	}{
		{"MSRP tr4ns 200 OK", 200, "OK"},
		{"MSRP tr4ns 481", 481, ""},
		{"MSRP tr4ns 425 Nickname reserved or already in use", 425, "Nickname reserved or already in use"},
	} {
		m := readOne(t, wire(tt.start, "To-Path: "+fromURI, "From-Path: "+toURI, "-------tr4ns$"))
		if m.IsRequest() || m.StatusCode != tt.code || m.Comment != tt.comment {
			t.Errorf("%q read as %d %q", tt.start, m.StatusCode, m.Comment)
		}
	}
}

func TestReadMessageAcceptsExtensionMethods(t *testing.T) {
	m := readOne(t, wire(
		"MSRP n1ck NICKNAME",
		"To-Path: "+toURI,
		"From-Path: "+fromURI,
		`Use-Nickname: "Alice the great"`,
		"-------n1ck$",
	))
	if m.Method != MethodNickname {
		t.Fatalf("method = %q", m.Method)
	}
	if v, _ := m.Get("Use-Nickname"); v != `"Alice the great"` {
		t.Fatalf("Use-Nickname = %q", v)
	}
}

func TestHeaderNamesAndReportValuesAreCaseInsensitive(t *testing.T) {
	m := readOne(t, wire(
		"MSRP c4se SEND",
		"to-path: "+toURI,
		"FROM-PATH: "+fromURI,
		"message-id: msg1",
		"success-report: YES",
		"failure-report: No",
		"-------c4se$",
	))
	if m.MessageID != "msg1" || m.SuccessReport != ReportYes || m.FailureReport != ReportNo {
		t.Fatalf("parsed %+v", m)
	}
}

func TestBodyKeepsBytesThatOnlyLookLikeAnEndLine(t *testing.T) {
	bodies := []string{
		"-------other1$",                  // another transaction's end-line
		"x-------tidtid$\r\nmore",         // ours, but not at a line start
		"line\n-------tidtid$\r\nmore",    // ours, after a bare LF
		"line\r\n-------tidtid*\r\nmore",  // ours, with a bad flag
		"line\r\n-------tidtid$ \r\nmore", // ours, with trailing junk
		"line\r\n-------tidtidx$\r\n",     // a longer transaction id
		"\r\n\r\n\r",                      // CRs and CRLFs at the end
		"\r",
		"\n",
	}
	for _, body := range bodies {
		in := wire(
			"MSRP tidtid SEND",
			"To-Path: "+toURI,
			"From-Path: "+fromURI,
			"Message-ID: msg1",
			"Content-Type: application/octet-stream",
			"",
			body,
			"-------tidtid+",
		)
		m := readOne(t, in)
		if string(m.Body.Bytes()) != body || m.Continuation != FlagMore {
			t.Errorf("body %q read as %q, flag %q", body, m.Body, m.Continuation)
		}
	}
}

func TestEndLineIsFoundWhereverTheBufferBoundaryFalls(t *testing.T) {
	// Long body lines overflow the 4 KiB read buffer, so the CR of the
	// framing CRLF can land in one read and its LF in the next.
	for n := 4080; n <= 4110; n++ {
		body := strings.Repeat("a", n)
		in := wire(
			"MSRP bnd4ry SEND",
			"To-Path: "+toURI,
			"From-Path: "+fromURI,
			"Message-ID: msg1",
			"Content-Type: text/plain",
			"",
			body+"\r",
			"-------bnd4ry$",
		)
		for name, src := range map[string]io.Reader{
			"whole":    strings.NewReader(in),
			"one byte": iotest.OneByteReader(strings.NewReader(in)),
		} {
			m, err := NewReader(src, 0).ReadMessage(DefaultMaxMessageSize)
			if err != nil {
				t.Fatalf("n=%d %s: %v", n, name, err)
			}
			if string(m.Body.Bytes()) != body+"\r" {
				t.Fatalf("n=%d %s: body of %d octets, want %d", n, name, m.Body.Len(), n+1)
			}
		}
	}
}

func TestBodyCanBeStreamedAndSetsTheFlagAtItsEnd(t *testing.T) {
	body := strings.Repeat("0123456789\r\n", 1000)
	in := wire(
		"MSRP str3am SEND",
		"To-Path: "+toURI,
		"From-Path: "+fromURI,
		"Message-ID: msg1",
		"Content-Type: text/plain",
		"",
		body,
		"-------str3am#",
	) + wire("MSRP n3xt 200 OK", "To-Path: "+fromURI, "From-Path: "+toURI, "-------n3xt$")
	r := NewReader(iotest.HalfReader(strings.NewReader(in)), 0)
	m, err := r.ReadHeader()
	if err != nil {
		t.Fatal(err)
	}
	if m.Continuation != 0 {
		t.Fatal("flag known before the body was read")
	}
	got, err := io.ReadAll(iotest.OneByteReader(r.Body()))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body || m.Continuation != FlagAbort {
		t.Fatalf("streamed %d octets, flag %q", len(got), m.Continuation)
	}
	next, err := r.ReadHeader()
	if err != nil || next.StatusCode != 200 {
		t.Fatalf("next message: %+v, %v", next, err)
	}
}

func TestUnreadBodyIsSkippedByTheNextRead(t *testing.T) {
	in := wire("MSRP sk1p SEND", "To-Path: "+toURI, "From-Path: "+fromURI, "Message-ID: msg1",
		"Content-Type: text/plain", "", "ignored", "-------sk1p$") +
		wire("MSRP n3xt REPORT", "To-Path: "+toURI, "From-Path: "+fromURI, "Message-ID: msg1",
			"Status: 000 200 OK", "-------n3xt$")
	r := NewReader(strings.NewReader(in), 0)
	if _, err := r.ReadHeader(); err != nil {
		t.Fatal(err)
	}
	m, err := r.ReadHeader()
	if err != nil || m.Method != MethodReport || m.Status.Code != 200 {
		t.Fatalf("second message %+v, %v", m, err)
	}
	if b, _ := io.ReadAll(r.Body()); len(b) != 0 {
		t.Fatal("bodiless message has a body")
	}
	if err := r.ReadBody(10); err != nil {
		t.Fatalf("ReadBody on a bodiless message: %v", err)
	}
}

func TestReaderReportsACleanEndBetweenMessages(t *testing.T) {
	r := NewReader(strings.NewReader(wire("MSRP abcd 200", "To-Path: "+fromURI, "From-Path: "+toURI, "-------abcd$")), 0)
	if _, err := r.ReadMessage(10); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage(10); err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestMalformedMessagesAreRefusedWith400AndTheStreamStaysInStep(t *testing.T) {
	head := []string{"To-Path: " + toURI, "From-Path: " + fromURI}
	send := func(tid string, lines ...string) string {
		return wire(append([]string{"MSRP " + tid + " SEND"}, lines...)...)
	}
	tests := map[string]string{
		"To-Path not first":          send("bad1", "From-Path: "+fromURI, "To-Path: "+toURI, "Message-ID: msg1", "-------bad1$"),
		"From-Path missing":          send("bad1", "To-Path: "+toURI, "Message-ID: msg1", "-------bad1$"),
		"no headers":                 send("bad1", "-------bad1$"),
		"empty path":                 send("bad1", "To-Path: ", "From-Path: "+fromURI, "Message-ID: msg1", "-------bad1$"),
		"two spaces in a path":       send("bad1", "To-Path: "+toURI+"  "+toURI, "From-Path: "+fromURI, "Message-ID: msg1", "-------bad1$"),
		"bad URI":                    send("bad1", "To-Path: msrp://x", "From-Path: "+fromURI, "Message-ID: msg1", "-------bad1$"),
		"repeated Message-ID":        send("bad1", append(head, "Message-ID: msg1", "message-id: msg2", "-------bad1$")...),
		"bad Message-ID":             send("bad1", append(head, "Message-ID: m", "-------bad1$")...),
		"missing Message-ID":         send("bad1", append(head, "-------bad1$")...),
		"Byte-Range without total":   send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 1-2", "-------bad1$")...),
		"Byte-Range from zero":       send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 0-2/3", "-------bad1$")...),
		"Byte-Range backwards":       send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 5-2/9", "-------bad1$")...),
		"Byte-Range past total":      send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 1-9/3", "-------bad1$")...),
		"Byte-Range signed":          send("bad1", append(head, "Message-ID: msg1", "Byte-Range: +1-2/3", "-------bad1$")...),
		"Byte-Range overflowing":     send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 1-2/99999999999999999999", "-------bad1$")...),
		"Success-Report partial":     send("bad1", append(head, "Message-ID: msg1", "Success-Report: partial", "-------bad1$")...),
		"Failure-Report maybe":       send("bad1", append(head, "Message-ID: msg1", "Failure-Report: maybe", "-------bad1$")...),
		"no space after the colon":   send("bad1", append(head, "Message-ID:msg1", "-------bad1$")...),
		"no colon":                   send("bad1", append(head, "Message-ID msg1", "-------bad1$")...),
		"header name with a space":   send("bad1", append(head, "Message ID: m1", "-------bad1$")...),
		"control character":          send("bad1", append(head, "Message-ID: msg1", "X-A: a\x01b", "-------bad1$")...),
		"invalid UTF-8":              send("bad1", append(head, "Message-ID: msg1", "X-A: \xff", "-------bad1$")...),
		"body without Content-Type":  send("bad1", append(head, "Message-ID: msg1", "", "x", "-------bad1$")...),
		"Content-Type without body":  send("bad1", append(head, "Message-ID: msg1", "Content-Type: text/plain", "-------bad1$")...),
		"MIME header without body":   send("bad1", append(head, "Message-ID: msg1", "Content-ID: <a@b>", "-------bad1$")...),
		"Content-Type not last":      send("bad1", append(head, "Message-ID: msg1", "Content-Type: text/plain", "Content-ID: <a@b>", "", "x", "-------bad1$")...),
		"bad Content-Type":           send("bad1", append(head, "Message-ID: msg1", "Content-Type: text", "", "x", "-------bad1$")...),
		"body longer than its range": send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 1-2/9", "Content-Type: text/plain", "", "xyz", "-------bad1+")...),
		"body past the total":        send("bad1", append(head, "Message-ID: msg1", "Byte-Range: 8-*/9", "Content-Type: text/plain", "", "xyz", "-------bad1+")...),
		"REPORT without Status":      wire(append(append([]string{"MSRP bad1 REPORT"}, head...), "Message-ID: msg1", "-------bad1$")...),
		"REPORT with Success-Report": wire(append(append([]string{"MSRP bad1 REPORT"}, head...), "Message-ID: msg1", "Status: 000 200 OK", "Success-Report: no", "-------bad1$")...),
		"REPORT with a bad Status":   wire(append(append([]string{"MSRP bad1 REPORT"}, head...), "Message-ID: msg1", "Status: 0 200", "-------bad1$")...),
		"REPORT continued":           wire(append(append([]string{"MSRP bad1 REPORT"}, head...), "Message-ID: msg1", "Status: 000 200 OK", "-------bad1+")...),
		"response with a body":       wire("MSRP bad1 200 OK", "To-Path: "+fromURI, "From-Path: "+toURI, "Content-Type: text/plain", "", "x", "-------bad1$"),
	}
	good := wire("MSRP g00d 200 OK", "To-Path: "+fromURI, "From-Path: "+toURI, "-------g00d$")
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			r := NewReader(strings.NewReader(in+good), 0)
			m, err := r.ReadMessage(DefaultMaxMessageSize)
			var me *MessageError
			if !errors.As(err, &me) || me.Code != StatusBadRequest {
				t.Fatalf("err = %v, want a 400 MessageError", err)
			}
			if m == nil || m.TransactionID != "bad1" || me.Error() == "" {
				t.Fatalf("partial message %+v", m)
			}
			next, err := r.ReadMessage(DefaultMaxMessageSize)
			if err != nil || next.TransactionID != "g00d" {
				t.Fatalf("stream out of step: %+v, %v", next, err)
			}
		})
	}
}

func TestARefusedRequestStillCarriesItsPaths(t *testing.T) {
	_, err := NewReader(strings.NewReader(wire("MSRP p4ths SEND", "To-Path: "+toURI, "From-Path: "+fromURI,
		"Message-ID: msg1", "Byte-Range: x", "-------p4ths$")), 0).ReadMessage(10)
	var me *MessageError
	if !errors.As(err, &me) {
		t.Fatal(err)
	}
	if _, err := NewResponse(me.Message, me.Code, ""); err != nil {
		t.Fatalf("cannot answer the refused request: %v", err)
	}
}

func TestFramingErrorsEndTheStream(t *testing.T) {
	tests := map[string]string{
		"not MSRP":                "HTTP/1.1 200 OK\r\n\r\n",
		"bad transaction id":      "MSRP a SEND\r\n",
		"no method":               "MSRP abcd\r\n",
		"lower-case method":       "MSRP abcd send\r\n",
		"bad response comment":    "MSRP abcd 200 \x01\r\n",
		"bare LF":                 "MSRP abcd SEND\n",
		"bare LF in the headers":  "MSRP abcd SEND\r\nTo-Path: " + toURI + "\n",
		"ends in the start line":  "MSRP abcd SE",
		"ends in the headers":     "MSRP abcd SEND\r\nTo-Path: " + toURI + "\r\n",
		"ends in the body":        wire("MSRP abcd SEND", "To-Path: "+toURI, "From-Path: "+fromURI, "Message-ID: msg1", "Content-Type: text/plain", "", "partial"),
		"header section too long": "MSRP abcd SEND\r\nX-Pad: " + strings.Repeat("p", DefaultMaxHeaderBytes) + "\r\n",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewReader(strings.NewReader(in), 0).ReadMessage(DefaultMaxMessageSize)
			if !errors.Is(err, ErrFraming) {
				t.Fatalf("err = %v, want ErrFraming", err)
			}
		})
	}
}

func TestReadErrorsAreReturnedAsTheyAre(t *testing.T) {
	boom := errors.New("connection reset")
	in := wire("MSRP abcd SEND", "To-Path: "+toURI, "From-Path: "+fromURI, "Message-ID: msg1", "Content-Type: text/plain", "", "x")
	for _, src := range []io.Reader{
		iotest.ErrReader(boom),
		io.MultiReader(strings.NewReader("MSRP ab"), iotest.ErrReader(boom)),
		io.MultiReader(strings.NewReader(in), iotest.ErrReader(boom)),
	} {
		if _, err := NewReader(src, 0).ReadMessage(10); !errors.Is(err, boom) {
			t.Errorf("err = %v, want %v", err, boom)
		}
	}
}

func TestOversizedBodiesAreSkippedAndRefused(t *testing.T) {
	good := wire("MSRP g00d 200 OK", "To-Path: "+fromURI, "From-Path: "+toURI, "-------g00d$")
	for _, tt := range []struct {
		method string
		extra  string
		size   int
		limit  int64
		code   int
	}{
		{MethodSend, "Message-ID: msg1", 101, 100, StatusMessageTooLarge},
		{MethodReport, "Message-ID: msg1\r\nStatus: 000 200 OK", maxNonSendBody + 1, DefaultMaxMessageSize, StatusBadRequest},
		{MethodNickname, "Use-Nickname: \"x\"", maxNonSendBody + 1, DefaultMaxMessageSize, StatusBadRequest},
	} {
		in := wire("MSRP big1 "+tt.method, "To-Path: "+toURI, "From-Path: "+fromURI, tt.extra,
			"Content-Type: text/plain", "", strings.Repeat("z", tt.size), "-------big1$") + good
		r := NewReader(strings.NewReader(in), 0)
		_, err := r.ReadMessage(tt.limit)
		var me *MessageError
		if !errors.As(err, &me) || me.Code != tt.code || !errors.Is(err, ErrBodyTooLarge) {
			t.Fatalf("%s: err = %v, want %d", tt.method, err, tt.code)
		}
		if next, err := r.ReadMessage(tt.limit); err != nil || next.TransactionID != "g00d" {
			t.Fatalf("%s: stream out of step: %v", tt.method, err)
		}
	}
}

func TestHeaderLimitIsConfigurable(t *testing.T) {
	in := wire("MSRP abcd 200 OK", "To-Path: "+fromURI, "From-Path: "+toURI, "-------abcd$")
	if _, err := NewReader(strings.NewReader(in), 40).ReadMessage(10); !errors.Is(err, ErrFraming) {
		t.Fatalf("err = %v, want ErrFraming", err)
	}
	if _, err := NewReader(strings.NewReader(in), len(in)).ReadMessage(10); err != nil {
		t.Fatalf("a header section exactly at the limit: %v", err)
	}
}

func TestMarshalAndReadMessageRoundTrip(t *testing.T) {
	to, from := mustURI(t, toURI), mustURI(t, fromURI)
	msgs := []*Message{
		{TransactionID: "r0und1", Method: MethodSend, ToPath: []URI{to}, FromPath: []URI{from, to},
			MessageID: "msg1", ByteRange: &ByteRange{Start: 1, End: Unknown, Total: Unknown},
			SuccessReport: ReportYes, FailureReport: ReportPartial,
			Header:      []Field{{"Content-ID", "<p1@client.example.com>"}, {"X-Ext", "v"}},
			ContentType: "message/cpim", Body: BodyOf([]byte("To: <sip:x@example.com>\r\n\r\n-------r0und2$\r\n")), Continuation: FlagMore},
		{TransactionID: "r0und1", Method: MethodSend, ToPath: []URI{to}, FromPath: []URI{from},
			MessageID: "msg1", ByteRange: &ByteRange{Start: 1, End: 0, Total: 0}},
		{TransactionID: "r0und1", Method: MethodReport, ToPath: []URI{to}, FromPath: []URI{from},
			MessageID: "msg1", ByteRange: &ByteRange{Start: 1, End: 5, Total: 5}, Status: &Status{Code: 413, Comment: "Message Too Large"}},
		{TransactionID: "r0und1", StatusCode: 200, Comment: "OK", ToPath: []URI{from}, FromPath: []URI{to}},
		{TransactionID: "r0und1", StatusCode: 506, ToPath: []URI{from}, FromPath: []URI{to}},
	}
	for _, want := range msgs {
		b, err := want.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		got := readOne(t, string(b))
		again, err := got.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, again) {
			t.Fatalf("round trip changed the message:\n%s\n%s", b, again)
		}
		if got.flag() != want.flag() || !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
			t.Fatalf("flag or body changed")
		}
		var sb strings.Builder
		if n, err := want.WriteTo(&sb); err != nil || n != int64(len(b)) || sb.String() != string(b) {
			t.Fatalf("WriteTo = %d, %v", n, err)
		}
	}
}

func TestMarshalPutsMIMEHeadersAfterTheOthersAndContentTypeLast(t *testing.T) {
	m := &Message{TransactionID: "0rder1", Method: MethodSend, ToPath: []URI{mustURI(t, toURI)},
		FromPath: []URI{mustURI(t, fromURI)}, MessageID: "msg1",
		Header:      []Field{{"Content-Disposition", "inline"}, {"X-Ext", "v"}},
		ContentType: "text/plain", Body: BodyOf([]byte("x"))}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	ext, disp, ct := strings.Index(s, "X-Ext"), strings.Index(s, "Content-Disposition"), strings.Index(s, "Content-Type")
	if ext >= disp || disp >= ct {
		t.Fatalf("header order wrong:\n%s", s)
	}
}

func TestMarshalRefusesMessagesThatBreakTheRules(t *testing.T) {
	to, from := []URI{mustURI(t, toURI)}, []URI{mustURI(t, fromURI)}
	base := func() *Message {
		return &Message{TransactionID: "v4lid1", Method: MethodSend, ToPath: to, FromPath: from, MessageID: "msg1"}
	}
	tests := map[string]func(m *Message){
		"bad transaction id":         func(m *Message) { m.TransactionID = "x" },
		"bad method":                 func(m *Message) { m.Method = "Send" },
		"no To-Path":                 func(m *Message) { m.ToPath = nil },
		"no From-Path":               func(m *Message) { m.FromPath = nil },
		"bad path URI":               func(m *Message) { m.ToPath = []URI{{Host: "a b", Transport: "tcp"}} },
		"bad Message-ID":             func(m *Message) { m.MessageID = "m" },
		"bad Byte-Range":             func(m *Message) { m.ByteRange = &ByteRange{Start: 0, End: 1, Total: 1} },
		"Success-Report partial":     func(m *Message) { m.SuccessReport = ReportPartial },
		"bad Status":                 func(m *Message) { m.Status = &Status{Code: 1000} },
		"bad flag":                   func(m *Message) { m.Continuation = '!' },
		"header injection":           func(m *Message) { m.Header = []Field{{"X-A", "v\r\nTo-Path: x"}} },
		"bad header name":            func(m *Message) { m.Header = []Field{{"X A", "v"}} },
		"typed header in Header":     func(m *Message) { m.Header = []Field{{"byte-range", "1-1/1"}} },
		"MIME header without body":   func(m *Message) { m.Header = []Field{{"Content-ID", "<a@b>"}} },
		"body without Content-Type":  func(m *Message) { m.Body = BodyOf([]byte("x")) },
		"bad Content-Type":           func(m *Message) { m.ContentType = "text"; m.Body = BodyOf([]byte("x")) },
		"end-line in the body":       func(m *Message) { m.ContentType = "text/plain"; m.Body = BodyOf([]byte("a\r\n-------v4lid1$\r\n")) },
		"chunked REPORT":             func(m *Message) { m.Method = MethodReport; m.Status = &Status{Code: 200}; m.Continuation = FlagMore },
		"REPORT without Status":      func(m *Message) { m.Method = MethodReport },
		"REPORT with Failure-Report": func(m *Message) { m.Method = MethodReport; m.Status = &Status{Code: 200}; m.FailureReport = ReportNo },
		"large non-SEND body": func(m *Message) {
			m.Method = MethodNickname
			m.ContentType = "text/plain"
			m.Body = BodyOf(bytes.Repeat([]byte("a"), maxNonSendBody+1))
		},
		"response with a body":    func(m *Message) { m.Method = ""; m.StatusCode = 200; m.ContentType = "text/plain" },
		"response continued":      func(m *Message) { m.Method = ""; m.StatusCode = 200; m.Continuation = FlagMore },
		"response code too large": func(m *Message) { m.Method = ""; m.StatusCode = 1000 },
	}
	for name, mutate := range tests {
		m := base()
		mutate(m)
		if _, err := m.Marshal(); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v, want ErrInvalidMessage", name, err)
		}
		if _, err := m.WriteTo(io.Discard); err == nil {
			t.Errorf("%s: WriteTo accepted it", name)
		}
	}
}

func TestReportModesAndRangesFormatAsOnTheWire(t *testing.T) {
	if ReportUnset.String() != "" || ReportPartial.String() != "partial" {
		t.Fatal("report mode text wrong")
	}
	if got := (ByteRange{Start: 3, End: Unknown, Total: Unknown}).String(); got != "3-*/*" {
		t.Fatalf("ByteRange = %q", got)
	}
	if got := (Status{Namespace: 0, Code: 200}).String(); got != "000 200" {
		t.Fatalf("Status = %q", got)
	}
	var m Message
	if m.Range() != wholeUnknown || m.FailureMode() != ReportYes || m.WantsSuccessReport() || m.MediaType() != "" {
		t.Fatal("absent headers do not take their §7.1.1 defaults")
	}
}
