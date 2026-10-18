package cpim

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	alice  = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"
	bob    = "sip:+15550100002@ims.mnc001.mcc001.3gppnetwork.org"
	carol  = "tel:+15550100003"
	imdnNS = "urn:ietf:params:imdn"
)

// crlf turns a readable multi-line literal into wire format.
func crlf(s string) []byte {
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

var chatMessage = crlf(`From: Alice <` + alice + `>
To: <` + bob + `>
DateTime: 2026-10-18T09:30:00+09:00
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: Kd3Pq8sXw2
imdn.Disposition-Notification: positive-delivery, display

Content-Type: text/plain;charset=UTF-8
Content-Length: 5

Hello`)

func mustParse(t *testing.T, data []byte) *Message {
	t.Helper()
	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestParseReadsEveryPartOfAChatMessage(t *testing.T) {
	m := mustParse(t, chatMessage)

	wantHeaders := []Header{
		{Name: "From", Value: "Alice <" + alice + ">"},
		{Name: "To", Value: "<" + bob + ">"},
		{Name: "DateTime", Value: "2026-10-18T09:30:00+09:00"},
		{Name: "NS", Value: "imdn <urn:ietf:params:imdn>"},
		{Name: "imdn.Message-ID", Value: "Kd3Pq8sXw2"},
		{Name: "imdn.Disposition-Notification", Value: "positive-delivery, display"},
	}
	if !reflect.DeepEqual(m.Headers, wantHeaders) {
		t.Errorf("Headers = %#v", m.Headers)
	}
	wantContent := []Field{
		{Name: "Content-Type", Value: "text/plain;charset=UTF-8"},
		{Name: "Content-Length", Value: "5"},
	}
	if !reflect.DeepEqual(m.ContentHeaders, wantContent) {
		t.Errorf("ContentHeaders = %#v", m.ContentHeaders)
	}
	if string(m.Body) != "Hello" {
		t.Errorf("Body = %q", m.Body)
	}

	from, err := m.From()
	if err != nil || from != (Address{Name: "Alice", URI: alice}) {
		t.Errorf("From() = %+v, %v", from, err)
	}
	to, err := m.To()
	if err != nil || !reflect.DeepEqual(to, []Address{{URI: bob}}) {
		t.Errorf("To() = %+v, %v", to, err)
	}
	dt, err := m.DateTime()
	if err != nil || !dt.Equal(time.Date(2026, 10, 18, 0, 30, 0, 0, time.UTC)) {
		t.Errorf("DateTime() = %v, %v", dt, err)
	}
	if id, ok := m.Get(imdnNS, "Message-ID"); !ok || id.Value != "Kd3Pq8sXw2" {
		t.Errorf("Get(imdn, Message-ID) = %+v, %v", id, ok)
	}
	if got := m.ContentType(); got != "text/plain;charset=UTF-8" {
		t.Errorf("ContentType() = %q", got)
	}
}

func TestParseThenMarshalReproducesMessageHeadersExactly(t *testing.T) {
	tests := map[string][]byte{
		"chat message": chatMessage,
		"parameters, escapes and extensions": crlf(`From: "Alice \"A\" Smith" <` + alice + `>
To: Bob <` + bob + `>
cc: <` + carol + `>
Subject: line one\nline two
Subject:;lang=ko;x="a b; c" 안녕하세요
NS: MyFeatures <mid:features@example.com>
Require: MyFeatures.VitalOption
MyFeatures.VitalOption: Confirmation-requested
MyFeatures.WackyOption: Use-silly-font

Content-Type: application/vnd.example+xml
Content-ID: <1234@example.com>

<body/>`),
		"empty body": crlf("From: <" + alice + ">\nTo: <" + bob + ">\n\nContent-Type: text/plain\n\n"),
		"binary body with CRLF inside": append(crlf("From: <"+alice+">\nTo: <"+bob+">\n\nContent-Type: application/octet-stream\n\n"),
			0x00, '\r', '\n', '\r', '\n', 0xff),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, data)
			out, err := m.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !bytes.Equal(out, data) {
				t.Errorf("Marshal() =\n%q\nwant\n%q", out, data)
			}
		})
	}
}

func TestMalformedMessagesAreRejectedWithACountableReason(t *testing.T) {
	const ok = "From: <" + alice + ">\nTo: <" + bob + ">\n"
	const content = "\nContent-Type: text/plain\n\nHi"
	tests := map[string]struct {
		data   []byte
		reason Reason
	}{
		"no line end at all":              {[]byte("From: <" + alice + ">"), ReasonFraming},
		"no empty line after headers":     {crlf(ok), ReasonFraming},
		"no empty line after content":     {crlf(ok + "\nContent-Type: text/plain"), ReasonFraming},
		"content headers missing":         {crlf(ok + "\nHi"), ReasonFraming},
		"continuation before any content": {crlf(ok + "\n Content-Type: text/plain\n\nHi"), ReasonFraming},
		"CRLF then LF":                    {[]byte("From: <" + alice + ">\r\nTo: <" + bob + ">\n\r\nContent-Type: text/plain\r\n\r\n"), ReasonLineEnding},
		"LF then CRLF":                    {[]byte("From: <" + alice + ">\nTo: <" + bob + ">\r\n\nContent-Type: text/plain\n\n"), ReasonLineEnding},
		"LF then CRLF in content":         {[]byte("From: <" + alice + ">\n\nContent-Type: text/plain\r\n\n"), ReasonLineEnding},
		"bare CR in header":               {crlf("Subject: a\rb\n" + content), ReasonLineEnding},
		"invalid UTF-8":                   {crlf("Subject: \xff\n" + content), ReasonEncoding},
		"tab inside a header value":       {crlf("Subject: a\tb\n" + content), ReasonControl},
		"tab inside parameters":           {crlf("Subject:;x=\"a\tb\" hi\n" + content), ReasonControl},
		"NUL in header":                   {crlf("Subject: a\x00\n" + content), ReasonControl},
		"control in content header":       {crlf(ok + "\nContent-Type: text/plain\x00\n\nHi"), ReasonControl},
		"header without colon":            {crlf("From <" + alice + ">\n" + content), ReasonHeaderName},
		"space in header name":            {crlf("Fr om: <" + alice + ">\n" + content), ReasonHeaderName},
		"separator in header name":        {crlf("Fr@m: x\n" + content), ReasonHeaderName},
		"two dots in header name":         {crlf("NS: a <urn:x:y>\na.b.c: x\n" + content), ReasonHeaderName},
		"empty prefix":                    {crlf(".Message-ID: x\n" + content), ReasonHeaderName},
		"leading white space":             {crlf(" From: <" + alice + ">\n" + content), ReasonHeaderName},
		"invalid content header name":     {crlf(ok + "\nContent Type: text/plain\n\nHi"), ReasonHeaderName},
		"parameter without value":         {crlf("Subject:;lang hi\n" + content), ReasonParameter},
		"parameter with empty value":      {crlf("Subject:;lang= hi\n" + content), ReasonParameter},
		"unterminated quoted parameter":   {crlf(`Subject:;x="a hi` + "\n" + content), ReasonParameter},
		"prefix used before declaration":  {crlf("imdn.Message-ID: x\nNS: imdn <urn:ietf:params:imdn>\n" + content), ReasonNamespace},
		"NS without angle brackets":       {crlf("NS: imdn urn:ietf:params:imdn\n" + content), ReasonNamespace},
		"NS with relative URI":            {crlf("NS: imdn <imdn>\n" + content), ReasonNamespace},
		"NS with fragment":                {crlf("NS: imdn <urn:x:y#z>\n" + content), ReasonNamespace},
		"NS with invalid prefix":          {crlf("NS: im/dn <urn:x:y>\n" + content), ReasonNamespace},
		"empty NS":                        {crlf("NS:\n" + content), ReasonNamespace},
		"no Content-Type":                 {crlf(ok + "\nContent-ID: <x@example.com>\n\nHi"), ReasonContentType},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tt.data)
			if !errors.Is(err, ErrMalformed) || ReasonOf(err) != tt.reason {
				t.Fatalf("Parse() error = %v (reason %q), want ErrMalformed with reason %q", err, ReasonOf(err), tt.reason)
			}
		})
	}
}

func TestErrorsNameTheLine(t *testing.T) {
	_, err := Parse(crlf("From: <" + alice + ">\nFr@m: x\n\nContent-Type: text/plain\n\n"))
	var e *Error
	if !errors.As(err, &e) || e.Line != 2 || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("Parse() error = %#v", err)
	}
	_, err = Parse(crlf("From: <" + alice + ">\n\nContent-Type: text/plain\nContent Type: x\n\n"))
	if !errors.As(err, &e) || e.Line != 4 {
		t.Errorf("content header error = %#v", err)
	}
	if ReasonOf(errors.New("other")) != "" {
		t.Error("ReasonOf invented a reason for a foreign error")
	}
}

func TestLayoutDeviationsAreReadWithoutRewritingTheValue(t *testing.T) {
	tests := map[string]struct {
		data []byte
		want []Header
	}{
		"bare LF throughout": {
			[]byte("From: <" + alice + ">\nTo: <" + bob + ">\n\nContent-Type: text/plain\n\nHi\r\n"),
			[]Header{{Name: "From", Value: "<" + alice + ">"}, {Name: "To", Value: "<" + bob + ">"}},
		},
		"no space after the colon": {
			crlf("From:<" + alice + ">\nSubject:;lang=fr Bonjour\n\nContent-Type: text/plain\n\nHi"),
			[]Header{{Name: "From", Value: "<" + alice + ">"}, {Name: "Subject", Params: ";lang=fr", Value: "Bonjour"}},
		},
		"several spaces and trailing white space": {
			crlf("From:   <" + alice + ">  \nSubject: hi\t\n\nContent-Type: text/plain\n\nHi"),
			[]Header{{Name: "From", Value: "<" + alice + ">"}, {Name: "Subject", Value: "hi"}},
		},
		"empty values": {
			crlf("Subject:\nNS: imdn <urn:ietf:params:imdn>\nimdn.Disposition-Notification: \n\nContent-Type: text/plain\n\nHi"),
			[]Header{{Name: "Subject"}, {Name: "NS", Value: "imdn <urn:ietf:params:imdn>"}, {Name: "imdn.Disposition-Notification"}},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, tt.data)
			if !reflect.DeepEqual(m.Headers, tt.want) {
				t.Errorf("Headers = %#v", m.Headers)
			}
			if m.ContentType() != "text/plain" {
				t.Errorf("ContentType() = %q", m.ContentType())
			}
		})
	}
	m := mustParse(t, []byte("From: <"+alice+">\n\nContent-Type: text/plain\n\nline\r\nend\n"))
	if string(m.Body) != "line\r\nend\n" {
		t.Errorf("Body = %q; the body is never touched", m.Body)
	}
	out, err := m.Marshal()
	if err != nil || !bytes.HasPrefix(out, crlf("From: <"+alice+">\n\nContent-Type: text/plain\n\n")) {
		t.Errorf("Marshal() = %q, %v; Marshal always writes CRLF", out, err)
	}
}

func TestMarshalRefusesEmptyValuesParseAccepted(t *testing.T) {
	m := mustParse(t, crlf("Subject:\n\nContent-Type: text/plain\n\n"))
	if _, err := m.Marshal(); ReasonOf(err) != ReasonValue {
		t.Errorf("Marshal() error = %v, want a value error", err)
	}
}

func TestInvalidCoreValuesAreLeftToTheAccessors(t *testing.T) {
	m := mustParse(t, crlf(`From: `+alice+`
To: <`+bob+`>
cc: Smith, Carol <`+carol+`>
DateTime: 18 Oct 2026
Require: a b

Content-Type: text/plain

Hi`))
	if _, err := m.From(); ReasonOf(err) != ReasonValue {
		t.Errorf("From() error = %v", err)
	}
	if to, err := m.To(); err != nil || to[0].URI != bob {
		t.Errorf("To() = %v, %v; a valid header is unaffected by invalid neighbours", to, err)
	}
	if _, err := m.Cc(); ReasonOf(err) != ReasonValue {
		t.Errorf("Cc() error = %v", err)
	}
	if _, err := m.DateTime(); ReasonOf(err) != ReasonValue {
		t.Errorf("DateTime() error = %v", err)
	}
	if _, err := m.Marshal(); ReasonOf(err) != ReasonValue {
		t.Errorf("Marshal() error = %v; sending stays strict", err)
	}
}

func TestErrorsDoNotQuoteTheInput(t *testing.T) {
	const content = "\nContent-Type: text/plain\n\n"
	tests := map[string][]byte{
		"invalid From":                  crlf("From: " + alice + "\n" + content),
		"invalid To":                    crlf("To: <sip:+15550100001 x>\n" + content),
		"identifier-shaped header name": crlf("+15550100001: a\x01\n" + content),
		"identifier-shaped empty value": crlf("+15550100001:\n" + content),
		"identifier-shaped prefix":      crlf("+15550100001.x: v\n" + content),
		"invalid header name":           crlf("+15550100001 x: v\n" + content),
		"invalid NS":                    crlf("NS: +15550100001 urn:x\n" + content),
		"invalid DateTime":              crlf("DateTime: +15550100001\n" + content),
		"invalid Require":               crlf("Require: +15550100001 x\n" + content),
		"control in content header":     crlf("From: <" + alice + ">\n\n+15550100001: a\x01\n\n"),
		"invalid content header name":   crlf("From: <" + alice + ">\n\n+15550100001 x: a\n\n"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			// Parse rejects some of these; the rest are accepted and fail in
			// the accessors or in Marshal, whose errors must be as clean.
			var errs []error
			m, err := Parse(data)
			if err != nil {
				errs = append(errs, err)
			} else {
				_, e1 := m.From()
				_, e2 := m.To()
				_, e3 := m.DateTime()
				_, e4 := m.Marshal()
				errs = append(errs, e1, e2, e3, e4)
			}
			failed := false
			for _, err := range errs {
				if err == nil {
					continue
				}
				failed = true
				if strings.Contains(err.Error(), "15550100001") {
					t.Errorf("error %q quotes the input", err)
				}
			}
			if !failed {
				t.Fatal("no step rejected the input")
			}
		})
	}
	bad := &Message{
		Headers:        []Header{{Name: "From", Value: "<" + alice + ">"}},
		ContentHeaders: []Field{{Name: "+15550100001", Value: " padded"}},
	}
	if _, err := bad.Marshal(); err == nil || strings.Contains(err.Error(), "15550100001") {
		t.Errorf("Marshal() error = %v", err)
	}
}

// foldedHeaders returns a message whose single content header is folded over
// continuation lines until the content header section is size bytes long.
func foldedHeaders(size int) []byte {
	head := crlf("From: <" + alice + ">\n\nContent-Type: text/plain;\n")
	fold := []byte(" x=y;\r\n")
	section := make([]byte, 0, size+len(head))
	section = append(section, head...)
	for len(section)+len(fold)+2 <= size+len(head)-len("From: <"+alice+">\r\n\r\n") {
		section = append(section, fold...)
	}
	return append(section, "\r\nbody"...)
}

func TestContentHeaderLimitsCountEveryLineAndByte(t *testing.T) {
	if _, err := Parse(foldedHeaders(DefaultMaxContentHeaderSize + 64)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a content header section over the default size: %v, want ErrTooLarge", err)
	}
	if _, err := (Limits{MaxContentHeaderSize: 1 << 20}).Parse(foldedHeaders(1024)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("more continuation lines than MaxHeaders: %v, want ErrTooLarge", err)
	}
	m, err := (Limits{MaxHeaders: 1 << 20}).Parse(foldedHeaders(DefaultMaxContentHeaderSize - 64))
	if err != nil {
		t.Fatalf("a section within the limits: %v", err)
	}
	if !strings.HasPrefix(m.ContentType(), "text/plain; x=y;") {
		t.Errorf("ContentType() = %.40q", m.ContentType())
	}
}

// TestFoldedContentHeadersCostLinearTime guards against joining continuation
// lines by repeated concatenation, which made a 1 MiB message cost gigabytes
// of allocation. With every limit raised to admit the worst case, parsing must
// allocate a small multiple of the input; the time bound is two orders of
// magnitude above what a linear parse takes, so it cannot flake.
func TestFoldedContentHeadersCostLinearTime(t *testing.T) {
	data := foldedHeaders(DefaultMaxSize - 64)
	l := Limits{MaxSize: DefaultMaxSize, MaxHeaders: DefaultMaxSize, MaxContentHeaderSize: DefaultMaxSize}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	m, err := l.Parse(data)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m.ContentType()); n < DefaultMaxSize/2 {
		t.Fatalf("ContentType is only %d bytes; the input did not exercise folding", n)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8*uint64(len(data)) {
		t.Errorf("parsing %d bytes allocated %d bytes", len(data), allocated)
	}
	if elapsed > 5*time.Second {
		t.Errorf("parsing %d bytes took %v", len(data), elapsed)
	}
}

func TestHeaderNamesAreCaseSensitive(t *testing.T) {
	m := mustParse(t, crlf("from: <"+alice+">\nTo: <"+bob+">\n\nContent-Type: text/plain\n\n"))
	if _, err := m.From(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("From() error = %v, want ErrMissingHeader for a lower-case from", err)
	}
	if h, ok := m.Get(CoreNamespace, "from"); !ok || h.Value != "<"+alice+">" {
		t.Errorf("the lower-case header is kept as an unknown header, got %+v %v", h, ok)
	}
}

func TestNamespacedHeadersResolveThroughWhateverPrefixTheSenderChose(t *testing.T) {
	m := mustParse(t, crlf(`NS: x <urn:ietf:params:imdn>
x.Message-ID: abc
NS: imdn <urn:example:other>
imdn.Message-ID: other

Content-Type: text/plain

`))
	all := m.All(imdnNS, "Message-ID")
	if len(all) != 1 || all[0].Value != "abc" {
		t.Errorf("All(imdn, Message-ID) = %+v", all)
	}
	if h, ok := m.Get("urn:example:other", "Message-ID"); !ok || h.Value != "other" {
		t.Errorf("Get(other, Message-ID) = %+v, %v", h, ok)
	}
}

func TestUnprefixedNSChangesTheDefaultNamespaceForLaterHeaders(t *testing.T) {
	m := mustParse(t, crlf(`From: <`+alice+`>
NS: <urn:example:wily>
runner-trap: set
From: <`+bob+`>

Content-Type: text/plain

`))
	if _, err := Parse(crlf("NS: <urn:example:wily>\ncpim.From: x\n\nContent-Type: text/plain\n\n")); !errors.Is(err, ErrMalformed) {
		t.Errorf("an undeclared cpim prefix should be rejected, got %v", err)
	}
	if h, ok := m.Get("urn:example:wily", "runner-trap"); !ok || h.Value != "set" {
		t.Errorf("runner-trap not found in the new default namespace: %+v %v", h, ok)
	}
	if h, ok := m.Get("urn:example:wily", "From"); !ok || h.Value != "<"+bob+">" {
		t.Errorf("a From after the default changed belongs to the new namespace: %+v %v", h, ok)
	}
	if got := m.All(CoreNamespace, HeaderFrom); len(got) != 1 || got[0].Value != "<"+alice+">" {
		t.Errorf("core From headers = %+v, want only the one before NS", got)
	}
}

func TestAPrefixBoundToTheCoreNamespaceWorksAfterTheDefaultChanges(t *testing.T) {
	m := mustParse(t, crlf(`NS: cpim <urn:ietf:params:cpim-headers:>
NS: <urn:example:wily>
cpim.From: <`+alice+`>

Content-Type: text/plain

`))
	from, err := m.From()
	if err != nil || from.URI != alice {
		t.Errorf("From() = %+v, %v", from, err)
	}
}

func TestUnknownHeadersArePreservedInOrder(t *testing.T) {
	data := crlf(`X-First: 1
NS: ext <urn:example:ext>
ext.Second: 2
From: <` + alice + `>
ext.Second: 3

Content-Type: text/plain

`)
	m := mustParse(t, data)
	var names []string
	for _, h := range m.Headers {
		names = append(names, h.Name+"="+h.Value)
	}
	want := "X-First=1,NS=ext <urn:example:ext>,ext.Second=2,From=<" + alice + ">,ext.Second=3"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("headers = %s\nwant %s", got, want)
	}
	if got := m.All("urn:example:ext", "Second"); len(got) != 2 || got[1].Value != "3" {
		t.Errorf("All(ext, Second) = %+v", got)
	}
}

func TestHeaderParametersAreKeptAndReadable(t *testing.T) {
	m := mustParse(t, crlf(`Subject:;lang=fr;note="a \"b\"; c" Bonjour

Content-Type: text/plain

`))
	h, _ := m.Get(CoreNamespace, HeaderSubject)
	if h.Params != `;lang=fr;note="a \"b\"; c"` || h.Value != "Bonjour" {
		t.Fatalf("Subject = %+v", h)
	}
	if v, ok := h.Param("lang"); !ok || v != "fr" {
		t.Errorf("Param(lang) = %q, %v", v, ok)
	}
	if v, ok := h.Param("note"); !ok || v != `a "b"; c` {
		t.Errorf("Param(note) = %q, %v", v, ok)
	}
	if _, ok := h.Param("missing"); ok {
		t.Error("Param(missing) reported a value")
	}
	if _, ok := (Header{Params: ";broken"}).Param("broken"); ok {
		t.Error("Param on malformed parameters reported a value")
	}
}

func TestFoldedContentHeadersAreUnfolded(t *testing.T) {
	m := mustParse(t, crlf("From: <"+alice+">\n\nContent-Type: multipart/mixed;\n\tboundary=\"imdn-boundary\"\nContent-Disposition: notification\n\n"))
	if got := m.ContentType(); got != "multipart/mixed;\tboundary=\"imdn-boundary\"" {
		t.Errorf("ContentType() = %q", got)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	again := mustParse(t, out)
	if !reflect.DeepEqual(again, m) {
		t.Errorf("unfolded message does not round-trip: %#v", again)
	}
}

func TestContentHeaderNamesAreCaseInsensitive(t *testing.T) {
	m := mustParse(t, crlf("From: <"+alice+">\n\ncontent-type:   text/plain  \nCONTENT-disposition: notification\n\n"))
	if got := m.ContentType(); got != "text/plain" {
		t.Errorf("ContentType() = %q", got)
	}
	if v, ok := m.ContentHeader("Content-Disposition"); !ok || v != "notification" {
		t.Errorf("ContentHeader(Content-Disposition) = %q, %v", v, ok)
	}
	if _, ok := m.ContentHeader("Content-ID"); ok {
		t.Error("ContentHeader reported an absent header")
	}
}

func TestLimitsBoundWhatParseAccepts(t *testing.T) {
	headers := func(n int) string {
		return strings.Repeat("X-H: v\n", n)
	}
	tests := []struct {
		name   string
		limits Limits
		data   []byte
	}{
		{"body beyond the default size", Limits{}, append(crlf("From: <"+alice+">\n\nContent-Type: text/plain\n\n"), make([]byte, DefaultMaxSize)...)},
		{"body beyond a configured size", Limits{MaxSize: 64}, append(crlf("From: <"+alice+">\n\nContent-Type: text/plain\n\n"), make([]byte, 64)...)},
		{"too many message headers", Limits{}, crlf(headers(DefaultMaxHeaders+1) + "\nContent-Type: text/plain\n\n")},
		{"too many content header lines", Limits{MaxHeaders: 2}, crlf("From: <" + alice + ">\n\nContent-Type: text/plain\n" + headers(2) + "\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.limits.Parse(tt.data); !errors.Is(err, ErrTooLarge) {
				t.Errorf("Parse() error = %v, want ErrTooLarge", err)
			}
		})
	}
	if _, err := (Limits{MaxHeaders: DefaultMaxHeaders + 1}).Parse(crlf(headers(DefaultMaxHeaders+1) + "\nContent-Type: text/plain\n\n")); err != nil {
		t.Errorf("a raised header limit is honoured: %v", err)
	}
}

func TestMarshalRefusesWhatParseWouldReject(t *testing.T) {
	valid := func() *Message {
		return &Message{
			Headers:        []Header{{Name: HeaderFrom, Value: "<" + alice + ">"}},
			ContentHeaders: []Field{{Name: "Content-Type", Value: "text/plain"}},
		}
	}
	tests := map[string]func(m *Message){
		"line break in a value":           func(m *Message) { m.Headers[0].Value = "<" + alice + ">\r\nTo: <" + bob + ">" },
		"colon in a name":                 func(m *Message) { m.Headers[0].Name = "Fr:om" },
		"empty value":                     func(m *Message) { m.Headers[0].Value = "" },
		"parameters without a semicolon":  func(m *Message) { m.Headers[0].Params = "lang=en" },
		"space inside parameters":         func(m *Message) { m.Headers[0].Params = ";lang=en x" },
		"invalid From":                    func(m *Message) { m.Headers[0].Value = alice },
		"undeclared prefix":               func(m *Message) { m.Headers[0].Name = "imdn.Message-ID" },
		"line break in a content header":  func(m *Message) { m.ContentHeaders[0].Value = "text/plain\r\nX: y" },
		"white space around content":      func(m *Message) { m.ContentHeaders[0].Value = " text/plain" },
		"invalid content header name":     func(m *Message) { m.ContentHeaders[0].Name = "Content Type" },
		"no Content-Type":                 func(m *Message) { m.ContentHeaders[0].Name = "Content-ID" },
		"invalid UTF-8 in content header": func(m *Message) { m.ContentHeaders[0].Value = "text/\xff" },
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			m := valid()
			breakIt(m)
			if _, err := m.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("Marshal() error = %v, want ErrMalformed", err)
			}
		})
	}
	if _, err := valid().Marshal(); err != nil {
		t.Errorf("the unbroken message marshals: %v", err)
	}
}

func TestBuildingAMessageWithAnExtensionNamespace(t *testing.T) {
	m := &Message{}
	if err := m.Add(imdnNS, "Message-ID", "abc"); !errors.Is(err, ErrUndeclaredNamespace) {
		t.Fatalf("Add before Declare: %v", err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(m.Add(CoreNamespace, HeaderFrom, Address{Name: "Alice", URI: alice}.String()))
	must(m.Add(CoreNamespace, HeaderTo, Address{URI: bob}.String()))
	must(m.Add(CoreNamespace, HeaderDateTime, FormatDateTime(time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC))))
	must(m.Declare("imdn", imdnNS))
	must(m.Declare("other", imdnNS))
	must(m.Add(imdnNS, "Message-ID", "abc"))
	m.ContentHeaders = []Field{{Name: "Content-Type", Value: "text/plain"}}
	m.Body = []byte("Hi")

	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := crlf(`From: Alice <` + alice + `>
To: <` + bob + `>
DateTime: 2026-10-18T09:30:00Z
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: abc

Content-Type: text/plain

Hi`)
	if !bytes.Equal(out, want) {
		t.Errorf("Marshal() =\n%s\nwant\n%s", out, want)
	}
}

func TestDeclareWithAnEmptyPrefixChangesTheDefaultNamespace(t *testing.T) {
	m := &Message{}
	if err := m.Declare("", "urn:example:wily"); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("urn:example:wily", "runner-trap", "set"); err != nil {
		t.Fatal(err)
	}
	if got := m.Headers[len(m.Headers)-1].Name; got != "runner-trap" {
		t.Errorf("header name = %q, want it unprefixed", got)
	}
	if err := m.Add(CoreNamespace, HeaderFrom, "<"+alice+">"); !errors.Is(err, ErrUndeclaredNamespace) {
		t.Errorf("core headers cannot be added once the default changed: %v", err)
	}
	if err := m.Declare("imdn", imdnNS); !errors.Is(err, ErrUndeclaredNamespace) {
		t.Errorf("an NS header cannot be written once the default changed: %v", err)
	}
}

func TestDeclareWritesNSThroughACorePrefixOnceTheDefaultChanged(t *testing.T) {
	m := &Message{Headers: []Header{
		{Name: HeaderNS, Value: "cpim <" + CoreNamespace + ">"},
		{Name: HeaderNS, Value: "<urn:example:wily>"},
	}}
	if err := m.Declare("imdn", imdnNS); err != nil {
		t.Fatal(err)
	}
	if got := m.Headers[2]; got.Name != "cpim.NS" {
		t.Errorf("NS header written as %q", got.Name)
	}
	if err := m.Add(imdnNS, "Message-ID", "abc"); err != nil {
		t.Errorf("the declaration took effect: %v", err)
	}
}

func TestDeclarePrefersTheSmallestOfSeveralPrefixes(t *testing.T) {
	m := &Message{Headers: []Header{
		{Name: HeaderNS, Value: "b <" + imdnNS + ">"},
		{Name: HeaderNS, Value: "a <" + imdnNS + ">"},
	}}
	if err := m.Add(imdnNS, "Message-ID", "x"); err != nil {
		t.Fatal(err)
	}
	if got := m.Headers[2].Name; got != "a.Message-ID" {
		t.Errorf("name = %q", got)
	}
}

func TestDeclareRejectsInvalidPrefixesAndNamespaces(t *testing.T) {
	for _, tt := range []struct{ prefix, ns string }{
		{"im dn", imdnNS},
		{"imdn", "not-a-uri"},
		{"imdn", "urn:x:y#frag"},
	} {
		if err := (&Message{}).Declare(tt.prefix, tt.ns); !errors.Is(err, ErrMalformed) {
			t.Errorf("Declare(%q, %q) = %v, want ErrMalformed", tt.prefix, tt.ns, err)
		}
	}
}

func TestAddressAccessorsReportMissingAndInvalidHeaders(t *testing.T) {
	m := &Message{}
	if _, err := m.From(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("From() = %v", err)
	}
	if _, err := m.To(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("To() = %v", err)
	}
	if _, err := m.DateTime(); !errors.Is(err, ErrMissingHeader) {
		t.Errorf("DateTime() = %v", err)
	}
	if cc, err := m.Cc(); err != nil || cc != nil {
		t.Errorf("Cc() = %v, %v; cc is optional", cc, err)
	}

	// A constructed message is not validated until Marshal, so the accessors
	// check what they read.
	bad := &Message{Headers: []Header{
		{Name: HeaderFrom, Value: "nobody"},
		{Name: HeaderTo, Value: "nobody"},
		{Name: HeaderCc, Value: "nobody"},
		{Name: HeaderDateTime, Value: "yesterday"},
	}}
	if _, err := bad.From(); !errors.Is(err, ErrMalformed) {
		t.Errorf("From() = %v", err)
	}
	if _, err := bad.To(); !errors.Is(err, ErrMalformed) {
		t.Errorf("To() = %v", err)
	}
	if _, err := bad.Cc(); !errors.Is(err, ErrMalformed) {
		t.Errorf("Cc() = %v", err)
	}
	if _, err := bad.DateTime(); !errors.Is(err, ErrMalformed) {
		t.Errorf("DateTime() = %v", err)
	}
}

func TestEveryRecipientIsReturnedInOrder(t *testing.T) {
	m := mustParse(t, crlf("To: <"+alice+">\nTo: Bob <"+bob+">\ncc: <"+carol+">\n\nContent-Type: text/plain\n\n"))
	to, err := m.To()
	if err != nil || !reflect.DeepEqual(to, []Address{{URI: alice}, {Name: "Bob", URI: bob}}) {
		t.Errorf("To() = %+v, %v", to, err)
	}
	cc, err := m.Cc()
	if err != nil || !reflect.DeepEqual(cc, []Address{{URI: carol}}) {
		t.Errorf("Cc() = %+v, %v", cc, err)
	}
}

func TestDateTimeAcceptsEveryRFC3339Form(t *testing.T) {
	want := time.Date(2026, 10, 18, 0, 30, 0, 0, time.UTC)
	for _, v := range []string{
		"2026-10-18T00:30:00Z",
		"2026-10-18T09:30:00.250+09:00",
		"2026-10-17T19:30:00-05:00",
		"2026-10-18t00:30:00z",
		"2026-10-18t09:30:00+09:00",
	} {
		m := mustParse(t, crlf("DateTime: "+v+"\n\nContent-Type: text/plain\n\n"))
		got, err := m.DateTime()
		if err != nil || !got.Truncate(time.Second).Equal(want) {
			t.Errorf("DateTime(%s) = %v, %v", v, got, err)
		}
		if h, _ := m.Get(CoreNamespace, HeaderDateTime); h.Value != v {
			t.Errorf("raw DateTime = %q, want %q kept verbatim", h.Value, v)
		}
	}
	leap, err := ParseDateTime("2016-12-31T23:59:60Z")
	if err != nil || !leap.Equal(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("leap second = %v, %v", leap, err)
	}
	if leap, err := ParseDateTime("2016-12-31t23:59:60.5z"); err != nil || !leap.Equal(time.Date(2017, 1, 1, 0, 0, 0, 5e8, time.UTC)) {
		t.Errorf("fractional leap second = %v, %v", leap, err)
	}
	for _, v := range []string{"", "2026-10-18", "2026-10-18T00:61:00Z", "2026-10-18T00:30:00", "2026-10-18 00:30:00Z"} {
		if _, err := ParseDateTime(v); ReasonOf(err) != ReasonValue {
			t.Errorf("ParseDateTime(%q) error = %v", v, err)
		}
	}
}

func TestAddFirstPutsTheNewHeaderOnTop(t *testing.T) {
	const route = "IMDN-Record-Route"
	m := &Message{Headers: []Header{
		{Name: HeaderNS, Value: "x <" + imdnNS + ">"},
		{Name: "x.Message-ID", Value: "abc"},
		{Name: "x." + route, Value: "<sip:first@example.com>"},
		{Name: HeaderNS, Value: "imdn <" + imdnNS + ">"},
		{Name: "imdn." + route, Value: "<sip:second@example.com>"},
	}}
	if err := m.AddFirst(imdnNS, route, "<sip:new@example.com>"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range m.All(imdnNS, route) {
		got = append(got, h.Value)
	}
	if want := "<sip:new@example.com>,<sip:first@example.com>,<sip:second@example.com>"; strings.Join(got, ",") != want {
		t.Errorf("routes = %v", got)
	}
	if m.Headers[2].Name != "x."+route {
		t.Errorf("inserted header = %+v; it takes the prefix in force where it goes", m.Headers[2])
	}

	empty := &Message{}
	if err := empty.AddFirst(imdnNS, route, "<sip:a@example.com>"); !errors.Is(err, ErrUndeclaredNamespace) {
		t.Errorf("AddFirst without a declaration: %v", err)
	}
	_ = empty.Declare("imdn", imdnNS)
	if err := empty.AddFirst(imdnNS, route, "<sip:a@example.com>"); err != nil || empty.Headers[1].Name != "imdn."+route {
		t.Errorf("AddFirst with no existing header appends: %+v, %v", empty.Headers, err)
	}
}

func TestParsedMessageDoesNotAliasTheInput(t *testing.T) {
	data := bytes.Clone(chatMessage)
	m := mustParse(t, data)
	for i := range data {
		data[i] = 'x'
	}
	if string(m.Body) != "Hello" || m.Headers[0].Name != "From" {
		t.Errorf("message changed with its input: %q", m.Body)
	}
}
