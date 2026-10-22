package imdn

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
)

// sentAt is the DateTime of the reported message as its sender wrote it,
// with a fraction an RFC3339Nano round trip would rewrite.
const sentAt = "2026-10-18T09:30:00.250+09:00"

func TestParseNotificationReadsEveryElement(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<imdn xmlns="urn:ietf:params:xml:ns:imdn">
  <message-id>Kd3Pq8sXw2</message-id>
  <datetime>2026-10-18T09:30:00.250+09:00</datetime>
  <recipient-uri>` + bob + `</recipient-uri>
  <original-recipient-uri>` + focus + `</original-recipient-uri>
  <subject xml:lang="ko">점심 &amp; 회의</subject>
  <delivery-notification>
    <status>
      <delivered/>
    </status>
  </delivery-notification>
</imdn>`
	n, err := ParseNotification([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := Notification{
		MessageID:            "Kd3Pq8sXw2",
		DateTime:             sentAt,
		RecipientURI:         bob,
		OriginalRecipientURI: focus,
		Subject:              "점심 & 회의",
		SubjectLang:          "ko",
		Kind:                 DeliveryNotification,
		Status:               Delivered,
	}
	if n != want {
		t.Errorf("ParseNotification() = %+v\nwant %+v", n, want)
	}
}

func TestMarshalWritesSchemaOrderWithOneNamespaceDeclaration(t *testing.T) {
	n := Notification{
		MessageID:            "Kd3Pq8sXw2",
		DateTime:             sentAt,
		RecipientURI:         bob,
		OriginalRecipientURI: focus,
		Subject:              "a < b",
		SubjectLang:          "en-GB",
		Kind:                 DisplayNotification,
		Status:               Displayed,
	}
	out, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<imdn xmlns="urn:ietf:params:xml:ns:imdn">` +
		`<message-id>Kd3Pq8sXw2</message-id>` +
		`<datetime>2026-10-18T09:30:00.250+09:00</datetime>` +
		`<recipient-uri>` + bob + `</recipient-uri>` +
		`<original-recipient-uri>` + focus + `</original-recipient-uri>` +
		`<subject xml:lang="en-GB">a &lt; b</subject>` +
		`<display-notification><status><displayed></displayed></status></display-notification>` +
		`</imdn>`
	if string(out) != want {
		t.Errorf("Marshal() =\n%s\nwant\n%s", out, want)
	}
}

func TestEveryKindAndStatusRoundTrips(t *testing.T) {
	for kind, list := range statuses {
		for _, status := range list {
			n := Notification{MessageID: "id-1", DateTime: sentAt, Kind: kind, Status: status}
			out, err := n.Marshal()
			if err != nil {
				t.Fatalf("%s/%s: Marshal: %v", kind, status, err)
			}
			back, err := ParseNotification(out)
			if err != nil || back != n {
				t.Errorf("%s/%s: ParseNotification() = %+v, %v", kind, status, back, err)
			}
		}
	}
}

func TestDocumentTypeDeclarationsAreRejected(t *testing.T) {
	tests := map[string]string{
		"plain DOCTYPE": `<!DOCTYPE imdn><imdn xmlns="urn:ietf:params:xml:ns:imdn"/>`,
		"internal entity": `<?xml version="1.0"?><!DOCTYPE imdn [<!ENTITY id "abc">]>
<imdn xmlns="urn:ietf:params:xml:ns:imdn"><message-id>&id;</message-id></imdn>`,
		"external entity": `<!DOCTYPE imdn [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<imdn xmlns="urn:ietf:params:xml:ns:imdn"><subject>&x;</subject></imdn>`,
		"entity expansion": `<!DOCTYPE lolz [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<imdn xmlns="urn:ietf:params:xml:ns:imdn"><subject>&b;</subject></imdn>`,
		"DOCTYPE after a comment": `<!-- c --><!DOCTYPE imdn SYSTEM "http://example.com/imdn.dtd"><imdn/>`,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNotification([]byte(doc)); !errors.Is(err, ErrDTD) {
				t.Errorf("ParseNotification() error = %v, want ErrDTD", err)
			}
		})
	}
}

const validBody = `<message-id>abc</message-id><datetime>2026-10-18T00:30:00Z</datetime>`

func doc(inner string) string {
	return `<imdn xmlns="urn:ietf:params:xml:ns:imdn">` + inner + `</imdn>`
}

func delivered(extra string) string {
	return `<delivery-notification><status><delivered/>` + extra + `</status></delivery-notification>`
}

func TestMalformedNotificationsAreRejected(t *testing.T) {
	tests := map[string]string{
		"not XML":                     "hello",
		"empty":                       "",
		"only a declaration":          `<?xml version="1.0"?>`,
		"unclosed root":               `<imdn xmlns="urn:ietf:params:xml:ns:imdn">`,
		"wrong namespace":             `<imdn xmlns="urn:example:other">` + validBody + delivered("") + `</imdn>`,
		"no namespace":                `<imdn>` + validBody + delivered("") + `</imdn>`,
		"wrong root":                  `<receipt xmlns="urn:ietf:params:xml:ns:imdn">` + validBody + delivered("") + `</receipt>`,
		"two roots":                   doc(validBody+delivered("")) + doc(validBody+delivered("")),
		"text after the root":         doc(validBody+delivered("")) + "junk",
		"undefined entity":            doc(`<message-id>&id;</message-id>`),
		"not UTF-8":                   `<?xml version="1.0" encoding="ISO-8859-1"?>` + doc(validBody+delivered("")),
		"repeated attribute":          `<imdn xmlns="urn:ietf:params:xml:ns:imdn" a="1" a="2">` + validBody + delivered("") + `</imdn>`,
		"nested too deep":             doc(validBody + delivered("") + `<x:e xmlns:x="urn:x">` + strings.Repeat("<x:e>", maxDepth) + strings.Repeat("</x:e>", maxDepth) + `</x:e>`),
		"missing message-id":          doc(`<datetime>2026-10-18T00:30:00Z</datetime>` + delivered("")),
		"two message-ids":             doc(`<message-id>a</message-id>` + validBody + delivered("")),
		"message-id with a space":     doc(`<message-id>a b</message-id><datetime>2026-10-18T00:30:00Z</datetime>` + delivered("")),
		"missing datetime":            doc(`<message-id>abc</message-id>` + delivered("")),
		"two datetimes":               doc(validBody + `<datetime>2026-10-18T00:30:00Z</datetime>` + delivered("")),
		"empty datetime":              doc(`<message-id>abc</message-id><datetime/>` + delivered("")),
		"two recipient-uris":          doc(validBody + `<recipient-uri>` + bob + `</recipient-uri><recipient-uri>` + bob + `</recipient-uri>` + delivered("")),
		"two original-recipient-uris": doc(validBody + `<original-recipient-uri>` + bob + `</original-recipient-uri><original-recipient-uri>` + bob + `</original-recipient-uri>` + delivered("")),
		"recipient-uri with a space":  doc(validBody + `<recipient-uri>sip:a b</recipient-uri>` + delivered("")),
		"two subjects":                doc(validBody + `<subject>a</subject><subject>b</subject>` + delivered("")),
		"invalid subject language":    doc(validBody + `<subject xml:lang="not a tag">a</subject>` + delivered("")),
		"no notification element":     doc(validBody),
		"two notification elements":   doc(validBody + delivered("") + `<display-notification><status><displayed/></status></display-notification>`),
		"two delivery elements":       doc(validBody + delivered("") + delivered("")),
		"no status":                   doc(validBody + `<delivery-notification/>`),
		"two statuses":                doc(validBody + `<delivery-notification><status><delivered/></status><status><failed/></status></delivery-notification>`),
		"empty status":                doc(validBody + `<delivery-notification><status/></delivery-notification>`),
		"two status values":           doc(validBody + delivered(`<failed/>`)),
		"status of another kind":      doc(validBody + `<display-notification><status><delivered/></status></display-notification>`),
		"unknown status":              doc(validBody + `<processing-notification><status><lost/></status></processing-notification>`),
		"unqualified status":          doc(validBody + `<delivery-notification><status><delivered xmlns=""/></status></delivery-notification>`),
	}
	for name, d := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNotification([]byte(d)); !errors.Is(err, ErrMalformed) {
				t.Errorf("ParseNotification() error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestExtensionElementsAreIgnored(t *testing.T) {
	d := `<imdn xmlns="urn:ietf:params:xml:ns:imdn" xmlns:x="urn:example:ext">` +
		`<x:message-id>not-this-one</x:message-id>` + validBody + `<x:note>kept out</x:note>` +
		`<delivery-notification><status><x:reason code="1"/><failed/></status></delivery-notification>` +
		`<x:trailer/></imdn>`
	n, err := ParseNotification([]byte(d))
	if err != nil || n.MessageID != "abc" || n.Status != Failed {
		t.Errorf("ParseNotification() = %+v, %v", n, err)
	}
}

func TestWhiteSpaceAroundTokensAndURIsIsNotPartOfTheValue(t *testing.T) {
	d := doc("\n  <message-id>\n    abc\n  </message-id>\n  <datetime>2026-10-18T00:30:00Z</datetime>\n" +
		"  <recipient-uri> " + bob + " </recipient-uri>\n" + delivered("") + "\n")
	n, err := ParseNotification([]byte(d))
	if err != nil || n.MessageID != "abc" || n.RecipientURI != bob {
		t.Errorf("ParseNotification() = %+v, %v", n, err)
	}
}

func TestOversizedDocumentsAreRejectedBeforeDecoding(t *testing.T) {
	d := doc(validBody + delivered("") + "<!--" + strings.Repeat("x", MaxDocumentSize) + "-->")
	if _, err := ParseNotification([]byte(d)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ParseNotification() error = %v, want ErrTooLarge", err)
	}
}

func TestMarshalRejectsInvalidNotifications(t *testing.T) {
	valid := Notification{MessageID: "abc", DateTime: sentAt, Kind: DeliveryNotification, Status: Delivered}
	tests := map[string]func(n *Notification){
		"empty message-id":           func(n *Notification) { n.MessageID = "" },
		"message-id with a space":    func(n *Notification) { n.MessageID = "a b" },
		"message-id XML cannot hold": func(n *Notification) { n.MessageID = "a￾b" },
		"no datetime":                func(n *Notification) { n.DateTime = "" },
		"datetime XML cannot hold":   func(n *Notification) { n.DateTime = "2026\x00" },
		"recipient with a space":     func(n *Notification) { n.RecipientURI = "sip:a b" },
		"original with a newline":    func(n *Notification) { n.OriginalRecipientURI = "sip:a\nb" },
		"subject with a control":     func(n *Notification) { n.Subject = "a\x01" },
		"invalid language":           func(n *Notification) { n.Subject, n.SubjectLang = "s", "en_GB" },
		"empty language subtag":      func(n *Notification) { n.Subject, n.SubjectLang = "s", "en--GB" },
		"overlong language subtag":   func(n *Notification) { n.Subject, n.SubjectLang = "s", "languages" },
		"status of another kind":     func(n *Notification) { n.Status = Displayed },
		"unknown kind":               func(n *Notification) { n.Kind = "receipt" },
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			n := valid
			breakIt(&n)
			if _, err := n.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("Marshal() error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestRequestNotificationAnswersOnlyWhatWasAsked(t *testing.T) {
	r := Request{
		MessageID:    "Kd3Pq8sXw2",
		DateTime:     sentAt,
		Dispositions: NegativeDelivery | Display,
		OriginalTo:   cpim.Address{URI: focus},
	}
	n, err := r.Notification(DisplayNotification, Displayed, bob)
	want := Notification{MessageID: "Kd3Pq8sXw2", DateTime: sentAt, RecipientURI: bob, OriginalRecipientURI: focus, Kind: DisplayNotification, Status: Displayed}
	if err != nil || n != want {
		t.Errorf("Notification(display, displayed) = %+v, %v", n, err)
	}
	if _, err := r.Notification(DeliveryNotification, Delivered, bob); !errors.Is(err, ErrNotRequested) {
		t.Errorf("a positive delivery nobody asked for: %v", err)
	}
	if _, err := r.Notification(DeliveryNotification, Forbidden, bob); err != nil {
		t.Errorf("a negative delivery that was asked for: %v", err)
	}
	if _, err := (Request{Dispositions: Display}).Notification(DisplayNotification, Displayed, bob); !errors.Is(err, ErrMalformed) {
		t.Errorf("a request without Message-ID cannot be answered: %v", err)
	}
}

func displayed() Notification {
	return Notification{MessageID: "Kd3Pq8sXw2", DateTime: sentAt, RecipientURI: bob, Kind: DisplayNotification, Status: Displayed}
}

func envelope() Envelope {
	return Envelope{
		From:      cpim.Address{URI: bob},
		To:        cpim.Address{Name: "Alice", URI: alice},
		Route:     []cpim.Address{{URI: relay}, {URI: focus}},
		MessageID: "n0t1f1cat10n",
		DateTime:  time.Date(2026, 10, 18, 0, 31, 0, 0, time.UTC),
	}
}

func TestNotificationMessageWrapsTheDocumentInCPIM(t *testing.T) {
	m, err := displayed().Message(envelope())
	if err != nil {
		t.Fatal(err)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := displayed().Marshal()
	want := append(crlf(`From: <`+bob+`>
To: Alice <`+alice+`>
DateTime: 2026-10-18T00:31:00Z
NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: n0t1f1cat10n
imdn.IMDN-Route: <`+relay+`>
imdn.IMDN-Route: <`+focus+`>

Content-Type: message/imdn+xml
Content-Disposition: notification

`), body...)
	if !bytes.Equal(out, want) {
		t.Errorf("Marshal() =\n%s\nwant\n%s", out, want)
	}

	parsed, err := cpim.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !IsNotification(parsed) {
		t.Error("the wrapped message is not recognised as a notification")
	}
	n, err := ParseNotificationMessage(parsed)
	if err != nil || n != displayed() {
		t.Errorf("ParseNotificationMessage() = %+v, %v", n, err)
	}
	if r, err := ParseRequest(parsed); err != nil || r.Dispositions != 0 {
		t.Errorf("a notification asks for nothing: %+v, %v", r, err)
	}
}

func TestNotificationMessageRefusesAnInvalidEnvelope(t *testing.T) {
	tests := map[string]func(n *Notification, e *Envelope){
		"invalid notification":   func(n *Notification, _ *Envelope) { n.Status = Delivered },
		"Message-ID not a token": func(_ *Notification, e *Envelope) { e.MessageID = "a b" },
		"Message-ID reused":      func(n *Notification, e *Envelope) { e.MessageID = n.MessageID },
		"no DateTime":            func(_ *Notification, e *Envelope) { e.DateTime = time.Time{} },
		"DateTime after 9999":    func(_ *Notification, e *Envelope) { e.DateTime = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"no From":                func(_ *Notification, e *Envelope) { e.From = cpim.Address{} },
		"invalid To":             func(_ *Notification, e *Envelope) { e.To = cpim.Address{URI: "alice"} },
		"invalid route":          func(_ *Notification, e *Envelope) { e.Route[1].URI = "sip:a b" },
	}
	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			n, e := displayed(), envelope()
			breakIt(&n, &e)
			if _, err := n.Message(e); err == nil {
				t.Error("Message() succeeded")
			}
		})
	}
}

func TestParseNotificationMessageChecksTheContent(t *testing.T) {
	msg := func(ctype, disp string, body string) *cpim.Message {
		m := &cpim.Message{ContentHeaders: []cpim.Field{{Name: "Content-Type", Value: ctype}}, Body: content.BodyOf([]byte(body))}
		if disp != "" {
			m.ContentHeaders = append(m.ContentHeaders, cpim.Field{Name: "Content-Disposition", Value: disp})
		}
		return m
	}
	body, _ := displayed().Marshal()
	tests := []struct {
		name string
		m    *cpim.Message
		want error
	}{
		{"chat message", msg("text/plain", "", "hi"), ErrNotNotification},
		{"aggregated", msg(`multipart/mixed; boundary="imdn-boundary"`, "notification", ""), ErrUnsupported},
		{"wrong content type", msg("text/plain", "notification", "hi"), ErrMalformed},
		{"unreadable content type", msg("message/", "notification", "hi"), ErrMalformed},
		{"bad document", msg(ContentType, "notification", "<imdn/>"), ErrMalformed},
		{"content type parameters", msg("Message/IMDN+XML; charset=utf-8", "notification", string(body)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseNotificationMessage(tt.m)
			if !errors.Is(err, tt.want) || (tt.want == nil && err != nil) {
				t.Errorf("ParseNotificationMessage() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDatetimeIsKeptVerbatimAndInterpretedOnDemand(t *testing.T) {
	for _, v := range []string{"2026-10-18t00:30:00.000z", "18 Oct 2026", " 2026-10-18T00:30:00Z "} {
		n, err := ParseNotification([]byte(doc(`<message-id>abc</message-id><datetime>` + v + `</datetime>` + delivered(""))))
		if err != nil || n.DateTime != v {
			t.Fatalf("ParseNotification(%q) = %+v, %v; the receipt must survive with its datetime intact", v, n, err)
		}
		out, err := n.Marshal()
		if err != nil || !strings.Contains(string(out), "<datetime>"+v+"</datetime>") {
			t.Errorf("Marshal() = %s, %v; datetime must be echoed verbatim", out, err)
		}
	}
	n := Notification{DateTime: "2026-10-18t00:30:00z"}
	if got, err := n.Time(); err != nil || !got.Equal(time.Date(2026, 10, 18, 0, 30, 0, 0, time.UTC)) {
		t.Errorf("Time() = %v, %v", got, err)
	}
	if _, err := (Notification{DateTime: "18 Oct 2026"}).Time(); err == nil {
		t.Error("Time() parsed a non-RFC 3339 datetime")
	}
}

func TestAnUnparseableDateTimeIsEchoedNotRejected(t *testing.T) {
	m := mustCPIM(t, `NS: imdn <urn:ietf:params:imdn>
imdn.Message-ID: abc
DateTime: 2026-10-18t09:30:00.000+09:00
imdn.Disposition-Notification: display

Content-Type: text/plain

`)
	r, err := ParseRequest(m)
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.Notification(DisplayNotification, Displayed, bob)
	if err != nil {
		t.Fatal(err)
	}
	body, err := n.Marshal()
	if err != nil || !strings.Contains(string(body), "<datetime>2026-10-18t09:30:00.000+09:00</datetime>") {
		t.Errorf("Marshal() = %s, %v", body, err)
	}

	odd := mustCPIM(t, "NS: imdn <urn:ietf:params:imdn>\nimdn.Message-ID: abc\nDateTime: yesterday\nimdn.Disposition-Notification: display\n\nContent-Type: text/plain\n\n")
	r, err = ParseRequest(odd)
	if err != nil || r.DateTime != "yesterday" {
		t.Fatalf("ParseRequest() = %+v, %v", r, err)
	}
	if _, err := r.Time(); err == nil {
		t.Error("Time() parsed yesterday")
	}
	if _, err := r.Notification(DisplayNotification, Displayed, bob); err != nil {
		t.Errorf("the sender still gets its receipt: %v", err)
	}
}

func TestAByteOrderMarkIsAccepted(t *testing.T) {
	body, _ := displayed().Marshal()
	n, err := ParseNotification(append([]byte("\xef\xbb\xbf"), body...))
	if err != nil || n != displayed() {
		t.Errorf("ParseNotification(BOM + document) = %+v, %v", n, err)
	}
	if _, err := ParseNotification([]byte("\xef\xbb\xbf\xef\xbb\xbf" + string(body))); !errors.Is(err, ErrMalformed) {
		t.Errorf("two byte order marks: %v", err)
	}
}

func TestASubjectWithOnlyALanguageRoundTrips(t *testing.T) {
	n, err := ParseNotification([]byte(doc(validBody + `<subject xml:lang="en"></subject>` + delivered(""))))
	if err != nil || n.Subject != "" || n.SubjectLang != "en" {
		t.Fatalf("ParseNotification() = %+v, %v", n, err)
	}
	out, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := ParseNotification(out); err != nil || back != n {
		t.Errorf("round trip = %+v, %v", back, err)
	}
}

func TestXMLErrorsDoNotQuoteTheInput(t *testing.T) {
	const marker = "15550100001"
	tests := map[string]string{
		"entity reference":      doc(`<message-id>&sip:+` + marker + `;</message-id>`),
		"invalid element name":  doc(`<1` + marker + `/>`),
		"wrong root":            `<x` + marker + ` xmlns="urn:ietf:params:xml:ns:imdn"/>`,
		"mismatched end tag":    doc(`<a` + marker + `></b>`),
		"unknown encoding":      `<?xml version="1.0" encoding="x` + marker + `"?>` + doc(""),
		"unsupported version":   `<?xml version="+` + marker + `"?>` + doc(""),
		"repeated attribute":    `<a` + marker + ` x="1" x="2"/>`,
		"unknown status":        doc(validBody + `<delivery-notification><status><s` + marker + `/></status></delivery-notification>`),
		"message-id not token":  doc(`<message-id>+` + marker + ` x</message-id><datetime>d</datetime>` + delivered("")),
		"recipient with space":  doc(validBody + `<recipient-uri>sip:+` + marker + ` x</recipient-uri>` + delivered("")),
		"invalid character ref": doc(`<subject>&#x` + marker + `;</subject>`),
	}
	for name, d := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseNotification([]byte(d))
			if err == nil {
				t.Fatal("ParseNotification accepted the document")
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error %q quotes the input", err)
			}
		})
	}
	m := &cpim.Message{ContentHeaders: []cpim.Field{
		{Name: "Content-Type", Value: "application/x" + marker},
		{Name: "Content-Disposition", Value: "notification"},
	}}
	if _, err := ParseNotificationMessage(m); err == nil || strings.Contains(err.Error(), marker) {
		t.Errorf("ParseNotificationMessage() error = %v", err)
	}
}

func TestDateTimeLengthIsBoundedSoReceiptsStayReadable(t *testing.T) {
	long := strings.Repeat("9", MaxDateTimeLength+1)
	m := mustCPIM(t, "NS: imdn <urn:ietf:params:imdn>\nimdn.Message-ID: abc\nDateTime: "+long+"\nimdn.Disposition-Notification: display\n\nContent-Type: text/plain\n\n")
	if _, err := ParseRequest(m); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseRequest() error = %v, want ErrMalformed", err)
	}
	n := displayed()
	n.DateTime = long
	if _, err := n.Marshal(); !errors.Is(err, ErrMalformed) {
		t.Errorf("Marshal() error = %v, want ErrMalformed", err)
	}
	if _, err := ParseNotification([]byte(doc(`<message-id>abc</message-id><datetime>` + long + `</datetime>` + delivered("")))); !errors.Is(err, ErrMalformed) {
		t.Errorf("ParseNotification() error = %v, want ErrMalformed", err)
	}
	n.DateTime = strings.Repeat("9", MaxDateTimeLength)
	if _, err := n.Marshal(); err != nil {
		t.Errorf("a datetime of exactly %d bytes: %v", MaxDateTimeLength, err)
	}
}

func TestMarshalNeverWritesWhatParseWouldRefuse(t *testing.T) {
	n := displayed()
	n.Subject = strings.Repeat("s", MaxDocumentSize)
	if _, err := n.Marshal(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Marshal() error = %v, want ErrTooLarge", err)
	}
}

func TestTimeIgnoresWhiteSpaceAroundThePrettyPrintedValue(t *testing.T) {
	n, err := ParseNotification([]byte(doc("<message-id>abc</message-id><datetime>\n  2026-10-18T09:30:00Z\n</datetime>" + delivered(""))))
	if err != nil || n.DateTime != "\n  2026-10-18T09:30:00Z\n" {
		t.Fatalf("ParseNotification() = %q, %v; the raw value is kept", n.DateTime, err)
	}
	if got, err := n.Time(); err != nil || !got.Equal(time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)) {
		t.Errorf("Time() = %v, %v", got, err)
	}
}
