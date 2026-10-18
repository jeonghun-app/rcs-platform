package imdn

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
)

// XMLNamespace is the namespace of notification documents (RFC 5438 §11.1).
const XMLNamespace = "urn:ietf:params:xml:ns:imdn"

// xmlLangNamespace is the namespace encoding/xml gives the xml: prefix.
const xmlLangNamespace = "http://www.w3.org/XML/1998/namespace"

// Kind is the disposition type a notification reports, named by its element
// (RFC 5438 §11.1.6).
type Kind string

// The kinds RFC 5438 §11.1.6 defines.
const (
	DeliveryNotification   Kind = "delivery-notification"
	DisplayNotification    Kind = "display-notification"
	ProcessingNotification Kind = "processing-notification"
)

// Status is the outcome a notification reports, named by its element inside
// <status> (RFC 5438 §11.1.7).
type Status string

// The statuses RFC 5438 §11.1.7 defines. Forbidden means the disposition was
// denied and Error an internal error; both apply to every kind.
const (
	Delivered Status = "delivered"
	Failed    Status = "failed"
	Displayed Status = "displayed"
	Processed Status = "processed"
	Stored    Status = "stored"
	Forbidden Status = "forbidden"
	Error     Status = "error"
)

// statuses lists the statuses each kind may carry (RFC 5438 §11.1.7).
var statuses = map[Kind][]Status{
	DeliveryNotification:   {Delivered, Failed, Forbidden, Error},
	DisplayNotification:    {Displayed, Forbidden, Error},
	ProcessingNotification: {Processed, Stored, Forbidden, Error},
}

func (k Kind) allows(s Status) bool {
	return slices.Contains(statuses[k], s)
}

// Notification is one message/imdn+xml document.
type Notification struct {
	// MessageID is the Message-ID of the message being reported on, not of
	// the notification (RFC 5438 §11.1.1).
	MessageID string
	// DateTime is the DateTime of the message being reported on (§11.1.2).
	DateTime time.Time
	// RecipientURI is the final recipient; optional (§11.1.3).
	RecipientURI string
	// OriginalRecipientURI is the recipient named by Original-To; present
	// whenever the message carried that header (§11.1.4).
	OriginalRecipientURI string
	// Subject and SubjectLang echo a Subject header of the message; optional
	// (§11.1.5).
	Subject     string
	SubjectLang string
	Kind        Kind
	Status      Status
}

// Notification builds the notification of kind k and status s that answers r
// on behalf of recipient, or returns ErrNotRequested if the sender did not ask
// for it.
func (r Request) Notification(k Kind, s Status, recipient string) (Notification, error) {
	if !r.Dispositions.Wants(k, s) {
		return Notification{}, fmt.Errorf("%w: %s %s", ErrNotRequested, k, s)
	}
	n := Notification{
		MessageID:            r.MessageID,
		DateTime:             r.DateTime,
		RecipientURI:         recipient,
		OriginalRecipientURI: r.OriginalTo.URI,
		Kind:                 k,
		Status:               s,
	}
	return n, n.validate()
}

func (n Notification) validate() error {
	switch {
	case !cpim.IsToken(n.MessageID) || !isXMLText(n.MessageID):
		return fmt.Errorf("%w: message-id is not a token", ErrMalformed)
	case n.DateTime.IsZero() || n.DateTime.Year() > 9999 || n.DateTime.Year() < 0:
		return fmt.Errorf("%w: datetime missing or out of range", ErrMalformed)
	case !isURIText(n.RecipientURI) || !isURIText(n.OriginalRecipientURI):
		return fmt.Errorf("%w: recipient URI contains white space or invalid characters", ErrMalformed)
	case !isXMLText(n.Subject):
		return fmt.Errorf("%w: subject contains characters XML cannot carry", ErrMalformed)
	case n.SubjectLang != "" && (n.Subject == "" || !isLanguageTag(n.SubjectLang)):
		return fmt.Errorf("%w: subject language without subject or not a language tag", ErrMalformed)
	case !n.Kind.allows(n.Status):
		return fmt.Errorf("%w: status %q is not defined for %q", ErrMalformed, n.Status, n.Kind)
	}
	return nil
}

// isURIText reports whether s can be an anyURI value that survives a round
// trip; empty means absent.
func isURIText(s string) bool {
	return isXMLText(s) && !strings.ContainsAny(s, " \t\r\n")
}

// isLanguageTag checks the xs:language shape: alphanumeric subtags of one to
// eight characters joined by hyphens.
func isLanguageTag(s string) bool {
	for sub := range strings.SplitSeq(s, "-") {
		if len(sub) == 0 || len(sub) > 8 {
			return false
		}
		for i := 0; i < len(sub); i++ {
			c := sub[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
				return false
			}
		}
	}
	return true
}

// Marshal serializes n as a message/imdn+xml document in the element order of
// the RFC 5438 §11.1.9 schema.
func (n Notification) Marshal() ([]byte, error) {
	if err := n.validate(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString(xml.Header)
	w := &xmlWriter{e: xml.NewEncoder(&b)}
	// The namespace is declared once on the root; encoding/xml would repeat
	// it on every element if the names carried it.
	w.start("imdn", xml.Attr{Name: xml.Name{Local: "xmlns"}, Value: XMLNamespace})
	w.text("message-id", n.MessageID)
	w.text("datetime", n.DateTime.Format(time.RFC3339Nano))
	if n.RecipientURI != "" {
		w.text("recipient-uri", n.RecipientURI)
	}
	if n.OriginalRecipientURI != "" {
		w.text("original-recipient-uri", n.OriginalRecipientURI)
	}
	if n.Subject != "" {
		var attrs []xml.Attr
		if n.SubjectLang != "" {
			attrs = append(attrs, xml.Attr{Name: xml.Name{Space: xmlLangNamespace, Local: "lang"}, Value: n.SubjectLang})
		}
		w.start("subject", attrs...)
		w.chars(n.Subject)
		w.end("subject")
	}
	w.start(string(n.Kind))
	w.start("status")
	w.start(string(n.Status))
	w.end(string(n.Status))
	w.end("status")
	w.end(string(n.Kind))
	w.end("imdn")
	if err := w.close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// The wire types decode with namespace-qualified names, so an extension
// element that shares a local name with an IMDN element is never mistaken for
// it. Repeatable fields are slices so a duplicated element is detected rather
// than silently overwritten.
type wireIMDN struct {
	XMLName              xml.Name           `xml:"urn:ietf:params:xml:ns:imdn imdn"`
	MessageID            []string           `xml:"urn:ietf:params:xml:ns:imdn message-id"`
	DateTime             []string           `xml:"urn:ietf:params:xml:ns:imdn datetime"`
	RecipientURI         []string           `xml:"urn:ietf:params:xml:ns:imdn recipient-uri"`
	OriginalRecipientURI []string           `xml:"urn:ietf:params:xml:ns:imdn original-recipient-uri"`
	Subject              []wireSubject      `xml:"urn:ietf:params:xml:ns:imdn subject"`
	Delivery             []wireNotification `xml:"urn:ietf:params:xml:ns:imdn delivery-notification"`
	Display              []wireNotification `xml:"urn:ietf:params:xml:ns:imdn display-notification"`
	Processing           []wireNotification `xml:"urn:ietf:params:xml:ns:imdn processing-notification"`
}

type wireSubject struct {
	Lang string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Text string `xml:",chardata"`
}

type wireNotification struct {
	Status []wireStatus `xml:"urn:ietf:params:xml:ns:imdn status"`
}

type wireStatus struct {
	Children []struct {
		XMLName xml.Name
	} `xml:",any"`
}

// ParseNotification parses a message/imdn+xml document.
func ParseNotification(data []byte) (Notification, error) {
	if err := checkDocument(data); err != nil {
		return Notification{}, err
	}
	var w wireIMDN
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&w); err != nil {
		return Notification{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var n Notification
	var err error
	// message-id is an xs:token and the URIs are xs:anyURI, whose surrounding
	// white space is not part of the value; datetime is a plain string.
	if n.MessageID, err = one("message-id", w.MessageID, true); err != nil {
		return Notification{}, err
	}
	n.MessageID = strings.TrimSpace(n.MessageID)
	dt, err := one("datetime", w.DateTime, true)
	if err != nil {
		return Notification{}, err
	}
	if n.DateTime, err = time.Parse(time.RFC3339, dt); err != nil {
		return Notification{}, fmt.Errorf("%w: datetime is not an RFC 3339 date-time", ErrMalformed)
	}
	if n.RecipientURI, err = one("recipient-uri", w.RecipientURI, false); err != nil {
		return Notification{}, err
	}
	n.RecipientURI = strings.TrimSpace(n.RecipientURI)
	if n.OriginalRecipientURI, err = one("original-recipient-uri", w.OriginalRecipientURI, false); err != nil {
		return Notification{}, err
	}
	n.OriginalRecipientURI = strings.TrimSpace(n.OriginalRecipientURI)
	switch len(w.Subject) {
	case 0:
	case 1:
		n.Subject, n.SubjectLang = w.Subject[0].Text, w.Subject[0].Lang
	default:
		return Notification{}, fmt.Errorf("%w: more than one <subject>", ErrMalformed)
	}

	kinds := []struct {
		kind Kind
		els  []wireNotification
	}{
		{DeliveryNotification, w.Delivery},
		{DisplayNotification, w.Display},
		{ProcessingNotification, w.Processing},
	}
	var found []wireNotification
	for _, k := range kinds {
		if len(k.els) > 0 {
			n.Kind = k.kind
			found = append(found, k.els...)
		}
	}
	// §11.1.6: exactly one notification element.
	if len(found) != 1 {
		return Notification{}, fmt.Errorf("%w: need exactly one notification element, found %d", ErrMalformed, len(found))
	}
	if n.Status, err = parseStatus(found[0]); err != nil {
		return Notification{}, err
	}
	if err := n.validate(); err != nil {
		return Notification{}, err
	}
	return n, nil
}

// parseStatus finds the single status element. Elements of other namespaces
// are extensions and are skipped (§11.1.9); an unqualified or unknown IMDN
// element is not allowed there.
func parseStatus(el wireNotification) (Status, error) {
	if len(el.Status) != 1 {
		return "", fmt.Errorf("%w: need exactly one <status>", ErrMalformed)
	}
	var found []Status
	for _, c := range el.Status[0].Children {
		switch c.XMLName.Space {
		case XMLNamespace:
			found = append(found, Status(c.XMLName.Local))
		case "":
			return "", fmt.Errorf("%w: unqualified element in <status>", ErrMalformed)
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("%w: need exactly one status value, found %d", ErrMalformed, len(found))
	}
	return found[0], nil
}

// one returns the single value of an element that may appear at most once.
func one(name string, values []string, required bool) (string, error) {
	switch {
	case len(values) > 1:
		return "", fmt.Errorf("%w: more than one <%s>", ErrMalformed, name)
	case len(values) == 1:
		return values[0], nil
	case required:
		return "", fmt.Errorf("%w: <%s> is missing", ErrMalformed, name)
	}
	return "", nil
}

// Envelope addresses the CPIM message that carries a notification.
type Envelope struct {
	// From is whoever reports: the recipient, or an intermediary for
	// processing and negative delivery notifications.
	From cpim.Address
	// To is the sender of the message being reported on.
	To cpim.Address
	// Route is the message's RecordRoute, which RFC 5438 §7.2.1 has the
	// recipient copy, in order, into IMDN-Route headers.
	Route []cpim.Address
	// MessageID is a fresh ID for the notification itself; it must differ
	// from the reported message's (§7.2.1). See NewMessageID.
	MessageID string
	// DateTime is when the notification is sent.
	DateTime time.Time
}

// Message wraps n in the CPIM message that carries it: content type
// message/imdn+xml with Content-Disposition notification (RFC 5438 §7.2.1).
// It never adds Disposition-Notification, since nobody may ask for a
// notification about a notification.
func (n Notification) Message(e Envelope) (*cpim.Message, error) {
	body, err := n.Marshal()
	if err != nil {
		return nil, err
	}
	if !cpim.IsToken(e.MessageID) {
		return nil, fmt.Errorf("%w: notification Message-ID is not a token", ErrMalformed)
	}
	if e.MessageID == n.MessageID {
		return nil, fmt.Errorf("%w: notification reuses the Message-ID it reports on", ErrMalformed)
	}
	if e.DateTime.IsZero() {
		return nil, fmt.Errorf("%w: notification has no DateTime", ErrMalformed)
	}
	for _, a := range append([]cpim.Address{e.From, e.To}, e.Route...) {
		if _, err := cpim.ParseAddress(a.String()); err != nil {
			return nil, err
		}
	}

	m := &cpim.Message{}
	add := func(ns, name, value string) {
		if err == nil {
			err = m.Add(ns, name, value)
		}
	}
	add(cpim.CoreNamespace, cpim.HeaderFrom, e.From.String())
	add(cpim.CoreNamespace, cpim.HeaderTo, e.To.String())
	add(cpim.CoreNamespace, cpim.HeaderDateTime, cpim.FormatDateTime(e.DateTime))
	if err == nil {
		err = m.Declare(Prefix, Namespace)
	}
	add(Namespace, HeaderMessageID, e.MessageID)
	for _, r := range e.Route {
		add(Namespace, HeaderRoute, r.String())
	}
	if err != nil {
		return nil, err
	}
	m.ContentHeaders = []cpim.Field{
		{Name: "Content-Type", Value: ContentType},
		{Name: "Content-Disposition", Value: ContentDisposition},
	}
	m.Body = body
	return m, nil
}

// ParseNotificationMessage returns the notification carried by m.
func ParseNotificationMessage(m *cpim.Message) (Notification, error) {
	if !IsNotification(m) {
		return Notification{}, ErrNotNotification
	}
	mt, _, err := mime.ParseMediaType(m.ContentType())
	switch {
	case err != nil:
		return Notification{}, fmt.Errorf("%w: unreadable Content-Type", ErrMalformed)
	case mt == "multipart/mixed":
		return Notification{}, ErrUnsupported
	case mt != ContentType:
		return Notification{}, fmt.Errorf("%w: notification content is %s", ErrMalformed, mt)
	}
	return ParseNotification(m.Body)
}
