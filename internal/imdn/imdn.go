// Package imdn implements Instant Message Disposition Notification (RFC 5438),
// the delivery and display receipts of RCS chat: reading which notifications
// the sender of a CPIM message asked for, and building and parsing the
// message/imdn+xml notifications that answer it.
//
// A recipient answers with delivery and display notifications; an
// intermediary such as a store-and-forward server may answer with processing
// and negative delivery notifications (RFC 5438 §7.2, §8). Disposition.Wants
// and Request.Notification apply those rules so a service cannot send a
// notification nobody asked for.
//
// A notification echoes the DateTime of the message it reports on as the
// sender wrote it (RFC 5438 §11.1.2), so Request and Notification keep it as a
// string; their Time methods interpret it. A time this package cannot parse
// therefore never costs anyone a receipt.
//
// Notification documents are decoded with encoding/xml behind a size limit, a
// nesting limit and a refusal of any document type declaration, so entity
// tricks never reach the decoder.
//
// Aggregated notifications (multipart/mixed, RFC 5438 §8.3) are recognised
// but not decoded: ParseNotificationMessage reports ErrUnsupported for them.
package imdn

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
)

// Namespace is the CPIM header namespace of the IMDN headers (RFC 5438 §6.1).
const Namespace = "urn:ietf:params:imdn"

// MaxDateTimeLength bounds the DateTime a notification echoes. An RFC 3339
// date-time is at most a few dozen bytes; without a bound a sender could fill
// its message with one and have every recipient echo it back.
const MaxDateTimeLength = 64

// Prefix is the namespace prefix this package declares when it adds IMDN
// headers. Receivers must accept any prefix (RFC 5438 §6.1); this one is the
// conventional choice.
const Prefix = "imdn"

// Names of the IMDN headers in Namespace (RFC 5438 §6.2-§6.6).
const (
	HeaderMessageID               = "Message-ID"
	HeaderDispositionNotification = "Disposition-Notification"
	HeaderOriginalTo              = "Original-To"
	HeaderRecordRoute             = "IMDN-Record-Route"
	HeaderRoute                   = "IMDN-Route"
)

// ContentType is the MIME type of a notification document (RFC 5438 §11.1.8).
const ContentType = "message/imdn+xml"

// ContentDisposition marks a CPIM message as a notification (RFC 5438 §7.2.1).
const ContentDisposition = "notification"

var (
	// ErrMalformed reports input outside RFC 5438.
	ErrMalformed = errors.New("imdn: malformed")
	// ErrIncompleteRequest reports a message that asks for notifications
	// without the Message-ID and DateTime needed to answer it (RFC 5438
	// §7.1.1.1, §7.1.1.2).
	ErrIncompleteRequest = errors.New("imdn: notification requested without Message-ID and DateTime")
	// ErrNotRequested reports a notification the sender did not ask for.
	ErrNotRequested = errors.New("imdn: notification not requested")
	// ErrNotNotification reports a CPIM message that is not an IMDN.
	ErrNotNotification = errors.New("imdn: message is not a disposition notification")
	// ErrUnsupported reports an aggregated IMDN, which this package does not
	// decode.
	ErrUnsupported = errors.New("imdn: aggregated notifications are not supported")
)

// Disposition is a set of notification types a sender requests in the
// Disposition-Notification header (RFC 5438 §7.1.1.3).
type Disposition uint8

// The dispositions RFC 5438 §10 defines.
const (
	PositiveDelivery Disposition = 1 << iota
	NegativeDelivery
	Display
	Processing
)

var dispositionNames = []struct {
	d    Disposition
	name string
}{
	{PositiveDelivery, "positive-delivery"},
	{NegativeDelivery, "negative-delivery"},
	{Display, "display"},
	{Processing, "processing"},
}

// ParseDispositions parses a Disposition-Notification value. Values are
// compared case-sensitively (RFC 5438 §10); unknown ones and their parameters
// are ignored, as RFC 5438 §7.2.1 tells a recipient to do. An empty value
// requests nothing. No parameter is defined for any value, so a quoted
// parameter value containing a comma is not supported.
func ParseDispositions(v string) (Disposition, error) {
	var d Disposition
	if strings.Trim(v, " ") == "" {
		return 0, nil
	}
	for req := range strings.SplitSeq(v, ",") {
		name, params, hasParams := strings.Cut(req, ";")
		name = strings.Trim(name, " ")
		if !cpim.IsToken(name) {
			return 0, fmt.Errorf("%w: invalid Disposition-Notification value", ErrMalformed)
		}
		if hasParams {
			for p := range strings.SplitSeq(params, ";") {
				pn, pv, ok := strings.Cut(strings.Trim(p, " "), "=")
				if !ok || pn == "" || pv == "" {
					return 0, fmt.Errorf("%w: invalid Disposition-Notification parameter", ErrMalformed)
				}
			}
		}
		for _, dn := range dispositionNames {
			if dn.name == name {
				d |= dn.d
			}
		}
	}
	return d, nil
}

// String formats d as a Disposition-Notification value.
func (d Disposition) String() string {
	var names []string
	for _, dn := range dispositionNames {
		if d&dn.d != 0 {
			names = append(names, dn.name)
		}
	}
	return strings.Join(names, ", ")
}

// Wants reports whether a sender that requested d wants a notification of
// kind k with status s:
//
//   - delivered answers positive-delivery, and failed and error answer
//     negative-delivery, since both report a delivery that did not happen
//     (RFC 5438 §7.1.1.3, §8.2);
//   - forbidden refuses the requested notification itself (§5.1), so it
//     answers a request for either delivery notification;
//   - display and processing statuses answer their own request whatever the
//     outcome (§5.2, §5.3).
func (d Disposition) Wants(k Kind, s Status) bool {
	if !k.allows(s) {
		return false
	}
	switch k {
	case DeliveryNotification:
		switch s {
		case Delivered:
			return d&PositiveDelivery != 0
		case Forbidden:
			return d&(PositiveDelivery|NegativeDelivery) != 0
		}
		return d&NegativeDelivery != 0
	case DisplayNotification:
		return d&Display != 0
	case ProcessingNotification:
		return d&Processing != 0
	}
	return false
}

// Request is what a CPIM message asks of its recipients.
type Request struct {
	// MessageID identifies the message; every notification quotes it.
	MessageID string
	// DateTime is the message's DateTime header exactly as sent. A
	// notification echoes this string (RFC 5438 §11.1.2) so the sender can
	// match it however it formatted the time; Time interprets it.
	DateTime string
	// Dispositions are the notifications requested; zero means none.
	Dispositions Disposition
	// OriginalTo is the recipient before an intermediary rewrote To (RFC 5438
	// §6.4); its URI is empty when the header is absent.
	OriginalTo cpim.Address
	// RecordRoute lists the intermediaries notifications must traverse, in
	// order (RFC 5438 §6.5).
	RecordRoute []cpim.Address
}

// ParseRequest reads the IMDN request carried by m. A message that requests
// nothing, including any IMDN (RFC 5438 §7.2.1 forbids answering one), yields
// zero Dispositions and no error.
func ParseRequest(m *cpim.Message) (Request, error) {
	if IsNotification(m) {
		return Request{}, nil
	}
	var r Request
	for _, h := range m.All(Namespace, HeaderDispositionNotification) {
		d, err := ParseDispositions(h.Value)
		if err != nil {
			return Request{}, err
		}
		r.Dispositions |= d
	}

	ids := m.All(Namespace, HeaderMessageID)
	switch {
	case len(ids) > 1:
		return Request{}, fmt.Errorf("%w: more than one Message-ID", ErrMalformed)
	case len(ids) == 1:
		if !cpim.IsToken(ids[0].Value) {
			return Request{}, fmt.Errorf("%w: Message-ID is not a token", ErrMalformed)
		}
		r.MessageID = ids[0].Value
	}

	if h, ok := m.Get(cpim.CoreNamespace, cpim.HeaderDateTime); ok {
		if len(h.Value) > MaxDateTimeLength {
			return Request{}, fmt.Errorf("%w: DateTime longer than %d bytes", ErrMalformed, MaxDateTimeLength)
		}
		r.DateTime = h.Value
	}
	if r.Dispositions != 0 && (r.MessageID == "" || r.DateTime == "") {
		return Request{}, ErrIncompleteRequest
	}

	orig := m.All(Namespace, HeaderOriginalTo)
	if len(orig) > 1 {
		return Request{}, fmt.Errorf("%w: more than one Original-To", ErrMalformed)
	}
	if len(orig) == 1 {
		a, err := cpim.ParseAddress(orig[0].Value)
		if err != nil {
			return Request{}, err
		}
		r.OriginalTo = a
	}
	for _, h := range m.All(Namespace, HeaderRecordRoute) {
		a, err := cpim.ParseAddress(h.Value)
		if err != nil {
			return Request{}, err
		}
		r.RecordRoute = append(r.RecordRoute, a)
	}
	return r, nil
}

// Time interprets DateTime, which ParseRequest keeps uninterpreted so that a
// time this package cannot parse still gets its notifications.
func (r Request) Time() (time.Time, error) {
	return cpim.ParseDateTime(r.DateTime)
}

// AddRecordRoute puts an intermediary's address on top of the IMDN-Record-Route
// list of m, as RFC 5438 §8 has an intermediary do when it wants to see the
// notifications. The recipient copies the list in order into IMDN-Route, so
// the notification reaches the last intermediary to add itself first.
func AddRecordRoute(m *cpim.Message, a cpim.Address) error {
	if _, err := cpim.ParseAddress(a.String()); err != nil {
		return err
	}
	if err := m.Declare(Prefix, Namespace); err != nil {
		return err
	}
	return m.AddFirst(Namespace, HeaderRecordRoute, a.String())
}

// AddRequest asks the recipients of m for the notifications in d, adding the
// Message-ID and Disposition-Notification headers. m must already carry the
// DateTime header the notifications will quote (RFC 5438 §7.1.1.2).
func AddRequest(m *cpim.Message, id string, d Disposition) error {
	if d.String() == "" {
		return fmt.Errorf("%w: no disposition requested", ErrMalformed)
	}
	if !cpim.IsToken(id) {
		return fmt.Errorf("%w: Message-ID is not a token", ErrMalformed)
	}
	if _, err := m.DateTime(); err != nil {
		return err
	}
	if _, ok := m.Get(Namespace, HeaderMessageID); ok {
		return fmt.Errorf("%w: message already has a Message-ID", ErrMalformed)
	}
	if _, ok := m.Get(Namespace, HeaderDispositionNotification); ok {
		return fmt.Errorf("%w: message already requests notifications", ErrMalformed)
	}
	if err := m.Declare(Prefix, Namespace); err != nil {
		return err
	}
	if err := m.Add(Namespace, HeaderMessageID, id); err != nil {
		return err
	}
	return m.Add(Namespace, HeaderDispositionNotification, d.String())
}

// NewMessageID returns a Message-ID with 128 random bits read from r; nil
// means crypto/rand.Reader. RFC 5438 §6.3 asks for at least 64 bits from a
// secure generator so that an attacker cannot guess the ID of a message and
// forge its receipts.
func NewMessageID(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("imdn: generating Message-ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// IsNotification reports whether m is an IMDN, which RFC 5438 §7.1.2 lets a
// receiver tell from Content-Disposition alone.
func IsNotification(m *cpim.Message) bool {
	v, ok := m.ContentHeader("Content-Disposition")
	if !ok {
		return false
	}
	disp, _, err := mime.ParseMediaType(v)
	return err == nil && disp == ContentDisposition
}
