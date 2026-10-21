package cpim

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// LogValue logs the header names, the From, To and cc addresses as
// Address.LogValue logs them, the media type of the encapsulated object and
// the body's length. Header values and the body are left out: they are the
// sender's text and content, and a header such as a formal name or a
// Subject can name a person (#109). The names, the sender's tokens, are
// masked like other text (internal/pii). An address that does not parse is
// left out. A nil *Message logs as an empty group.
//
// The receiver is a pointer so that a nil one can be told apart: a value
// receiver would make slog log the panic of its call. A Message value,
// which has no LogValue then, reaches slog's JSON handler through
// encoding/json, and MarshalJSON writes the same fields; it reaches the
// text handler through fmt, and Format prints them.
func (m *Message) LogValue() slog.Value {
	if m == nil {
		return slog.GroupValue()
	}
	l := m.logged()
	attrs := []slog.Attr{slog.Any("headers", l.Headers)}
	if l.From != nil {
		attrs = append(attrs, slog.Any("from", *l.From))
	}
	if l.To != nil {
		attrs = append(attrs, slog.Any("to", l.To))
	}
	if l.Cc != nil {
		attrs = append(attrs, slog.Any("cc", l.Cc))
	}
	return slog.GroupValue(append(attrs,
		slog.String("content_type", l.ContentType),
		slog.Int("body_bytes", l.BodyBytes))...)
}

// MarshalJSON writes the fields of the log value, so that a Message in a
// struct field or a slice, which slog's JSON handler hands to encoding/json,
// is redacted too. Nothing encodes a Message as JSON for another purpose.
func (m Message) MarshalJSON() ([]byte, error) { return json.Marshal(m.logged()) }

// Format implements fmt.Formatter with what MarshalJSON writes, whatever the
// verb, so that a Message value, which has no LogValue, never prints its
// formal names, Subject or body: not through fmt, and not through slog's
// text handler, which formats such a value with %+v (#171). fmt prints a nil
// *Message as <nil>, as it prints any nil pointer whose method panics.
func (m Message) Format(f fmt.State, _ rune) {
	// The encoding cannot fail: the log form holds only strings and ints.
	b, _ := m.MarshalJSON()
	_, _ = f.Write(b)
}

type loggedMessage struct {
	Headers     []string  `json:"headers"`
	From        *Address  `json:"from,omitempty"`
	To          Addresses `json:"to,omitempty"`
	Cc          Addresses `json:"cc,omitempty"`
	ContentType string    `json:"content_type"`
	BodyBytes   int       `json:"body_bytes"`
}

func (m Message) logged() loggedMessage {
	l := loggedMessage{Headers: make([]string, len(m.Headers)), BodyBytes: len(m.Body)}
	for i, h := range m.Headers {
		l.Headers[i] = pii.Redact(h.Name)
	}
	if from, err := m.From(); err == nil {
		l.From = &from
	}
	if to, err := m.To(); err == nil {
		l.To = to
	}
	if cc, err := m.Cc(); err == nil && len(cc) > 0 {
		l.Cc = cc
	}
	// The parameters of the type, such as a file name, are the sender's.
	mediaType, _, _ := strings.Cut(m.ContentType(), ";")
	l.ContentType = pii.Redact(strings.ToLower(strings.TrimSpace(mediaType)))
	return l
}
