package msrp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// The session-id in an MSRP URI is the only secret that ties a connection
// to a session (ADR 0004), and a message body is user content, so neither
// may reach a log. URI and Message therefore present themselves to fmt,
// slog and encoding/json without them, including inside slices and
// structs, which slog encodes through encoding/json. String and Marshal
// remain the only wire forms: store a URI by its String, never as JSON.

const redacted = "[redacted]"

// Redacted returns u as String does, but with the session-id and any
// userinfo replaced by a placeholder.
func (u URI) Redacted() string {
	v := u
	if v.SessionID != "" {
		v.SessionID = redacted
	}
	if v.User != "" {
		v.User = redacted
	}
	return v.String()
}

// LogValue implements slog.LogValuer with the redacted form.
func (u URI) LogValue() slog.Value { return slog.StringValue(u.Redacted()) }

// Format implements fmt.Formatter so that every verb, %v and %s
// included, prints the redacted form; only String gives the wire form.
func (u URI) Format(f fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = f.Write([]byte(strconv.Quote(u.Redacted())))
		return
	}
	_, _ = f.Write([]byte(u.Redacted()))
}

// MarshalJSON encodes the redacted form as a JSON string.
func (u URI) MarshalJSON() ([]byte, error) { return json.Marshal(u.Redacted()) }

func redactedPath(path []URI) string {
	parts := make([]string, len(path))
	for i, u := range path {
		parts[i] = u.Redacted()
	}
	return strings.Join(parts, " ")
}

// LogValue implements slog.LogValuer: the start line, the identifiers and
// sizes that help trace a transaction, header names but not their values,
// and the body length but not the body.
func (m Message) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("tid", m.TransactionID)}
	if m.IsRequest() {
		attrs = append(attrs, slog.String("method", m.Method))
	} else {
		attrs = append(attrs, slog.Int("status", m.StatusCode))
	}
	attrs = append(attrs,
		slog.String("to", redactedPath(m.ToPath)),
		slog.String("from", redactedPath(m.FromPath)))
	if m.MessageID != "" {
		attrs = append(attrs, slog.String("message_id", m.MessageID))
	}
	if m.ByteRange != nil {
		attrs = append(attrs, slog.String("byte_range", m.ByteRange.String()))
	}
	if m.Status != nil {
		attrs = append(attrs, slog.Int("report_status", m.Status.Code))
	}
	if m.ContentType != "" {
		attrs = append(attrs, slog.String("content_type", m.MediaType()))
	}
	if len(m.Header) > 0 {
		names := make([]string, len(m.Header))
		for i, f := range m.Header {
			names[i] = f.Name
		}
		attrs = append(attrs, slog.String("headers", strings.Join(names, ",")))
	}
	attrs = append(attrs,
		slog.Int("body_octets", len(m.Body)),
		slog.String("flag", string(m.flag())))
	return slog.GroupValue(attrs...)
}

// MarshalJSON encodes the same summary as LogValue.
func (m Message) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	for _, a := range m.LogValue().Group() {
		out[a.Key] = a.Value.Any()
	}
	return json.Marshal(out)
}

// Format implements fmt.Formatter with the same content as LogValue, so
// printing a Message with any verb never shows its body or session-ids.
func (m Message) Format(f fmt.State, _ rune) {
	var b strings.Builder
	for i, a := range m.LogValue().Group() {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
	}
	_, _ = f.Write([]byte(b.String()))
}
