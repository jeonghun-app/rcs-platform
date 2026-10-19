package msrp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// The session-id in an MSRP URI is the only secret that ties a connection
// to a session (ADR 0004), and a message body is user content, so neither
// may reach a log. URI and Message therefore present themselves to fmt,
// slog and encoding/json without them, including inside slices and
// structs, which slog encodes through encoding/json. String and Marshal
// remain the only wire forms: store a URI by its String, never as JSON.

const redacted = "[redacted]"

// Redacted returns u as String does, but with the session-id and any
// userinfo replaced by a placeholder, an IP address host logged as its
// network only, and no parameters after the transport.
//
// A client's a=path names the UE's own address, which is personal data
// whatever its range (#36, #80): only its /24 or /48 is logged, without the
// port, by the rule sip's hosts follow (pii.TruncateIP). A host name is
// kept, with its port, and any long digit run in it masked like other text.
// The parameters are the client's own text, which could name the address
// again, and sip's log values leave theirs out too.
func (u URI) Redacted() string {
	v := u
	v.Params = nil
	if v.SessionID != "" {
		v.SessionID = redacted
	}
	if v.User != "" {
		v.User = redacted
	}
	if ipHost(v.Host) {
		v.Host, v.Port = pii.TruncateIP(v.Host), 0
	} else {
		v.Host = pii.Redact(v.Host)
	}
	return v.String()
}

// ipHost reports whether host is an IP address rather than a name: an IPv6
// address (Host holds it without brackets), or digits and dots only, which
// pii.TruncateIP reads as an IPv4 address or masks whole.
func ipHost(host string) bool {
	return strings.IndexByte(host, ':') >= 0 || host != "" && strings.Trim(host, "0123456789.") == ""
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
func (m Message) Format(f fmt.State, _ rune) { formatGroup(f, m.LogValue()) }

// The connection-layer types hold URIs in unexported fields, which fmt
// prints without calling URI.Format, so they summarise themselves too.

func formatGroup(f fmt.State, v slog.Value) {
	var b strings.Builder
	for i, a := range v.Group() {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(a.Value.String())
	}
	_, _ = f.Write([]byte(b.String()))
}

// LogValue implements slog.LogValuer with redacted URIs and the state.
func (s *Session) LogValue() slog.Value {
	s.mu.Lock()
	bound, closed := s.conn != nil, s.closed
	// SetRemote writes remote under the lock.
	remote := s.remote
	s.mu.Unlock()
	return slog.GroupValue(
		slog.String("local", s.local.Redacted()),
		slog.String("remote", redactedPath(remote)),
		slog.Bool("bound", bound),
		slog.Bool("closed", closed),
	)
}

// Format implements fmt.Formatter with the content of LogValue.
func (s *Session) Format(f fmt.State, _ rune) { formatGroup(f, s.LogValue()) }

// LogValue implements slog.LogValuer: the role, the number of sessions and
// whether the connection has ended.
func (c *Conn) LogValue() slog.Value {
	c.mu.Lock()
	n, closed := len(c.sessions), c.closed
	c.mu.Unlock()
	role := "active"
	if c.passive {
		role = "passive"
	}
	return slog.GroupValue(slog.String("role", role), slog.Int("sessions", n), slog.Bool("closed", closed))
}

// Format implements fmt.Formatter with the content of LogValue.
func (c *Conn) Format(f fmt.State, _ rune) { formatGroup(f, c.LogValue()) }

// LogValue implements slog.LogValuer with the number of sessions held.
func (r *Registry) LogValue() slog.Value {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slog.GroupValue(slog.Int("sessions", len(r.sessions)))
}

// Format implements fmt.Formatter with the content of LogValue.
func (r *Registry) Format(f fmt.State, _ rune) { formatGroup(f, r.LogValue()) }

// LogValue implements slog.LogValuer with the number of connections held.
func (p *Pool) LogValue() slog.Value {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slog.GroupValue(slog.Int("connections", len(p.conns)))
}

// Format implements fmt.Formatter with the content of LogValue.
func (p *Pool) Format(f fmt.State, _ rune) { formatGroup(f, p.LogValue()) }
