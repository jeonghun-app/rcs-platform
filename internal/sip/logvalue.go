package sip

import (
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// The values below carry subscriber identities (a SIP user part or tel number is
// an MSISDN or IMSI-based identity) and credentials, which docs/architecture.md
// §8 keeps out of logs. A service that passes one to log/slog gets these
// redacted forms instead of the exported fields, the same line of defence as
// messages having no String method.
//
// slog applies LogValue only to the value it is handed. A slice of these values,
// or a struct of the service's own that holds one, reaches the JSON handler
// through encoding/json, which ignores LogValue and writes every field: log the
// elements or the fields one by one instead.
//
// TODO(#2): pass user parts and numbers through internal/pii once it lands, so
// operators can correlate the masked form; until then they are left out.

const redactedMark = "***"

// LogValue logs the scheme and host only, an IP host truncated to its
// network.
func (u URI) LogValue() slog.Value { return slog.StringValue(u.redacted()) }

func (u URI) redacted() string {
	switch u.Scheme {
	case "":
		return ""
	case "sip", "sips":
		host := loggedHost(u.Host)
		if u.User == "" {
			return u.Scheme + ":" + host
		}
		return u.Scheme + ":" + redactedMark + "@" + host
	default:
		return u.Scheme + ":" + redactedMark
	}
}

// loggedHost is a URI or Via host as it may be logged. An IP address there
// is a client's as far as a log can tell, the address of a UE's Contact or
// first Via, and is personal data whatever its range: a UE on an operator's
// APN often has an RFC 1918 address, and a link-local or unique local IPv6
// address can carry the device's MAC address. So only its network is logged
// (pii.TruncateIP, #36), and an address it cannot read is masked rather than
// logged as if it were a name. A domain name is kept, with any digit run in
// it masked like other text.
func loggedHost(host string) string {
	if isIPv4(host) || strings.HasPrefix(host, "[") {
		return pii.TruncateIP(host)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return pii.TruncateIP(host)
	}
	return pii.Redact(host)
}

// LogValue logs the redacted URI and the tag; the display name is left out.
func (a Address) LogValue() slog.Value {
	return slog.GroupValue(slog.String("uri", a.URI.redacted()), slog.String("tag", a.Tag()))
}

// LogValue logs a contact as an Address, or "*".
func (c Contact) LogValue() slog.Value {
	if c.Star {
		return slog.StringValue("*")
	}
	return c.Address.LogValue()
}

// LogValue logs the scheme, realm, algorithm and qop. The nonce and opaque
// value are left out.
func (c Challenge) LogValue() slog.Value { return authLogValue(c.Scheme, c.Params) }

// LogValue logs the scheme, realm, algorithm and qop. The username (an IMPI,
// which holds the IMSI), nonce, response and cnonce are left out.
func (c Credentials) LogValue() slog.Value { return authLogValue(c.Scheme, c.Params) }

func authLogValue(scheme string, ps Params) slog.Value {
	attrs := []slog.Attr{slog.String("scheme", scheme)}
	for _, name := range []string{"realm", "algorithm", "qop"} {
		if v, ok := ps.Get(name); ok {
			attrs = append(attrs, slog.String(name, v))
		}
	}
	return slog.GroupValue(attrs...)
}

// LogValue logs the transport, the sent-by host (truncated like a URI's when
// it is an IP address) and the branch; received and rport, which hold the
// client's address as the server saw it, are left out. slog applies LogValue
// only to the value it is given, not to the elements of a slice, so log a
// whole header's Via elements as [Vias].
func (v Via) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("transport", v.Transport),
		slog.String("host", loggedHost(v.Host)),
		slog.String("branch", v.Branch()),
	)
}

// Vias is a Via header's elements, top first, as ParseVia and Header.Via
// return them. It exists so that logging them all goes through Via.LogValue:
// a plain []Via would be logged field by field, received included.
type Vias []Via

// LogValue logs each element by its position, top first.
func (vs Vias) LogValue() slog.Value {
	attrs := make([]slog.Attr, len(vs))
	for i, v := range vs {
		attrs[i] = slog.Any(strconv.Itoa(i), v)
	}
	return slog.GroupValue(attrs...)
}

// LogValue logs the number of fields; names and values are left out, since
// either can carry input chosen by the peer.
func (h Header) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("fields", len(h.fields)))
}

// LogValue logs the method, the redacted Request-URI and sizes; header values
// and the body are left out. The receiver is a value so that a Request and a
// *Request both log this way.
func (r Request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("uri", r.URI.redacted()),
		slog.Int("headers", r.Header.Len()),
		slog.Int("body_bytes", len(r.Body)),
	)
}

// LogValue logs the status and sizes; header values and the body are left out.
// Like Request.LogValue it has a value receiver.
func (r Response) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("status", r.StatusCode),
		slog.String("reason", r.Reason),
		slog.Int("headers", r.Header.Len()),
		slog.Int("body_bytes", len(r.Body)),
	)
}
