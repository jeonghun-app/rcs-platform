package sip

import "log/slog"

// The values below carry subscriber identities (a SIP user part or tel number is
// an MSISDN or IMSI-based identity) and credentials, which docs/architecture.md
// §8 keeps out of logs. A service that passes one to log/slog gets these
// redacted forms instead of the exported fields, the same line of defence as
// messages having no String method.
//
// TODO(#2): pass user parts and numbers through internal/pii once it lands, so
// operators can correlate the masked form; until then they are left out.

const redactedMark = "***"

// LogValue logs the scheme and host only.
func (u URI) LogValue() slog.Value { return slog.StringValue(u.redacted()) }

func (u URI) redacted() string {
	switch u.Scheme {
	case "":
		return ""
	case "sip", "sips":
		if u.User == "" {
			return u.Scheme + ":" + u.Host
		}
		return u.Scheme + ":" + redactedMark + "@" + u.Host
	default:
		return u.Scheme + ":" + redactedMark
	}
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

// LogValue logs the method, the redacted Request-URI and sizes; header values
// and the body are left out.
func (r *Request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("uri", r.URI.redacted()),
		slog.Int("headers", r.Header.Len()),
		slog.Int("body_bytes", len(r.Body)),
	)
}

// LogValue logs the status and sizes; header values and the body are left out.
func (r *Response) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("status", r.StatusCode),
		slog.String("reason", r.Reason),
		slog.Int("headers", r.Header.Len()),
		slog.Int("body_bytes", len(r.Body)),
	)
}
