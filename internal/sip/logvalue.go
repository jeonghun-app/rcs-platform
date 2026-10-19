package sip

import (
	"log/slog"
	"net/netip"
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

// LogValue logs the scheme and host only, a public IP host truncated.
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

// loggedHost is a URI or Via host as it may be logged. A public IP address
// there is a client's, the address of a UE's Contact or first Via, and is
// personal data, so only its network is logged (pii.TruncateIP: /24 or /48,
// #36). A private address (RFC 1918, ULA, loopback, link-local) names a task
// inside the VPC, such as the pcscf instance a Path or Record-Route points
// at (ADR 0005), or a UE's LAN behind NAT, which identifies no one; it is
// kept so operators can tell instances apart. Domain names are kept.
func loggedHost(host string) string {
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if err != nil {
		return host
	}
	if ip = ip.Unmap(); ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return host
	}
	return pii.TruncateIP(host)
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
// it is a public IP address) and the branch; received and rport, which hold
// the client's address as the server saw it, are left out.
func (v Via) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("transport", v.Transport),
		slog.String("host", loggedHost(v.Host)),
		slog.String("branch", v.Branch()),
	)
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
