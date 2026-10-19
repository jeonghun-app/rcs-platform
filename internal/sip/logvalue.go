package sip

import (
	"bytes"
	"encoding/json"
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
// slog applies LogValue only to the value it is handed. A plain slice of these
// values, or a struct of the service's own that holds one, reaches the JSON
// handler through encoding/json, which ignores LogValue. So the parsers and
// accessors return lists as the slice types below (Vias, Contacts, Addresses,
// Challenges, CredentialsList, AcceptContacts, Reasons), which log each
// element through its LogValue,
// and every type with a LogValue also has a MarshalJSON writing the same
// redacted form, which covers plain slices and struct fields. Text handlers
// format such values with fmt instead; the platform logs JSON only
// (docs/architecture.md §8).
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

// LogValue logs the names of the feature parameters and flags only: their
// values are the peer's text, and +sip.instance carries the device's
// instance identifier, often its IMEI (RFC 5626 §4.1, RFC 7254) (#109).
// The names, the peer's text too, go through internal/pii.
func (a AcceptContact) LogValue() slog.Value {
	names := make([]string, len(a.Params))
	for i, p := range a.Params {
		names[i] = p.Name
	}
	return slog.GroupValue(slog.String("params", pii.Redact(strings.Join(names, ";"))))
}

// LogValue logs the protocol and the cause; the text is the peer's free
// text and is left out (#109).
func (r Reason) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("protocol", pii.Redact(r.Protocol))}
	if c, ok := r.Cause(); ok {
		attrs = append(attrs, slog.Int("cause", c))
	}
	return slog.GroupValue(attrs...)
}

// Vias is a Via header's elements, top first, as ParseVia and Header.Via
// return them. It exists so that logging them all goes through Via.LogValue:
// a plain []Via would be logged field by field, received included.
type Vias []Via

// Contacts is a Contact header's elements, as ParseContacts and
// Header.Contact return them; logged, each goes through Contact.LogValue.
type Contacts []Contact

// Addresses is the name-addrs of a header such as Route, Record-Route, Path
// or P-Asserted-Identity; logged, each goes through Address.LogValue.
type Addresses []Address

// Challenges is one challenge per WWW-Authenticate or Proxy-Authenticate
// field; logged, each goes through Challenge.LogValue, nonce left out.
type Challenges []Challenge

// AcceptContacts is an Accept-Contact header's elements; logged, each goes
// through AcceptContact.LogValue.
type AcceptContacts []AcceptContact

// Reasons is a Reason header's elements; logged, each goes through
// Reason.LogValue.
type Reasons []Reason

// LogValue logs each element by its position.
func (as AcceptContacts) LogValue() slog.Value { return listValue(as) }

// LogValue logs each element by its position.
func (rs Reasons) LogValue() slog.Value { return listValue(rs) }

// CredentialsList is one set of credentials per Authorization or
// Proxy-Authorization field; logged, each goes through Credentials.LogValue,
// response and nonce left out.
type CredentialsList []Credentials

// LogValue logs each element by its position, top first.
func (vs Vias) LogValue() slog.Value { return listValue(vs) }

// LogValue logs each element by its position.
func (cs Contacts) LogValue() slog.Value { return listValue(cs) }

// LogValue logs each element by its position, top first.
func (as Addresses) LogValue() slog.Value { return listValue(as) }

// LogValue logs each element by its position.
func (cs Challenges) LogValue() slog.Value { return listValue(cs) }

// LogValue logs each element by its position.
func (cs CredentialsList) LogValue() slog.Value { return listValue(cs) }

// listValue is a group of the elements' own log values, keyed by position.
func listValue[T slog.LogValuer](vs []T) slog.Value {
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
		// The reason phrase is the peer's text: identifiers in it are
		// masked like any other text (internal/pii).
		slog.String("reason", pii.Redact(r.Reason)),
		slog.Int("headers", r.Header.Len()),
		slog.Int("body_bytes", len(r.Body)),
	)
}

// The types above also marshal to JSON as their log values, so that a plain
// slice of them, or a field of a struct of the service's own, logged through
// slog's JSON handler (which hands such values to encoding/json) or encoded
// any other way, is redacted too. No API encodes these types as JSON for
// another purpose; one that needs the full value encodes its String form.

// MarshalJSON writes the log value.
func (u URI) MarshalJSON() ([]byte, error) { return jsonOf(u.LogValue()) }

// MarshalJSON writes the log value.
func (a Address) MarshalJSON() ([]byte, error) { return jsonOf(a.LogValue()) }

// MarshalJSON writes the log value.
func (c Contact) MarshalJSON() ([]byte, error) { return jsonOf(c.LogValue()) }

// MarshalJSON writes the log value.
func (c Challenge) MarshalJSON() ([]byte, error) { return jsonOf(c.LogValue()) }

// MarshalJSON writes the log value.
func (c Credentials) MarshalJSON() ([]byte, error) { return jsonOf(c.LogValue()) }

// MarshalJSON writes the log value.
func (v Via) MarshalJSON() ([]byte, error) { return jsonOf(v.LogValue()) }

// MarshalJSON writes the log value.
func (a AcceptContact) MarshalJSON() ([]byte, error) { return jsonOf(a.LogValue()) }

// MarshalJSON writes the log value.
func (r Reason) MarshalJSON() ([]byte, error) { return jsonOf(r.LogValue()) }

// MarshalJSON writes the log value.
func (h Header) MarshalJSON() ([]byte, error) { return jsonOf(h.LogValue()) }

// MarshalJSON writes the log value.
func (r Request) MarshalJSON() ([]byte, error) { return jsonOf(r.LogValue()) }

// MarshalJSON writes the log value.
func (r Response) MarshalJSON() ([]byte, error) { return jsonOf(r.LogValue()) }

// jsonOf writes v as JSON in the shape slog's JSON handler gives it: a group
// as an object with its attributes in order, anything else as encoding/json
// writes it.
func jsonOf(v slog.Value) ([]byte, error) {
	var b bytes.Buffer
	err := appendJSON(&b, v)
	return b.Bytes(), err
}

func appendJSON(b *bytes.Buffer, v slog.Value) error {
	v = v.Resolve()
	if v.Kind() != slog.KindGroup {
		j, err := json.Marshal(v.Any())
		b.Write(j)
		return err
	}
	b.WriteByte('{')
	for i, a := range v.Group() {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(a.Key)
		if err != nil {
			return err
		}
		b.Write(k)
		b.WriteByte(':')
		if err := appendJSON(b, a.Value); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}
