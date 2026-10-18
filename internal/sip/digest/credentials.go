package digest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
)

// Credentials is the value of an Authorization or Proxy-Authorization header
// field with the Digest scheme (RFC 7616 §3.4, RFC 3310 §3.4).
//
// Nonce and Response may be empty: an IMS client's first REGISTER carries
// credentials with only the identity filled in, so that scscf knows whom to
// challenge (TS 24.229 §5.1.1.2.2 for IMS AKA, §5.1.1.2.3 for SIP Digest;
// RFC 8760 §2.7). Such credentials parse, and Check, Verify and VerifyAKA
// reject them with ErrInvalidNonce.
type Credentials struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string    // hex request-digest
	Algorithm Algorithm // MD5 when the client sent none
	CNonce    string
	NC        uint32 // nonce-count; zero when absent
	QOP       string // as sent, normally "auth"
	Opaque    string
	AUTS      []byte // decoded auts (RFC 3310 §3.4); empty when absent
}

// ParseCredentials parses one set of Digest credentials.
func ParseCredentials(value string) (Credentials, error) {
	params, err := parseHeader(value)
	if err != nil {
		return Credentials{}, err
	}
	p, err := pick(params, "username", "realm", "nonce", "uri", "response",
		"algorithm", "cnonce", "nc", "qop", "opaque", "auts")
	if err != nil {
		return Credentials{}, err
	}
	for _, required := range []string{"username", "realm", "nonce", "uri", "response"} {
		if _, ok := p[required]; !ok {
			return Credentials{}, malformed("credentials have no %s", required)
		}
	}
	alg, ok := parseAlgorithm(p["algorithm"])
	if !ok {
		return Credentials{}, ErrUnsupportedAlgorithm
	}
	c := Credentials{
		Username:  p["username"],
		Realm:     p["realm"],
		Nonce:     p["nonce"],
		URI:       p["uri"],
		Response:  p["response"],
		Algorithm: alg,
		CNonce:    p["cnonce"],
		QOP:       p["qop"],
		Opaque:    p["opaque"],
	}
	if nc, ok := p["nc"]; ok {
		if c.NC, err = parseNC(nc); err != nil {
			return Credentials{}, err
		}
	}
	if auts, ok := p["auts"]; ok {
		if c.AUTS, err = base64.StdEncoding.Strict().DecodeString(auts); err != nil || len(c.AUTS) == 0 {
			return Credentials{}, malformed("auts is not base64")
		}
	}
	return c, nil
}

// parseNC reads nc-value: exactly eight lower-case hex digits (RFC 7616
// §3.4). Upper case is refused rather than folded, because the client hashed
// the digits exactly as it wrote them.
func parseNC(s string) (uint32, error) {
	if len(s) != 8 {
		return 0, malformed("nc is not eight hex digits")
	}
	var n uint32
	for i := range len(s) {
		c := s[i]
		switch {
		case '0' <= c && c <= '9':
			n = n<<4 | uint32(c-'0')
		case 'a' <= c && c <= 'f':
			n = n<<4 | uint32(c-'a'+10)
		default:
			return 0, malformed("nc is not eight lower-case hex digits")
		}
	}
	return n, nil
}

func formatNC(nc uint32) string { return fmt.Sprintf("%08x", nc) }

// Header formats the credentials as a header field value. The five required
// parameters are always written, empty or not; algorithm, qop and nc are
// unquoted and the rest quoted, as RFC 7616 §3.4 and RFC 8760 §2.6 require of
// senders. The value holds the username (for IMS the IMSI-based IMPI) and the
// nonce, so it must not be logged; String and LogValue give a summary that
// may be.
func (c Credentials) Header() string {
	var h headerBuilder
	h.quoted("username", c.Username)
	h.quoted("realm", c.Realm)
	h.quoted("nonce", c.Nonce)
	h.quoted("uri", c.URI)
	h.quoted("response", c.Response)
	if c.Algorithm != "" {
		h.add("algorithm", algorithmValue(c.Algorithm))
	}
	if c.CNonce != "" {
		h.quoted("cnonce", c.CNonce)
	}
	if c.Opaque != "" {
		h.quoted("opaque", c.Opaque)
	}
	if c.QOP != "" {
		if isToken(c.QOP) {
			h.add("qop", c.QOP)
		} else {
			h.quoted("qop", c.QOP)
		}
	}
	if c.NC != 0 {
		h.add("nc", formatNC(c.NC))
	}
	if len(c.AUTS) > 0 {
		h.quoted("auts", base64.StdEncoding.EncodeToString(c.AUTS))
	}
	return h.String()
}

// String returns a summary for logs and errors: realm, algorithm, qop,
// nonce-count and whether auts is present. The username is left out because
// for IMS it is the IMSI-based IMPI, which reaches a log only through
// internal/pii, and so are the nonce, cnonce, opaque, response and AUTS.
func (c Credentials) String() string {
	return fmt.Sprintf("digest.Credentials{realm=%q algorithm=%s qop=%q nc=%s auts=%t}",
		c.Realm, c.Algorithm, c.QOP, formatNC(c.NC), len(c.AUTS) > 0)
}

// GoString returns the same summary as String.
func (c Credentials) GoString() string { return c.String() }

// Format makes every fmt verb produce the summary.
func (c Credentials) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue gives log/slog the summary fields.
func (c Credentials) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("realm", c.Realm),
		slog.String("algorithm", string(c.Algorithm)),
		slog.String("qop", c.QOP),
		slog.String("nc", formatNC(c.NC)),
		slog.Bool("auts", len(c.AUTS) > 0),
	)
}

// MarshalJSON emits the summary fields, because a value nested in another one
// reaches a JSON log handler through encoding/json, which ignores LogValue.
func (c Credentials) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Realm     string    `json:"realm"`
		Algorithm Algorithm `json:"algorithm"`
		QOP       string    `json:"qop"`
		NC        string    `json:"nc"`
		AUTS      bool      `json:"auts"`
	}{c.Realm, c.Algorithm, c.QOP, formatNC(c.NC), len(c.AUTS) > 0})
}
