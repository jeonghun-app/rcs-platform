package digest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ErrUnsupportedAlgorithm means the algorithm parameter names an algorithm
// this package does not implement. A client should ignore such a challenge
// and use another one (RFC 8760 §2.4, RFC 3310 §3.1).
var ErrUnsupportedAlgorithm = errors.New("digest: unsupported algorithm")

// QOPAuth is the only quality of protection this package uses.
const QOPAuth = "auth"

// Challenge is the value of a WWW-Authenticate or Proxy-Authenticate header
// field with the Digest scheme (RFC 7616 §3.3).
type Challenge struct {
	Realm     string
	Nonce     string
	Opaque    string    // empty when the server sent none
	Algorithm Algorithm // MD5 when the server sent none
	QOP       []string  // qop-options in the server's order
	Stale     bool      // the previous credentials were right but the nonce had expired
}

// ParseChallenge parses one challenge. A header value holding several
// challenges, which HTTP allows, is rejected: SIP carries one challenge per
// header field (RFC 3261 §20.44) and the servers this package talks to send one
// per field as well.
func ParseChallenge(value string) (Challenge, error) {
	params, err := parseHeader(value)
	if err != nil {
		return Challenge{}, err
	}
	p, err := pick(params, "realm", "nonce", "opaque", "algorithm", "qop", "stale")
	if err != nil {
		return Challenge{}, err
	}
	for _, required := range []string{"realm", "nonce"} {
		if _, ok := p[required]; !ok {
			return Challenge{}, malformed("challenge has no %s", required)
		}
	}
	alg, ok := parseAlgorithm(p["algorithm"])
	if !ok {
		return Challenge{}, ErrUnsupportedAlgorithm
	}
	c := Challenge{
		Realm:     p["realm"],
		Nonce:     p["nonce"],
		Opaque:    p["opaque"],
		Algorithm: alg,
		// Anything other than true, in any case, means false (RFC 7616 §3.3).
		Stale: strings.EqualFold(p["stale"], "true"),
	}
	if qop, ok := p["qop"]; ok {
		for option := range strings.SplitSeq(qop, ",") {
			if option = strings.Trim(option, " \t"); option != "" {
				c.QOP = append(c.QOP, option)
			}
		}
	}
	return c, nil
}

// offersAuth reports whether qop=auth is among the challenge's options.
func (c Challenge) offersAuth() bool {
	for _, q := range c.QOP {
		if strings.EqualFold(q, QOPAuth) {
			return true
		}
	}
	return false
}

// Header formats the challenge as a header field value. realm, nonce, opaque
// and qop are quoted and algorithm and stale are not, as RFC 7616 §3.3
// requires of senders. The value holds the nonce, so it must not be logged;
// String and LogValue give a summary that may be.
func (c Challenge) Header() string {
	var h headerBuilder
	h.quoted("realm", c.Realm)
	h.quoted("nonce", c.Nonce)
	if c.Opaque != "" {
		h.quoted("opaque", c.Opaque)
	}
	if c.Algorithm != "" {
		h.add("algorithm", algorithmValue(c.Algorithm))
	}
	if len(c.QOP) > 0 {
		h.quoted("qop", strings.Join(c.QOP, ","))
	}
	if c.Stale {
		h.add("stale", "true")
	}
	return h.String()
}

// algorithmValue writes a hand-built, unsupported algorithm quoted when it is
// not a token, so String never produces something ParseChallenge would split
// differently.
func algorithmValue(a Algorithm) string {
	if isToken(string(a)) {
		return string(a)
	}
	return quote(string(a))
}

// String returns a summary for logs and errors: the realm, the algorithm and
// whether the challenge is stale. The nonce (for AKA, RAND ‖ AUTN) and the
// opaque value are left out, because neither may reach a log.
func (c Challenge) String() string {
	return fmt.Sprintf("digest.Challenge{realm=%q algorithm=%s stale=%t}", c.Realm, c.Algorithm, c.Stale)
}

// GoString returns the same summary as String.
func (c Challenge) GoString() string { return c.String() }

// Format makes every fmt verb produce the summary.
func (c Challenge) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue gives log/slog the summary fields.
func (c Challenge) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("realm", c.Realm),
		slog.String("algorithm", string(c.Algorithm)),
		slog.Bool("stale", c.Stale),
	)
}

// MarshalJSON emits the summary fields, because a value nested in another one
// reaches a JSON log handler through encoding/json, which ignores LogValue.
func (c Challenge) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Realm     string    `json:"realm"`
		Algorithm Algorithm `json:"algorithm"`
		Stale     bool      `json:"stale"`
	}{c.Realm, c.Algorithm, c.Stale})
}
