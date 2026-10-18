package digest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// ClientParams is what a client supplies to answer a challenge. It formats as
// a redacted placeholder because it holds the password.
type ClientParams struct {
	Username string
	// Password is the user's password, or for AKAv1-MD5 the RES the card
	// computed (RFC 3310 §3.3). Ignored when AUTS is set.
	Password []byte
	Method   string // SIP or HTTP method of the request being authorised
	URI      string // Request-URI (SIP) or request-target (HTTP)
	// CNonce is the client nonce; NewCNonce makes one. A parameter so that
	// tests can fix it.
	CNonce string
	// NC is the nonce-count: 1 for the first request with a nonce, then one
	// more for each further request with the same nonce.
	NC uint32
	// AUTS, when set, reports an AKA synchronisation failure instead of
	// answering: the response is computed with the empty password and the
	// token is sent in auts (RFC 3310 §3.4).
	AUTS []byte
}

// Respond computes the credentials that answer ch for p (RFC 7616 §3.4.1).
// It fails for algorithms and qop values this package does not implement,
// leaving the caller to try another challenge.
func Respond(ch Challenge, p ClientParams) (Credentials, error) {
	alg := ch.Algorithm
	if alg == "" {
		alg = MD5
	}
	switch {
	case !alg.supported():
		return Credentials{}, ErrUnsupportedAlgorithm
	case !ch.offersAuth():
		return Credentials{}, ErrUnsupportedQOP
	case p.NC == 0:
		return Credentials{}, errors.New("digest: nonce count starts at 1")
	case p.CNonce == "":
		return Credentials{}, errors.New("digest: cnonce is required with qop=auth")
	case p.AUTS != nil && alg != AKAv1MD5:
		return Credentials{}, errors.New("digest: auts is only defined for Digest AKA")
	case p.AUTS != nil && len(p.AUTS) != 14:
		return Credentials{}, errors.New("digest: AUTS is 14 bytes")
	}
	for _, v := range []string{p.Username, p.URI, p.CNonce, p.Method, ch.Realm, ch.Nonce, ch.Opaque} {
		if !representable(v) {
			return Credentials{}, errors.New("digest: value contains a control character")
		}
	}
	password := p.Password
	if p.AUTS != nil {
		password = nil
	}
	h := ha1(alg, p.Username, ch.Realm, password)
	return Credentials{
		Username:  p.Username,
		Realm:     ch.Realm,
		Nonce:     ch.Nonce,
		URI:       p.URI,
		Response:  response(alg, h, ch.Nonce, formatNC(p.NC), p.CNonce, QOPAuth, p.Method, p.URI),
		Algorithm: alg,
		CNonce:    p.CNonce,
		NC:        p.NC,
		QOP:       QOPAuth,
		Opaque:    ch.Opaque,
		AUTS:      append([]byte(nil), p.AUTS...),
	}, nil
}

// NewCNonce returns a client nonce of 128 random bits from r (normally
// crypto/rand.Reader).
func NewCNonce(r io.Reader) (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("digest: generating a cnonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const redactedClientParams = "digest.ClientParams{redacted}"

// String returns a fixed placeholder: the password must not reach a log.
func (p ClientParams) String() string { return redactedClientParams }

// GoString returns the same placeholder as String.
func (p ClientParams) GoString() string { return redactedClientParams }

// Format makes every fmt verb produce the placeholder.
func (p ClientParams) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedClientParams) }

// LogValue keeps log/slog handlers from serialising the fields.
func (p ClientParams) LogValue() slog.Value { return slog.StringValue(redactedClientParams) }

// MarshalJSON emits the placeholder, because a value nested in another one
// reaches a JSON log handler through encoding/json, which ignores LogValue.
func (p ClientParams) MarshalJSON() ([]byte, error) { return json.Marshal(redactedClientParams) }
