package digest

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ErrNoSecret means Verify was given the zero Secret.
var ErrNoSecret = errors.New("digest: no secret to verify against")

// ErrSecretAlgorithm means a stored HA1 was computed for a different
// algorithm than the client used, so it cannot verify the response.
var ErrSecretAlgorithm = errors.New("digest: HA1 is for another algorithm")

// Secret is what the server knows about a user: either the password (for AKA,
// XRES) or a stored HA1. Build one with Password or HA1. It formats as a
// redacted placeholder.
type Secret struct {
	password []byte
	ha1      string    // lower-case hex
	ha1Alg   Algorithm // empty for a password
	set      bool
}

// Password returns a Secret holding a password, or the XRES of an AKA vector
// (RFC 3310 §3.3: RES takes the place of the password). The bytes are copied.
func Password(p []byte) Secret {
	return Secret{password: append([]byte{}, p...), set: true}
}

// HA1 returns a Secret holding a stored H(username:realm:password) for alg, so
// that the password itself need not be stored (RFC 7616 §5.2). The digest is
// given in hex, in either case.
func HA1(alg Algorithm, hexDigest string) (Secret, error) {
	if !alg.supported() {
		return Secret{}, ErrUnsupportedAlgorithm
	}
	if len(hexDigest) != alg.hexLen() {
		return Secret{}, fmt.Errorf("digest: HA1 for %s must be %d hex digits", alg, alg.hexLen())
	}
	if _, err := hex.DecodeString(hexDigest); err != nil {
		return Secret{}, errors.New("digest: HA1 is not hex")
	}
	return Secret{ha1: strings.ToLower(hexDigest), ha1Alg: alg, set: true}, nil
}

// ComputeHA1 returns H(username:realm:password) in hex, the value an operator
// provisions instead of the password.
func ComputeHA1(alg Algorithm, username, realm string, password []byte) (string, error) {
	if !alg.supported() {
		return "", ErrUnsupportedAlgorithm
	}
	return ha1(alg, username, realm, password), nil
}

// ha1For returns the HA1 to verify a response under alg.
func (s Secret) ha1For(alg Algorithm, username, realm string) (string, error) {
	switch {
	case !s.set:
		return "", ErrNoSecret
	case s.ha1Alg == "":
		return ha1(alg, username, realm, s.password), nil
	case s.ha1Alg != alg:
		return "", ErrSecretAlgorithm
	}
	return s.ha1, nil
}

const redactedSecret = "digest.Secret{redacted}"

// String returns a fixed placeholder.
func (s Secret) String() string { return redactedSecret }

// GoString returns the same placeholder as String.
func (s Secret) GoString() string { return redactedSecret }

// Format makes every fmt verb produce the placeholder.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redactedSecret) }

// LogValue keeps log/slog handlers from serialising the fields.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redactedSecret) }
