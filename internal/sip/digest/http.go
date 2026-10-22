package digest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrNoCredentials means an HTTP request carries no Authorization header
// field with the Digest scheme.
var ErrNoCredentials = errors.New("digest: no Digest credentials")

// ErrURIMismatch means the uri parameter does not name the request target,
// which RFC 7616 §3.4.6 requires of HTTP. The RFC suggests answering 400; that
// reveals nothing about the user, because the check runs before any lookup.
var ErrURIMismatch = errors.New("digest: uri is not the request target")

// SecretLookup returns the secret of username for credentials under alg. An
// error, such as an unknown user, makes verification fail with that error
// wrapped.
type SecretLookup func(ctx context.Context, username string, alg Algorithm) (Secret, error)

// VerifyHTTP authenticates an HTTP request with the same rules as Verify, plus
// the request-target check HTTP requires. On success it returns the
// credentials, whose Username is the authenticated user.
//
// lookup runs only after the nonce and opaque have verified, so a forged
// nonce costs no lookup. A genuine nonce is free to obtain, though, so lookup
// can still run for any username a client sends, and its error comes back
// wrapped. Callers must answer every error except ErrStaleNonce (and, if they
// wish, ErrURIMismatch) with the same 401 from ChallengeHTTP, with no
// difference in body or timing they can avoid, so that a client cannot tell
// which usernames exist.
//
// A client that reuses a nonce may have its requests verified out of
// nonce-count order: each count is accepted once inside NonceCountWindow
// (UsedCounts), so a request overtaken by a later one still verifies. A count
// already used, or one below the window, fails with ErrReplayed and the
// client is re-challenged. Digest AKA is refused:
// over HTTP it belongs to GBA, which this package does not implement.
func (s *Server) VerifyHTTP(r *http.Request, lookup SecretLookup) (Credentials, error) {
	var values []string
	for _, v := range r.Header.Values("Authorization") {
		if isDigestScheme(v) {
			values = append(values, v)
		}
	}
	switch len(values) {
	case 0:
		return Credentials{}, ErrNoCredentials
	case 1:
	default:
		return Credentials{}, malformed("more than one Digest Authorization field")
	}
	c, err := ParseCredentials(values[0])
	if err != nil {
		return Credentials{}, err
	}
	if c.Algorithm == AKAv1MD5 {
		return Credentials{}, ErrUnsupportedAlgorithm
	}
	if target := requestTarget(r); c.URI != target && !(s.httpPathOnlyURI && isPathOf(c.URI, target)) {
		return Credentials{}, ErrURIMismatch
	}
	issued, err := s.precheck(c)
	if err != nil {
		return Credentials{}, err
	}
	secret, err := lookup(r.Context(), c.Username, c.Algorithm)
	if err != nil {
		return Credentials{}, fmt.Errorf("digest: looking up the secret: %w", err)
	}
	if err := s.verifyDigest(r.Context(), r.Method, c, secret, issued); err != nil {
		return Credentials{}, err
	}
	return c, nil
}

// PathOnlyURI reports whether c's uri names only the path of r's request
// target, the form ServerConfig.HTTPPathOnlyURI lets VerifyHTTP accept, so a
// caller can count how often it does.
func PathOnlyURI(r *http.Request, c Credentials) bool {
	target := requestTarget(r)
	return c.URI != target && isPathOf(c.URI, target)
}

func requestTarget(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	return r.URL.RequestURI()
}

// isPathOf reports whether uri is target up to, not including, its '?':
// the absolute-path RFC 7616 §3.4.6 allows the uri to be. A uri with a query
// of its own, or with any other path, is not.
func isPathOf(uri, target string) bool {
	path, _, hasQuery := strings.Cut(target, "?")
	return hasQuery && uri == path
}

// ChallengeHTTP answers 401 with a SHA-256 and an MD5 challenge, in that order
// of preference (RFC 7616 §3.7). Set stale when VerifyHTTP returned
// ErrStaleNonce. Nothing is written if a nonce cannot be generated.
//
// The order is also what keeps MD5-only clients working: the GSMA rcsjta
// client reads only the last WWW-Authenticate field (HttpURLConnection's
// getHeaderField) and answers it as MD5 without an algorithm parameter, so
// MD5 must stay the last field.
func (s *Server) ChallengeHTTP(w http.ResponseWriter, stale bool) error {
	var values []string
	for _, alg := range []Algorithm{SHA256, MD5} {
		c, err := s.Challenge(alg, stale)
		if err != nil {
			return err
		}
		values = append(values, c.Header())
	}
	for _, v := range values {
		w.Header().Add("WWW-Authenticate", v)
	}
	w.WriteHeader(http.StatusUnauthorized)
	return nil
}

func isDigestScheme(v string) bool {
	v = strings.TrimLeft(v, " \t")
	const scheme = "Digest"
	return len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) && isWSP(v[len(scheme)])
}
