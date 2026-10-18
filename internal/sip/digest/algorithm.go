package digest

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strings"
)

// Algorithm is the value of the algorithm parameter, spelled as on the wire.
type Algorithm string

// The algorithms this package implements. MD5 stays because RFC 3261 and
// RFC 3310 define Digest and Digest AKA with it and many SIP clients offer
// nothing else; ChallengeHTTP offers SHA-256 first (RFC 8760 §2.3).
const (
	MD5      Algorithm = "MD5"       // RFC 7616 §3.3; the default when the parameter is absent
	SHA256   Algorithm = "SHA-256"   // RFC 7616 §3.3, RFC 8760 §2.1
	AKAv1MD5 Algorithm = "AKAv1-MD5" // RFC 3310 §3.1: MD5 with RES as the password
)

// parseAlgorithm maps a wire value to a supported Algorithm. Matching ignores
// case, since RFC 7616 §3.3 does not make the token case-sensitive and clients
// differ. An absent parameter means MD5 (RFC 7616 §3.3, RFC 3310 §3.1).
func parseAlgorithm(s string) (Algorithm, bool) {
	switch {
	case s == "":
		return MD5, true
	case strings.EqualFold(s, string(MD5)):
		return MD5, true
	case strings.EqualFold(s, string(SHA256)):
		return SHA256, true
	case strings.EqualFold(s, string(AKAv1MD5)):
		return AKAv1MD5, true
	}
	return "", false
}

// newHash returns the hash function H of RFC 7616 §3.4 for a, or nil when a
// is not supported.
func (a Algorithm) newHash() func() hash.Hash {
	switch a {
	case MD5, AKAv1MD5:
		return md5.New
	case SHA256:
		return sha256.New
	}
	return nil
}

func (a Algorithm) supported() bool { return a.newHash() != nil }

// hexLen is the length of a hex digest under a.
func (a Algorithm) hexLen() int { return 2 * a.newHash()().Size() }

// h returns the lower-case hex digest of the parts joined by colons, which is
// every H(...) and KD(...) of RFC 7616 §3.4.1 to §3.4.3.
func (a Algorithm) h(parts ...[]byte) string {
	d := a.newHash()()
	for i, p := range parts {
		if i > 0 {
			d.Write([]byte{':'})
		}
		d.Write(p)
	}
	return hex.EncodeToString(d.Sum(nil))
}

// ha1 computes H(username:realm:password) (RFC 7616 §3.4.2). For AKAv1-MD5
// the password is the raw RES (RFC 3310 §3.3).
func ha1(a Algorithm, username, realm string, password []byte) string {
	return a.h([]byte(username), []byte(realm), password)
}

// response computes the request-digest for qop=auth (RFC 7616 §3.4.1):
// KD(HA1, nonce:nc:cnonce:qop:H(method:uri)).
func response(a Algorithm, ha1, nonce, nc, cnonce, qop, method, uri string) string {
	ha2 := a.h([]byte(method), []byte(uri))
	return a.h([]byte(ha1), []byte(nonce), []byte(nc), []byte(cnonce), []byte(qop), []byte(ha2))
}
