package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"
)

// Nonce layouts.
//
//	Digest:          kind ‖ issued ‖ random(16) ‖ tag, base64url without padding
//	AKA (default):   RAND ‖ AUTN, base64
//	AKA, opt-in:     RAND ‖ AUTN ‖ kind ‖ issued ‖ tag, base64
//
// A Digest nonce carries its issue time (Unix seconds, big-endian) and an
// HMAC-SHA-256 tag, truncated to 128 bits, over the kind, the realm, the time
// and the body. It therefore verifies on any instance holding the key, cannot
// be moved to another realm and cannot be given a later time.
//
// The default AKA nonce is exactly the 32 bytes of RAND ‖ AUTN. RFC 3310 §3.2
// allows server data after them, but many deployed UE stacks decode only the
// bare form. AKA does not need the tag either: scscf keeps the issued vector
// in auth-challenges, keyed by IMPI and nonce, with its own expiry (ADR 0005).
// ServerConfig.AKAServerData restores the time and tag for deployments that
// want them.
const (
	kindDigest byte = 1
	kindAKA    byte = 2

	randSize       = 16
	autnSize       = 16
	issuedSize     = 8
	tagSize        = 16
	nonceRandSize  = 16
	digestNonceLen = 1 + issuedSize + nonceRandSize + tagSize
	akaPlainLen    = randSize + autnSize
	akaTaggedLen   = akaPlainLen + 1 + issuedSize + tagSize

	// maxClockSkew is how far in the future an issue time may lie, because
	// the instance that issued the nonce may run slightly ahead of the one
	// verifying it.
	maxClockSkew = 30 * time.Second
)

// Labels keep the nonce tag and the opaque value from ever being computed
// over the same HMAC input.
const (
	labelNonce  = "rcs-platform/sip/digest nonce v1\x00"
	labelOpaque = "rcs-platform/sip/digest opaque v1\x00"
)

func (s *Server) nonceTag(kind byte, issued []byte, body []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(labelNonce))
	m.Write([]byte{kind})
	var realmLen [2]byte
	binary.BigEndian.PutUint16(realmLen[:], uint16(len(s.realm)))
	m.Write(realmLen[:])
	m.Write([]byte(s.realm))
	m.Write(issued)
	m.Write(body)
	return m.Sum(nil)[:tagSize]
}

func (s *Server) issuedNow() []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(s.now().Unix()))
}

func (s *Server) newDigestNonce() (string, error) {
	random := make([]byte, nonceRandSize)
	if _, err := io.ReadFull(s.random, random); err != nil {
		return "", err
	}
	issued := s.issuedNow()
	b := make([]byte, 0, digestNonceLen)
	b = append(b, kindDigest)
	b = append(b, issued...)
	b = append(b, random...)
	b = append(b, s.nonceTag(kindDigest, issued, random)...)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) newAKANonce(rand, autn []byte) string {
	body := append(append(make([]byte, 0, akaTaggedLen), rand...), autn...)
	if !s.akaServerData {
		return base64.StdEncoding.EncodeToString(body)
	}
	issued := s.issuedNow()
	b := append(body, kindAKA)
	b = append(b, issued...)
	b = append(b, s.nonceTag(kindAKA, issued, body[:akaPlainLen])...)
	return base64.StdEncoding.EncodeToString(b)
}

// checkNonce verifies that nonce has the form this server issues for alg and,
// where the form has a tag, that this server issued it for this realm. It
// returns the issue time, or the zero time for the default AKA form, which
// carries none.
func (s *Server) checkNonce(alg Algorithm, nonce string) (time.Time, error) {
	if alg == AKAv1MD5 {
		return s.checkAKANonce(nonce)
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil || len(b) != digestNonceLen || b[0] != kindDigest {
		return time.Time{}, ErrInvalidNonce
	}
	issued := b[1 : 1+issuedSize]
	body, tag := b[1+issuedSize:1+issuedSize+nonceRandSize], b[1+issuedSize+nonceRandSize:]
	return s.checkTag(kindDigest, issued, body, tag)
}

// checkAKANonce accepts only the form the server is configured to issue, so a
// nonce of the other form, which this server never handed out, is invalid.
func (s *Server) checkAKANonce(nonce string) (time.Time, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(nonce)
	if err != nil {
		return time.Time{}, ErrInvalidNonce
	}
	if !s.akaServerData {
		if len(b) != akaPlainLen {
			return time.Time{}, ErrInvalidNonce
		}
		return time.Time{}, nil
	}
	if len(b) != akaTaggedLen || b[akaPlainLen] != kindAKA {
		return time.Time{}, ErrInvalidNonce
	}
	issued := b[akaPlainLen+1 : akaPlainLen+1+issuedSize]
	return s.checkTag(kindAKA, issued, b[:akaPlainLen], b[akaPlainLen+1+issuedSize:])
}

func (s *Server) checkTag(kind byte, issued, body, tag []byte) (time.Time, error) {
	if !hmac.Equal(tag, s.nonceTag(kind, issued, body)) {
		return time.Time{}, ErrInvalidNonce
	}
	at := time.Unix(int64(binary.BigEndian.Uint64(issued)), 0)
	if at.After(s.now().Add(maxClockSkew)) {
		return time.Time{}, ErrInvalidNonce
	}
	return at, nil
}

// opaqueFor derives the opaque value from the nonce, so it needs no storage
// and a client cannot pair a nonce with another nonce's opaque. For the
// default AKA nonce, which has no tag, it is also what shows that this server
// issued the nonce before scscf looks the vector up.
func (s *Server) opaqueFor(nonce string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(labelOpaque))
	m.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:12])
}

// ParseAKANonce extracts RAND and AUTN from the nonce of an AKAv1-MD5
// challenge (RFC 3310 §3.2), for the client side. Server data after them, if
// a server sends any, is ignored, as it is meaningful only to that server.
func ParseAKANonce(nonce string) (rand, autn [16]byte, err error) {
	if len(nonce) > MaxHeaderLength {
		return rand, autn, malformed("AKA nonce too long")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(nonce)
	if err != nil || len(b) < randSize+autnSize {
		return rand, autn, malformed("AKA nonce does not hold RAND and AUTN")
	}
	copy(rand[:], b[:randSize])
	copy(autn[:], b[randSize:randSize+autnSize])
	return rand, autn, nil
}
