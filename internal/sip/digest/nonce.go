package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"
)

// Nonce layouts. Every nonce carries its issue time and an HMAC-SHA-256 tag,
// truncated to 128 bits, over the kind, the realm, the time and the body, so a
// nonce verifies on any instance holding the key and cannot be moved to
// another realm or forged with a later time.
//
//	Digest: kind ‖ issued ‖ random(16) ‖ tag, base64url without padding
//	AKA:    RAND ‖ AUTN ‖ kind ‖ issued ‖ tag, base64 (RFC 3310 §3.2 puts
//	        RAND and AUTN first and calls the rest server data)
//
// issued is Unix seconds, big-endian.
const (
	kindDigest byte = 1
	kindAKA    byte = 2

	randSize       = 16
	autnSize       = 16
	issuedSize     = 8
	tagSize        = 16
	nonceRandSize  = 16
	digestNonceLen = 1 + issuedSize + nonceRandSize + tagSize
	akaNonceLen    = randSize + autnSize + 1 + issuedSize + tagSize

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
	issued := s.issuedNow()
	body := append(append(make([]byte, 0, randSize+autnSize), rand...), autn...)
	b := make([]byte, 0, akaNonceLen)
	b = append(b, body...)
	b = append(b, kindAKA)
	b = append(b, issued...)
	b = append(b, s.nonceTag(kindAKA, issued, body)...)
	return base64.StdEncoding.EncodeToString(b)
}

// checkNonce verifies that nonce was issued by this server for this realm and
// for alg's kind of challenge, and returns when it was issued.
func (s *Server) checkNonce(alg Algorithm, nonce string) (time.Time, error) {
	var kind byte
	var issued, body, tag []byte
	if alg == AKAv1MD5 {
		b, err := base64.StdEncoding.Strict().DecodeString(nonce)
		if err != nil || len(b) != akaNonceLen {
			return time.Time{}, ErrInvalidNonce
		}
		body, kind = b[:randSize+autnSize], b[randSize+autnSize]
		issued = b[randSize+autnSize+1 : randSize+autnSize+1+issuedSize]
		tag = b[randSize+autnSize+1+issuedSize:]
	} else {
		b, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
		if err != nil || len(b) != digestNonceLen {
			return time.Time{}, ErrInvalidNonce
		}
		kind, issued = b[0], b[1:1+issuedSize]
		body, tag = b[1+issuedSize:1+issuedSize+nonceRandSize], b[1+issuedSize+nonceRandSize:]
	}
	want := kindDigest
	if alg == AKAv1MD5 {
		want = kindAKA
	}
	if kind != want || !hmac.Equal(tag, s.nonceTag(kind, issued, body)) {
		return time.Time{}, ErrInvalidNonce
	}
	at := time.Unix(int64(binary.BigEndian.Uint64(issued)), 0)
	if at.After(s.now().Add(maxClockSkew)) {
		return time.Time{}, ErrInvalidNonce
	}
	return at, nil
}

// opaqueFor derives the opaque value from the nonce, so it needs no storage
// and a client cannot pair a nonce with another nonce's opaque.
func (s *Server) opaqueFor(nonce string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(labelOpaque))
	m.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:12])
}

// ParseAKANonce extracts RAND and AUTN from the nonce of an AKAv1-MD5
// challenge (RFC 3310 §3.2), for the client side. Server data after them is
// ignored, as it is meaningful only to the server.
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
