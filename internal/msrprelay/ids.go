package msrprelay

import (
	"crypto/sha256"
	"encoding/base32"
)

// idEncoding is lower-case RFC 4648 base32 without padding, the alphabet
// internal/msrp uses for session ids.
var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// bindingIDLen is the length of a SHA-256 digest in idEncoding.
const bindingIDLen = 52

// BindingID returns the id of the binding whose client-side URI carries
// sessionID: SHA-256 of the session id. The session id is the only secret
// that lets a client connection into a session (ADR 0004, RFC 4975 §14.1),
// so it is kept out of the table and out of the control API's URLs, where
// access logs, a table export or a stack trace could expose it; the relay
// still finds the binding from the To-Path of the client's first SEND.
func BindingID(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return idEncoding.EncodeToString(sum[:])
}

// validBindingID reports whether s can be a binding id at all, so a
// malformed one is answered without a store call.
func validBindingID(s string) bool {
	if len(s) != bindingIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || '2' <= c && c <= '7') {
			return false
		}
	}
	return true
}
