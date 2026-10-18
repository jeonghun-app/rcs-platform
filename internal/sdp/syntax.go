package sdp

import (
	"strconv"
	"strings"
)

// The character classes below are the ones RFC 8866 §9 builds every field
// from. Parse and Validate share them, so anything the parser accepts can be
// serialized and anything a caller builds is held to the same rules.

// tokenChars lists the token-char punctuation of RFC 8866 §9.
const tokenChars = "!#$%&'*+-.^_`{|}~"

func isTokenChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.IndexByte(tokenChars, c) >= 0
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isNonWS reports whether s is a non-ws-string: visible ASCII or any byte of a
// UTF-8 sequence, no space, no control character.
func isNonWS(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// isText reports whether s is a byte-string: anything but NUL, CR and LF, and
// at least one byte. Excluding CR and LF is what stops a value from injecting a
// line into the output.
func isText(s string) bool {
	return s != "" && !strings.ContainsAny(s, "\x00\r\n")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseUint accepts only ASCII digits; strconv alone would also accept a sign
// or underscores in some of its entry points, which SDP never allows.
func parseUint(s string) (uint64, bool) {
	if !isDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// parseInt64 is parseUint limited to the non-negative int64 range, for sizes
// that callers compare with int64 lengths.
func parseInt64(s string) (int64, bool) {
	if !isDigits(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// isProto reports whether s is a transport protocol: tokens joined by "/"
// (RFC 8866 §9, proto).
func isProto(s string) bool {
	for _, part := range strings.Split(s, "/") {
		if !isToken(part) {
			return false
		}
	}
	return true
}

// isTypedTime reports whether s is a typed-time: digits with an optional d, h,
// m or s unit (RFC 8866 §5.10).
func isTypedTime(s string) bool {
	if n := len(s); n > 1 && strings.IndexByte("dhms", s[n-1]) >= 0 {
		s = s[:n-1]
	}
	return isDigits(s)
}
