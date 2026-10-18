package sip

import (
	"strings"
	"unicode/utf8"
)

// Character classes of the RFC 3261 §25.1 grammar (and RFC 3966 for tel numbers).
// They are a table because the parser consults one for nearly every byte.
const (
	classToken     uint16 = 1 << iota // token
	classWord                         // word, the alphabet of Call-ID
	classUser                         // user part of a SIP URI, besides escapes
	classPassword                     // password of a SIP URI, besides escapes
	classParam                        // paramchar of a URI parameter, besides escapes
	classURIHeader                    // hname and hvalue of a URI header, besides escapes
	classGenValue                     // unquoted header parameter value: token or host
	classURIC                         // absoluteURI of any other scheme, besides escapes
	classTelNumber                    // phonedigit-hex and the leading "+" of a tel number
	classTelPName                     // pname of a tel URI parameter
)

var charClasses = func() (t [256]uint16) {
	set := func(cls uint16, chars string) {
		for i := 0; i < len(chars); i++ {
			t[chars[i]] |= cls
		}
	}
	const (
		alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		mark  = "-_.!~*'()"
		token = alnum + "-.!%*_+`'~"
	)
	set(classToken, token)
	set(classWord, token+"()<>:\\\"/[]?{}")
	set(classUser, alnum+mark+"&=+$,;?/")
	set(classPassword, alnum+mark+"&=+$,")
	set(classParam, alnum+mark+"[]/:&+$")
	set(classURIHeader, alnum+mark+"[]/?:+$")
	set(classGenValue, token+":[]")
	set(classURIC, alnum+mark+";/?:@&=+$,[]")
	set(classTelNumber, "0123456789abcdefABCDEF*#-.()+")
	set(classTelPName, alnum+"-")
	return t
}()

const upperHex = "0123456789ABCDEF"

// invalidValue is what the String methods of the value types write for a part
// that has no valid form, such as a host with a space, a tel number with a
// letter or a parameter name that is not a token. It is a NUL byte, which
// Header.Add, Set and Prepend refuse and Request.Bytes refuses on the start line.
// A value built wrongly in code therefore fails where it is added, and cannot
// reach the wire as something else: a host of "p.example.com>,<sip:x" would
// otherwise add a hop to a Route.
const invalidValue = "\x00"

func in(c byte, cls uint16) bool { return charClasses[c]&cls != 0 }

// isAll reports whether s is non-empty and made only of characters in cls.
func isAll(s string, cls uint16) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !in(s[i], cls) {
			return false
		}
	}
	return true
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

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

func isAlpha(c byte) bool {
	u := c &^ 0x20 // upper-case an ASCII letter
	return 'A' <= u && u <= 'Z'
}

func isAlnum(c byte) bool { return isAlpha(c) || '0' <= c && c <= '9' }

// isEscape reports whether s[i:] starts with a well-formed "%" HEXDIG HEXDIG.
func isEscape(s string, i int) bool {
	return s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2])
}

// validEscaped reports whether every byte of s is in cls or part of an escape.
// The empty string is valid; callers that need content check for it.
func validEscaped(s string, cls uint16) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case isEscape(s, i):
			i += 2
		case s[i] == '%' || !in(s[i], cls):
			return false
		}
	}
	return true
}

// appendEscaped writes s escaping every byte outside cls. A well-formed escape is
// copied as is, so escaping text that was parsed is a no-op and escaping twice is
// the same as escaping once.
func appendEscaped(b []byte, s string, cls uint16) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isEscape(s, i):
			b = append(b, s[i:i+3]...)
			i += 2
		case c != '%' && in(c, cls):
			b = append(b, c)
		default:
			b = append(b, '%', upperHex[c>>4], upperHex[c&15])
		}
	}
	return b
}

// isReserved reports whether c is in the RFC 2396 reserved set, whose escaped and
// plain forms RFC 3261 §19.1.4 does not treat as equal.
func isReserved(c byte) bool { return strings.IndexByte(";/?:@&=+$,", c) >= 0 }

// normalizeEscapes rewrites s so that two spellings RFC 3261 §19.1.4 treats as
// equal compare equal: an escaped character outside the reserved set is decoded,
// and the hex digits of the escapes that remain are upper-cased. "%25" stays
// escaped so a decoded "%" can never be mistaken for the start of an escape.
func normalizeEscapes(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !isEscape(s, i) {
			b = append(b, s[i])
			continue
		}
		c := unhex(s[i+1])<<4 | unhex(s[i+2])
		if c == '%' || isReserved(c) {
			b = append(b, '%', upperHex[c>>4], upperHex[c&15])
		} else {
			b = append(b, c)
		}
		i += 2
	}
	return string(b)
}

// unescape decodes every escape in s. It is used only to read a telephone number
// out of a user part; comparison uses normalizeEscapes.
func unescape(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if isEscape(s, i) {
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

// isCTL reports a control character other than HTAB.
func isCTL(c byte) bool { return c < 0x20 && c != '\t' || c == 0x7f }

// validFieldValue checks a header field value, unfolded, against what
// docs/architecture.md §8 lets through: valid UTF-8 and no control character
// other than HTAB (RFC 3261 §25.1 TEXT-UTF8char), except as the second byte of a
// quoted-pair inside a quoted string, which RFC 4475 §3.1.1.2 shows is valid. CR
// and LF are refused even there: quoted-pair excludes them.
func validFieldValue(v string) bool {
	inQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case inQuote && c == '\\':
			if i+1 == len(v) || v[i+1] == '\r' || v[i+1] == '\n' {
				return false
			}
			i++
		case c == '"':
			inQuote = !inQuote
		case isCTL(c):
			return false
		}
	}
	return utf8.ValidString(v)
}

// lowerASCII lower-cases ASCII letters only. Unlike strings.ToLower it leaves
// other bytes alone, so two different invalid UTF-8 sequences never compare
// equal, and it does not allocate when there is nothing to change.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func isWS(c byte) bool { return c == ' ' || c == '\t' }

// skipWS skips SP and HTAB. Header values reach the value parsers unfolded, so
// this is all the LWS of RFC 3261 §25.1 there is to skip.
func skipWS(s string, i int) int {
	for i < len(s) && isWS(s[i]) {
		i++
	}
	return i
}

func trimWS(s string) string {
	i, j := 0, len(s)
	for i < j && isWS(s[i]) {
		i++
	}
	for j > i && isWS(s[j-1]) {
		j--
	}
	return s[i:j]
}

func scanClass(s string, i int, cls uint16) int {
	for i < len(s) && in(s[i], cls) {
		i++
	}
	return i
}

// parseQuoted reads the quoted-string that starts at s[i] (which must be '"') and
// returns its content with quoted-pairs resolved and the index after the closing
// quote. It allocates only when a quoted-pair has to be resolved.
func parseQuoted(s string, i int) (string, int, bool) {
	i++
	start := i
	var b []byte
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			if b == nil {
				return s[start:i], i + 1, true
			}
			return string(b), i + 1, true
		case c == '\\':
			// quoted-pair excludes CR and LF (RFC 3261 §25.1).
			if i+1 >= len(s) || s[i+1] == '\r' || s[i+1] == '\n' {
				return "", 0, false
			}
			if b == nil {
				b = append(make([]byte, 0, len(s)-start), s[start:i]...)
			}
			b = append(b, s[i+1])
			i += 2
		case isCTL(c):
			// qdtext excludes control characters other than HTAB.
			return "", 0, false
		default:
			if b != nil {
				b = append(b, c)
			}
			i++
		}
	}
	return "", 0, false
}

// appendQuoted writes s as a quoted-string. Characters qdtext cannot carry are
// written as quoted-pairs. CR and LF cannot be represented at all; they are
// written as invalid quoted-pairs so that Header.Add, which refuses CR and LF,
// rejects the value instead of letting it split a header line.
func appendQuoted(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' || isCTL(c) {
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	return append(b, '"')
}

// splitList splits a header field value into the elements of a comma-separated
// list (RFC 3261 §7.3.1). Commas inside quoted strings and angle brackets do not
// separate elements. An empty element is an error: the grammar has none, and the
// RFC 4475 §3.1.2.1 message shows how they are used to confuse parsers.
func splitList(v string) ([]string, error) {
	var out []string
	start, inQuote, inAngle := 0, false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case inAngle:
			if c == '>' {
				inAngle = false
			}
		case inQuote:
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
		case c == '<':
			inAngle = true
		case c == ',':
			el := trimWS(v[start:i])
			if el == "" {
				return nil, syntaxError("empty list element")
			}
			out = append(out, el)
			start = i + 1
		}
	}
	if inQuote || inAngle {
		return nil, syntaxError("unterminated quoted string or angle bracket")
	}
	el := trimWS(v[start:])
	if el == "" {
		return nil, syntaxError("empty list element")
	}
	return append(out, el), nil
}
