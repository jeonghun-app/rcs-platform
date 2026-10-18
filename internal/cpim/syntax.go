package cpim

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"
)

func checkRequire(v string) error {
	for name := range strings.SplitSeq(v, ",") {
		if !isHeaderName(strings.Trim(name, " ")) {
			return fmt.Errorf("%w: Require lists an invalid header name", ErrMalformed)
		}
	}
	return nil
}

// nextLine splits data at the first CRLF, the only line terminator RFC 3862
// §2.2 allows. A bare CR or LF stays inside the line, where the control
// character checks reject it.
func nextLine(data []byte) (line, rest []byte, ok bool) {
	i := bytes.Index(data, []byte("\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	return data[:i], data[i+2:], true
}

// parseHeaderLine parses Header-name ":" *( ";" Parameter ) SP Header-value
// (RFC 3862 §3.6).
func parseHeaderLine(line string) (Header, error) {
	if !utf8.ValidString(line) {
		return Header{}, fmt.Errorf("%w: header is not UTF-8", ErrMalformed)
	}
	// §2.2: control characters are written as escape sequences.
	if hasControl(line, false) {
		return Header{}, fmt.Errorf("%w: control character in header", ErrMalformed)
	}
	name, rest, ok := strings.Cut(line, ":")
	if !ok || !isHeaderName(name) {
		return Header{}, fmt.Errorf("%w: invalid header name", ErrMalformed)
	}
	_, n, err := parseParams(rest)
	if err != nil {
		return Header{}, err
	}
	params, rest := rest[:n], rest[n:]
	// §2.2: exactly one space after the colon and no white space at the end
	// of the line, which also rules out an empty value.
	value, ok := strings.CutPrefix(rest, " ")
	if !ok || value == "" || value[0] == ' ' || value[len(value)-1] == ' ' {
		return Header{}, fmt.Errorf("%w: header %s needs one space before a value without surrounding white space", ErrMalformed, name)
	}
	return Header{Name: name, Params: params, Value: value}, nil
}

// checkHeader reports whether Marshal can write h as one line that parses back
// to exactly h.
func checkHeader(h Header) error {
	parsed, err := parseHeaderLine(h.Name + ":" + h.Params + " " + h.Value)
	if err != nil {
		return err
	}
	if parsed != h {
		return fmt.Errorf("%w: header fields do not survive serialization", ErrMalformed)
	}
	return nil
}

type param struct {
	name  string
	value string
}

// parseParams parses the *( ";" Parameter ) prefix of s and returns the
// parameters and the number of bytes they occupy.
func parseParams(s string) ([]param, int, error) {
	var out []param
	i := 0
	for i < len(s) && s[i] == ';' {
		start := i + 1
		eq := start
		for eq < len(s) && isNameChar(s[eq]) {
			eq++
		}
		if eq == start || eq >= len(s) || s[eq] != '=' {
			return nil, 0, fmt.Errorf("%w: invalid header parameter", ErrMalformed)
		}
		var value string
		end := eq + 1
		if end < len(s) && s[end] == '"' {
			q := quotedEnd(s, end)
			if q < 0 {
				return nil, 0, fmt.Errorf("%w: unterminated quoted header parameter", ErrMalformed)
			}
			value = Unescape(s[end+1 : q-1])
			end = q
		} else {
			for end < len(s) {
				r, size := utf8.DecodeRuneInString(s[end:])
				if !isTokenRune(r) {
					break
				}
				end += size
			}
			if end == eq+1 {
				return nil, 0, fmt.Errorf("%w: empty header parameter value", ErrMalformed)
			}
			value = s[eq+1 : end]
		}
		out = append(out, param{name: s[start:eq], value: value})
		i = end
	}
	return out, i, nil
}

// quotedEnd returns the index just past the DQUOTE closing the quoted string
// that starts at s[start], or -1. A backslash escapes the next character, so
// \" does not close the string (§3.6 String).
func quotedEnd(s string, start int) int {
	for i := start + 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

// parseFieldLine parses a MIME header, whose syntax is looser than a message
// header's: case-insensitive name, optional white space around the value
// (RFC 5322 §2.2).
func parseFieldLine(line string) (Field, error) {
	name, value, ok := strings.Cut(line, ":")
	if !ok || !isFieldName(name) {
		return Field{}, fmt.Errorf("%w: invalid content header name", ErrMalformed)
	}
	value = strings.Trim(value, " \t")
	if !utf8.ValidString(value) || hasControl(value, true) {
		return Field{}, fmt.Errorf("%w: invalid character in content header %s", ErrMalformed, name)
	}
	return Field{Name: name, Value: value}, nil
}

// checkField reports whether Marshal can write f so that it parses back to f.
func checkField(f Field) error {
	parsed, err := parseFieldLine(f.Name + ": " + f.Value)
	if err != nil {
		return err
	}
	if parsed != f {
		return fmt.Errorf("%w: content header %s has surrounding white space", ErrMalformed, f.Name)
	}
	return nil
}

// isFieldName reports whether s is an RFC 5322 §3.6.8 field name.
func isFieldName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '!' || s[i] > '~' || s[i] == ':' {
			return false
		}
	}
	return true
}

// hasControl reports whether s contains a control character (U+0000-U+001F,
// U+007F), optionally allowing horizontal tab.
func hasControl(s string, allowTab bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 || c == 0x7f) && !(allowTab && c == '\t') {
			return true
		}
	}
	return false
}

// isHeaderName reports whether s is [ Name-prefix "." ] Name (§3.6).
func isHeaderName(s string) bool {
	prefix, name, ok := strings.Cut(s, ".")
	if !ok {
		return isName(s)
	}
	return isName(prefix) && isName(name)
}

// isName reports whether s is 1*NAMECHAR (§3.6).
func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isNameChar(s[i]) {
			return false
		}
	}
	return true
}

// isNameChar reports whether c is a NAMECHAR: US-ASCII except ".", controls
// and separators (§3.1, §3.6).
func isNameChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-^_`|~", c) >= 0
}

// isTokenRune reports whether r is a TOKENCHAR: a NAMECHAR, "." or any
// non-ASCII character (§3.6).
func isTokenRune(r rune) bool {
	if r >= utf8.RuneSelf {
		return true
	}
	return r == '.' || isNameChar(byte(r))
}

// IsToken reports whether s is a Token in the RFC 3862 §3.6 grammar, the
// syntax of values such as the IMDN Message-ID (RFC 5438 §10).
func IsToken(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !isTokenRune(r) {
			return false
		}
	}
	return true
}
