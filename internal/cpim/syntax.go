package cpim

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

func checkRequire(v string) error {
	for name := range strings.SplitSeq(v, ",") {
		if !isHeaderName(strings.Trim(name, " ")) {
			return reject(ReasonValue, "Require lists an invalid header name")
		}
	}
	return nil
}

// usesBareLF reports whether data ends its first line with a bare LF. RFC 3862
// §2.2 requires CRLF, but a writer that uses LF throughout is unambiguous,
// so Parse reads such headers rather than reject them. A message whose
// headers mix the two is still rejected.
func usesBareLF(data []byte) bool {
	i := bytes.IndexByte(data, '\n')
	return i >= 0 && (i == 0 || data[i-1] != '\r')
}

// nextLine splits data at the first line end: CRLF, or LF when lf is set. A
// stray CR or LF stays inside the line, where checkChars reports it as mixed
// line endings.
func nextLine(data []byte, lf bool) (line, rest []byte, ok bool) {
	if lf {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return nil, nil, false
		}
		return data[:i], data[i+1:], true
	}
	i := bytes.Index(data, []byte("\r\n"))
	if i < 0 {
		return nil, nil, false
	}
	return data[:i], data[i+2:], true
}

// checkChars rejects invalid UTF-8 and control characters (RFC 3862 §2.2),
// optionally allowing horizontal tab.
func checkChars(s string, allowTab bool) error {
	if !utf8.ValidString(s) {
		return reject(ReasonEncoding, "header is not UTF-8")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\r' || c == '\n':
			return reject(ReasonLineEnding, "CRLF and LF line ends are mixed")
		case c == '\t' && allowTab:
		case c < 0x20 || c == 0x7f:
			return reject(ReasonControl, "control character in header")
		}
	}
	return nil
}

// parseHeaderLine parses Header-name ":" *( ";" Parameter ) SP Header-value
// (RFC 3862 §3.6), reading the value leniently: any amount of space or tab
// around it, including none, is not part of the value, and the value may be
// empty. Nothing else about the grammar is relaxed. checkHeader holds what
// Marshal writes to the exact grammar.
func parseHeaderLine(line string) (Header, error) {
	if err := checkChars(line, true); err != nil {
		return Header{}, err
	}
	name, rest, ok := strings.Cut(line, ":")
	if !ok || !isHeaderName(name) {
		return Header{}, reject(ReasonHeaderName, "invalid header name")
	}
	_, n, err := parseParams(rest)
	if err != nil {
		return Header{}, err
	}
	params, value := rest[:n], strings.Trim(rest[n:], " \t")
	if strings.ContainsRune(params, '\t') || strings.ContainsRune(value, '\t') {
		return Header{}, reject(ReasonControl, "control character in header")
	}
	return Header{Name: name, Params: params, Value: value}, nil
}

// layoutDeviations reports how line, which parsed to h, departs from the
// canonical Name ":" Params SP Value layout.
func layoutDeviations(line string, h Header) Deviation {
	after := line[len(h.Name)+1+len(h.Params):]
	if h.Value == "" {
		return DeviationEmptyValue
	}
	var d Deviation
	lead := len(after) - len(strings.TrimLeft(after, " \t"))
	if after[:lead] != " " {
		d |= DeviationSpacing
	}
	if len(strings.TrimRight(after, " \t")) != len(after) {
		d |= DeviationTrailingWS
	}
	return d
}

// checkHeader reports whether Marshal can write h as one canonical line,
// exactly one space after the colon and no white space at either end (RFC
// 3862 §2.2), that parses back to exactly h. A canonical line cannot carry an
// empty value: it would end in a space.
func checkHeader(h Header) error {
	if h.Value == "" {
		return reject(ReasonValue, "an empty value cannot be written")
	}
	parsed, err := parseHeaderLine(h.Name + ":" + h.Params + " " + h.Value)
	if err != nil {
		return err
	}
	if parsed != h {
		return reject(ReasonValue, "header fields do not survive serialization")
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
			return nil, 0, reject(ReasonParameter, "invalid header parameter")
		}
		var value string
		end := eq + 1
		if end < len(s) && s[end] == '"' {
			q := quotedEnd(s, end)
			if q < 0 {
				return nil, 0, reject(ReasonParameter, "unterminated quoted header parameter")
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
				return nil, 0, reject(ReasonParameter, "empty header parameter value")
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
		return Field{}, reject(ReasonHeaderName, "invalid content header name")
	}
	value = strings.Trim(value, " \t")
	if err := checkChars(value, true); err != nil {
		return Field{}, err
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
		return reject(ReasonValue, "content header has surrounding white space")
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
