package digest

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// MaxHeaderLength is the longest header field value Parse* accepts. The
// longest legitimate value, an Authorization with a SHA-256 response and a
// long URI, is well under 1 KiB; the limit only stops a peer from making the
// parser work on megabytes.
const MaxHeaderLength = 8192

// maxParams bounds the parameter list for the same reason. RFC 7616 defines
// about a dozen parameters per header.
const maxParams = 64

// ErrMalformed means a header field value does not follow the Digest grammar
// (RFC 7235 §2.1, RFC 3261 §25.1, RFC 7616 §3.3 and §3.4). Errors wrapping it
// name the problem but never quote the input, which can hold identities and
// nonces.
var ErrMalformed = errors.New("digest: malformed header")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

type param struct {
	name  string // lower case: parameter names are case-insensitive (RFC 7235 §2.1)
	value string // unquoted and unescaped
}

// parseHeader splits `Digest name=value, name="value", ...` into parameters.
// Values may be tokens or quoted-strings wherever they appear: RFC 7235
// §5.1.2 expects auth-params to allow both so that one generic parser serves
// every scheme, and clients do send qop="auth" in Authorization. Empty list
// elements (",," or a trailing comma) are skipped, as RFC 7230 §7 requires of
// recipients of the HTTP list rule the auth-params use (RFC 7235 §2.1); SIP
// has no empty elements, so accepting them there costs nothing. Line folding
// (CRLF followed by whitespace, RFC 3261 §7.3.1) counts as whitespace.
// Anything else outside the grammar is an error, never repaired.
func parseHeader(s string) ([]param, error) {
	if len(s) > MaxHeaderLength {
		return nil, malformed("longer than %d bytes", MaxHeaderLength)
	}
	l := lexer{s: s}
	l.skipLWS()
	if scheme := l.token(); !strings.EqualFold(scheme, "Digest") {
		return nil, malformed("scheme is not Digest")
	}
	if l.skipLWS() == 0 {
		return nil, malformed("no parameters after the scheme")
	}
	var params []param
	for {
		l.skipEmptyElements()
		if l.eof() {
			break
		}
		name := l.token()
		if name == "" {
			return nil, malformed("expected a parameter name at offset %d", l.i)
		}
		l.skipLWS()
		if !l.consume('=') {
			return nil, malformed("expected '=' at offset %d", l.i)
		}
		l.skipLWS()
		var value string
		if l.peek() == '"' {
			var err error
			if value, err = l.quotedString(); err != nil {
				return nil, err
			}
		} else if value = l.token(); value == "" {
			return nil, malformed("expected a parameter value at offset %d", l.i)
		}
		params = append(params, param{name: strings.ToLower(name), value: value})
		if len(params) > maxParams {
			return nil, malformed("more than %d parameters", maxParams)
		}
		l.skipLWS()
		if l.eof() {
			break
		}
		if !l.consume(',') {
			return nil, malformed("expected ',' at offset %d", l.i)
		}
	}
	if len(params) == 0 {
		return nil, malformed("no parameters after the scheme")
	}
	return params, nil
}

// pick returns the values of the parameters named in known. A known parameter
// that appears twice is an error (RFC 7235 §2.1); unknown parameters are
// ignored (RFC 7616 §3.3, §3.4).
func pick(params []param, known ...string) (map[string]string, error) {
	out := make(map[string]string, len(known))
	for _, p := range params {
		if !slices.Contains(known, p.name) {
			continue
		}
		if _, dup := out[p.name]; dup {
			return nil, malformed("parameter %s appears twice", p.name)
		}
		out[p.name] = p.value
	}
	return out, nil
}

type lexer struct {
	s string
	i int
}

func (l *lexer) eof() bool { return l.i >= len(l.s) }

func (l *lexer) peek() byte {
	if l.eof() {
		return 0
	}
	return l.s[l.i]
}

func (l *lexer) consume(c byte) bool {
	if !l.eof() && l.s[l.i] == c {
		l.i++
		return true
	}
	return false
}

// skipLWS skips SP, HTAB and folded line breaks, returning how many bytes it
// skipped.
func (l *lexer) skipLWS() int {
	start := l.i
	for !l.eof() {
		switch {
		case l.s[l.i] == ' ' || l.s[l.i] == '\t':
			l.i++
		case l.fold():
			l.i += 2
		default:
			return l.i - start
		}
	}
	return l.i - start
}

// fold reports whether a folded line break (CRLF then SP or HTAB) starts here.
func (l *lexer) fold() bool {
	return strings.HasPrefix(l.s[l.i:], "\r\n") && l.i+2 < len(l.s) && isWSP(l.s[l.i+2])
}

// skipEmptyElements skips whitespace and any commas that only delimit empty
// list elements.
func (l *lexer) skipEmptyElements() {
	for l.skipLWS(); l.consume(','); l.skipLWS() {
	}
}

func (l *lexer) token() string {
	start := l.i
	for !l.eof() && isTokenChar(l.s[l.i]) {
		l.i++
	}
	return l.s[start:l.i]
}

// quotedString reads a quoted-string (RFC 7230 §3.2.6, RFC 3261 §25.1) with
// the opening quote at the current position and returns its unescaped
// content. A folded line break inside becomes a single space, as RFC 7230
// §3.2.4 says recipients should treat it.
func (l *lexer) quotedString() (string, error) {
	l.i++ // opening quote
	var b strings.Builder
	for !l.eof() {
		c := l.s[l.i]
		switch {
		case c == '"':
			l.i++
			return b.String(), nil
		case c == '\\':
			if l.i+1 >= len(l.s) || !isQuotable(l.s[l.i+1]) {
				return "", malformed("bad escape in quoted string at offset %d", l.i)
			}
			b.WriteByte(l.s[l.i+1])
			l.i += 2
		case l.fold():
			b.WriteByte(' ')
			l.i += 2
		case isQuotable(c):
			b.WriteByte(c)
			l.i++
		default:
			return "", malformed("control character in quoted string at offset %d", l.i)
		}
	}
	return "", malformed("unterminated quoted string")
}

func isWSP(c byte) bool { return c == ' ' || c == '\t' }

// isTokenChar is tchar of RFC 7230 §3.2.6, a superset of the SIP token
// characters of RFC 3261 §25.1.
func isTokenChar(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// isQuotable reports whether c may appear in a quoted-string, escaped or not:
// HTAB, SP, visible ASCII and any non-ASCII byte (RFC 7230 §3.2.6 qdtext and
// obs-text; RFC 3261 allows UTF-8 there).
func isQuotable(c byte) bool {
	return c == '\t' || (c >= 0x20 && c != 0x7f)
}

// isToken reports whether s can be written without quotes.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// representable reports whether s can be carried in a quoted-string at all.
// CR, LF and other control characters cannot, and letting one through would
// let a value split the header.
func representable(s string) bool {
	for i := range len(s) {
		if !isQuotable(s[i]) {
			return false
		}
	}
	return true
}

// quote returns s as a quoted-string. Characters that cannot be represented
// are dropped rather than written, so a value that slipped past validation
// still cannot inject a header line.
func quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		if !isQuotable(c) {
			continue
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return b.String()
}

// headerBuilder writes `Digest a="x", b=y` in parameter order.
type headerBuilder struct {
	b     strings.Builder
	count int
}

func (h *headerBuilder) add(name, value string) {
	if h.count == 0 {
		h.b.WriteString("Digest ")
	} else {
		h.b.WriteString(", ")
	}
	h.count++
	h.b.WriteString(name)
	h.b.WriteByte('=')
	h.b.WriteString(value)
}

func (h *headerBuilder) quoted(name, value string) { h.add(name, quote(value)) }

func (h *headerBuilder) String() string { return h.b.String() }
