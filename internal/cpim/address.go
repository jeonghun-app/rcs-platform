package cpim

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Address is the value of a From, To or cc header:
// [ Formal-name ] "<" URI ">" (RFC 3862 §4.1-§4.3).
type Address struct {
	// Name is the formal name with quoting and escapes removed; empty when
	// the header carries only a URI.
	Name string
	// URI is the address, for example a sip: or tel: URI.
	URI string
}

// ParseAddress parses a From, To or cc header value.
func ParseAddress(v string) (Address, error) {
	if !utf8.ValidString(v) || hasControl(v, false) {
		return Address{}, fmt.Errorf("%w: address contains an invalid character", ErrMalformed)
	}
	var a Address
	rest := v
	switch {
	case strings.HasPrefix(v, `"`):
		end := quotedEnd(v, 0)
		if end < 0 {
			return Address{}, fmt.Errorf("%w: unterminated formal name", ErrMalformed)
		}
		a.Name = Unescape(v[1 : end-1])
		// The grammar puts "<" straight after the closing quote, but writers
		// commonly separate them with a space.
		rest = strings.TrimPrefix(v[end:], " ")
	case !strings.HasPrefix(v, "<"):
		i := strings.IndexByte(v, '<')
		if i < 0 || !isFormalTokens(v[:i]) {
			return Address{}, fmt.Errorf("%w: formal name is not 1*( Token SP ) or a quoted string", ErrMalformed)
		}
		a.Name = v[:i-1]
		rest = v[i:]
	}
	uri, ok := strings.CutPrefix(rest, "<")
	if !ok {
		return Address{}, fmt.Errorf("%w: address has no <URI>", ErrMalformed)
	}
	uri, ok = strings.CutSuffix(uri, ">")
	if !ok || !isAbsoluteURI(uri) {
		return Address{}, fmt.Errorf("%w: address URI is not an absolute URI in angle brackets", ErrMalformed)
	}
	a.URI = uri
	return a, nil
}

// String formats a as a header value, quoting the formal name only when it is
// not a plain sequence of tokens.
func (a Address) String() string {
	switch {
	case a.Name == "":
		return "<" + a.URI + ">"
	case isFormalTokens(a.Name + " "):
		return a.Name + " <" + a.URI + ">"
	default:
		return `"` + strings.ReplaceAll(Escape(a.Name), `"`, `\"`) + `" <` + a.URI + ">"
	}
}

// isFormalTokens reports whether s is 1*( Token SP ).
func isFormalTokens(s string) bool {
	body, ok := strings.CutSuffix(s, " ")
	if !ok {
		return false
	}
	for tok := range strings.SplitSeq(body, " ") {
		if !IsToken(tok) {
			return false
		}
	}
	return true
}

// isAbsoluteURI reports whether s looks like scheme ":" rest. The URI itself is
// interpreted by the protocol that uses it (internal/sip for sip: and tel:);
// here it only has to be delimited unambiguously.
func isAbsoluteURI(s string) bool {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || scheme == "" || rest == "" {
		return false
	}
	for i := 0; i < len(scheme); i++ {
		c := scheme[i]
		alpha := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
		if !alpha && (i == 0 || !('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return !strings.ContainsAny(rest, " <>\"") && !hasControl(rest, false)
}

// Escape applies the RFC 3862 §2.3.1 escape mechanism so that s can appear in a
// header value: backslash and the control characters become escape sequences.
// Double quotes are left alone; they need escaping only inside a quoted string.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// Unescape decodes RFC 3862 §2.3 escape sequences the way §2.3.1 asks a
// receiver to: an unknown sequence stands for the character after the
// backslash and a trailing lone backslash is dropped. \uxxxx encodes a UCS-2
// unit, so a surrogate pair is combined and a lone surrogate becomes U+FFFD.
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 == len(s) {
			break
		}
		i++
		switch s[i] {
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'u':
			r, ok := hex4(s[i+1:])
			if !ok {
				b.WriteByte('u')
				continue
			}
			i += 4
			if utf16.IsSurrogate(r) {
				pair := utf8.RuneError
				if rest, ok := strings.CutPrefix(s[i+1:], `\u`); ok {
					if lo, ok := hex4(rest); ok {
						if pair = utf16.DecodeRune(r, lo); pair != utf8.RuneError {
							i += 6
						}
					}
				}
				r = pair
			}
			b.WriteRune(r)
		default:
			// Escaped quotes and backslashes land here too: the escaped
			// character is the character itself.
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func hex4(s string) (rune, bool) {
	if len(s) < 4 {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(s[i])) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s[:4], 16, 16)
	return rune(n), err == nil
}
