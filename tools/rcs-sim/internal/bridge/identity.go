package bridge

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// maxNameLength bounds an endpoint name, in bytes.
const maxNameLength = 64

// validName reports whether name may name an endpoint: 1 to 64 bytes of
// letters, digits, marks and ".", "_", "~", "-", in any script, compared
// byte for byte. No ":" and no "/": a name stands in a URL path, and "to"
// tells a name from a sip: or tel: URI by its ":".
func validName(name string) bool {
	if name == "" || len(name) > maxNameLength || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		switch {
		case r == '.' || r == '_' || r == '~' || r == '-':
		case r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'):
		case r >= utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r)):
		default:
			return false
		}
	}
	return true
}

// numberOf returns the telephone number u names, "+" and its digits: a
// global tel URI, or a SIP URI whose user part is a global number, with
// user=phone or without it, as the platform's identities are
// (docs/rcs-as.md, Who sends, and to whom). The network names a sender by
// either form of one implicit registration set.
func numberOf(u sip.URI) (string, bool) {
	if n, ok := u.E164(); ok {
		return n, true
	}
	if !u.IsSIP() || !strings.HasPrefix(u.User, "+") {
		return "", false
	}
	digits := u.User[1:]
	if len(digits) == 0 || len(digits) > 15 {
		return "", false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", false
		}
	}
	return u.User, true
}

// sameUser reports whether a and b name one user: one telephone number,
// or else the same scheme, user and host.
func sameUser(a, b sip.URI) bool {
	na, okA := numberOf(a)
	nb, okB := numberOf(b)
	if okA || okB {
		return okA && okB && na == nb
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && a.User == b.User && strings.EqualFold(a.Host, b.Host)
}
