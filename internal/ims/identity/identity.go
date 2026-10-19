// Package identity holds the rules for IMS user identities that more than
// one service must apply the same way: what a private identity (IMPI) and an
// IMSI look like, and the one canonical form of a public identity (IMPU).
//
// The HSS stores IMPUs in canonical form and sends them so in User-Data;
// icscf and scscf put the identities of a SIP request into the same form
// before they compare them with the HSS's, or look them up, so that
// sip:+1555...@IMS.example registers the user provisioned as
// sip:+1555...@ims.example (RFC 3261 §19.1.4).
package identity

import (
	"errors"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// MaxLength bounds every identity: no IMPI, IMPU or IMSI legitimately comes
// near it, and it keeps them inside one DynamoDB key and one log field.
const MaxLength = 255

// Errors of the validators. They describe the rule, never the value.
var (
	ErrIMPI = errors.New("not a private user identity of the form user@realm")
	ErrIMPU = errors.New("not a SIP URI or global tel URI without parameters")
	ErrIMSI = errors.New("not an IMSI of 6 to 15 digits")
)

// ValidIMPI checks a private user identity: an NAI user@realm (TS 23.003
// §13.3, RFC 7542) of printable ASCII without white space, with a realm
// that is a domain name. '/' and '%' are refused because the IMPI is a path
// segment of the provisioning API.
func ValidIMPI(impi string) error {
	user, realm, ok := strings.Cut(impi, "@")
	if !ok || user == "" || len(impi) > MaxLength || strings.Contains(realm, "@") || !IsDomainName(realm) {
		return ErrIMPI
	}
	for i := 0; i < len(user); i++ {
		if c := user[i]; c <= ' ' || c >= 0x7f || c == '/' || c == '%' || c == '\\' {
			return ErrIMPI
		}
	}
	return nil
}

// ValidIMSI checks an IMSI: MCC, MNC and MSIN, at most 15 digits (TS 23.003
// §2.2).
func ValidIMSI(imsi string) error {
	if len(imsi) < 6 || len(imsi) > 15 || strings.Trim(imsi, "0123456789") != "" {
		return ErrIMSI
	}
	return nil
}

// IsDomainName reports whether s is a domain name of LDH labels (RFC 1035
// §2.3.1, RFC 1123 §2.1).
func IsDomainName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// CanonicalIMPU returns the form in which the HSS stores and matches a
// public identity, and in which every service compares one, or false when s is not one: a SIP or SIPS URI becomes
// scheme:user@host with the escapes in the user part decoded and the host
// in lower case (RFC 3261 §19.1.4: hosts compare without regard to case,
// users with it, and escaped characters equal their unescaped form); a tel
// URI becomes tel:+digits without visual separators (RFC 3966 §5.1.1). URI
// parameters, which an IMPU in a Cx request may carry (user=phone), are
// dropped. A SIP URI needs a user part and no password, port or headers.
func CanonicalIMPU(s string) (string, bool) {
	if len(s) > MaxLength {
		return "", false
	}
	u, err := sip.ParseURI(s)
	if err != nil {
		return "", false
	}
	switch u.Scheme {
	case "sip", "sips":
		user, ok := unescape(u.User)
		if !ok || user == "" || u.Password != "" || u.Port != 0 || len(u.Headers) > 0 || u.Host == "" {
			return "", false
		}
		// The canonical form must itself be a valid URI, since it is what
		// the S-CSCF receives in User-Data: an escape that decodes to a
		// character the user part cannot carry unescaped is refused rather
		// than re-escaped.
		for i := 0; i < len(user); i++ {
			if !isUserChar(user[i]) {
				return "", false
			}
		}
		return u.Scheme + ":" + user + "@" + strings.ToLower(u.Host), true
	case "tel":
		if !strings.HasPrefix(u.User, "+") {
			return "", false // a local number needs a phone-context: not an IMPU
		}
		digits := strings.Map(func(r rune) rune {
			if r == '-' || r == '.' || r == '(' || r == ')' {
				return -1
			}
			return r
		}, u.User[1:])
		if digits == "" || len(digits) > 15 || strings.Trim(digits, "0123456789") != "" {
			return "", false
		}
		return "tel:+" + digits, true
	}
	return "", false
}

// isUserChar reports whether c may appear unescaped in a SIP user part:
// unreserved or user-unreserved (RFC 3261 §25.1).
func isUserChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.IndexByte("-_.!~*'()&=+$,;?/", c) >= 0
}

// unescape decodes the %XX escapes of a SIP user part (RFC 3261 §25.1).
func unescape(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, lo := unhex(s[i+1]), unhex(s[i+2])
		if hi < 0 || lo < 0 {
			return "", false
		}
		b.WriteByte(byte(hi<<4 | lo))
		i += 2
	}
	return b.String(), true
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
