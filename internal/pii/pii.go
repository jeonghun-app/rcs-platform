// Package pii masks subscriber identifiers before they reach a log line.
//
// Logs leave the platform (CloudWatch, support tickets, screenshots), so an
// IMSI, IMEI, MSISDN or SIP user name in a log line is a disclosure of
// subscriber data. Every identifier a service logs goes through this package
// (docs/architecture.md §8); log lines must still let an operator follow one
// subscriber across services, so each mask carries a short hint that is the same
// for the same identifier but cannot be turned back into it.
//
// Masking is deliberately over-inclusive: any run of eight or more ASCII digits
// is treated as an identifier, because national-format MSISDNs, IMSIs (TS 23.003
// §2.2) and IMEIs (TS 23.003 §6.2) are all digit runs and a false positive costs
// only a less useful log line. Digit groups separated by spaces outside a tel URI
// are not recognised.
//
// Redaction is for identifiers only. Display names, message bodies, keys,
// nonces, RAND/AUTN, digest responses and tokens are not recognised and must
// never be logged at all (CONTRIBUTING.md, Privacy).
package pii

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"log/slog"
	"strings"
	"sync/atomic"
)

// minRun is the shortest digit run treated as an identifier. Eight digits is the
// shortest E.164 number the platform has to protect and is longer than the
// CSeq numbers, ports and status codes that fill SIP logs.
const minRun = 8

// mark starts every masked identifier, so a reader sees at once that something
// was removed and the hint that follows is not data.
const mark = "***"

// unkeyedHintMinLen is the shortest value whose last two characters are shown
// without a key; for anything shorter two characters are too large a part of it.
const unkeyedHintMinLen = 6

// keyedHintLen is how many hint characters an HMAC contributes: 32 bits keep
// accidental collisions rare within the volume of one incident's logs.
const keyedHintLen = 8

// A Redactor masks identifiers. The zero value is ready to use and unkeyed.
//
// Unkeyed, a mask shows the last two characters of the identifier: an unkeyed
// hash would not do, because a phone number has few enough possible values to be
// recovered from its hash by trying them all. Keyed, the hint is a prefix of
// HMAC-SHA256 over the identifier, which correlates log lines without revealing
// any digit to someone who does not hold the key.
type Redactor struct {
	// The key exists only inside this closure, so printing a Redactor with fmt
	// can never write the key into a log.
	newMAC func() hash.Hash
}

// NewRedactor returns a Redactor keyed with key, or an unkeyed one when key is
// empty. The key is copied.
func NewRedactor(key []byte) *Redactor {
	if len(key) == 0 {
		return &Redactor{}
	}
	k := append([]byte(nil), key...)
	return &Redactor{newMAC: func() hash.Hash { return hmac.New(sha256.New, k) }}
}

// String hides the Redactor's contents from fmt.
func (r *Redactor) String() string { return "pii.Redactor" }

// GoString hides the Redactor's contents from fmt's %#v.
func (r *Redactor) GoString() string { return "pii.Redactor" }

var current atomic.Pointer[Redactor]

// SetDefault makes r the Redactor used by the package-level functions; nil
// restores the unkeyed default. A service calls it once at startup.
func SetDefault(r *Redactor) {
	current.Store(r)
}

func defaultRedactor() *Redactor {
	if r := current.Load(); r != nil {
		return r
	}
	return &Redactor{}
}

// Redact masks identifiers in s using the default Redactor; see
// [Redactor.Redact].
func Redact(s string) string { return defaultRedactor().Redact(s) }

// URI returns a log attribute holding v redacted as a URI by the default
// Redactor; see [Redactor.URI].
func URI(key, v string) slog.Attr { return defaultRedactor().URI(key, v) }

// Identity returns a log attribute holding v masked whole by the default
// Redactor; see [Redactor.Identity].
func Identity(key, v string) slog.Attr { return defaultRedactor().Identity(key, v) }

// URI returns a log attribute for a SIP, SIPS, tel or urn:gsma:imei URI. The
// subscriber part is masked and the scheme, host and parameters are kept, since
// they say which node or route was involved. A value that does not start with
// one of those schemes is masked whole: its identifying part cannot be told apart
// from the rest.
func (r *Redactor) URI(key, v string) slog.Attr {
	if schemeLen(v) > 0 {
		return slog.String(key, r.Redact(v))
	}
	return slog.String(key, r.mask(v))
}

// Identity returns a log attribute for a bare identifier (IMSI, IMPI, MSISDN,
// IMEI, user name), masked whole whatever it looks like.
func (r *Redactor) Identity(key, v string) slog.Attr {
	return slog.String(key, r.mask(v))
}

// Redact returns s with every identifier inside it masked:
//
//   - runs of eight or more digits, which covers IMSIs (14–15 digits), IMEIs and
//     IMEISVs (15–16 digits) and E.164 numbers; a leading "+" is kept;
//   - the subscriber of a tel URI (RFC 3966 §3), visual separators included;
//   - the userinfo of a sip or sips URI (RFC 3261 §19.1.1), password included;
//   - the IMEI of a urn:gsma:imei URN (RFC 7254 §3), all of its digit groups.
//
// Schemes match case-insensitively (RFC 3261 §19.1.4, RFC 3966 §3). The output
// never contains a run of eight or more digits. Redact runs in time linear in
// len(s), because it is given attacker-controlled header values.
func (r *Redactor) Redact(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	// A sip or sips URI that starts before noUserBefore has no '@' before its end:
	// remembering this keeps a line full of "sip:" prefixes linear.
	noUserBefore := 0
	for i := 0; i < len(s); {
		if isDigit(s[i]) {
			j := i + 1
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			if j-i >= minRun {
				b.WriteString(r.mask(s[i:j]))
			} else {
				b.WriteString(s[i:j])
			}
			i = j
			continue
		}
		n := schemeLen(s[i:])
		if n == 0 {
			b.WriteByte(s[i])
			i++
			continue
		}
		start := i + n
		b.WriteString(s[i:start])
		i = start
		switch {
		case isSIP(s[start-n : start]):
			if start < noUserBefore {
				continue
			}
			end := start
			for end < len(s) && s[end] != '@' && !endsURI(s[end]) {
				end++
			}
			if end == len(s) || s[end] != '@' {
				noUserBefore = end
				continue
			}
			if end > start {
				b.WriteString(r.mask(sipUser(s[start:end])))
				i = end
			}
		default:
			// tel and urn:gsma:imei: the identifier is the run of number characters
			// that follows the scheme, up to parameters or the end of the URI.
			end := start
			for end < len(s) && isNumberChar(s[end]) {
				end++
			}
			if end > start {
				num := s[start:end]
				if num[0] == '+' {
					b.WriteByte('+')
				}
				b.WriteString(r.mask(num))
				i = end
			}
		}
	}
	return b.String()
}

// mask returns the masked form of one identifier. The hint is computed from the
// identifier's canonical form so that +15550100001, tel:+1-555-010-0001 and
// sip:+15550100001@… carry the same hint.
func (r *Redactor) mask(v string) string {
	c := canonical(v)
	if r.newMAC != nil {
		m := r.newMAC()
		m.Write([]byte(c))
		return mark + letters(m.Sum(nil), keyedHintLen)
	}
	if len(c) >= unkeyedHintMinLen && isAlnum(c[len(c)-1]) && isAlnum(c[len(c)-2]) {
		return mark + c[len(c)-2:]
	}
	return mark
}

// letters encodes the first n nibbles of sum as the letters a–p. Digits are
// avoided so that a hint can never extend a neighbouring digit run or itself look
// like part of an identifier.
func letters(sum []byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		nibble := sum[i/2] >> 4
		if i%2 == 1 {
			nibble = sum[i/2] & 0x0f
		}
		out[i] = 'a' + nibble
	}
	return string(out)
}

// canonical reduces a telephone number to its digits, dropping the "+" and the
// visual separators of RFC 3966 §5.1.1; anything else is returned unchanged.
func canonical(v string) string {
	digits := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case isDigit(c):
			digits = true
		case c == '+' || isVisualSeparator(c):
		default:
			return v
		}
	}
	if !digits {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if isDigit(v[i]) {
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

// sipUser returns the user of a SIP userinfo, without the password (RFC 3261
// §19.1.1) and without user parameters such as phone-context (RFC 3261 §25.1,
// telephone-subscriber), so that the hint names the subscriber only.
func sipUser(userinfo string) string {
	if i := strings.IndexAny(userinfo, ":;"); i >= 0 {
		return userinfo[:i]
	}
	return userinfo
}

var schemes = []string{"sips:", "sip:", "tel:", "urn:gsma:imei:"}

// schemeLen returns the length of the URI scheme s starts with, or 0.
func schemeLen(s string) int {
	for _, p := range schemes {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return len(p)
		}
	}
	return 0
}

func isSIP(scheme string) bool {
	return strings.EqualFold(scheme, "sip:") || strings.EqualFold(scheme, "sips:")
}

// endsURI reports whether c cannot be part of a URI written in a log line or a
// SIP header: whitespace, controls and the delimiters of name-addr and quoted
// strings (RFC 3261 §25.1).
func endsURI(c byte) bool {
	return c <= ' ' || c == 0x7f || c == '<' || c == '>' || c == '"'
}

// isNumberChar reports whether c can appear in a tel URI subscriber (RFC 3966
// §3: digits, hex digits, "*", "#", "+" and visual separators) or in a
// urn:gsma:imei value (digits and "-").
func isNumberChar(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' ||
		c == '*' || c == '#' || c == '+' || isVisualSeparator(c)
}

func isVisualSeparator(c byte) bool {
	return c == '-' || c == '.' || c == '(' || c == ')'
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
