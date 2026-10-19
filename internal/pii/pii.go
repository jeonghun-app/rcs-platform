// Package pii masks subscriber identifiers before they reach a log line.
//
// Logs leave the platform (CloudWatch, support tickets, screenshots), so an
// IMSI, IMEI, MSISDN or SIP user name in a log line is a disclosure of
// subscriber data. Every identifier a service logs goes through this package
// (docs/architecture.md §8); log lines must still let an operator follow one
// subscriber across services, so each mask carries a short hint that is the same
// for the same identifier but cannot be turned back into it.
//
// Masking is deliberately over-inclusive: any run of eight or more decimal
// digits, in ASCII or another script, is treated as an identifier, because
// national-format MSISDNs, IMSIs (TS 23.003 §2.2) and IMEIs (TS 23.003 §6.2)
// are all digit runs and a false positive costs only a less useful log line.
// Numbers written in groups ("+1 555 010-0001", "010-0000-0001") are
// recognised when they start with "+" or with a word-initial trunk prefix
// such as 010; other grouped numbers are not (see numberAt).
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
	"unicode"
	"unicode/utf8"
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

// URI returns a log attribute for a SIP, SIPS, im, pres, tel or urn:gsma:imei
// URI. The subscriber part is masked and the scheme, host and parameters are
// kept, since they say which node or route was involved. A value that does
// not start with one of those schemes is masked whole: its identifying part
// cannot be told apart from the rest.
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
//   - numbers written in groups, with eight or more digits in total, that start
//     with "+" (international) or with a group of two or more digits starting
//     with 0 that begins a word (national trunk prefix: 010-0000-0001,
//     (07700) 900001, Tel.010-0000-0001); see [numberAt];
//   - the subscriber of a tel URI (RFC 3966 §3), visual separators included;
//   - the userinfo of a sip or sips URI (RFC 3261 §19.1.1), password included,
//     and the user of an im or pres URI (RFC 3860 §3, RFC 3859 §3), quoted or
//     not, as CPIM From and To carry them (RFC 3862 §3.4);
//   - the IMEI of a urn:gsma:imei URN (RFC 7254 §3), all of its digit groups.
//
// Digits of any script count: every decimal digit (Unicode Nd) outside ASCII,
// such as a full-width digit from a CJK input mode or an Arabic-Indic digit,
// is written as the ASCII digit of the same value first, so a number in any
// script is masked like the same number in ASCII, with the same hint. Other
// digit-like characters (superscripts, circled digits) are not digits here,
// and separators must be ASCII: a number grouped with full-width separators
// ("０１０－００００－０００１") is not recognised as one (#85).
//
// Schemes match case-insensitively (RFC 3261 §19.1.4, RFC 3966 §3). The output
// never contains a run of eight or more decimal digits. Redact runs in time
// linear in len(s), because it is given attacker-controlled header values.
func (r *Redactor) Redact(s string) string {
	s = asciiDigits(s)
	var b strings.Builder
	b.Grow(len(s))
	// A sip or sips URI that starts before noUserBefore has no '@' before its end:
	// remembering this keeps a line full of "sip:" prefixes linear.
	noUserBefore := 0
	for i := 0; i < len(s); {
		if startsNumber(s, i) {
			from, end := numberAt(s, i)
			if from < 0 {
				b.WriteString(s[i:end])
			} else {
				b.WriteString(s[i:from])
				if s[from] == '+' {
					b.WriteByte('+')
				}
				b.WriteString(r.mask(s[from:end]))
			}
			i = end
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
		case hasUserinfo(s[start-n : start]):
			if at := quotedUserEnd(s, start, s[start-n:start]); at > 0 {
				b.WriteString(r.mask(s[start+1 : at-1]))
				i = at
				continue
			}
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
			// that follows the scheme, up to parameters or the end of the URI, or
			// the number as a person wrote it with spaces, whichever is longer.
			end := start
			for end < len(s) && isNumberChar(s[end]) {
				end++
			}
			if startsNumber(s, start) {
				_, written := numberAt(s, start)
				end = max(end, written)
			}
			end = continueWritten(s, end)
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

// startsNumber reports whether a written number can start at s[i]: a digit, or
// "+" followed by a digit.
func startsNumber(s string, i int) bool {
	return i < len(s) && (isDigit(s[i]) || s[i] == '+' && i+1 < len(s) && isDigit(s[i+1]))
}

// numberAt scans the written number starting at s[i] (see startsNumber): digit
// groups joined by at most two separators from " -.()", as in "+1 (555)
// 010-0001". It returns the end of the number and where its identifying part
// starts, or from = -1 if it is not an identifier. It is one when it has a run
// of minRun digits, when it starts with "+" and has minRun digits, or from the
// first group of two or more digits that starts with 0 at the start of a word
// and is followed by minRun digits in total (a national number such as
// 010-0000-0001).
//
// The 0 rule keeps dates (2026-10-19), IPv4 addresses, versions, ranges
// (0-1048575) and lists ([0 1 2 3]) readable. It still masks a few non-numbers
// that look like national numbers, such as the date 09.10.2026 or the ports
// "05060 05061". National numbers without a trunk prefix written in groups,
// such as North American (555) 010-0001, are not recognised, nor are numbers
// grouped with tabs, en dashes or " - ". The number ends where three separators or a separator followed by
// something other than a digit appear, so each byte is scanned once.
func numberAt(s string, i int) (from, end int) {
	p := i
	if s[p] == '+' {
		p++
	}
	digits, run, longest := 0, 0, 0
	national, digitsBeforeNational := -1, 0
	for p < len(s) {
		if isDigit(s[p]) {
			if run == 0 && national < 0 && s[p] == '0' && startsWord(s, p) {
				national, digitsBeforeNational = p, digits
			}
			digits++
			run++
			longest = max(longest, run)
			p++
			end = p
			continue
		}
		// A trunk prefix has at least two digits (010, 02, 07700); a lone 0
		// group is a list or range ("bytes=0-1048575", "[0 1 2 3]"), so a
		// later group may still start the number.
		if national == p-1 {
			national = -1
		}
		q := p
		for q < len(s) && q-p < 3 && isNumberSeparator(s[q]) {
			q++
		}
		if q == p || q-p > 2 || q == len(s) || !isDigit(s[q]) {
			break
		}
		run = 0
		p = q
	}
	switch {
	case longest >= minRun, s[i] == '+' && digits >= minRun:
		return i, end
	case national >= 0 && digits-digitsBeforeNational >= minRun:
		return national, end
	}
	return -1, end
}

// continueWritten extends a number ending at end over further groups joined by
// one or two separators, so that a mask is never followed by a group whose
// digits would read as the rest of the number together with the mask's hint.
func continueWritten(s string, end int) int {
	for end < len(s) {
		q := end
		for q < len(s) && q-end < 3 && isNumberSeparator(s[q]) {
			q++
		}
		if q == end || q-end > 2 || q == len(s) || !isDigit(s[q]) {
			return end
		}
		_, end = numberAt(s, q)
	}
	return end
}

// startsWord reports whether the digit at s[p] begins a word. It does not when
// a letter or digit comes right before it ("v0", "10"), or a '.' or '-' that
// follows a digit, as inside an address, version or date ("10.0.1.2",
// "1-0"). A '.' or '-' after a letter does not join the number to the word:
// "Tel.010-0000-0001" and "phone-010-0000-0001" are labels before a number.
func startsWord(s string, p int) bool {
	if p == 0 {
		return true
	}
	switch c := s[p-1]; {
	case isAlnum(c):
		return false
	case c == '.' || c == '-':
		return p < 2 || !isDigit(s[p-2])
	}
	return true
}

func isNumberSeparator(c byte) bool {
	return c == ' ' || isVisualSeparator(c)
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

// canonical reduces a telephone number to its digits, dropping the "+", the
// visual separators of RFC 3966 §5.1.1 and spaces; anything else is returned
// unchanged.
func canonical(v string) string {
	digits := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case isDigit(c):
			digits = true
		case c == '+' || isNumberSeparator(c):
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

var schemes = []string{"sips:", "sip:", "tel:", "urn:gsma:imei:", "im:", "pres:"}

// schemeLen returns the length of the URI scheme s starts with, or 0.
func schemeLen(s string) int {
	for _, p := range schemes {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return len(p)
		}
	}
	return 0
}

// quotedUserEnd returns the index of the '@' after a quoted user that starts
// at s[start], or -1 when there is none. Only im and pres users may be quoted:
// RFC 3860 §3 and RFC 3859 §3 take the user from an RFC 5322 addr-spec, whose
// local part may be a quoted string with spaces and backslash-escaped
// characters. The scans of two such users never overlap, because a user's
// opening quote follows the scheme's ':' and so cannot be an escaped quote
// inside an earlier user, which keeps Redact linear.
func quotedUserEnd(s string, start int, scheme string) int {
	if start >= len(s) || s[start] != '"' || !strings.EqualFold(scheme, "im:") && !strings.EqualFold(scheme, "pres:") {
		return -1
	}
	for j := start + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++ // the escaped character, even a quote
		case '"':
			if j+1 < len(s) && s[j+1] == '@' {
				return j + 1
			}
			return -1
		}
	}
	return -1
}

// hasUserinfo reports whether the scheme's identifier is the part before '@'
// (sip, sips, im, pres) rather than a number (tel, urn:gsma:imei).
func hasUserinfo(scheme string) bool {
	for _, p := range []string{"sip:", "sips:", "im:", "pres:"} {
		if strings.EqualFold(scheme, p) {
			return true
		}
	}
	return false
}

// asciiDigits rewrites every decimal digit outside ASCII as the ASCII digit
// of the same value, so that the scan in Redact, which reads ASCII digits,
// treats a number in any script as it treats the number in ASCII: runs,
// numbers in groups and URI users alike. Rewriting only long runs would let a
// short run sit next to a mask and form a long one with the hint ("…-２３４５６７"
// after a tel number), and would miss full-width numbers written in ASCII
// groups. A short number such as "２０２６年" reads the same in ASCII. Only
// digit runes are replaced, so the text around them, valid UTF-8 or not, is
// kept.
func asciiDigits(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	last := 0 // s[:last] has been written
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= utf8.RuneSelf && unicode.IsDigit(r) {
			b.WriteString(s[last:i])
			b.WriteByte(asciiDigit(r))
			last = i + size
		}
		i += size
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// asciiDigit returns the ASCII digit with the value of the decimal digit r.
// Unicode allocates decimal digits in blocks of ten from zero to nine, and
// unicode.Nd lists them as ranges of whole blocks.
func asciiDigit(r rune) byte {
	for _, rg := range unicode.Nd.R16 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); lo <= r && r <= hi {
			return '0' + byte((r-lo)%10)
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); lo <= r && r <= hi {
			return '0' + byte((r-lo)%10)
		}
	}
	return '0'
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
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
