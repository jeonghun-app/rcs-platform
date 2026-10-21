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
// A client's IP address is personal data too, whatever its range;
// [ClientIP] and [TruncateIP] log only the network it belongs to (IPv4 /24,
// IPv6 /48).
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
// is written as the ASCII digit of the same value first, and the spaces,
// dashes and full-width "＋", "．", "（", "）" that group a number as ASCII
// ones, so a number in any script is masked like the same number in ASCII,
// with the same hint ("０１０－００００－０００１", "010ー0000ー0001" and
// "+1 555 010 0001" with no-break spaces like their ASCII forms); see
// [asciiNumberChars]. Other digit-like characters (superscripts, circled
// digits) are not digits here. The invisible format characters a log viewer
// hides (U+200B ZWSP, U+2060 WJ, U+00AD SHY, U+FEFF, variation selectors)
// inside a number are dropped first, so they split no number; see
// [dropInvisibles]. A "+" may be followed by a bracketed country code ("+(81)3
// 1234 5678"); the full-width "＊" and "＃" of a tel number and the small "﹢"
// read as "*", "#" and "+"; the wave dashes "〜" and "〰", which join ranges of
// hours, are not dashes (#154).
//
// Schemes match case-insensitively (RFC 3261 §19.1.4, RFC 3966 §3). The output
// never contains a run of eight or more decimal digits. Redact runs in time
// linear in len(s), because it is given attacker-controlled header values.
func (r *Redactor) Redact(s string) string {
	s = asciiNumberChars(dropInvisibles(s))
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
// "+" followed by a digit or by a bracketed country code ("+(81)3 1234
// 5678").
func startsNumber(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if isDigit(s[i]) {
		return true
	}
	return s[i] == '+' && i+1 < len(s) && (isDigit(s[i+1]) || s[i+1] == '(' && i+2 < len(s) && isDigit(s[i+2]))
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
// grouped with tabs or " - ". The number ends where three separators or a
// separator followed by something other than a digit appear, so each byte is
// scanned once. Spaces and dashes outside ASCII reach it as ASCII ones (see
// [asciiNumberChars]).
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

// asciiNumberChars rewrites the characters of a number written outside ASCII
// as their ASCII forms, so that the scan in Redact, which reads ASCII, treats
// a number in any script, input mode or typography as it treats the number in
// ASCII: runs, numbers in groups and URI users alike, with the same hint.
//
// Every decimal digit (Unicode Nd) becomes the ASCII digit of the same value,
// wherever it is: rewriting only long digit runs would let a short run sit
// next to a mask and form a long one with the hint ("…-２３４５６７" after a
// tel number). The characters that group a number become ASCII only where
// they do: every space (Unicode Zs: U+3000, no-break and thin spaces) becomes
// " ", every dash (Unicode Pd, U+2212 minus and the long vowel marks "ー" and
// "ｰ" that the "-" key types in a Japanese kana mode) becomes "-", and "．",
// "（", "）" and "＋" become ASCII,
//
//   - when one or two of them join two digits, as numberAt reads them
//     ("０１０ー１２３４", "+1 (555)" with U+3000 and "（");
//   - for "＋", before a digit;
//   - for brackets, around digits alone ("（０３）");
//   - in the user or subscriber of a URI, while it reads as a number
//     (isNumberChar), as Redact masks all of it ("tel:（０３）１２３４").
//
// Elsewhere they are prose, such as "名前　（注）　10", "failed — retry" or
// "データー", and are kept. Text without a digit is not rewritten at all.
// Only these runes are replaced, so the text around them, valid UTF-8 or not,
// is kept. Each rune is looked at a bounded number of times (two runes
// ahead, and the digits after an opening bracket once more), so this is
// linear.
func asciiNumberChars(s string) string {
	// Text without a digit holds no number, and is left alone.
	if isASCII(s) || !strings.ContainsFunc(s, unicode.IsDigit) {
		return s
	}
	var b strings.Builder
	last := 0 // s[:last] has been written
	// seps counts the separators since the last digit, or is -1 if something
	// else came after it.
	seps := -1
	inURI := false  // in the user or subscriber of a URI
	inUser := false // in the user of a sip, sips, im or pres URI, up to its "@"
	closeAt := -1   // where a non-ASCII bracket closes a group of digits
	afterPlus := false
	for i := 0; i < len(s); {
		if n := schemeLen(s[i:]); n > 0 {
			// Redact goes on from the end of a URI's number as from a digit
			// (continueWritten), and the number may be empty.
			seps, inURI, inUser = 0, true, hasUserinfo(s[i:i+n])
			i += n
			continue
		}
		if s[i] == '@' || s[i] < utf8.RuneSelf && endsURI(s[i]) {
			inUser = false
		}
		c, size := numberCharAt(s, i)
		rewrite := false
		switch {
		case isDigit(c):
			rewrite = true
		case inURI && isNumberChar(c):
			rewrite = true
		case c == '+':
			// Before a digit, or a bracket and a digit, as startsNumber
			// reads a number ("+(81)3").
			next, nextSize := numberCharAt(s, i+size)
			if rewrite = isDigit(next); next == '(' {
				after, _ := numberCharAt(s, i+size+nextSize)
				rewrite = isDigit(after)
			}
		case c == '(' && afterPlus && isDigitAt(s, i+size):
			rewrite = true
		case c == ' ' && size > 1 && inUser:
			// A space inside a user is no separator there; Redact reads the
			// user up to its "@" only while no ASCII space ends it.
		case isNumberSeparator(c):
			rewrite = i == closeAt || joinsDigits(s, i+size, seps)
			if c == '(' {
				if j, ok := bracketedDigits(s, i+size); ok {
					rewrite = true
					closeAt = j
				}
			}
		}
		if size > 1 && rewrite {
			b.WriteString(s[last:i])
			b.WriteByte(c)
			last = i + size
		}
		switch {
		case isDigit(c), inURI && isNumberChar(c):
			seps = 0
		case isNumberSeparator(c) && seps >= 0:
			seps++
		default:
			seps = -1
		}
		inURI = inURI && isNumberChar(c)
		afterPlus = c == '+'
		i += size
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// numberCharAt returns the ASCII form of the rune at s[i] if it has one (see
// asciiNumberChar), or 0, and the rune's size; at the end of s it returns 0,
// 0.
func numberCharAt(s string, i int) (c byte, size int) {
	if i >= len(s) {
		return 0, 0
	}
	if s[i] < utf8.RuneSelf {
		return s[i], 1
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	c, _ = asciiNumberChar(r)
	return c, size
}

// isDigitAt reports whether the rune at s[i] is a digit of any script.
func isDigitAt(s string, i int) bool {
	c, _ := numberCharAt(s, i)
	return isDigit(c)
}

// joinsDigits reports whether a separator that follows seps separators after
// a digit, and is followed by s[i:], is one of at most two separators between
// two digits.
func joinsDigits(s string, i, seps int) bool {
	next, size := numberCharAt(s, i)
	switch seps {
	case 0:
		if isNumberSeparator(next) {
			next, _ = numberCharAt(s, i+size)
		}
		return isDigit(next)
	case 1:
		return isDigit(next)
	}
	return false
}

// bracketedDigits reports whether s[i:] is one or more digits followed by a
// closing bracket, and where the bracket is if it is not ASCII, or -1.
func bracketedDigits(s string, i int) (closeAt int, ok bool) {
	j := i
	for {
		c, size := numberCharAt(s, j)
		switch {
		case isDigit(c):
			j += size
			continue
		case c == ')' && j > i:
			if size > 1 {
				return j, true
			}
			return -1, true
		}
		return -1, false
	}
}

// asciiNumberChar returns the ASCII character that r stands for in a number,
// if it stands for one: a decimal digit, a space, a dash, or one of the
// full-width "＋", "．", "（", "）".
func asciiNumberChar(r rune) (byte, bool) {
	switch {
	case r < utf8.RuneSelf:
		return 0, false
	case unicode.IsDigit(r):
		return asciiDigit(r), true
	case unicode.Is(unicode.Zs, r):
		return ' ', true
	case r == '\u301c', r == '\u3030':
		// The wave dashes join ranges of hours or dates (0900〜1800), not
		// the groups of a number (#154).
		return 0, false
	case unicode.Is(unicode.Pd, r), r == '\u2212', r == 'ー', r == 'ｰ':
		return '-', true
	case r == '＋', r == '．', r == '（', r == '）', r == '＊', r == '＃':
		// The full-width forms block mirrors ASCII 0x21-0x7E at U+FF01.
		return byte(r - '！' + '!'), true
	case r == '﹢':
		return '+', true
	}
	return 0, false
}

// dropInvisibles removes the invisible format characters that sit inside a
// number (#154): a run of characters of category Cf, Default_Ignorable or a
// variation selector (U+200B ZWSP, U+2060 WJ, U+00AD SHY, U+FEFF) between
// two number characters, one of them a digit. A log viewer shows such a
// number with its digits joined, and so it is masked as if written without
// them, with the same hint. Elsewhere they are text and are kept. Each run
// is looked at once, so this is linear.
func dropInvisibles(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	last := 0
	var prev rune = -1
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isInvisible(r) {
			prev = r
			i += size
			continue
		}
		end := i + size
		for end < len(s) {
			r2, size2 := utf8.DecodeRuneInString(s[end:])
			if !isInvisible(r2) {
				break
			}
			end += size2
		}
		next := rune(-1)
		if end < len(s) {
			next, _ = utf8.DecodeRuneInString(s[end:])
		}
		if numberSide(prev) && numberSide(next) && (digitRune(prev) || digitRune(next)) {
			b.WriteString(s[last:i])
			last = end
		}
		i = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// isInvisible reports whether r is a character a log viewer does not show:
// a format character (Cf), a variation selector or another Default_Ignorable
// one.
func isInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// numberSide reports whether r can be part of a number: a digit of any
// script, "+", "*", "#", a space, dash, dot or bracket, in ASCII or as
// asciiNumberChar reads it. Letters, even hex digits, are not.
func numberSide(r rune) bool {
	if r < 0 {
		return false
	}
	if r < utf8.RuneSelf {
		c := byte(r)
		return isDigit(c) || c == '+' || c == '*' || c == '#' || isNumberSeparator(c)
	}
	_, ok := asciiNumberChar(r)
	return ok
}

// digitRune reports whether r is a decimal digit of any script.
func digitRune(r rune) bool { return r >= 0 && unicode.IsDigit(r) }

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
