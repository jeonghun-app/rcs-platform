// Code generated from internal/pii/pii.go at 251d6ae by renaming every
// top-level identifier with the prefix "main"; DO NOT EDIT.

package pii

// This is main's Redact as it was before #154, frozen so that
// TestRedactMasksAtLeastWhatMainMasked can check that #154 never masks less
// than it did (review of #398). It is compared against the source with
//
//	git show 251d6ae:internal/pii/pii.go
//
// The fmt-hiding methods, the default Redactor and the attribute helpers are
// left out, since the check calls Redact only.

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"strings"
	"unicode"
	"unicode/utf8"
)

// mainMinRun is the shortest digit run treated as an identifier. Eight digits is the
// shortest E.164 number the platform has to protect and is longer than the
// CSeq numbers, ports and status codes that fill SIP logs.
const mainMinRun = 8

// mainMark starts every masked identifier, so a reader sees at once that something
// was removed and the hint that follows is not data.
const mainMark = "***"

// mainUnkeyedHintMinLen is the shortest value whose last two characters are shown
// without a key; for anything shorter two characters are too large a part of it.
const mainUnkeyedHintMinLen = 6

// mainKeyedHintLen is how many hint characters an HMAC contributes: 32 bits keep
// accidental collisions rare within the volume of one incident's logs.
const mainKeyedHintLen = 8

// A mainRedactor masks identifiers. The zero value is ready to use and unkeyed.
//
// Unkeyed, a mask shows the last two characters of the identifier: an unkeyed
// hash would not do, because a phone number has few enough possible values to be
// recovered from its hash by trying them all. Keyed, the hint is a prefix of
// HMAC-SHA256 over the identifier, which correlates log lines without revealing
// any digit to someone who does not hold the key.
type mainRedactor struct {
	// The key exists only inside this closure, so printing a mainRedactor with fmt
	// can never write the key into a log.
	newMAC func() hash.Hash
}

// mainNewRedactor returns a mainRedactor keyed with key, or an unkeyed one when key is
// empty. The key is copied.
func mainNewRedactor(key []byte) *mainRedactor {
	if len(key) == 0 {
		return &mainRedactor{}
	}
	k := append([]byte(nil), key...)
	return &mainRedactor{newMAC: func() hash.Hash { return hmac.New(sha256.New, k) }}
}

// Redact returns s with every identifier inside it masked:
//
//   - runs of eight or more digits, which covers IMSIs (14–15 digits), IMEIs and
//     IMEISVs (15–16 digits) and E.164 numbers; a leading "+" is kept;
//   - numbers written in groups, with eight or more digits in total, that start
//     with "+" (international) or with a group of two or more digits starting
//     with 0 that begins a word (national trunk prefix: 010-0000-0001,
//     (07700) 900001, Tel.010-0000-0001); see [mainNumberAt];
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
// [mainAsciiNumberChars]. Other digit-like characters (superscripts, circled
// digits) are not digits here.
//
// Schemes match case-insensitively (RFC 3261 §19.1.4, RFC 3966 §3). The output
// never contains a run of eight or more decimal digits. Redact runs in time
// linear in len(s), because it is given attacker-controlled header values.
func (r *mainRedactor) Redact(s string) string {
	s = mainAsciiNumberChars(s)
	var b strings.Builder
	b.Grow(len(s))
	// A sip or sips URI that starts before noUserBefore has no '@' before its end:
	// remembering this keeps a line full of "sip:" prefixes linear.
	noUserBefore := 0
	for i := 0; i < len(s); {
		if mainStartsNumber(s, i) {
			from, end := mainNumberAt(s, i)
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
		n := mainSchemeLen(s[i:])
		if n == 0 {
			b.WriteByte(s[i])
			i++
			continue
		}
		start := i + n
		b.WriteString(s[i:start])
		i = start
		switch {
		case mainHasUserinfo(s[start-n : start]):
			if at := mainQuotedUserEnd(s, start, s[start-n:start]); at > 0 {
				b.WriteString(r.mask(s[start+1 : at-1]))
				i = at
				continue
			}
			if start < noUserBefore {
				continue
			}
			end := start
			for end < len(s) && s[end] != '@' && !mainEndsURI(s[end]) {
				end++
			}
			if end == len(s) || s[end] != '@' {
				noUserBefore = end
				continue
			}
			if end > start {
				b.WriteString(r.mask(mainSipUser(s[start:end])))
				i = end
			}
		default:
			// tel and urn:gsma:imei: the identifier is the run of number characters
			// that follows the scheme, up to parameters or the end of the URI, or
			// the number as a person wrote it with spaces, whichever is longer.
			end := start
			for end < len(s) && mainIsNumberChar(s[end]) {
				end++
			}
			if mainStartsNumber(s, start) {
				_, written := mainNumberAt(s, start)
				end = max(end, written)
			}
			end = mainContinueWritten(s, end)
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

// mainStartsNumber reports whether a written number can start at s[i]: a digit, or
// "+" followed by a digit.
func mainStartsNumber(s string, i int) bool {
	return i < len(s) && (mainIsDigit(s[i]) || s[i] == '+' && i+1 < len(s) && mainIsDigit(s[i+1]))
}

// mainNumberAt scans the written number starting at s[i] (see mainStartsNumber): digit
// groups joined by at most two separators from " -.()", as in "+1 (555)
// 010-0001". It returns the end of the number and where its identifying part
// starts, or from = -1 if it is not an identifier. It is one when it has a run
// of mainMinRun digits, when it starts with "+" and has mainMinRun digits, or from the
// first group of two or more digits that starts with 0 at the start of a word
// and is followed by mainMinRun digits in total (a national number such as
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
// [mainAsciiNumberChars]).
func mainNumberAt(s string, i int) (from, end int) {
	p := i
	if s[p] == '+' {
		p++
	}
	digits, run, longest := 0, 0, 0
	national, digitsBeforeNational := -1, 0
	for p < len(s) {
		if mainIsDigit(s[p]) {
			if run == 0 && national < 0 && s[p] == '0' && mainStartsWord(s, p) {
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
		for q < len(s) && q-p < 3 && mainIsNumberSeparator(s[q]) {
			q++
		}
		if q == p || q-p > 2 || q == len(s) || !mainIsDigit(s[q]) {
			break
		}
		run = 0
		p = q
	}
	switch {
	case longest >= mainMinRun, s[i] == '+' && digits >= mainMinRun:
		return i, end
	case national >= 0 && digits-digitsBeforeNational >= mainMinRun:
		return national, end
	}
	return -1, end
}

// mainContinueWritten extends a number ending at end over further groups joined by
// one or two separators, so that a mask is never followed by a group whose
// digits would read as the rest of the number together with the mask's hint.
func mainContinueWritten(s string, end int) int {
	for end < len(s) {
		q := end
		for q < len(s) && q-end < 3 && mainIsNumberSeparator(s[q]) {
			q++
		}
		if q == end || q-end > 2 || q == len(s) || !mainIsDigit(s[q]) {
			return end
		}
		_, end = mainNumberAt(s, q)
	}
	return end
}

// mainStartsWord reports whether the digit at s[p] begins a word. It does not when
// a letter or digit comes right before it ("v0", "10"), or a '.' or '-' that
// follows a digit, as inside an address, version or date ("10.0.1.2",
// "1-0"). A '.' or '-' after a letter does not join the number to the word:
// "Tel.010-0000-0001" and "phone-010-0000-0001" are labels before a number.
func mainStartsWord(s string, p int) bool {
	if p == 0 {
		return true
	}
	switch c := s[p-1]; {
	case mainIsAlnum(c):
		return false
	case c == '.' || c == '-':
		return p < 2 || !mainIsDigit(s[p-2])
	}
	return true
}

func mainIsNumberSeparator(c byte) bool {
	return c == ' ' || mainIsVisualSeparator(c)
}

// mask returns the masked form of one identifier. The hint is computed from the
// identifier's mainCanonical form so that +15550100001, tel:+1-555-010-0001 and
// sip:+15550100001@… carry the same hint.
func (r *mainRedactor) mask(v string) string {
	c := mainCanonical(v)
	if r.newMAC != nil {
		m := r.newMAC()
		m.Write([]byte(c))
		return mainMark + mainLetters(m.Sum(nil), mainKeyedHintLen)
	}
	if len(c) >= mainUnkeyedHintMinLen && mainIsAlnum(c[len(c)-1]) && mainIsAlnum(c[len(c)-2]) {
		return mainMark + c[len(c)-2:]
	}
	return mainMark
}

// mainLetters encodes the first n nibbles of sum as the mainLetters a–p. Digits are
// avoided so that a hint can never extend a neighbouring digit run or itself look
// like part of an identifier.
func mainLetters(sum []byte, n int) string {
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

// mainCanonical reduces a telephone number to its digits, dropping the "+", the
// visual separators of RFC 3966 §5.1.1 and spaces; anything else is returned
// unchanged.
func mainCanonical(v string) string {
	digits := false
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case mainIsDigit(c):
			digits = true
		case c == '+' || mainIsNumberSeparator(c):
		default:
			return v
		}
	}
	if !digits {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if mainIsDigit(v[i]) {
			b.WriteByte(v[i])
		}
	}
	return b.String()
}

// mainSipUser returns the user of a SIP userinfo, without the password (RFC 3261
// §19.1.1) and without user parameters such as phone-context (RFC 3261 §25.1,
// telephone-subscriber), so that the hint names the subscriber only.
func mainSipUser(userinfo string) string {
	if i := strings.IndexAny(userinfo, ":;"); i >= 0 {
		return userinfo[:i]
	}
	return userinfo
}

var mainSchemes = []string{"sips:", "sip:", "tel:", "urn:gsma:imei:", "im:", "pres:"}

// mainSchemeLen returns the length of the URI scheme s starts with, or 0.
func mainSchemeLen(s string) int {
	for _, p := range mainSchemes {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return len(p)
		}
	}
	return 0
}

// mainQuotedUserEnd returns the index of the '@' after a quoted user that starts
// at s[start], or -1 when there is none. Only im and pres users may be quoted:
// RFC 3860 §3 and RFC 3859 §3 take the user from an RFC 5322 addr-spec, whose
// local part may be a quoted string with spaces and backslash-escaped
// characters. The scans of two such users never overlap, because a user's
// opening quote follows the scheme's ':' and so cannot be an escaped quote
// inside an earlier user, which keeps Redact linear.
func mainQuotedUserEnd(s string, start int, scheme string) int {
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

// mainHasUserinfo reports whether the scheme's identifier is the part before '@'
// (sip, sips, im, pres) rather than a number (tel, urn:gsma:imei).
func mainHasUserinfo(scheme string) bool {
	for _, p := range []string{"sip:", "sips:", "im:", "pres:"} {
		if strings.EqualFold(scheme, p) {
			return true
		}
	}
	return false
}

// mainAsciiNumberChars rewrites the characters of a number written outside ASCII
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
//   - when one or two of them join two digits, as mainNumberAt reads them
//     ("０１０ー１２３４", "+1 (555)" with U+3000 and "（");
//   - for "＋", before a digit;
//   - for brackets, around digits alone ("（０３）");
//   - in the user or subscriber of a URI, while it reads as a number
//     (mainIsNumberChar), as Redact masks all of it ("tel:（０３）１２３４").
//
// Elsewhere they are prose, such as "名前　（注）　10", "failed — retry" or
// "データー", and are kept. Text without a digit is not rewritten at all.
// Only these runes are replaced, so the text around them, valid UTF-8 or not,
// is kept. Each rune is looked at a bounded number of times (two runes
// ahead, and the digits after an opening bracket once more), so this is
// linear.
func mainAsciiNumberChars(s string) string {
	// Text without a digit holds no number, and is left alone.
	if mainIsASCII(s) || !strings.ContainsFunc(s, unicode.IsDigit) {
		return s
	}
	var b strings.Builder
	last := 0 // s[:last] has been written
	// seps counts the separators since the last digit, or is -1 if something
	// else came after it.
	seps := -1
	inURI := false // in the user or subscriber of a URI
	closeAt := -1  // where a non-ASCII bracket closes a group of digits
	for i := 0; i < len(s); {
		if n := mainSchemeLen(s[i:]); n > 0 {
			// Redact goes on from the end of a URI's number as from a digit
			// (mainContinueWritten), and the number may be empty.
			i += n
			seps, inURI = 0, true
			continue
		}
		c, size := mainNumberCharAt(s, i)
		rewrite := false
		switch {
		case mainIsDigit(c):
			rewrite = true
		case inURI && mainIsNumberChar(c):
			rewrite = true
		case c == '+':
			next, _ := mainNumberCharAt(s, i+size)
			rewrite = mainIsDigit(next)
		case mainIsNumberSeparator(c):
			rewrite = i == closeAt || mainJoinsDigits(s, i+size, seps)
			if c == '(' {
				if j, ok := mainBracketedDigits(s, i+size); ok {
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
		case mainIsDigit(c), inURI && mainIsNumberChar(c):
			seps = 0
		case mainIsNumberSeparator(c) && seps >= 0:
			seps++
		default:
			seps = -1
		}
		inURI = inURI && mainIsNumberChar(c)
		i += size
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// mainNumberCharAt returns the ASCII form of the rune at s[i] if it has one (see
// mainAsciiNumberChar), or 0, and the rune's size; at the end of s it returns 0,
// 0.
func mainNumberCharAt(s string, i int) (c byte, size int) {
	if i >= len(s) {
		return 0, 0
	}
	if s[i] < utf8.RuneSelf {
		return s[i], 1
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	c, _ = mainAsciiNumberChar(r)
	return c, size
}

// mainJoinsDigits reports whether a separator that follows seps separators after
// a digit, and is followed by s[i:], is one of at most two separators between
// two digits.
func mainJoinsDigits(s string, i, seps int) bool {
	next, size := mainNumberCharAt(s, i)
	switch seps {
	case 0:
		if mainIsNumberSeparator(next) {
			next, _ = mainNumberCharAt(s, i+size)
		}
		return mainIsDigit(next)
	case 1:
		return mainIsDigit(next)
	}
	return false
}

// mainBracketedDigits reports whether s[i:] is one or more digits followed by a
// closing bracket, and where the bracket is if it is not ASCII, or -1.
func mainBracketedDigits(s string, i int) (closeAt int, ok bool) {
	j := i
	for {
		c, size := mainNumberCharAt(s, j)
		switch {
		case mainIsDigit(c):
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

// mainAsciiNumberChar returns the ASCII character that r stands for in a number,
// if it stands for one: a decimal digit, a space, a dash, or one of the
// full-width "＋", "．", "（", "）".
func mainAsciiNumberChar(r rune) (byte, bool) {
	switch {
	case r < utf8.RuneSelf:
		return 0, false
	case unicode.IsDigit(r):
		return mainAsciiDigit(r), true
	case unicode.Is(unicode.Zs, r):
		return ' ', true
	case unicode.Is(unicode.Pd, r), r == '\u2212', r == 'ー', r == 'ｰ':
		return '-', true
	case r == '＋', r == '．', r == '（', r == '）':
		// The full-width forms block mirrors ASCII 0x21-0x7E at U+FF01.
		return byte(r - '！' + '!'), true
	}
	return 0, false
}

// mainAsciiDigit returns the ASCII digit with the value of the decimal digit r.
// Unicode allocates decimal digits in blocks of ten from zero to nine, and
// unicode.Nd lists them as ranges of whole blocks.
func mainAsciiDigit(r rune) byte {
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

func mainIsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// mainEndsURI reports whether c cannot be part of a URI written in a log line or a
// SIP header: whitespace, controls and the delimiters of name-addr and quoted
// strings (RFC 3261 §25.1).
func mainEndsURI(c byte) bool {
	return c <= ' ' || c == 0x7f || c == '<' || c == '>' || c == '"'
}

// mainIsNumberChar reports whether c can appear in a tel URI subscriber (RFC 3966
// §3: digits, hex digits, "*", "#", "+" and visual separators) or in a
// urn:gsma:imei value (digits and "-").
func mainIsNumberChar(c byte) bool {
	return mainIsDigit(c) || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' ||
		c == '*' || c == '#' || c == '+' || mainIsVisualSeparator(c)
}

func mainIsVisualSeparator(c byte) bool {
	return c == '-' || c == '.' || c == '(' || c == ')'
}

func mainIsDigit(c byte) bool { return '0' <= c && c <= '9' }

func mainIsAlnum(c byte) bool {
	return mainIsDigit(c) || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
