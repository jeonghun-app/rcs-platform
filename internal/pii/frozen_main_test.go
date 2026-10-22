// Code generated from internal/pii/pii.go at 609488e by renaming every
// top-level identifier with the prefix "main"; DO NOT EDIT.

package pii

// This is main's Redact as it was at 609488e, after #154, #413, #444 and #453,
// frozen so that TestRedactMasksAtLeastWhatMainMasked and FuzzRedact can
// check that a later change never masks less than it did (review of #398,
// #490). It is compared against the source with
//
//	git show 609488e:internal/pii/pii.go
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
// digits) are not digits here. The invisible format characters a log viewer
// hides (U+200B ZWSP, U+2060 WJ, U+00AD SHY, U+FEFF, variation selectors)
// inside a number, and the combining marks drawn over one of its digits (a
// keycap "1<VS16><U+20E3>"), are dropped first, so they split no number,
// though they still end the word before them; see [mainDropInvisibles]. So are
// invisible characters inside a URI scheme ("si<SHY>p:", [mainJoinSchemes]) and
// inside a URI user, whose hint is then the plain user's. The line and
// paragraph separators and the braille blank group a number as spaces do. A
// "+" may be followed by a bracketed country code ("+(81)3 1234 5678"); the
// full-width "＊" and "＃" of a tel number and the small "﹢" read as "*", "#"
// and "+" (#154, #413).
//
// Schemes match case-insensitively (RFC 3261 §19.1.4, RFC 3966 §3). The output
// never contains a run of eight or more decimal digits. Redact runs in time
// linear in len(s), because it is given attacker-controlled header values.
func (r *mainRedactor) Redact(s string) string {
	s, cutAt := mainAsciiNumberChars(mainDropInvisibles(mainJoinSchemes(s)))
	cuts := &mainCutList{at: cutAt}
	var b strings.Builder
	b.Grow(len(s))
	// A sip or sips URI that starts before noUserBefore has no '@' before its end:
	// remembering this keeps a line full of "sip:" prefixes linear.
	noUserBefore := 0
	for i := 0; i < len(s); {
		if mainStartsNumber(s, i) {
			from, end := mainNumberAt(s, i, cuts)
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
				_, written := mainNumberAt(s, start, cuts)
				end = max(end, written)
			}
			end = mainContinueWritten(s, end, cuts)
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
// "+" followed by a digit or by a bracketed country code ("+(81)3 1234
// 5678").
func mainStartsNumber(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if mainIsDigit(s[i]) {
		return true
	}
	return s[i] == '+' && i+1 < len(s) && (mainIsDigit(s[i+1]) || s[i+1] == '(' && i+2 < len(s) && mainIsDigit(s[i+2]))
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
// [mainAsciiNumberChars]). cuts are where mainDropInvisibles removed characters, as
// mainStartsWord reads them.
func mainNumberAt(s string, i int, cuts *mainCutList) (from, end int) {
	p := i
	if s[p] == '+' {
		p++
	}
	digits, run, longest := 0, 0, 0
	national, digitsBeforeNational := -1, 0
	for p < len(s) {
		if mainIsDigit(s[p]) {
			// A removed run splits a group for this as it did before it
			// was removed ("30<BOM>010-0000-0001").
			if (run == 0 || cuts.before(p)) && national < 0 && s[p] == '0' && mainStartsWord(s, p, cuts) {
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
func mainContinueWritten(s string, end int, cuts *mainCutList) int {
	for end < len(s) {
		q := end
		for q < len(s) && q-end < 3 && mainIsNumberSeparator(s[q]) {
			q++
		}
		if q == end || q-end > 2 || q == len(s) || !mainIsDigit(s[q]) {
			return end
		}
		_, end = mainNumberAt(s, q, cuts)
	}
	return end
}

// mainStartsWord reports whether the digit at s[p] begins a word. It does not when
// a letter or digit comes right before it ("v0", "10"), or a '.' or '-' that
// follows a digit, as inside an address, version or date ("10.0.1.2",
// "1-0"). A '.' or '-' after a letter does not join the number to the word:
// "Tel.010-0000-0001" and "phone-010-0000-0001" are labels before a number.
// Where mainDropInvisibles removed characters (cuts), they still end the word,
// as they did before they were removed: "1<ZWSP>-010-0000-0001" is masked
// as it was before #154.
func mainStartsWord(s string, p int, cuts *mainCutList) bool {
	if p == 0 || cuts.before(p) {
		return true
	}
	switch c := s[p-1]; {
	case mainIsAlnum(c):
		return false
	case c == '.' || c == '-':
		return p < 2 || cuts.before(p-1) || !mainIsDigit(s[p-2])
	}
	return true
}

// mainCutList holds, in increasing order, the positions before which
// mainDropInvisibles removed characters, and reads them with a cursor: mainNumberAt
// asks about positions mostly in increasing order, and goes back only over
// what it reads again, so the cursor moves as far as the scans do (#413).
type mainCutList struct {
	at []int
	k  int // at[:k] are before the position last asked about
}

// before reports whether mainDropInvisibles removed characters right before
// s[p].
func (c *mainCutList) before(p int) bool {
	for c.k > 0 && c.at[c.k-1] >= p {
		c.k--
	}
	for c.k < len(c.at) && c.at[c.k] < p {
		c.k++
	}
	return c.k < len(c.at) && c.at[c.k] == p
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
// visual separators of RFC 3966 §5.1.1 and spaces, also the Unicode spaces
// that mainAsciiNumberChars keeps inside a URI user; anything else is returned
// unchanged.
func mainCanonical(v string) string {
	digits := false
	for _, r := range v {
		switch c, _ := mainAsciiNumberChar(r); {
		case r < utf8.RuneSelf && mainIsDigit(byte(r)):
			digits = true
		case r < utf8.RuneSelf && (r == '+' || mainIsNumberSeparator(byte(r))), c == ' ':
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
// they do: every space (Unicode Zs: U+3000, no-break and thin spaces), the
// line and paragraph separators (Zl, Zp) and U+2800 BRAILLE PATTERN BLANK
// become " ", every dash (Unicode Pd, U+2212 minus and the long vowel marks
// "ー" and "ｰ" that the "-" key types in a Japanese kana mode) becomes "-",
// and "．", "（", "）", "＋", "﹢", "＊" and "＃" become ASCII,
//
//   - when one or two of them join two digits, as mainNumberAt reads them
//     ("０１０ー１２３４", "+1 (555)" with U+3000 and "（");
//   - for "＋" and "﹢", before a digit, or before a bracket and a digit, and
//     for "（" after a "+" and before a digit, as mainStartsNumber reads them
//     ("＋（８１）３");
//   - for brackets, around digits alone ("（０３）");
//   - in the user or subscriber of a URI, while it reads as a number
//     (mainIsNumberChar), as Redact masks all of it ("tel:（０３）１２３４",
//     "tel:１２３＊４５").
//
// A space stays as it is inside the user of a sip, sips, im or pres URI
// that reaches an "@": Redact masks such a user whole, up to the "@", and an
// ASCII space there would end it. Without an "@" there is no user, and a
// space after the scheme groups a number as anywhere else.
//
// Elsewhere they are prose, such as "名前　（注）　10", "failed — retry" or
// "データー", and are kept. Text without a digit is not rewritten at all.
// Only these runes are replaced, so the text around them, valid UTF-8 or not,
// is kept. Each rune is looked at a bounded number of times (two runes
// ahead, and the digits after an opening bracket once more), and the scans
// for the "@" of a user do not overlap, so this is linear.
//
// cuts are the positions in s before which mainDropInvisibles removed
// characters, in increasing order; mainAsciiNumberChars moves them to the same
// places in its result.
func mainAsciiNumberChars(s string, cuts []int) (string, []int) {
	// Text without a digit holds no number, and is left alone.
	if mainIsASCII(s) || !strings.ContainsFunc(s, unicode.IsDigit) {
		return s, cuts
	}
	var b strings.Builder
	last := 0 // s[:last] has been written
	// shift is how many bytes the rewrites before s[i] saved; cuts[:k] are
	// moved.
	shift, k := 0, 0
	// seps counts the separators since the last digit, or is -1 if something
	// else came after it.
	seps := -1
	inURI := false // in the user or subscriber of a URI
	// Before s[userAt] is the user of a sip, sips, im or pres URI, which
	// Redact masks whole up to its "@", whatever mainSchemes it holds. The scan
	// for the "@" from a scheme ended at s[userEnd]; one from a later scheme
	// before it ends there too.
	userAt, userEnd := -1, -1
	closeAt := -1 // where a non-ASCII bracket closes a group of digits
	afterPlus := false
	for i := 0; i < len(s); {
		for ; k < len(cuts) && cuts[k] <= i; k++ {
			cuts[k] -= shift
		}
		if n := mainSchemeLen(s[i:]); n > 0 {
			// Redact goes on from the end of a URI's number as from a digit
			// (mainContinueWritten), and the number may be empty.
			seps, inURI = 0, true
			if mainHasUserinfo(s[i:i+n]) && i+n > userEnd {
				userEnd = mainUserScanEnd(s, i+n)
				// Redact masks a user only up to an "@"; without one, a
				// Unicode space after the scheme groups a number.
				if userEnd < len(s) && s[userEnd] == '@' {
					userAt = userEnd
				}
			}
			i += n
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
			// Before a digit, or a bracket and a digit, as mainStartsNumber
			// reads a number ("+(81)3").
			next, nextSize := mainNumberCharAt(s, i+size)
			if rewrite = mainIsDigit(next); next == '(' {
				after, _ := mainNumberCharAt(s, i+size+nextSize)
				rewrite = mainIsDigit(after)
			}
		case c == '(' && afterPlus && mainIsDigitAt(s, i+size):
			rewrite = true
		case c == ' ' && size > 1 && i < userAt:
			// A space inside a user is no separator there; Redact reads the
			// user up to its "@" only while no ASCII space ends it.
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
			shift += size - 1
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
		afterPlus = c == '+'
		i += size
	}
	for ; k < len(cuts); k++ {
		cuts[k] -= shift
	}
	if last == 0 {
		return s, cuts
	}
	b.WriteString(s[last:])
	return b.String(), cuts
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

// mainIsDigitAt reports whether the rune at s[i] is a digit of any script.
func mainIsDigitAt(s string, i int) bool {
	c, _ := mainNumberCharAt(s, i)
	return mainIsDigit(c)
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
// full-width "＋", "．", "（", "）", "＊", "＃" and the small "﹢".
func mainAsciiNumberChar(r rune) (byte, bool) {
	switch {
	case r < utf8.RuneSelf:
		return 0, false
	case unicode.IsDigit(r):
		return mainAsciiDigit(r), true
	case unicode.In(r, unicode.Zs, unicode.Zl, unicode.Zp), r == '\u2800':
		// Every space, the line and paragraph separators, and the braille
		// blank, which shows as one (#413).
		return ' ', true
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

// mainJoinSchemes removes the runs of invisible characters inside a URI scheme
// ("si<SHY>p:", "tel<ZWSP>:"), which a log viewer shows as the scheme, so
// that Redact finds the scheme as it does without them (#413). A run is
// removed when the text before it ends with the start of a scheme and the
// text after it, read past further runs, goes on with the rest. The rest is
// at most 13 bytes, so this is linear.
func mainJoinSchemes(s string) string {
	if mainIsASCII(s) {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !mainIsInvisible(r) {
			i += size
			continue
		}
		end := i + size
		for end < len(s) {
			r2, size2 := utf8.DecodeRuneInString(s[end:])
			if !mainIsInvisible(r2) {
				break
			}
			end += size2
		}
		if mainSplitsScheme(b.String(), s[last:i], s[end:]) {
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

// mainSplitsScheme reports whether a run of invisible characters, after the text
// written followed by pending and before rest, is inside a scheme.
func mainSplitsScheme(written, pending, rest string) bool {
	for _, sch := range mainSchemes {
		for k := 1; k < len(sch); k++ {
			if mainEndsWithFold(written, pending, sch[:k]) && mainStartsWithFoldPast(rest, sch[k:]) {
				return true
			}
		}
	}
	return false
}

// mainEndsWithFold reports whether written followed by pending ends with p,
// ignoring case.
func mainEndsWithFold(written, pending, p string) bool {
	if n := len(pending); n >= len(p) {
		return strings.EqualFold(pending[n-len(p):], p)
	}
	k := len(p) - len(pending)
	return len(written) >= k && strings.EqualFold(written[len(written)-k:], p[:k]) && strings.EqualFold(pending, p[k:])
}

// mainStartsWithFoldPast reports whether s starts with p, ignoring case and the
// invisible characters between p's bytes.
func mainStartsWithFoldPast(s, p string) bool {
	j := 0
	for i := 0; i < len(p); i++ {
		for j < len(s) {
			r, size := utf8.DecodeRuneInString(s[j:])
			if !mainIsInvisible(r) {
				break
			}
			j += size
		}
		if j == len(s) || !strings.EqualFold(s[j:j+1], p[i:i+1]) {
			return false
		}
		j++
	}
	return true
}

// mainDropInvisibles removes the invisible format characters that sit inside a
// number (#154): a run of characters of category Cf, Default_Ignorable or a
// variation selector (U+200B ZWSP, U+2060 WJ, U+00AD SHY, U+FEFF), and of
// combining marks (Mn, Me) when it follows a number character (#413, #453),
// between two number characters, one of them a digit; between two number
// characters of a tel or urn:gsma:imei URI, which Redact masks all of; or
// where at most two separators lead to a digit after it, and before it to a
// digit or the end of a URI's number, as mainNumberAt and mainContinueWritten join
// groups, or a "+" is just before it ("+1 <ZWSP>(555)", "+<ZWSP>(81)"). A
// log viewer shows such a number with its digits joined, and so it is masked
// as if written without them, with the same hint. Every such run inside the
// user of a sip, sips, im or pres URI that reaches its "@" is removed too,
// so that the user's hint is the plain user's (#413). Elsewhere they are
// text and are kept.
//
// It returns, in increasing order, the positions in its result before which
// it removed a run: there a removed run still ends a word (mainStartsWord), as it
// did before #154. The look for a digit after a run crosses at most two
// separators, and so at most two later runs, and the scans for the "@" of a
// user do not overlap, so this is linear.
func mainDropInvisibles(s string) (string, []int) {
	if mainIsASCII(s) {
		return s, nil
	}
	var b strings.Builder
	var cuts []int
	last := 0
	var prev rune = -1
	inURI := false // in the number of a tel or urn:gsma:imei URI
	// seps counts the separators since a digit or the end of a URI's
	// number, or is -1 if something else came after it.
	seps := -1
	// Before s[userAt] is the user of a sip, sips, im or pres URI that
	// reaches its "@", as mainAsciiNumberChars finds it.
	userAt, userEnd := -1, -1
	for i := 0; i < len(s); {
		if n := mainSchemeLen(s[i:]); n > 0 {
			// Redact goes on from the end of a tel or urn:gsma:imei URI's
			// number, which may be empty, as from a digit (mainContinueWritten).
			inURI, prev, seps = !mainHasUserinfo(s[i:i+n]), ':', -1
			if inURI {
				seps = 0
			} else if i+n > userEnd {
				if userEnd = mainUserScanEnd(s, i+n); userEnd < len(s) && s[userEnd] == '@' {
					userAt = userEnd
				}
			}
			i += n
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		// A combining mainMark right after a number character is drawn over
		// it, and so joins the run (a keycap "1<VS16><U+20E3>", #413, or
		// "*<VS16><U+20E3>", #453); whether the run is dropped is still
		// for the rules below, so "café" stays.
		marks := mainNumberSide(prev) || inURI && mainUriNumberRune(prev)
		if !mainIsInvisible(r) && !(marks && mainIsMark(r)) {
			inURI = inURI && mainUriNumberRune(r)
			switch {
			case mainDigitRune(r) || inURI:
				seps = 0
			case mainSeparatorRune(r) && seps >= 0:
				seps++
			default:
				seps = -1
			}
			prev = r
			i += size
			continue
		}
		end := i + size
		for end < len(s) {
			r2, size2 := utf8.DecodeRuneInString(s[end:])
			if !mainIsInvisible(r2) && !(marks && mainIsMark(r2)) {
				break
			}
			end += size2
		}
		next := rune(-1)
		if end < len(s) {
			next, _ = utf8.DecodeRuneInString(s[end:])
		}
		joins := mainNumberSide(prev) && mainNumberSide(next) && (mainDigitRune(prev) || mainDigitRune(next)) ||
			// prev is the scheme's ':' only right after it, where the
			// URI's number starts.
			inURI && (mainUriNumberRune(prev) || prev == ':') && mainUriNumberRune(next)
		switch {
		case i < userAt:
			// Inside a user, which Redact masks whole: dropped, so that
			// the hint is the plain user's (#413).
			b.WriteString(s[last:i])
			last = end
		case joins || (mainPlusRune(prev) || 0 <= seps && seps <= 2) && mainDigitAfter(s, end):
			b.WriteString(s[last:i])
			cuts = append(cuts, b.Len())
			last = end
		}
		i = end
	}
	if last == 0 {
		return s, nil
	}
	b.WriteString(s[last:])
	return b.String(), cuts
}

// mainDigitAfter reports whether a digit comes at or after s[i] with at most two
// separators, and any invisible characters and the marks on the separators
// (#453), before it.
func mainDigitAfter(s string, i int) bool {
	for seps := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case mainIsInvisible(r), mainIsMark(r):
		case mainDigitRune(r):
			return true
		case mainSeparatorRune(r) && seps < 2:
			seps++
		default:
			return false
		}
	}
	return false
}

// mainSeparatorRune reports whether r is a space, dash, dot or bracket, in ASCII
// or as mainAsciiNumberChar reads it.
func mainSeparatorRune(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 0 && mainIsNumberSeparator(byte(r))
	}
	c, _ := mainAsciiNumberChar(r)
	return mainIsNumberSeparator(c)
}

// mainUriNumberRune reports whether r is a character of a tel or urn:gsma:imei
// number (mainIsNumberChar), in ASCII or as mainAsciiNumberChar reads it.
func mainUriNumberRune(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 0 && mainIsNumberChar(byte(r))
	}
	c, _ := mainAsciiNumberChar(r)
	return mainIsNumberChar(c)
}

// mainPlusRune reports whether r is "+" in ASCII or as mainAsciiNumberChar reads it.
func mainPlusRune(r rune) bool {
	c, _ := mainAsciiNumberChar(r)
	return r == '+' || c == '+'
}

// mainIsMark reports whether r is a combining mainMark (Mn, Me).
func mainIsMark(r rune) bool { return unicode.In(r, unicode.Mn, unicode.Me) }

// mainUserScanEnd returns where the user of a sip, sips, im or pres URI that
// starts at s[i] ends, as Redact reads it: at its "@", or at the first byte
// that ends a URI (mainEndsURI), or at the end of s.
func mainUserScanEnd(s string, i int) int {
	for i < len(s) && s[i] != '@' && (s[i] >= utf8.RuneSelf || !mainEndsURI(s[i])) {
		i++
	}
	return i
}

// mainIsInvisible reports whether r is a character a log viewer does not show:
// a format character (Cf), a variation selector or another Default_Ignorable
// one.
func mainIsInvisible(r rune) bool {
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

// mainNumberSide reports whether r can be part of a number: a digit of any
// script, "+", "*", "#", a space, dash, dot or bracket, in ASCII or as
// mainAsciiNumberChar reads it. Letters, even hex digits, are not.
func mainNumberSide(r rune) bool {
	if r < 0 {
		return false
	}
	if r < utf8.RuneSelf {
		c := byte(r)
		return mainIsDigit(c) || c == '+' || c == '*' || c == '#' || mainIsNumberSeparator(c)
	}
	_, ok := mainAsciiNumberChar(r)
	return ok
}

// mainDigitRune reports whether r is a decimal digit of any script.
func mainDigitRune(r rune) bool { return r >= 0 && unicode.IsDigit(r) }

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
