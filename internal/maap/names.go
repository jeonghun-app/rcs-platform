package maap

import (
	"unicode"
)

// Code points the display name rule names.
const (
	zeroWidthNonJoiner  = '\u200c'
	zeroWidthJoiner     = '\u200d'
	variationSelector16 = '\ufe0f'
	combiningKeycap     = '\u20e3'
	blackFlag           = '\U0001F3F4'
	cancelTag           = '\U000E007F'
)

// displayNameProblem says why name cannot be shown as a chatbot's name, or
// returns "" (T13; #717 and #741 reviews, lead decisions on #709). Beyond
// the C0 controls, which refuseControls refuses first, it refuses every
// character that shows as nothing or as space between others, with which a
// name can look like another's or blank: DEL and the C1 controls; Unicode
// Default_Ignorable_Code_Point, approximated as Cf, Other_DICP and the
// variation selectors (so every bidi control and the Hangul fillers); line
// and paragraph separators; U+2800, which shows blank; and a name of white
// space only. Three exceptions keep real names and emoji working:
//   - ZWJ between an emoji and another, and VS16 after an emoji or in a
//     keycap; an emoji here is a Unicode So symbol, after its skin-tone
//     modifier or VS16 for a ZWJ;
//   - ZWNJ between letters (a letter or mark before it, as after a virama),
//     which Persian and Indic names need;
//   - tag characters in a subdivision flag, U+1F3F4, tag letters or digits,
//     then CANCEL TAG.
//
// Look-alike letters (homoglyphs) and spellings that differ only in Unicode
// normalisation are left as T13's residual risk.
func displayNameProblem(name string) string {
	rs := []rune(name)
	at := func(i int) rune {
		if i < 0 || i >= len(rs) {
			return -1
		}
		return rs[i]
	}
	blank := true
	for i := 0; i < len(rs); i++ {
		r, prev, next := rs[i], at(i-1), at(i+1)
		switch {
		case r == blackFlag && isTagSpec(next):
			// Skip the flag's tags, which must end in CANCEL TAG.
			j := i + 1
			for isTagSpec(at(j)) {
				j++
			}
			if at(j) != cancelTag {
				return "an emoji tag sequence that is not a subdivision flag"
			}
			i, blank = j, false
		case r == zeroWidthJoiner:
			if !emojiBeforeJoiner(prev) || !emoji(next) {
				return "a zero-width joiner outside an emoji sequence"
			}
		case r == variationSelector16:
			if !emoji(prev) && !(keycapBase(prev) && next == combiningKeycap) {
				return "a variation selector outside an emoji"
			}
		case r == zeroWidthNonJoiner:
			if !unicode.IsLetter(prev) && !unicode.IsMark(prev) || !unicode.IsLetter(next) {
				return "a zero-width non-joiner outside a word"
			}
		case invisible(r):
			return "a control, format or invisible character"
		case !unicode.IsSpace(r):
			blank = false
		}
	}
	if blank && name != "" {
		return "white space only"
	}
	return ""
}

func invisible(r rune) bool {
	return 0x7f <= r && r <= 0x9f || r == '\u2800' ||
		unicode.In(r, unicode.Cf, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector, unicode.Zl, unicode.Zp)
}

// emoji approximates an emoji as an So symbol: the standard library has no
// Extended_Pictographic table.
func emoji(r rune) bool { return unicode.Is(unicode.So, r) && !invisible(r) }

// emojiBeforeJoiner says whether r may end the emoji a ZWJ follows: the
// emoji itself, its skin-tone modifier (U+1F3FB–U+1F3FF) or VS16.
func emojiBeforeJoiner(r rune) bool {
	return emoji(r) || 0x1F3FB <= r && r <= 0x1F3FF || r == variationSelector16
}

func keycapBase(r rune) bool { return '0' <= r && r <= '9' || r == '#' || r == '*' }

// isTagSpec reports whether r is a tag letter or digit, the characters a
// subdivision flag spells its region with (U+E0061–U+E007A, U+E0030–U+E0039).
func isTagSpec(r rune) bool {
	return 0xE0061 <= r && r <= 0xE007A || 0xE0030 <= r && r <= 0xE0039
}
