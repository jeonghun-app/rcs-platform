package ifc

import "strings"

// ereDeparture names the first construct in source that Go's POSIX parser
// reads differently from an ERE as IEEE 1003.1 §9 defines it, or returns ""
// when there is none (#67). Such a pattern is refused rather than compiled
// with Go's reading, which an operator who wrote it for a POSIX regcomp would
// not expect:
//
//   - A backslash inside a bracket expression is literal in an ERE (§9.3.5),
//     so "[\.]com" matches "\com"; Go reads an escape and matches ".com".
//   - A backslash before a letter or digit is undefined in an ERE (§9.4.2);
//     Go reads \x41, \101 and \n as the characters they spell and refuses \d,
//     \w, \b and \p with a message that does not say why.
//   - Go has no collating symbols ("[.a.]") or equivalence classes
//     ("[=a=]") and reads their brackets as members of the class.
//
// A backslash before punctuation, as in "conf\.example\.com" or "\+1555",
// stays a literal: every ERE implementation and Go read it so. The names
// returned quote no part of the pattern beyond the construct's own
// characters, since a pattern can hold an identity.
func ereDeparture(source string) string {
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '\\':
			if i+1 < len(source) && isASCIIAlnum(source[i+1]) {
				return `the escape \` + source[i+1:i+2]
			}
			i++ // the escaped character is a literal, even "[" or "\"
		case '[':
			end, departure := bracketEnd(source, i)
			if departure != "" {
				return departure
			}
			i = end
		}
	}
	return ""
}

// bracketEnd returns the index of the "]" that closes the bracket
// expression opening at source[open], following §9.3.5: a "]" first in the
// list, after an optional "^", is a member, and "[:", "[." and "[=" open an
// element that runs to ":]", ".]" or "=]". It names a construct Go reads
// differently instead, if one comes first. An unclosed expression ends at
// the end of source; the parser refuses it.
func bracketEnd(source string, open int) (int, string) {
	i := open + 1
	if i < len(source) && source[i] == '^' {
		i++
	}
	if i < len(source) && source[i] == ']' {
		i++
	}
	for ; i < len(source); i++ {
		switch source[i] {
		case '\\':
			return 0, "a backslash inside a bracket expression"
		case ']':
			return i, ""
		case '[':
			if i+1 >= len(source) {
				continue
			}
			switch source[i+1] {
			case '.':
				return 0, "the collating symbol [. .]"
			case '=':
				return 0, "the equivalence class [= =]"
			case ':':
				if end := strings.Index(source[i+2:], ":]"); end >= 0 {
					i += 2 + end + 1 // at the "]" of ":]"
				}
			}
		}
	}
	return len(source), ""
}

func isASCIIAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
