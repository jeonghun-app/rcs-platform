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
//   - A backslash before a character that is not special is undefined in an
//     ERE (§9.4.2). Go reads \x41, \101 and \n as the characters they spell,
//     refuses \d, \w, \b and \p with a message that does not say why, and
//     reads \< and \@ as "<" and "@", where glibc and musl read \< as a
//     word boundary. Only the characters of ereSpecial may be escaped.
//   - Go has no collating symbols ("[.a.]") or equivalence classes
//     ("[=a=]") and reads their brackets as members of the class.
//   - "[:^alpha:]" is not a class name (§9.3.5); glibc refuses it and Go
//     reads it as the negated class.
//   - An interval without its lower bound, "{,3}", is undefined (§9.4.6);
//     glibc reads {0,3}, Go the text "{,3}".
//
// A backslash before a special character, as in "conf\.example\.com" or
// "\+1555", is a literal everywhere. The names returned quote no part of the
// pattern beyond the construct's own characters, since a pattern can hold an
// identity. The scan is linear in len(source).
func ereDeparture(source string) string {
	var s classScan
	for i := 0; i < len(source); i++ {
		switch source[i] {
		case '\\':
			if i+1 < len(source) && !strings.ContainsRune(ereSpecial, rune(source[i+1])) {
				return escapeName(source[i+1])
			}
			i++ // the escaped character is a literal, even "[" or "\"
		case '{':
			if i+1 < len(source) && source[i+1] == ',' {
				return "the interval {,n}"
			}
		case '[':
			end, departure := s.bracketEnd(source, i)
			if departure != "" {
				return departure
			}
			i = end
		}
	}
	return ""
}

// classScan remembers, across the bracket expressions of one pattern, that
// no ":]" follows some position, so that a pattern full of "[:" is searched
// once rather than once per "[:".
type classScan struct {
	noCloseAfter int // no ":]" starts at or after this index, once known
	known        bool
}

// namedClassEnd returns the index of the ":" of the ":]" that ends a named
// class whose name starts at from, or -1 when there is none.
func (s *classScan) namedClassEnd(source string, from int) int {
	if s.known && from >= s.noCloseAfter {
		return -1
	}
	end := strings.Index(source[from:], ":]")
	if end < 0 {
		s.known, s.noCloseAfter = true, from
		return -1
	}
	return from + end
}

// bracketEnd returns the index of the "]" that closes the bracket
// expression opening at source[open], following §9.3.5: a "]" first in the
// list, after an optional "^", is a member, and "[:", "[." and "[=" open an
// element that runs to ":]", ".]" or "=]". It names a construct Go reads
// differently instead, if one comes first. An unclosed expression ends at
// the end of source; the parser refuses it.
func (s *classScan) bracketEnd(source string, open int) (int, string) {
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
				if end := s.namedClassEnd(source, i+2); end >= 0 {
					if strings.HasPrefix(source[i+2:], "^") {
						return 0, "the negated class [:^ :]"
					}
					i = end + 1 // at the "]" of ":]"
				}
			}
		}
	}
	return len(source), ""
}

// ereSpecial lists the characters a backslash may escape: the ERE special
// characters of §9.4.3 ("^.[$()|*+?{\"), and "]" and "}", which close what
// "[" and "{" open. A backslash before any other character is undefined
// (§9.4.2), and implementations differ: glibc and musl read "\<" and "\>"
// as word boundaries and glibc "\`" and "\'" as the ends of the value,
// where Go reads the characters themselves.
const ereSpecial = `^.[$()|*+?{\]}`

// escapeName names the escape of c for an error, quoting c only when it is
// a visible ASCII character, never a byte of a multi-byte character.
func escapeName(c byte) string {
	if '!' <= c && c <= '~' {
		return `the escape \` + string(rune(c))
	}
	return "a backslash before a character that is not special"
}
