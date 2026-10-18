package ifc

// The document checks here are the same as in internal/diameter/sh and in the
// imdn and conference packages of #9, apart from names and limits. Issue #17
// moves them into one shared package.

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxDocumentSize bounds an IMSSubscription document. A profile with tens of
// filter criteria is a few tens of KiB; 128 KiB keeps the document well
// inside the 256 KiB Diameter message limit the S-CSCF and HSS use. A larger
// one is what DIAMETER_ERROR_TOO_MUCH_DATA (TS 29.229 §6.2.2.8) is for.
const MaxDocumentSize = 128 << 10

// maxDepth bounds element nesting. The deepest element of the schema is nine
// levels down (five PublicIdentity extensions); the margin leaves room for
// extensions this package skips while keeping a hostile document from driving
// the decoder's recursion.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or expand
	// input without bound (docs/architecture.md §8).
	ErrDTD = errors.New("ifc: document type declarations are not accepted")
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = errors.New("ifc: document too large")
	// ErrMalformed reports a document that is not well-formed XML or does
	// not follow the TS 29.228 Annex E schema. The wrapping error says what
	// is wrong and where, but never quotes the document.
	ErrMalformed = errors.New("ifc: malformed user data")
)

// checkDocument enforces what xml.Unmarshal does not: a size limit, no DTD, a
// nesting limit, exactly one root element with nothing but white space around
// it, and no repeated attribute. The decoder already refuses undefined
// entities and encodings other than UTF-8.
func checkDocument(data []byte) error {
	if len(data) > MaxDocumentSize {
		return ErrTooLarge
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots := 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return decodeError(err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return ErrDTD
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if roots > 1 {
				return fmt.Errorf("%w: more than one root element", ErrMalformed)
			}
			if depth > maxDepth {
				return fmt.Errorf("%w: elements nested deeper than %d", ErrMalformed, maxDepth)
			}
			if hasRepeatedAttr(t.Attr) {
				return fmt.Errorf("%w: repeated attribute", ErrMalformed)
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && len(bytes.Trim(t, " \t\r\n")) > 0 {
				return fmt.Errorf("%w: text outside the root element", ErrMalformed)
			}
		}
	}
	if roots == 0 {
		return fmt.Errorf("%w: no root element", ErrMalformed)
	}
	return nil
}

// withoutBOM drops a leading UTF-8 byte order mark, which XML 1.0 §4.3.3
// allows before a UTF-8 document and encoding/xml would read as text.
func withoutBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
}

// decodeError reduces an encoding/xml error to its line number. The decoder's
// messages quote the input, such as an element name or a value, and could put
// a subscriber identity into a log.
func decodeError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%w: XML syntax error on line %d", ErrMalformed, se.Line)
	}
	return fmt.Errorf("%w: document does not have the expected structure", ErrMalformed)
}

func hasRepeatedAttr(attrs []xml.Attr) bool {
	seen := make(map[xml.Name]bool, len(attrs))
	for _, a := range attrs {
		if seen[a.Name] {
			return true
		}
		seen[a.Name] = true
	}
	return false
}

// isXMLText reports whether s can be written as XML 1.0 character data
// unchanged. encoding/xml silently replaces other characters with U+FFFD,
// which would alter an identity or a pattern without telling anyone.
func isXMLText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		ok := r == '\t' || r == '\n' || r == '\r' ||
			0x20 <= r && r <= 0xD7FF ||
			0xE000 <= r && r <= 0xFFFD ||
			0x10000 <= r && r <= 0x10FFFF
		if !ok {
			return false
		}
	}
	return true
}

// collapse applies the XML Schema "collapse" white space rule (XML Schema
// Part 2 §4.3.6) that anyURI, integer and boolean values follow: runs of the
// four XML white space characters become one space, and leading and trailing
// ones go.
func collapse(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}), " ")
}
