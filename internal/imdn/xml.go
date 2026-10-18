package imdn

// This file is kept identical to internal/conference/xml.go, apart from names
// and limits, until #17 moves it into a shared package.

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxDocumentSize bounds a notification document. A real one is a few hundred
// bytes; the margin covers a long subject and extension elements.
const MaxDocumentSize = 16 << 10

// maxDepth bounds element nesting. A notification is four levels deep; the
// margin leaves room for extensions while keeping a hostile document from
// driving the decoder's recursion.
const maxDepth = 32

var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or
	// expand input without bound (docs/architecture.md §8).
	ErrDTD = errors.New("imdn: document type declarations are not accepted")
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = errors.New("imdn: document too large")
)

// checkDocument enforces what xml.Decoder.Decode does not: a size limit, no
// DTD, a nesting limit, exactly one root element with nothing but white space
// around it, and no repeated attribute. The decoder already refuses undefined
// entities and encodings other than UTF-8, which RFC 5438 §11.1 requires.
func checkDocument(data []byte) error {
	if len(data) > MaxDocumentSize {
		return ErrTooLarge
	}
	d := xml.NewDecoder(bytes.NewReader(withoutBOM(data)))
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

// decodeError reduces an encoding/xml error to its line number. The
// decoder's messages quote the input, such as an entity name or a value,
// and could put a subscriber address into a log.
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
// which would alter a message ID or subject without telling anyone.
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

// xmlWriter keeps the first encoding error so that Marshal reads as the
// document it writes.
type xmlWriter struct {
	e   *xml.Encoder
	err error
}

func (w *xmlWriter) token(t xml.Token) {
	if w.err == nil {
		w.err = w.e.EncodeToken(t)
	}
}

func (w *xmlWriter) start(name string, attrs ...xml.Attr) {
	w.token(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
}

func (w *xmlWriter) end(name string) {
	w.token(xml.EndElement{Name: xml.Name{Local: name}})
}

func (w *xmlWriter) chars(s string) {
	w.token(xml.CharData(s))
}

func (w *xmlWriter) text(name, value string) {
	w.start(name)
	w.chars(value)
	w.end(name)
}

func (w *xmlWriter) close() error {
	if w.err != nil {
		return w.err
	}
	return w.e.Close()
}
