// Package xmlsafe holds the protections every XML document rcs-platform
// reads and writes needs (docs/architecture.md §8), in one place: a size
// limit, no DTD, a nesting limit, one root element, no repeated attribute,
// and what encoding/xml lets through that a well-formed document cannot
// have. Each package that reads a document describes it with a Doc, whose
// errors are the package's own.
package xmlsafe

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The errors a Doc reports when it names none of its own; a package's own
// wrap these (fmt.Errorf("pkg: %w", xmlsafe.ErrDTD)), so that both match.
var (
	// ErrDTD reports a document type declaration, which is never accepted:
	// entity definitions are how XML parsers are made to read files or
	// expand input without bound.
	ErrDTD = errors.New("document type declarations are not accepted")
	// ErrTooLarge reports a document beyond Doc.MaxSize.
	ErrTooLarge = errors.New("document too large")
	// ErrMalformed reports a document that is not well-formed XML, or not
	// of the shape a Doc asks; the wrapping error says what and where, but
	// never quotes the document.
	ErrMalformed = errors.New("malformed document")
)

// Doc describes one kind of document: its limits and the errors its
// package reports. A zero error field is the package-level one.
type Doc struct {
	// MaxSize bounds the document in bytes, MaxDepth the nesting of its
	// elements.
	MaxSize, MaxDepth int
	// DTD, TooLarge and Malformed are returned for ErrDTD, ErrTooLarge
	// and ErrMalformed; Malformed is wrapped with what is wrong.
	DTD, TooLarge, Malformed error
	// SurrogateRefs lets a character reference to a surrogate through, as
	// U+FFFD, for a document whose reader refuses the value that holds it
	// on its own and keeps the rest (resource lists: one bad entry does
	// not refuse a list, docs/rcs-as.md).
	SurrogateRefs bool
}

func (d Doc) errDTD() error       { return or(d.DTD, ErrDTD) }
func (d Doc) errTooLarge() error  { return or(d.TooLarge, ErrTooLarge) }
func (d Doc) errMalformed() error { return or(d.Malformed, ErrMalformed) }

func or(err, def error) error {
	if err != nil {
		return err
	}
	return def
}

// Check reads the whole document with a Reader: the checks of Token, and
// at least one root element.
func (d Doc) Check(data []byte) error {
	r, err := d.NewReader(data)
	if err != nil {
		return err
	}
	for {
		if _, err := r.Token(); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
	}
}

// DecodeError reduces an encoding/xml error, as from Decode after Check,
// to its line number: the decoder's messages quote the input, such as an
// entity name or a value, and could put a subscriber address into a log.
func (d Doc) DecodeError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%w: XML syntax error on line %d", d.errMalformed(), se.Line)
	}
	return fmt.Errorf("%w: document does not have the expected structure", d.errMalformed())
}

// Reader reads one document's tokens, checking each.
type Reader struct {
	doc   Doc
	data  []byte
	d     *xml.Decoder
	depth int
	roots int
	at    int64
}

// NewReader is a Reader of data, a leading byte order mark dropped, or
// Doc.TooLarge.
func (d Doc) NewReader(data []byte) (*Reader, error) {
	if len(data) > d.MaxSize {
		return nil, d.errTooLarge()
	}
	data = WithoutBOM(data)
	return &Reader{doc: d, data: data, d: xml.NewDecoder(bytes.NewReader(data))}, nil
}

// Token is the next token, or io.EOF after the root element. On top of
// what encoding/xml refuses (undefined entities, encodings other than
// UTF-8, unbalanced elements), it refuses:
//   - a DTD (Doc.DTD);
//   - elements nested deeper than Doc.MaxDepth, a second root element, no
//     root element, and text outside the root;
//   - a repeated attribute, and attributes with no white space between
//     them (XML 1.0 §3.1), which encoding/xml reads as two;
//   - a character reference to a surrogate (&#xD800; to &#xDFFF;), not a
//     Char (XML 1.0 §4.1), which encoding/xml reads as U+FFFD, so that two
//     different values could become one (unless Doc.SurrogateRefs);
//   - an XML declaration or processing instruction whose target is xml in
//     another case (<?XML ?>), which XML 1.0 §2.6 reserves, and an XML
//     declaration after anything but white space (§2.8). White space
//     before it, which §2.8 does not allow either, is taken: clients send
//     a leading CR LF, and main took it before #17 (lead's decision on
//     #403). A leading byte order mark is dropped first.
func (r *Reader) Token() (xml.Token, error) {
	malformed := r.doc.errMalformed()
	tok, err := r.d.Token()
	from, to := r.at, r.d.InputOffset()
	r.at = to
	if err == io.EOF {
		if r.roots == 0 {
			return nil, fmt.Errorf("%w: no root element", malformed)
		}
		return nil, io.EOF
	}
	if err != nil {
		return nil, r.doc.DecodeError(err)
	}
	raw := r.data[from:to]
	switch t := tok.(type) {
	case xml.Directive:
		return nil, r.doc.errDTD()
	case xml.ProcInst:
		switch {
		case t.Target != "xml" && strings.EqualFold(t.Target, "xml"):
			return nil, fmt.Errorf("%w: an XML declaration not in lower case", malformed)
		case t.Target == "xml" && len(bytes.Trim(r.data[:from], " \t\r\n")) > 0:
			return nil, fmt.Errorf("%w: an XML declaration not at the start", malformed)
		}
	case xml.StartElement:
		if r.depth == 0 {
			r.roots++
		}
		r.depth++
		switch {
		case r.roots > 1:
			return nil, fmt.Errorf("%w: more than one root element", malformed)
		case r.depth > r.doc.MaxDepth:
			return nil, fmt.Errorf("%w: elements nested deeper than %d", malformed, r.doc.MaxDepth)
		case hasRepeatedAttr(t.Attr):
			return nil, fmt.Errorf("%w: repeated attribute", malformed)
		case !attrsSeparated(raw):
			return nil, fmt.Errorf("%w: attributes not separated by white space", malformed)
		case !r.doc.SurrogateRefs && hasSurrogateRef(raw):
			return nil, fmt.Errorf("%w: a character reference to a surrogate", malformed)
		}
	case xml.EndElement:
		r.depth--
	case xml.CharData:
		if r.depth == 0 && len(bytes.Trim(t, " \t\r\n")) > 0 {
			return nil, fmt.Errorf("%w: text outside the root element", malformed)
		}
		if !r.doc.SurrogateRefs && !bytes.HasPrefix(raw, []byte("<![CDATA[")) && hasSurrogateRef(raw) {
			return nil, fmt.Errorf("%w: a character reference to a surrogate", malformed)
		}
	}
	return tok, nil
}

// WithoutBOM drops a leading UTF-8 byte order mark, which XML 1.0 §4.3.3
// allows before a UTF-8 document and encoding/xml would read as text.
func WithoutBOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
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

// attrsSeparated reports whether every attribute value in the start tag
// tag, which encoding/xml has read already, is followed by white space,
// "/" or ">".
func attrsSeparated(tag []byte) bool {
	var quote byte
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				if i+1 < len(tag) && !strings.ContainsRune(" \t\r\n/>", rune(tag[i+1])) {
					return false
				}
			}
		case c == '"' || c == '\'':
			quote = c
		}
	}
	return true
}

// hasSurrogateRef reports a character reference to a surrogate in raw,
// text or a start tag as written.
func hasSurrogateRef(raw []byte) bool {
	for {
		i := bytes.Index(raw, []byte("&#"))
		if i < 0 {
			return false
		}
		raw = raw[i+2:]
		end := bytes.IndexByte(raw, ';')
		if end < 0 {
			return false
		}
		ref, base := string(raw[:end]), 10
		if strings.HasPrefix(ref, "x") {
			ref, base = ref[1:], 16
		}
		if n, err := strconv.ParseUint(ref, base, 32); err == nil && 0xD800 <= n && n <= 0xDFFF {
			return true
		}
		raw = raw[end+1:]
	}
}

// IsText reports whether s can be written as XML 1.0 character data
// unchanged (XML 1.0 §2.2, Char). encoding/xml silently replaces other
// characters with U+FFFD, which would alter a name or URI without telling
// anyone.
func IsText(s string) bool {
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

// Collapse applies the XML Schema "collapse" white space rule (XML Schema
// Part 2 §4.3.6) that anyURI, integer and boolean values follow: runs of
// the four XML white space characters become one space, and leading and
// trailing ones go.
func Collapse(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}), " ")
}

// Writer writes a document token by token and keeps the first encoding
// error, so that a Marshal reads as the document it writes.
type Writer struct {
	e   *xml.Encoder
	err error
}

// NewWriter is a Writer to w.
func NewWriter(w io.Writer) *Writer { return &Writer{e: xml.NewEncoder(w)} }

// Token writes t, unless an earlier token failed.
func (w *Writer) Token(t xml.Token) {
	if w.err == nil {
		w.err = w.e.EncodeToken(t)
	}
}

// Start writes the start tag of name with attrs.
func (w *Writer) Start(name string, attrs ...xml.Attr) {
	w.Token(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
}

// End writes the end tag of name.
func (w *Writer) End(name string) {
	w.Token(xml.EndElement{Name: xml.Name{Local: name}})
}

// Chars writes s as character data.
func (w *Writer) Chars(s string) {
	w.Token(xml.CharData(s))
}

// Text writes an element name holding the text value.
func (w *Writer) Text(name, value string) {
	w.Start(name)
	w.Chars(value)
	w.End(name)
}

// Close flushes the document, and returns the first error.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	return w.e.Close()
}
