// Package resourcelists reads the entries of a resource-lists document
// (RFC 4826 §3.4), as an RCS client sends one in a group chat's INVITE to
// the conference factory (RFC 5366) and in a REFER that adds participants
// (RFC 5368).
//
// It reads the document as a stream and stops at the first entry beyond
// the limit it is given, so that a list too long for a group is refused
// before the rest is read. Like the platform's other XML readers it refuses
// a document type declaration, bounds size and nesting, and never puts the
// input into an error, which could carry a subscriber address into a log.
package resourcelists

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Namespace is the resource-lists namespace (RFC 4826 §3.4.1).
const Namespace = "urn:ietf:params:xml:ns:resource-lists"

// ContentType is the media type of a resource-lists document (RFC 4826
// §3.4.1).
const ContentType = "application/resource-lists+xml"

// MaxDocumentSize bounds a document: a list of a group's size, each entry
// a long URI and a name, is a few tens of kilobytes.
const MaxDocumentSize = 128 << 10

// maxDepth bounds element nesting: lists may nest (RFC 4826 §3.4.2), but
// no client nests them deep.
const maxDepth = 16

// maxNameBytes bounds a display name as read; what a group keeps is
// checked by the group.
const maxNameBytes = 1024

var (
	// ErrDTD reports a document type declaration, never accepted: entity
	// definitions are how XML parsers are made to read files or expand
	// input without bound (docs/architecture.md §8).
	ErrDTD = errors.New("resourcelists: document type declarations are not accepted")
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = errors.New("resourcelists: document too large")
	// ErrTooMany reports a document with more entries than allowed.
	ErrTooMany = errors.New("resourcelists: too many entries")
	// ErrMalformed reports a document that is not a resource-lists
	// document this package reads.
	ErrMalformed = errors.New("resourcelists: malformed document")
)

// Entry is one entry of a list: its uri attribute, and its display-name.
type Entry struct {
	URI         string
	DisplayName string
}

// Parse returns the entries of data, of every list in document order, or
// ErrTooMany as soon as there are more than limit. Entries by reference
// (entry-ref, external) are not followed: there is nothing to dereference
// them against here, and they are left out.
func Parse(data []byte, limit int) ([]Entry, error) {
	if len(data) > MaxDocumentSize {
		return nil, ErrTooLarge
	}
	d := xml.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	var (
		out    []Entry
		stack  []xml.Name
		entry  *Entry
		inName bool
		roots  int
	)
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, decodeError(err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, ErrDTD
		case xml.StartElement:
			if len(stack) == 0 {
				roots++
				if roots > 1 || t.Name != (xml.Name{Space: Namespace, Local: "resource-lists"}) {
					return nil, fmt.Errorf("%w: not one resource-lists root", ErrMalformed)
				}
			}
			if len(stack) >= maxDepth {
				return nil, fmt.Errorf("%w: elements nested deeper than %d", ErrMalformed, maxDepth)
			}
			if repeatedAttr(t.Attr) {
				return nil, fmt.Errorf("%w: repeated attribute", ErrMalformed)
			}
			parent := xml.Name{}
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, t.Name)
			if t.Name.Space != Namespace {
				continue // an extension, ignored (RFC 4826 §3.4.1)
			}
			switch {
			case t.Name.Local == "entry" && parent == (xml.Name{Space: Namespace, Local: "list"}):
				uri := attr(t.Attr, "uri")
				if uri == "" || !isText(uri) || strings.ContainsFunc(uri, unicode.IsSpace) || strings.ContainsFunc(uri, unicode.IsControl) {
					// A URI has neither white space nor control
					// characters (RFC 3986 §2), and one with a CR LF
					// could become a header wherever it is written.
					return nil, fmt.Errorf("%w: entry without a uri", ErrMalformed)
				}
				if len(out) == limit {
					return nil, ErrTooMany
				}
				out = append(out, Entry{URI: uri})
				entry = &out[len(out)-1]
			case t.Name.Local == "display-name" && entry != nil && parent == (xml.Name{Space: Namespace, Local: "entry"}):
				inName = true
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("%w: unbalanced element", ErrMalformed)
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch top {
			case xml.Name{Space: Namespace, Local: "display-name"}:
				inName = false
			case xml.Name{Space: Namespace, Local: "entry"}:
				if entry != nil && len(stack) > 0 && stack[len(stack)-1] == (xml.Name{Space: Namespace, Local: "list"}) {
					entry = nil
				}
			}
		case xml.CharData:
			switch {
			case len(stack) == 0 && len(bytes.Trim(t, " \t\r\n")) > 0:
				return nil, fmt.Errorf("%w: text outside the root element", ErrMalformed)
			case inName && entry != nil:
				if len(entry.DisplayName)+len(t) > maxNameBytes {
					return nil, fmt.Errorf("%w: display name too long", ErrMalformed)
				}
				entry.DisplayName += string(t)
			}
		}
	}
	if roots == 0 {
		return nil, fmt.Errorf("%w: no root element", ErrMalformed)
	}
	for i := range out {
		if !isText(out[i].DisplayName) {
			return nil, fmt.Errorf("%w: display name is not text", ErrMalformed)
		}
	}
	return out, nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func repeatedAttr(attrs []xml.Attr) bool {
	seen := make(map[xml.Name]bool, len(attrs))
	for _, a := range attrs {
		if seen[a.Name] {
			return true
		}
		seen[a.Name] = true
	}
	return false
}

// isText reports valid UTF-8 without U+FFFD: encoding/xml passes on what
// it could not read as U+FFFD, a character reference to a surrogate
// (&#xD800;) included, and no name or URI a client means has one (QA on
// #279).
func isText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, utf8.RuneError) }

// decodeError reduces an encoding/xml error to its line number: the
// decoder's messages quote the input.
func decodeError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("%w: XML syntax error on line %d", ErrMalformed, se.Line)
	}
	return fmt.Errorf("%w: document does not have the expected structure", ErrMalformed)
}
