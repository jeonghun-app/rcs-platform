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
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeonghun-app/rcs-platform/internal/xmlsafe"
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
	ErrDTD = fmt.Errorf("resourcelists: %w", xmlsafe.ErrDTD)
	// ErrTooLarge reports a document beyond MaxDocumentSize.
	ErrTooLarge = fmt.Errorf("resourcelists: %w", xmlsafe.ErrTooLarge)
	// ErrTooMany reports a document with more entries than allowed.
	ErrTooMany = errors.New("resourcelists: too many entries")
	// ErrMalformed reports a document that is not a resource-lists
	// document this package reads.
	ErrMalformed = errors.New("resourcelists: malformed document")
)

// document is what Parse checks a document for, and the errors it reports
// (internal/xmlsafe).
// A character reference to a surrogate is read as U+FFFD, and isText
// skips the entry that holds it rather than refusing the list.
var document = xmlsafe.Doc{MaxSize: MaxDocumentSize, MaxDepth: maxDepth, DTD: ErrDTD, TooLarge: ErrTooLarge, Malformed: ErrMalformed,
	SurrogateRefs: true}

// Entry is one entry of a list: its uri attribute, and its display-name.
type Entry struct {
	URI         string
	DisplayName string
}

// Parse returns the entries of data, of every list in document order, or
// ErrTooMany as soon as there are more than limit. Entries by reference
// (entry-ref, external) are not followed: there is nothing to dereference
// them against here, and they are left out.
//
// An entry whose uri is missing or no URI a client means (not text, or
// with white space or control characters) is left out too, and counted in
// skipped, but counts toward limit: one bad entry does not refuse a list
// (docs/rcs-as.md), and no list is read past limit. A display name that
// is not text is dropped, its entry kept.
func Parse(data []byte, limit int) (entries []Entry, skipped int, err error) {
	d, err := document.NewReader(data)
	if err != nil {
		return nil, 0, err
	}
	var (
		out    []Entry
		seen   int // entries, skipped ones included
		bad    int
		stack  []xml.Name
		entry  *Entry
		inName bool
	)
	for {
		// The Reader refuses a DTD, a second root, nesting past maxDepth,
		// repeated attributes and text outside the root.
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 && t.Name != (xml.Name{Space: Namespace, Local: "resource-lists"}) {
				return nil, 0, fmt.Errorf("%w: not one resource-lists root", ErrMalformed)
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
				if seen == limit {
					return nil, 0, ErrTooMany
				}
				seen++
				uri := attr(t.Attr, "uri")
				if uri == "" || !isText(uri) || strings.ContainsFunc(uri, unicode.IsSpace) || strings.ContainsFunc(uri, unicode.IsControl) {
					// A URI has neither white space nor control
					// characters (RFC 3986 §2), and one with a CR LF
					// could become a header wherever it is written.
					bad++
					entry = nil
					continue
				}
				out = append(out, Entry{URI: uri})
				entry = &out[len(out)-1]
			case t.Name.Local == "display-name" && entry != nil && parent == (xml.Name{Space: Namespace, Local: "entry"}):
				inName = true
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, 0, fmt.Errorf("%w: unbalanced element", ErrMalformed)
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
			if inName && entry != nil {
				if len(entry.DisplayName)+len(t) > maxNameBytes {
					return nil, 0, fmt.Errorf("%w: display name too long", ErrMalformed)
				}
				entry.DisplayName += string(t)
			}
		}
	}
	for i := range out {
		if !isText(out[i].DisplayName) {
			out[i].DisplayName = ""
		}
	}
	return out, bad, nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// isText reports valid UTF-8 without U+FFFD: encoding/xml passes on what
// it could not read as U+FFFD, a character reference to a surrogate
// (&#xD800;) included, and no name or URI a client means has one (QA on
// #279).
func isText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, utf8.RuneError) }
