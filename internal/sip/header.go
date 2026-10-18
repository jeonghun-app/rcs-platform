package sip

import (
	"slices"
	"strings"
)

// knownHeaders gives the canonical spelling and compact form of the header fields
// this package or the services above it handle. A field added in code under one of
// these names, in any case or compact form, is written with the canonical name.
var knownHeaders = []struct {
	name    string
	compact byte
}{
	{"Accept", 0},
	{"Accept-Contact", 'a'}, // RFC 3841
	{"Accept-Encoding", 0},
	{"Accept-Language", 0},
	{"Alert-Info", 0},
	{"Allow", 0},
	{"Allow-Events", 'u'}, // RFC 6665 §8.2.2
	{"Authentication-Info", 0},
	{"Authorization", 0},
	{"Call-ID", 'i'},
	{"Call-Info", 0},
	{"Contact", 'm'},
	{"Content-Disposition", 0},
	{"Content-Encoding", 'e'},
	{"Content-Language", 0},
	{"Content-Length", 'l'},
	{"Content-Type", 'c'},
	{"Contribution-ID", 0},
	{"Conversation-ID", 0},
	{"CSeq", 0},
	{"Date", 0},
	{"Error-Info", 0},
	{"Event", 'o'}, // RFC 6665 §8.2.1
	{"Expires", 0},
	{"Feature-Caps", 0},
	{"From", 'f'},
	{"Identity", 'y'},      // RFC 8224 §4
	{"Identity-Info", 'n'}, // RFC 4474, kept so the compact form is recognised
	{"In-Reply-To", 0},
	{"InReplyTo-Contribution-ID", 0},
	{"Max-Breadth", 0},
	{"Max-Forwards", 0},
	{"MIME-Version", 0},
	{"Min-Expires", 0},
	{"Min-SE", 0},
	{"Organization", 0},
	{"P-Access-Network-Info", 0},
	{"P-Asserted-Identity", 0},
	{"P-Asserted-Service", 0},
	{"P-Associated-URI", 0},
	{"P-Called-Party-ID", 0},
	{"P-Charging-Function-Addresses", 0},
	{"P-Charging-Vector", 0},
	{"P-Preferred-Identity", 0},
	{"P-Preferred-Service", 0},
	{"P-Visited-Network-ID", 0},
	{"Path", 0},
	{"Priority", 0},
	{"Privacy", 0},
	{"Proxy-Authenticate", 0},
	{"Proxy-Authorization", 0},
	{"Proxy-Require", 0},
	{"RAck", 0},
	{"Reason", 0},
	{"Record-Route", 0},
	{"Refer-Sub", 0},
	{"Refer-To", 'r'},    // RFC 3515 §2.1
	{"Referred-By", 'b'}, // RFC 3892
	{"Reject-Contact", 'j'},
	{"Reply-To", 0},
	{"Request-Disposition", 'd'},
	{"Require", 0},
	{"Retry-After", 0},
	{"Route", 0},
	{"RSeq", 0},
	{"Security-Client", 0},
	{"Security-Server", 0},
	{"Security-Verify", 0},
	{"Server", 0},
	{"Service-Route", 0},
	{"Session-Expires", 'x'}, // RFC 4028 §4
	{"Session-ID", 0},
	{"SIP-ETag", 0},
	{"SIP-If-Match", 0},
	{"Subject", 's'},
	{"Subscription-State", 0},
	{"Supported", 'k'},
	{"Timestamp", 0},
	{"To", 't'},
	{"Unsupported", 0},
	{"User-Agent", 0},
	{"Via", 'v'},
	{"Warning", 0},
	{"WWW-Authenticate", 0},
}

var (
	canonicalByKey = map[string]string{}
	compactKeys    [256]string
)

func init() {
	for _, h := range knownHeaders {
		key := strings.ToLower(h.name)
		canonicalByKey[key] = h.name
		if h.compact != 0 {
			compactKeys[h.compact] = key
			compactKeys[h.compact-'a'+'A'] = key
		}
	}
}

// headerKey is the lookup key of a header name: lower case, with a compact form
// replaced by its full name (RFC 3261 §7.3.3).
func headerKey(name string) string {
	if len(name) == 1 {
		if k := compactKeys[name[0]]; k != "" {
			return k
		}
	}
	return strings.ToLower(name)
}

// CanonicalName returns the specification spelling of a header name, expanding a
// compact form. An unknown name is returned unchanged.
func CanonicalName(name string) string {
	if c, ok := canonicalByKey[headerKey(name)]; ok {
		return c
	}
	return name
}

// Header is the ordered list of header fields of a message.
//
// Lookups are case-insensitive and treat a compact form as its full name, so
// Get("v") and Get("Via") read the same fields. A parsed field keeps its original
// name and bytes, which the serializer writes back unchanged until the field is
// replaced. Order is kept because RFC 3261 §7.3.1 makes the order of fields with
// the same name significant.
//
// The zero value is an empty header. Copying a Header shares its storage, so use
// Clone for a copy that is changed separately. A Header must not be modified
// concurrently.
type Header struct {
	fields []field
}

type field struct {
	name  string // as written, or canonical when added in code
	key   string // headerKey(name)
	value string // unfolded, without surrounding whitespace
	raw   string // the original line(s) without the final CRLF; empty when added in code
}

// HeaderField is one header field as Fields reports it.
type HeaderField struct {
	Name  string // as written: a parsed field keeps its case and compact form
	Value string // unfolded, without surrounding whitespace
}

// Len returns the number of header fields.
func (h *Header) Len() int { return len(h.fields) }

// Fields returns a copy of the header fields in order.
func (h *Header) Fields() []HeaderField {
	out := make([]HeaderField, len(h.fields))
	for i, f := range h.fields {
		out[i] = HeaderField{Name: f.name, Value: f.value}
	}
	return out
}

// Has reports whether at least one field has the given name.
func (h *Header) Has(name string) bool {
	key := headerKey(name)
	for i := range h.fields {
		if h.fields[i].key == key {
			return true
		}
	}
	return false
}

// Get returns the value of the first field with the given name, or "".
func (h *Header) Get(name string) string {
	key := headerKey(name)
	for i := range h.fields {
		if h.fields[i].key == key {
			return h.fields[i].value
		}
	}
	return ""
}

// Values returns the value of every field with the given name, one per field
// line, in order. Use Elements to split comma-separated lists.
func (h *Header) Values(name string) []string {
	key := headerKey(name)
	var out []string
	for i := range h.fields {
		if h.fields[i].key == key {
			out = append(out, h.fields[i].value)
		}
	}
	return out
}

// Elements returns the comma-separated elements of every field with the given
// name, in order, so "Route: <a>, <b>" and two Route lines read the same (RFC 3261
// §7.3.1). It must not be used for the fields that §7.3.1 excludes from list
// syntax, such as WWW-Authenticate, Authorization and Date, whose values contain
// commas of their own.
func (h *Header) Elements(name string) ([]string, error) {
	key := headerKey(name)
	var out []string
	for i := range h.fields {
		if h.fields[i].key != key {
			continue
		}
		els, err := splitList(h.fields[i].value)
		if err != nil {
			return nil, inHeader(CanonicalName(name), err)
		}
		out = append(out, els...)
	}
	return out, nil
}

// Add appends a field. A known name is written in its canonical spelling.
//
// Add, Set and Prepend refuse a name that is not a token and a value containing
// CR or LF: either would let the value start a header line of its own. Every
// value a service writes passes through them, so this is the one place the
// check is made.
func (h *Header) Add(name, value string) error {
	f, err := newField(name, value)
	if err != nil {
		return err
	}
	h.fields = append(h.fields, f)
	return nil
}

// Prepend inserts a field before the first field with the same name, or at the
// end if there is none. Proxies use it for the Via and Record-Route they add on
// top (RFC 3261 §16.6 steps 4 and 8).
func (h *Header) Prepend(name, value string) error {
	f, err := newField(name, value)
	if err != nil {
		return err
	}
	for i := range h.fields {
		if h.fields[i].key == f.key {
			h.fields = slices.Insert(h.fields, i, f)
			return nil
		}
	}
	h.fields = append(h.fields, f)
	return nil
}

// Set replaces every field with the given name by one field holding value, at the
// position of the first of them, or appends it if there is none.
func (h *Header) Set(name, value string) error {
	f, err := newField(name, value)
	if err != nil {
		return err
	}
	first := -1
	for i := range h.fields {
		if h.fields[i].key == f.key {
			first = i
			break
		}
	}
	if first < 0 {
		h.fields = append(h.fields, f)
		return nil
	}
	h.fields[first] = f
	h.removeAfter(first+1, f.key)
	return nil
}

// Del removes every field with the given name.
func (h *Header) Del(name string) { h.removeAfter(0, headerKey(name)) }

// removeAfter removes the fields with the given key from index start on.
func (h *Header) removeAfter(start int, key string) {
	out := h.fields[:start]
	for _, f := range h.fields[start:] {
		if f.key != key {
			out = append(out, f)
		}
	}
	clear(h.fields[len(out):])
	h.fields = out
}

// Clone returns a copy that can be modified independently.
func (h *Header) Clone() Header {
	if h.fields == nil {
		return Header{}
	}
	return Header{fields: append([]field(nil), h.fields...)}
}

func newField(name, value string) (field, error) {
	if !isAll(name, classToken) {
		return field{}, syntaxError("header name is not a token")
	}
	if strings.ContainsAny(value, "\r\n") {
		return field{}, headerError(CanonicalName(name), "value contains CR or LF")
	}
	name = CanonicalName(name)
	return field{name: name, key: headerKey(name), value: trimWS(value)}, nil
}

// appendTo writes the field as a header line without the final CRLF.
func (f *field) appendTo(b []byte) []byte {
	if f.raw != "" {
		return append(b, f.raw...)
	}
	b = append(b, f.name...)
	b = append(b, ':')
	if f.value != "" {
		b = append(b, ' ')
		b = append(b, f.value...)
	}
	return b
}

// single returns the value of a field that may appear at most once.
func (h *Header) single(name string) (string, error) {
	key := headerKey(name)
	var v string
	n := 0
	for i := range h.fields {
		if h.fields[i].key == key {
			v = h.fields[i].value
			n++
		}
	}
	switch n {
	case 0:
		return "", &ParseError{Header: name, Err: ErrMissingHeader}
	case 1:
		return v, nil
	default:
		return "", headerError(name, "appears more than once")
	}
}
