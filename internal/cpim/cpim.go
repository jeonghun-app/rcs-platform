// Package cpim reads and writes message/cpim bodies (RFC 3862), the envelope in
// which RCS clients exchange chat messages, standalone messages and disposition
// notifications.
//
// Message headers are kept exactly as received. RFC 3862 §2.2 forbids changing
// their octets or their order in transit and §6 forbids a gateway from changing
// the content at all, so a Message stores raw header values and Marshal of a
// parsed Message reproduces every message header octet. Accessors such as From,
// To and DateTime interpret the raw values on demand.
//
// Header names are case-sensitive (RFC 3862 §3). A prefixed name such as
// "imdn.Message-ID" belongs to the namespace an earlier NS header bound to the
// prefix (§3.4), so Get and Add take a namespace URI rather than a prefix: the
// prefix is the sender's choice and carries no meaning of its own.
//
// The encapsulated object keeps its MIME headers and body (§2.4). MIME header
// names are case-insensitive, folded MIME headers are unfolded, and the body is
// opaque bytes.
//
// Parse rejects rather than repairs: anything outside the §3.6 grammar is an
// error, and Limits bound what Parse accepts. Error messages never contain
// header values, because those carry subscriber addresses.
package cpim

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ContentType is the MIME type of a CPIM body.
const ContentType = "message/cpim"

// CoreNamespace is the namespace of the headers RFC 3862 §4 defines and the
// default namespace of unprefixed header names until an NS header changes it
// (§3.4).
const CoreNamespace = "urn:ietf:params:cpim-headers:"

// Names of the RFC 3862 §4 headers in CoreNamespace. They are case-sensitive:
// "cc" is lower case on the wire.
const (
	HeaderFrom     = "From"
	HeaderTo       = "To"
	HeaderCc       = "cc"
	HeaderDateTime = "DateTime"
	HeaderSubject  = "Subject"
	HeaderNS       = "NS"
	HeaderRequire  = "Require"
)

// Defaults applied by a zero Limits.
const (
	// DefaultMaxSize allows large-mode standalone messages and file transfer
	// descriptors with room to spare; a service accepting larger content sets
	// its own limit.
	DefaultMaxSize = 1 << 20
	// DefaultMaxHeaders is far above the dozen headers a real message carries.
	DefaultMaxHeaders = 64
)

var (
	// ErrMalformed reports input outside the RFC 3862 grammar.
	ErrMalformed = errors.New("cpim: malformed message")
	// ErrTooLarge reports input beyond the configured Limits.
	ErrTooLarge = errors.New("cpim: message exceeds limits")
	// ErrMissingHeader reports that a header an accessor needs is absent.
	ErrMissingHeader = errors.New("cpim: header not present")
	// ErrUndeclaredNamespace reports that no prefix is bound to a namespace.
	ErrUndeclaredNamespace = errors.New("cpim: namespace not declared")
)

// Header is one message header.
type Header struct {
	// Name is the header name as on the wire, including any namespace prefix,
	// for example "imdn.Message-ID".
	Name string
	// Params holds the header parameters exactly as on the wire, each with
	// its leading ';', for example ";lang=fr" (RFC 3862 §3.3). Usually empty.
	Params string
	// Value is the raw header value. Escape sequences (RFC 3862 §2.3) are not
	// decoded; use Unescape for display.
	Value string
}

// Param returns the value of the header parameter called name, with quotes and
// escapes removed.
func (h Header) Param(name string) (string, bool) {
	params, _, err := parseParams(h.Params)
	if err != nil {
		return "", false
	}
	for _, p := range params {
		if p.name == name {
			return p.value, true
		}
	}
	return "", false
}

// Field is one MIME header of the encapsulated object.
type Field struct {
	Name  string
	Value string
}

// Message is a parsed message/cpim body.
type Message struct {
	// Headers are the message headers in wire order.
	Headers []Header
	// ContentHeaders are the MIME headers of the encapsulated object. RFC 3862
	// §2.4 requires a Content-Type among them.
	ContentHeaders []Field
	// Body is the encapsulated content, ending where the transport's framing
	// ends (RFC 3862 §2).
	Body []byte
}

// Limits bounds the input Parse accepts. The zero value applies the defaults.
type Limits struct {
	// MaxSize is the largest body accepted, in bytes.
	MaxSize int
	// MaxHeaders is the largest number of headers accepted in each of the
	// message header and content header sections.
	MaxHeaders int
}

func (l Limits) maxSize() int {
	if l.MaxSize > 0 {
		return l.MaxSize
	}
	return DefaultMaxSize
}

func (l Limits) maxHeaders() int {
	if l.MaxHeaders > 0 {
		return l.MaxHeaders
	}
	return DefaultMaxHeaders
}

// Parse parses data with the default Limits.
func Parse(data []byte) (*Message, error) {
	return Limits{}.Parse(data)
}

// Parse parses a message/cpim body: the message headers, a blank line, the
// content headers, a blank line and the content (RFC 3862 §2). The returned
// Message does not alias data.
func (l Limits) Parse(data []byte) (*Message, error) {
	if len(data) > l.maxSize() {
		return nil, ErrTooLarge
	}
	m := &Message{}
	rest := data
	lineNo := 0
	for {
		line, r, ok := nextLine(rest)
		if !ok {
			return nil, fmt.Errorf("%w: message headers are not terminated by a blank line", ErrMalformed)
		}
		rest = r
		lineNo++
		if len(line) == 0 {
			break
		}
		if len(m.Headers) == l.maxHeaders() {
			return nil, fmt.Errorf("%w: more than %d message headers", ErrTooLarge, l.maxHeaders())
		}
		h, err := parseHeaderLine(string(line))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		m.Headers = append(m.Headers, h)
	}

	// A folded MIME header continues on lines starting with white space; it is
	// joined to its first line before being parsed (RFC 5322 §2.2.3).
	var raw []string
	for {
		line, r, ok := nextLine(rest)
		if !ok {
			return nil, fmt.Errorf("%w: content headers are not terminated by a blank line", ErrMalformed)
		}
		rest = r
		lineNo++
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(raw) == 0 {
				return nil, fmt.Errorf("%w: line %d: continuation line without a header", ErrMalformed, lineNo)
			}
			raw[len(raw)-1] += string(line)
			continue
		}
		if len(raw) == l.maxHeaders() {
			return nil, fmt.Errorf("%w: more than %d content headers", ErrTooLarge, l.maxHeaders())
		}
		raw = append(raw, string(line))
	}
	for i, s := range raw {
		f, err := parseFieldLine(s)
		if err != nil {
			return nil, fmt.Errorf("content header %d: %w", i+1, err)
		}
		m.ContentHeaders = append(m.ContentHeaders, f)
	}
	m.Body = bytes.Clone(rest)

	if err := m.checkSemantics(); err != nil {
		return nil, err
	}
	return m, nil
}

// Marshal serializes m. It fails rather than emit a body that Parse would
// reject, so a header value can never smuggle a line break into the output.
func (m *Message) Marshal() ([]byte, error) {
	for i, h := range m.Headers {
		if err := checkHeader(h); err != nil {
			return nil, fmt.Errorf("header %d: %w", i+1, err)
		}
	}
	for i, f := range m.ContentHeaders {
		if err := checkField(f); err != nil {
			return nil, fmt.Errorf("content header %d: %w", i+1, err)
		}
	}
	if err := m.checkSemantics(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, h := range m.Headers {
		b.WriteString(h.Name)
		b.WriteByte(':')
		b.WriteString(h.Params)
		b.WriteByte(' ')
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	for _, f := range m.ContentHeaders {
		b.WriteString(f.Name)
		b.WriteString(": ")
		b.WriteString(f.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(m.Body)
	return b.Bytes(), nil
}

// checkSemantics validates what the line syntax alone cannot: namespace
// declarations precede their use, core header values have their §4 syntax,
// and the content has a Content-Type (§2.4).
func (m *Message) checkSemantics() error {
	var firstErr error
	m.walk(func(i int, h Header, ns, local string, err error) {
		if firstErr != nil {
			return
		}
		if err != nil {
			firstErr = fmt.Errorf("header %d: %w", i+1, err)
			return
		}
		if ns != CoreNamespace {
			return
		}
		switch local {
		case HeaderFrom, HeaderTo, HeaderCc:
			_, err = ParseAddress(h.Value)
		case HeaderDateTime:
			_, err = parseDateTime(h.Value)
		case HeaderRequire:
			err = checkRequire(h.Value)
		}
		if err != nil {
			firstErr = fmt.Errorf("header %d (%s): %w", i+1, local, err)
		}
	})
	if firstErr != nil {
		return firstErr
	}
	if _, ok := m.ContentHeader("Content-Type"); !ok {
		return fmt.Errorf("%w: content has no Content-Type", ErrMalformed)
	}
	return nil
}

// walk calls fn for every header with the namespace and local name it
// resolves to, or with an error when it does not resolve. It returns the
// namespace bindings in force after the last header.
func (m *Message) walk(fn func(i int, h Header, ns, local string, err error)) *scope {
	s := newScope()
	for i, h := range m.Headers {
		ns, local, err := s.resolve(h.Name)
		if err == nil && ns == CoreNamespace && local == HeaderNS {
			err = s.declare(h.Value)
		}
		if fn != nil {
			fn(i, h, ns, local, err)
		}
	}
	return s
}

// Get returns the first header named name in namespace ns.
func (m *Message) Get(ns, name string) (Header, bool) {
	all := m.All(ns, name)
	if len(all) == 0 {
		return Header{}, false
	}
	return all[0], true
}

// All returns every header named name in namespace ns, in wire order.
func (m *Message) All(ns, name string) []Header {
	var out []Header
	m.walk(func(_ int, h Header, hns, local string, err error) {
		if err == nil && hns == ns && local == name {
			out = append(out, h)
		}
	})
	return out
}

// Add appends a header named name in namespace ns, using the prefix bound to
// ns at the end of the header block. Declare the namespace first.
func (m *Message) Add(ns, name, value string) error {
	prefix, ok := m.walk(nil).prefixFor(ns)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUndeclaredNamespace, ns)
	}
	if prefix != "" {
		name = prefix + "." + name
	}
	m.Headers = append(m.Headers, Header{Name: name, Value: value})
	return nil
}

// Declare makes ns usable by Add, appending "NS: prefix <ns>" unless some
// prefix is already bound to ns. An empty prefix makes ns the default namespace
// for every later unprefixed header, so core headers must be added before it.
func (m *Message) Declare(prefix, ns string) error {
	s := m.walk(nil)
	if _, ok := s.prefixFor(ns); ok {
		return nil
	}
	// The NS header is itself a core header, so once the default namespace
	// has changed it has to be written with a prefix bound to the core.
	corePrefix, ok := s.prefixFor(CoreNamespace)
	if !ok {
		return fmt.Errorf("%w: %s, needed to write an NS header", ErrUndeclaredNamespace, CoreNamespace)
	}
	if prefix != "" && !isName(prefix) {
		return fmt.Errorf("%w: invalid namespace prefix", ErrMalformed)
	}
	if !isAbsoluteURI(ns) || strings.ContainsRune(ns, '#') {
		return fmt.Errorf("%w: namespace is not an absolute URI", ErrMalformed)
	}
	value := "<" + ns + ">"
	if prefix != "" {
		value = prefix + " " + value
	}
	name := HeaderNS
	if corePrefix != "" {
		name = corePrefix + "." + HeaderNS
	}
	m.Headers = append(m.Headers, Header{Name: name, Value: value})
	return nil
}

// From returns the sender address.
func (m *Message) From() (Address, error) {
	h, ok := m.Get(CoreNamespace, HeaderFrom)
	if !ok {
		return Address{}, fmt.Errorf("%w: %s", ErrMissingHeader, HeaderFrom)
	}
	return ParseAddress(h.Value)
}

// To returns the recipient addresses; RFC 3862 §4.2 allows several.
func (m *Message) To() ([]Address, error) {
	to, err := m.addresses(HeaderTo)
	if err == nil && len(to) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingHeader, HeaderTo)
	}
	return to, err
}

// Cc returns the courtesy copy addresses, which are optional.
func (m *Message) Cc() ([]Address, error) {
	return m.addresses(HeaderCc)
}

func (m *Message) addresses(name string) ([]Address, error) {
	var out []Address
	for _, h := range m.All(CoreNamespace, name) {
		a, err := ParseAddress(h.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// DateTime returns the time the sender sent the message (RFC 3862 §4.4).
func (m *Message) DateTime() (time.Time, error) {
	h, ok := m.Get(CoreNamespace, HeaderDateTime)
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s", ErrMissingHeader, HeaderDateTime)
	}
	return parseDateTime(h.Value)
}

// FormatDateTime formats t for a DateTime header. Whole seconds are enough for
// the header's purpose, letting a person correlate a message with its
// notifications (RFC 5438 §7.1.1.2).
func FormatDateTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

func parseDateTime(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: DateTime is not an RFC 3339 date-time", ErrMalformed)
	}
	return t, nil
}

// ContentHeader returns the first content header called name, compared
// case-insensitively as MIME requires.
func (m *Message) ContentHeader(name string) (string, bool) {
	i := slices.IndexFunc(m.ContentHeaders, func(f Field) bool {
		return strings.EqualFold(f.Name, name)
	})
	if i < 0 {
		return "", false
	}
	return m.ContentHeaders[i].Value, true
}

// ContentType returns the Content-Type of the encapsulated object.
func (m *Message) ContentType() string {
	v, _ := m.ContentHeader("Content-Type")
	return v
}
