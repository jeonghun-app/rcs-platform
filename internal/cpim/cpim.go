// Package cpim reads and writes message/cpim bodies (RFC 3862), the envelope in
// which RCS clients exchange chat messages, standalone messages and disposition
// notifications.
//
// RFC 3862 §2.2 forbids changing message header octets or their order in
// transit, and §6 forbids a gateway from changing the content at all. A relay
// that forwards a message unchanged must therefore forward the bytes it
// received, not Marshal of the parsed Message: Marshal writes the canonical
// form, which differs from the input wherever Parse was lenient and wherever
// a content header was folded.
//
// Parse is lenient about how a header is laid out but strict about what it
// says. It accepts bare LF line ends when the headers use them throughout, any
// white space around a header value (or none), and empty values, because a
// rejected message is a lost message. It still rejects mixed line ends,
// control characters, invalid UTF-8, header names outside the grammar, broken
// namespace declarations, a missing Content-Type and anything beyond Limits.
// Header values are interpreted on demand: From, To, Cc and DateTime check
// their own header, so one bad cc does not lose the whole message. Marshal is
// strict and writes only what RFC 3862 §3.6 allows.
//
// Header names are case-sensitive (RFC 3862 §2.2): "from" is an unknown header,
// kept as such, not From. A prefixed name such as "imdn.Message-ID" belongs to
// the namespace an earlier NS header bound to the prefix (§3.4), so Get and Add
// take a namespace URI rather than a prefix: the prefix is the sender's choice
// and carries no meaning of its own.
//
// The encapsulated object keeps its MIME headers and body (§2.4). MIME header
// names are case-insensitive, folded MIME headers are unfolded, and the body is
// opaque bytes.
//
// Every rejection is an *Error whose Reason can be counted. Error messages
// identify input by line number only and never quote it: values carry
// subscriber addresses, and a header name can be shaped like one.
package cpim

import (
	"bytes"
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
	// DefaultMaxContentHeaderSize is far above the few hundred bytes of
	// content headers a real message carries.
	DefaultMaxContentHeaderSize = 8 << 10
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

	deviations Deviation
}

// Deviation is a set of the RFC 3862 §2.2 layout rules a parsed message broke
// and Parse tolerated. A service can count them to learn what real clients
// send before deciding how lenient to stay.
type Deviation uint8

// The tolerated deviations. Content headers are MIME, where the spacing that
// these flags record is legal, so only message headers set Spacing,
// TrailingWS and EmptyValue.
const (
	// DeviationBareLF: the headers end lines with LF instead of CRLF.
	DeviationBareLF Deviation = 1 << iota
	// DeviationSpacing: a header has no space, or more than one, or a tab,
	// between the colon (or parameters) and the value.
	DeviationSpacing
	// DeviationTrailingWS: a header line ends in space or tab.
	DeviationTrailingWS
	// DeviationEmptyValue: a header has an empty value.
	DeviationEmptyValue
)

var deviationNames = []struct {
	d    Deviation
	name string
}{
	{DeviationBareLF, "bare-lf"},
	{DeviationSpacing, "spacing"},
	{DeviationTrailingWS, "trailing-ws"},
	{DeviationEmptyValue, "empty-value"},
}

// Has reports whether d includes every deviation in x.
func (d Deviation) Has(x Deviation) bool {
	return d&x == x
}

// String lists the deviations as fixed names joined by commas, for example
// "bare-lf,spacing"; empty when there are none.
func (d Deviation) String() string {
	var names []string
	for _, dn := range deviationNames {
		if d&dn.d != 0 {
			names = append(names, dn.name)
		}
	}
	return strings.Join(names, ",")
}

// Deviations reports the layout deviations Parse tolerated in m; zero for a
// conforming message and for one built in code.
func (m *Message) Deviations() Deviation {
	return m.deviations
}

// Limits bounds the input Parse accepts. The zero value applies the defaults.
type Limits struct {
	// MaxSize is the largest message/cpim body accepted, headers included,
	// in bytes.
	MaxSize int
	// MaxHeaders is the largest number of lines accepted in each of the
	// message header and content header sections. Continuation lines of
	// folded content headers count.
	MaxHeaders int
	// MaxContentHeaderSize is the largest content header section accepted,
	// in bytes including line ends. The section is MIME, where a header may be
	// folded over any number of lines, so it gets a bound of its own rather
	// than a share of MaxSize.
	MaxContentHeaderSize int
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

func (l Limits) maxContentHeaderSize() int {
	if l.MaxContentHeaderSize > 0 {
		return l.MaxContentHeaderSize
	}
	return DefaultMaxContentHeaderSize
}

// Parse parses data with the default Limits.
func Parse(data []byte) (*Message, error) {
	return Limits{}.Parse(data)
}

// Parse parses a message/cpim body: the message headers, an empty line, the
// content headers, an empty line and the content (RFC 3862 §2). The returned
// Message does not alias data.
func (l Limits) Parse(data []byte) (*Message, error) {
	if len(data) > l.maxSize() {
		return nil, reject(ReasonTooLarge, "message larger than MaxSize")
	}
	lf := usesBareLF(data)
	m := &Message{}
	if lf {
		m.deviations |= DeviationBareLF
	}
	rest := data
	lineNo := 0
	for {
		line, r, ok := nextLine(rest, lf)
		if !ok {
			return nil, reject(ReasonFraming, "message headers do not end with an empty line")
		}
		rest = r
		lineNo++
		if len(line) == 0 {
			break
		}
		if len(m.Headers) == l.maxHeaders() {
			return nil, reject(ReasonTooLarge, "more message headers than MaxHeaders")
		}
		h, err := parseHeaderLine(string(line))
		if err != nil {
			return nil, atLine(err, lineNo)
		}
		m.deviations |= layoutDeviations(string(line), h)
		m.Headers = append(m.Headers, h)
	}

	// A folded MIME header continues on lines starting with white space; it is
	// joined to its first line before being parsed (RFC 5322 §2.2.3). Each
	// header is appended to in place, so joining costs time linear in its
	// length however many lines it is folded over.
	var raw [][]byte
	var rawLine []int
	sectionStart, lines := len(data)-len(rest), 0
	for {
		line, r, ok := nextLine(rest, lf)
		if !ok {
			return nil, reject(ReasonFraming, "content headers do not end with an empty line")
		}
		rest = r
		lineNo++
		if len(data)-len(rest)-sectionStart > l.maxContentHeaderSize() {
			return nil, reject(ReasonTooLarge, "content headers longer than MaxContentHeaderSize")
		}
		if len(line) == 0 {
			break
		}
		if lines == l.maxHeaders() {
			return nil, reject(ReasonTooLarge, "more content header lines than MaxHeaders")
		}
		lines++
		if line[0] == ' ' || line[0] == '\t' {
			if len(raw) == 0 {
				return nil, atLine(reject(ReasonFraming, "continuation line without a header"), lineNo)
			}
			raw[len(raw)-1] = append(raw[len(raw)-1], line...)
			continue
		}
		raw = append(raw, bytes.Clone(line))
		rawLine = append(rawLine, lineNo)
	}
	for i, b := range raw {
		f, err := parseFieldLine(string(b))
		if err != nil {
			return nil, atLine(err, rawLine[i])
		}
		m.ContentHeaders = append(m.ContentHeaders, f)
	}
	m.Body = bytes.Clone(rest)

	if err := m.checkStructure(); err != nil {
		return nil, err
	}
	return m, nil
}

// Marshal serializes m in canonical form: CRLF line ends, one space after
// each colon. It fails rather than emit anything Parse would reject or read
// differently, so a header value can never smuggle a line break into the
// output, and it checks the values of the core headers it knows.
func (m *Message) Marshal() ([]byte, error) {
	for i, h := range m.Headers {
		if err := checkHeader(h); err != nil {
			return nil, atLine(err, i+1)
		}
	}
	for i, f := range m.ContentHeaders {
		if err := checkField(f); err != nil {
			return nil, atLine(err, len(m.Headers)+2+i)
		}
	}
	if err := m.checkStructure(); err != nil {
		return nil, err
	}
	if err := m.checkCoreValues(); err != nil {
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

// checkStructure validates what every later header depends on: namespace
// declarations are valid and precede their use (§3.4), and the content has a
// Content-Type (§2.4).
func (m *Message) checkStructure() error {
	var firstErr error
	m.walk(func(i int, _ Header, _, _ string, err error) {
		if firstErr == nil && err != nil {
			firstErr = atLine(err, i+1)
		}
	})
	if firstErr != nil {
		return firstErr
	}
	if _, ok := m.ContentHeader("Content-Type"); !ok {
		return reject(ReasonContentType, "content has no Content-Type")
	}
	return nil
}

// checkCoreValues checks the §4 syntax of the core headers Marshal writes.
// Parse leaves this to the accessors.
func (m *Message) checkCoreValues() error {
	var firstErr error
	m.walk(func(i int, h Header, ns, local string, err error) {
		if firstErr != nil || err != nil || ns != CoreNamespace {
			return
		}
		switch local {
		case HeaderFrom, HeaderTo, HeaderCc:
			_, err = ParseAddress(h.Value)
		case HeaderDateTime:
			_, err = ParseDateTime(h.Value)
		case HeaderRequire:
			err = checkRequire(h.Value)
		}
		if err != nil {
			firstErr = atLine(err, i+1)
		}
	})
	return firstErr
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

// AddFirst inserts a header named name in namespace ns in front of every
// existing header of that name, or appends it like Add when there is none. A
// list such as IMDN-Record-Route, where each intermediary goes on top (RFC
// 5438 §8), needs this. The new header copies the existing first one's name,
// prefix included, so at that position it resolves to the same namespace.
func (m *Message) AddFirst(ns, name, value string) error {
	at := -1
	m.walk(func(i int, _ Header, hns, local string, err error) {
		if at < 0 && err == nil && hns == ns && local == name {
			at = i
		}
	})
	if at < 0 {
		return m.Add(ns, name, value)
	}
	m.Headers = slices.Insert(m.Headers, at, Header{Name: m.Headers[at].Name, Value: value})
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
		return reject(ReasonNamespace, "invalid namespace prefix")
	}
	if !isAbsoluteURI(ns) || strings.ContainsRune(ns, '#') {
		return reject(ReasonNamespace, "namespace is not an absolute URI")
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
func (m *Message) To() (Addresses, error) {
	to, err := m.addresses(HeaderTo)
	if err == nil && len(to) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrMissingHeader, HeaderTo)
	}
	return to, err
}

// Cc returns the courtesy copy addresses, which are optional.
func (m *Message) Cc() (Addresses, error) {
	return m.addresses(HeaderCc)
}

func (m *Message) addresses(name string) (Addresses, error) {
	var out Addresses
	for _, h := range m.All(CoreNamespace, name) {
		a, err := ParseAddress(h.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// DateTime returns the time the sender sent the message (RFC 3862 §4.4). The
// raw value, which an IMDN echoes, is Get(CoreNamespace, HeaderDateTime).
func (m *Message) DateTime() (time.Time, error) {
	h, ok := m.Get(CoreNamespace, HeaderDateTime)
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s", ErrMissingHeader, HeaderDateTime)
	}
	return ParseDateTime(h.Value)
}

// FormatDateTime formats t for a DateTime header. Whole seconds are enough for
// the header's purpose, letting a person correlate a message with its
// notifications (RFC 5438 §7.1.1.2).
func FormatDateTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// ParseDateTime parses an RFC 3339 date-time, including the forms Go's
// time.RFC3339 layout refuses: lower-case "t" and "z" (RFC 3339 §5.6) and a
// leap second, second 60 (§5.7). time.Time cannot hold a leap second, so it
// becomes the first instant after it.
func ParseDateTime(v string) (time.Time, error) {
	v = strings.Map(func(r rune) rune {
		switch r {
		case 't':
			return 'T'
		case 'z':
			return 'Z'
		}
		return r
	}, v)
	// Second 60 is accepted at any minute, not only where RFC 3339 §5.7 puts
	// leap seconds: receiving is lenient and the value only orders messages.
	leap := len(v) > 19 && v[10] == 'T' && v[16] == ':' && v[17:19] == "60"
	if leap {
		v = v[:17] + "59" + v[19:]
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, reject(ReasonValue, "DateTime is not an RFC 3339 date-time")
	}
	if leap {
		t = t.Add(time.Second)
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
