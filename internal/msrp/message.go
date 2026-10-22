package msrp

import (
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Methods this package knows by name. Any other upper-case method parses
// (§9 other-method) and is answered with 501 by an endpoint.
const (
	MethodSend   = "SEND"
	MethodReport = "REPORT"
	// MethodNickname is the RFC 7701 §7.1 chat-room nickname request.
	MethodNickname = "NICKNAME"
)

// Continuation flags of the end-line (§7.1).
const (
	FlagEnd   byte = '$' // last chunk of the message
	FlagMore  byte = '+' // more chunks follow
	FlagAbort byte = '#' // the sender gives up on the message
)

// Header field names with a meaning in RFC 4975. Names are matched
// case-insensitively on input (§9 uses case-insensitive literals) and
// written with this spelling.
const (
	hdrToPath        = "To-Path"
	hdrFromPath      = "From-Path"
	hdrMessageID     = "Message-ID"
	hdrSuccessReport = "Success-Report"
	hdrFailureReport = "Failure-Report"
	hdrByteRange     = "Byte-Range"
	hdrStatus        = "Status"
	hdrContentType   = "Content-Type"
)

// ReportMode is the value of a Success-Report or Failure-Report header.
// The zero value means the header is absent, which is not the same as any
// explicit value: REPORT requests must not carry either header (§7.1.2).
type ReportMode uint8

// Report modes. Success-Report only allows Yes and No.
const (
	ReportUnset ReportMode = iota
	ReportYes
	ReportNo
	ReportPartial
)

func (r ReportMode) String() string {
	switch r {
	case ReportYes:
		return "yes"
	case ReportNo:
		return "no"
	case ReportPartial:
		return "partial"
	}
	return ""
}

// Unknown marks a Byte-Range end or total written as "*".
const Unknown int64 = -1

// ByteRange is a Byte-Range header value (§7.1.1). Positions count from 1.
type ByteRange struct {
	Start int64
	End   int64 // Unknown for "*"
	Total int64 // Unknown for "*"
}

// wholeUnknown is what a SEND without Byte-Range means (§7.3.1).
var wholeUnknown = ByteRange{Start: 1, End: Unknown, Total: Unknown}

func (r ByteRange) String() string {
	return strconv.FormatInt(r.Start, 10) + "-" + starInt(r.End) + "/" + starInt(r.Total)
}

func starInt(n int64) string {
	if n == Unknown {
		return "*"
	}
	return strconv.FormatInt(n, 10)
}

// valid checks the relations §7.1.1 implies: positions start at 1, an
// empty range ends one before its start ("1-0/0"), and nothing lies beyond
// a known total.
func (r ByteRange) valid() bool {
	if r.Start < 1 || r.End < Unknown || r.Total < Unknown {
		return false
	}
	if r.End != Unknown && r.End < r.Start-1 {
		return false
	}
	if r.Total != Unknown {
		if r.Start-1 > r.Total || r.End != Unknown && r.End > r.Total {
			return false
		}
	}
	return true
}

// Status is a Status header value (§7.1.2). Namespace 0 ("000") means the
// code reads exactly like a transaction response code.
type Status struct {
	Namespace int
	Code      int
	Comment   string
}

func (s Status) String() string {
	v := pad3(s.Namespace) + " " + pad3(s.Code)
	if s.Comment != "" {
		v += " " + s.Comment
	}
	return v
}

func pad3(n int) string {
	s := strconv.Itoa(n)
	return strings.Repeat("0", 3-len(s)) + s
}

// Field is a header the Message struct has no typed field for: extension
// headers and the MIME headers other than Content-Type, such as
// Content-ID, Content-Description and Content-Disposition.
type Field struct {
	Name  string
	Value string
}

// Message is one MSRP request or response (§7). A request with a non-empty
// ContentType has a body, possibly empty; a request without one has no
// body at all, which §7.1 treats as different from an empty body.
type Message struct {
	TransactionID string

	// Method is set for requests and empty for responses.
	Method string
	// StatusCode and Comment are the response start line.
	StatusCode int
	Comment    string

	// ToPath and FromPath are the hop lists, leftmost hop first (§7.1).
	ToPath   []URI
	FromPath []URI

	MessageID     string
	ByteRange     *ByteRange
	SuccessReport ReportMode
	FailureReport ReportMode
	Status        *Status
	ContentType   string

	// Header holds every other header in wire order.
	Header []Field
	// Body is the content, which prints as "[redacted body]" (Body).
	Body Body

	// Continuation is the end-line flag. The zero value is written as
	// FlagEnd.
	Continuation byte
}

// IsRequest reports whether m is a request rather than a response.
func (m *Message) IsRequest() bool { return m.Method != "" }

// HasBody reports whether a request carries a body (§7.1: a body always
// comes with a Content-Type).
func (m *Message) HasBody() bool { return m.ContentType != "" }

// Get returns the first Header field named name, matched
// case-insensitively.
func (m *Message) Get(name string) (string, bool) {
	for _, f := range m.Header {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

// Range returns the Byte-Range in effect: a SEND without the header carries
// a whole message of unknown size (§7.3.1).
func (m *Message) Range() ByteRange {
	if m.ByteRange == nil {
		return wholeUnknown
	}
	return *m.ByteRange
}

// FailureMode is the Failure-Report value in effect; absent means yes
// (§7.1.1).
func (m *Message) FailureMode() ReportMode {
	if m.FailureReport == ReportUnset {
		return ReportYes
	}
	return m.FailureReport
}

// WantsSuccessReport reports whether the sender asked for success REPORTs;
// absent means no (§7.1.1).
func (m *Message) WantsSuccessReport() bool { return m.SuccessReport == ReportYes }

// flag returns the end-line flag that is written for m.
func (m *Message) flag() byte {
	if m.Continuation == 0 {
		return FlagEnd
	}
	return m.Continuation
}

// MediaType returns the lower-cased type/subtype of the Content-Type.
func (m *Message) MediaType() string {
	t, _, err := mime.ParseMediaType(m.ContentType)
	if err != nil {
		return ""
	}
	return t
}

// validContentType follows the §9 media-type rule: type "/" subtype and
// parameters. mime.ParseMediaType alone also takes a type with no subtype.
func validContentType(v string) bool {
	t, _, err := mime.ParseMediaType(v)
	if err != nil || !validText(v) {
		return false
	}
	main, sub, ok := strings.Cut(t, "/")
	return ok && isToken(main) && isToken(sub)
}

func isMIMEHeader(name string) bool {
	return len(name) >= len("Content-") && strings.EqualFold(name[:len("Content-")], "Content-")
}

func isKnownHeader(name string) bool {
	switch {
	case strings.EqualFold(name, hdrToPath), strings.EqualFold(name, hdrFromPath),
		strings.EqualFold(name, hdrMessageID), strings.EqualFold(name, hdrSuccessReport),
		strings.EqualFold(name, hdrFailureReport), strings.EqualFold(name, hdrByteRange),
		strings.EqualFold(name, hdrStatus), strings.EqualFold(name, hdrContentType):
		return true
	}
	return false
}

// validMethod follows §9 other-method: one or more upper-case letters.
func validMethod(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// validHeaderName follows §9 hname: a letter followed by token characters.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') && (len(s) == 1 || isToken(s[1:]))
}

// validText follows §9 utf8text: tab, printable ASCII and well-formed
// UTF-8 beyond ASCII. Rejecting every other control character is what keeps
// a CR or LF from ending a header line early.
func validText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != '\t' && (r < 0x20 || r == 0x7f) {
			return false
		}
	}
	return true
}
