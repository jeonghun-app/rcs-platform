package msrp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidMessage reports a Message that cannot be written because the
// result would break RFC 4975.
var ErrInvalidMessage = errors.New("msrp: invalid message")

// maxNonSendBody is the §7.1 limit on bodies of requests that cannot be
// interrupted, which is every request except SEND.
const maxNonSendBody = 10240

const endLinePrefix = "-------"

// Marshal returns the wire form of m. It refuses a message that would not
// parse back to the same content, in particular one whose body contains its
// own end-line (§7.1).
func (m *Message) Marshal() ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Grow(256 + len(m.Body))
	b.WriteString("MSRP ")
	b.WriteString(m.TransactionID)
	b.WriteByte(' ')
	if m.IsRequest() {
		b.WriteString(m.Method)
	} else {
		b.WriteString(pad3(m.StatusCode))
		if m.Comment != "" {
			b.WriteByte(' ')
			b.WriteString(m.Comment)
		}
	}
	b.WriteString("\r\n")

	writePath(&b, hdrToPath, m.ToPath)
	writePath(&b, hdrFromPath, m.FromPath)
	if m.MessageID != "" {
		writeHeader(&b, hdrMessageID, m.MessageID)
	}
	if m.ByteRange != nil {
		writeHeader(&b, hdrByteRange, m.ByteRange.String())
	}
	if m.SuccessReport != ReportUnset {
		writeHeader(&b, hdrSuccessReport, m.SuccessReport.String())
	}
	if m.FailureReport != ReportUnset {
		writeHeader(&b, hdrFailureReport, m.FailureReport.String())
	}
	if m.Status != nil {
		writeHeader(&b, hdrStatus, m.Status.String())
	}
	// §9 puts MIME headers after the MSRP ones and Content-Type last (§7.1).
	for _, f := range m.Header {
		if !isMIMEHeader(f.Name) {
			writeHeader(&b, f.Name, f.Value)
		}
	}
	for _, f := range m.Header {
		if isMIMEHeader(f.Name) {
			writeHeader(&b, f.Name, f.Value)
		}
	}
	if m.HasBody() {
		writeHeader(&b, hdrContentType, m.ContentType)
		b.WriteString("\r\n")
		b.Write(m.Body)
		b.WriteString("\r\n")
	}
	b.WriteString(endLinePrefix)
	b.WriteString(m.TransactionID)
	b.WriteByte(m.flag())
	b.WriteString("\r\n")
	return b.Bytes(), nil
}

// WriteTo writes the wire form of m to w.
func (m *Message) WriteTo(w io.Writer) (int64, error) {
	b, err := m.Marshal()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

func writePath(b *bytes.Buffer, name string, path []URI) {
	b.WriteString(name)
	b.WriteString(":")
	for _, u := range path {
		b.WriteByte(' ')
		b.WriteString(u.String())
	}
	b.WriteString("\r\n")
}

func writeHeader(b *bytes.Buffer, name, value string) {
	b.WriteString(name)
	b.WriteString(": ")
	b.WriteString(value)
	b.WriteString("\r\n")
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidMessage, fmt.Sprintf(format, args...))
}

func (m *Message) check() error {
	// A response echoes the request's id (§7.2), even one that was only
	// good enough to frame the request it refuses.
	if !validIdent(m.TransactionID) && (m.IsRequest() || !validFramingID(m.TransactionID)) {
		return invalid("transaction id %q", m.TransactionID)
	}
	if m.IsRequest() {
		if !validMethod(m.Method) {
			return invalid("method %q", m.Method)
		}
	} else {
		if m.StatusCode < 0 || m.StatusCode > 999 || !validText(m.Comment) {
			return invalid("response start line")
		}
		if m.HasBody() || len(m.Body) > 0 || m.flag() != FlagEnd {
			return invalid("a response has no body and is never continued (§7.2)")
		}
	}
	if len(m.ToPath) == 0 || len(m.FromPath) == 0 {
		return invalid("To-Path and From-Path are required")
	}
	for _, u := range append(append([]URI(nil), m.ToPath...), m.FromPath...) {
		if !u.valid() {
			return invalid("malformed path URI")
		}
	}
	if m.MessageID != "" && !validIdent(m.MessageID) {
		return invalid("Message-ID %q", m.MessageID)
	}
	if m.ByteRange != nil && !m.ByteRange.valid() {
		return invalid("Byte-Range %s", m.ByteRange)
	}
	if m.SuccessReport > ReportNo || m.FailureReport > ReportPartial {
		return invalid("report header value")
	}
	if s := m.Status; s != nil &&
		(s.Namespace < 0 || s.Namespace > 999 || s.Code < 0 || s.Code > 999 || !validText(s.Comment)) {
		return invalid("Status header")
	}
	switch c := m.flag(); c {
	case FlagEnd, FlagMore, FlagAbort:
	default:
		return invalid("continuation flag %q", c)
	}
	if m.IsRequest() && m.Method != MethodSend {
		if m.flag() != FlagEnd {
			return invalid("only SEND requests are chunked (§7.1)")
		}
		if len(m.Body) > maxNonSendBody {
			return invalid("%s body larger than %d octets (§7.1)", m.Method, maxNonSendBody)
		}
	}
	if m.Method == MethodReport {
		if m.Status == nil || m.SuccessReport != ReportUnset || m.FailureReport != ReportUnset {
			return invalid("REPORT needs Status and no report headers (§7.1.2)")
		}
	}
	for _, f := range m.Header {
		if !validHeaderName(f.Name) || !validText(f.Value) {
			return invalid("header %q", f.Name)
		}
		if isKnownHeader(f.Name) {
			return invalid("header %s has a typed field", f.Name)
		}
		if isMIMEHeader(f.Name) && !m.HasBody() {
			return invalid("MIME header %s without a body (§7.1)", f.Name)
		}
	}
	if m.HasBody() {
		if !validContentType(m.ContentType) {
			return invalid("Content-Type %q", m.ContentType)
		}
		if bodyHasBoundary(m.Body, m.TransactionID) {
			return invalid("body contains the end-line of transaction %s (§7.1)", m.TransactionID)
		}
	} else if len(m.Body) > 0 {
		return invalid("a body needs a Content-Type (§7.1)")
	}
	return nil
}

// bodyHasBoundary reports whether tid cannot frame body (§7.1).
func bodyHasBoundary(body []byte, tid string) bool {
	return bytes.Contains(body, []byte(endLinePrefix+tid))
}
