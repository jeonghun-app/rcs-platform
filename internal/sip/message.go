package sip

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Message is a *Request or a *Response.
type Message interface {
	// Headers returns the header fields, which the caller may modify.
	Headers() *Header
	// Bytes serializes the message; see Request.Bytes.
	Bytes() ([]byte, error)
	// WriteTo writes the serialized message to w.
	WriteTo(w io.Writer) (int64, error)
	// Validate checks the header fields every transaction depends on.
	Validate() error

	message()
}

// Request is a SIP request (RFC 3261 §7.1).
type Request struct {
	// Method is case-sensitive (RFC 3261 §7.1): "INVITE", "REGISTER", ...
	Method string
	// URI is the Request-URI.
	URI    URI
	Header Header
	Body   []byte
}

// Response is a SIP response (RFC 3261 §7.2).
type Response struct {
	StatusCode int
	Reason     string
	Header     Header
	Body       []byte
}

// Headers returns the header fields.
func (r *Request) Headers() *Header { return &r.Header }

// Headers returns the header fields.
func (r *Response) Headers() *Header { return &r.Header }

func (*Request) message()  {}
func (*Response) message() {}

// Clone returns a deep copy, for a proxy that forwards one request to several
// targets (RFC 3261 §16.6 step 1).
func (r *Request) Clone() *Request {
	c := *r
	c.URI = r.URI.clone()
	c.Header = r.Header.Clone()
	c.Body = cloneBytes(r.Body)
	return &c
}

// Clone returns a deep copy.
func (r *Response) Clone() *Response {
	c := *r
	c.Header = r.Header.Clone()
	c.Body = cloneBytes(r.Body)
	return &c
}

func (u URI) clone() URI {
	u.Params = append(Params(nil), u.Params...)
	u.Headers = append(Params(nil), u.Headers...)
	return u
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

// Bytes serializes the request. Parsed header fields are written exactly as they
// were received; fields added in code are written as "Name: value". The start line
// is rebuilt from Method and URI. Content-Length always matches Body: the received
// field is kept when it is still right, replaced when it is not, and added when
// missing. Bytes fails if Method is not a token or URI cannot appear on the start
// line, either of which would corrupt the framing.
func (r *Request) Bytes() ([]byte, error) {
	if !isAll(r.Method, classToken) {
		return nil, errors.New("sip: request method is not a token")
	}
	b := make([]byte, 0, r.Header.size()+len(r.Body)+128)
	b = append(b, r.Method...)
	b = append(b, ' ')
	n := len(b)
	b = r.URI.appendTo(b)
	if len(b) == n || !printableNoSpace(b[n:]) {
		return nil, errors.New("sip: Request-URI cannot be serialized")
	}
	b = append(b, " SIP/2.0\r\n"...)
	return r.Header.appendWithBody(b, r.Body), nil
}

// Bytes serializes the response; see Request.Bytes. It fails if the status code is
// outside 100–699 or the reason phrase contains a control character or invalid
// UTF-8.
func (r *Response) Bytes() ([]byte, error) {
	if r.StatusCode < 100 || r.StatusCode > 699 {
		return nil, errors.New("sip: status code outside 100-699")
	}
	if !validReasonPhrase(r.Reason) {
		return nil, errors.New("sip: reason phrase contains a control character")
	}
	b := make([]byte, 0, r.Header.size()+len(r.Body)+64)
	b = append(b, "SIP/2.0 "...)
	b = strconv.AppendInt(b, int64(r.StatusCode), 10)
	b = append(b, ' ')
	b = append(b, r.Reason...)
	b = append(b, "\r\n"...)
	return r.Header.appendWithBody(b, r.Body), nil
}

// WriteTo writes the serialized request to w.
func (r *Request) WriteTo(w io.Writer) (int64, error) { return writeTo(w, r) }

// WriteTo writes the serialized response to w.
func (r *Response) WriteTo(w io.Writer) (int64, error) { return writeTo(w, r) }

func writeTo(w io.Writer, m Message) (int64, error) {
	b, err := m.Bytes()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(b)
	return int64(n), err
}

func printableNoSpace(b []byte) bool {
	for _, c := range b {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// validReasonPhrase allows any valid UTF-8 without control characters other
// than HTAB. The grammar is narrower (RFC 3261 §25.1 Reason-Phrase), but reason
// phrases are for people and real ones use characters it leaves out.
func validReasonPhrase(s string) bool {
	for i := 0; i < len(s); i++ {
		if isCTL(s[i]) {
			return false
		}
	}
	return utf8.ValidString(s)
}

func (h *Header) size() int {
	n := 0
	for i := range h.fields {
		n += len(h.fields[i].raw) + len(h.fields[i].name) + len(h.fields[i].value) + 4
	}
	return n
}

// appendWithBody writes the header fields, the empty line and the body, with a
// Content-Length that matches the body. Only the first Content-Length is written:
// the parser refuses a message with two, and a message built in code must not
// carry a second, stale one either.
func (h *Header) appendWithBody(b []byte, body []byte) []byte {
	written := false
	for i := range h.fields {
		f := &h.fields[i]
		if f.key == "content-length" {
			if written {
				continue
			}
			written = true
			if f.raw == "" || parseContentLengthValue(f.value) != len(body) {
				b = append(b, f.name...)
				b = append(b, ": "...)
				b = strconv.AppendInt(b, int64(len(body)), 10)
				b = append(b, "\r\n"...)
				continue
			}
		}
		b = f.appendTo(b)
		b = append(b, "\r\n"...)
	}
	if !written {
		b = append(b, "Content-Length: "...)
		b = strconv.AppendInt(b, int64(len(body)), 10)
		b = append(b, "\r\n"...)
	}
	b = append(b, "\r\n"...)
	return append(b, body...)
}

// parseContentLengthValue returns the value of a Content-Length field the parser
// accepted, or -1.
func parseContentLengthValue(v string) int {
	if !isDigits(v) {
		return -1
	}
	if v = strings.TrimLeft(v, "0"); v == "" {
		return 0
	}
	if len(v) > 9 {
		return -1
	}
	n, _ := strconv.Atoi(v)
	return n
}

// Validate checks what RFC 3261 §8.1.1 requires of every request and §16.3 has a
// proxy check: exactly one each of To, From, Call-ID and CSeq, at least one Via, all
// well-formed, a valid Max-Forwards if there is one, a CSeq method equal to the
// request method (§8.1.1.5; RFC 4475 §3.1.2.17), and no header components in a
// SIP Request-URI (§19.1.1). A request without Max-Forwards passes, as §16.3 step
// 3 says it must.
func (r *Request) Validate() error {
	if r.URI.IsSIP() && len(r.URI.Headers) > 0 {
		return syntaxError("Request-URI carries header components")
	}
	cseq, err := validateCommon(&r.Header)
	if err != nil {
		return err
	}
	if r.Header.Has("Max-Forwards") {
		if _, err := r.Header.MaxForwards(); err != nil {
			return err
		}
	}
	if cseq.Method != r.Method {
		return headerError("CSeq", "method does not match the request method")
	}
	return nil
}

// Validate checks what a UAC or proxy needs to match a response to its request
// (RFC 3261 §8.1.3, §17.1.3): exactly one each of To, From, Call-ID and CSeq and
// at least one Via, all well-formed.
func (r *Response) Validate() error {
	_, err := validateCommon(&r.Header)
	return err
}

func validateCommon(h *Header) (CSeq, error) {
	vias, err := h.Via()
	if err != nil {
		return CSeq{}, err
	}
	if len(vias) == 0 {
		return CSeq{}, &ParseError{Header: "Via", Err: ErrMissingHeader}
	}
	if _, err := h.From(); err != nil {
		return CSeq{}, err
	}
	if _, err := h.To(); err != nil {
		return CSeq{}, err
	}
	if _, err := h.CallID(); err != nil {
		return CSeq{}, err
	}
	return h.CSeq()
}
