package sip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// Default limits. They are generous for IMS signalling, where a REGISTER response
// with many P-Associated-URIs or a MESSAGE with a CPIM body is still a few KiB,
// and small enough that a peer cannot make the parser hold much memory.
const (
	DefaultMaxHeaderBytes = 16 << 10
	DefaultMaxHeaders     = 128
	DefaultMaxBodyBytes   = 1 << 20
)

// Limits bound the resources one message may take. A zero or negative field
// takes its default, and a field above 1 GiB is treated as 1 GiB, so a limit set
// to math.MaxInt to mean "none" cannot overflow the arithmetic on it.
type Limits struct {
	// MaxHeaderBytes bounds the start line and header fields, CRLFs included.
	MaxHeaderBytes int
	// MaxHeaders bounds the number of header fields after unfolding.
	MaxHeaders int
	// MaxBodyBytes bounds the body.
	MaxBodyBytes int
}

const maxLimit = 1 << 30

func (l Limits) withDefaults() Limits {
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = DefaultMaxHeaders
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	l.MaxHeaderBytes = min(l.MaxHeaderBytes, maxLimit)
	l.MaxHeaders = min(l.MaxHeaders, maxLimit)
	l.MaxBodyBytes = min(l.MaxBodyBytes, maxLimit)
	return l
}

var crlfcrlf = []byte("\r\n\r\n")

// ParseMessage parses one message received as a datagram, with the default limits.
func ParseMessage(data []byte) (Message, error) { return ParseDatagram(data, Limits{}) }

// ParseDatagram parses one message received as a datagram (RFC 3261 §18.3): the
// body is Content-Length bytes, or the rest of the datagram when Content-Length is
// absent, and bytes beyond Content-Length are discarded. Leading CRLFs are skipped;
// a datagram of nothing else yields ErrKeepAlive.
//
// The message does not alias data, so the caller may reuse its read buffer.
func ParseDatagram(data []byte, lim Limits) (Message, error) {
	lim = lim.withDefaults()
	for len(data) >= 2 && data[0] == '\r' && data[1] == '\n' {
		data = data[2:]
	}
	if len(data) == 0 {
		return nil, ErrKeepAlive
	}
	// The terminator must start within MaxHeaderBytes-2 bytes, so the search never
	// looks further than that whatever the size of the datagram.
	window := data[:min(len(data), lim.MaxHeaderBytes+2)]
	end := bytes.Index(window, crlfcrlf)
	if end < 0 {
		if len(data) > len(window) {
			return nil, &ParseError{Err: ErrHeaderTooLarge}
		}
		return nil, syntaxError("header section not terminated by an empty line")
	}
	msg, cl, err := parseHead(string(data[:end+2]), lim)
	if err != nil {
		return nil, err
	}
	rest := data[end+4:]
	switch {
	case cl < 0:
		if len(rest) > lim.MaxBodyBytes {
			return nil, &ParseError{Err: ErrBodyTooLarge}
		}
		cl = len(rest)
	case cl > len(rest):
		// RFC 4475 §3.1.2.2.
		return nil, headerError("Content-Length", "larger than the datagram")
	}
	setBody(msg, cloneBytes(rest[:cl]))
	return msg, nil
}

func setBody(m Message, body []byte) {
	if len(body) == 0 {
		body = nil
	}
	switch m := m.(type) {
	case *Request:
		m.Body = body
	case *Response:
		m.Body = body
	}
}

// Reader reads messages from a stream transport such as TCP or TLS.
//
// After any error other than io.EOF the stream position is unknown and the
// connection must be closed: there is no way to find the start of the next
// message (RFC 3261 §18.3).
type Reader struct {
	r   *bufio.Reader
	lim Limits

	// OnKeepAlive, if set, is called for every CRLFCRLF keep-alive ping read
	// between messages so the transport can answer with a CRLF pong (RFC 5626
	// §3.5.1). It runs on the reading goroutine and must not block. A lone CRLF,
	// such as a pong, is skipped without a call.
	OnKeepAlive func()
}

// NewReader returns a Reader that reads messages from r within lim.
func NewReader(r *bufio.Reader, lim Limits) *Reader {
	return &Reader{r: r, lim: lim.withDefaults()}
}

// ReadMessage reads exactly one message. CRLFs before the start line are skipped
// (RFC 3261 §7.5, RFC 5626 §3.5.1). Content-Length is required (RFC 3261 §18.3).
// It returns io.EOF only when the stream ends cleanly between messages and
// io.ErrUnexpectedEOF when it ends inside one.
func (r *Reader) ReadMessage() (Message, error) {
	if err := r.skipKeepAlives(); err != nil {
		return nil, err
	}
	head, err := r.readHead()
	if err != nil {
		return nil, err
	}
	msg, cl, err := parseHead(string(head), r.lim)
	if err != nil {
		return nil, err
	}
	if cl < 0 {
		return nil, &ParseError{Header: "Content-Length", Err: ErrMissingContentLength}
	}
	if cl > 0 {
		// Read what arrives rather than allocating Content-Length up front, so a
		// peer that announces a large body and sends nothing costs no memory.
		body, err := io.ReadAll(io.LimitReader(r.r, int64(cl)))
		if err != nil {
			return nil, err
		}
		if len(body) < cl {
			return nil, io.ErrUnexpectedEOF
		}
		setBody(msg, body)
	}
	return msg, nil
}

func (r *Reader) skipKeepAlives() error {
	crlfs := 0
	for {
		p, err := r.r.Peek(2)
		if len(p) == 2 && p[0] == '\r' && p[1] == '\n' {
			r.r.Discard(2) // cannot fail: Peek buffered both bytes
			if crlfs++; crlfs == 2 {
				crlfs = 0
				if r.OnKeepAlive != nil {
					r.OnKeepAlive()
				}
			}
			continue
		}
		if len(p) == 2 {
			return nil
		}
		if errors.Is(err, io.EOF) {
			if len(p) == 0 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}
		return err
	}
}

// readHead reads up to and including the empty line that ends the header fields
// and returns the head without that empty line.
func (r *Reader) readHead() ([]byte, error) {
	buf := make([]byte, 0, 1024)
	for {
		line, err := r.r.ReadSlice('\n')
		buf = append(buf, line...)
		// The +2 lets the final empty line through; parseHead checks the rest.
		if len(buf) > r.lim.MaxHeaderBytes+2 {
			return nil, &ParseError{Err: ErrHeaderTooLarge}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil, io.ErrUnexpectedEOF
		case err != nil:
			return nil, err
		}
		// Every line ends in CRLF; finding a bare LF this early stops a peer that
		// uses LF line ends from filling the buffer before the error is noticed.
		if len(buf) < 2 || buf[len(buf)-2] != '\r' {
			return nil, syntaxError("line not terminated by CRLF")
		}
		if bytes.HasSuffix(buf, crlfcrlf) {
			return buf[:len(buf)-2], nil
		}
	}
}

// parseHead parses the start line and the header fields. head ends with the CRLF
// of the last field (or of the start line) and does not include the empty line.
// It returns the Content-Length, or -1 when there is none.
func parseHead(head string, lim Limits) (Message, int, error) {
	if len(head) > lim.MaxHeaderBytes {
		return nil, 0, &ParseError{Err: ErrHeaderTooLarge}
	}
	eol := strings.Index(head, "\r\n")
	msg, err := parseStartLine(head[:eol])
	if err != nil {
		return nil, 0, err
	}
	h := msg.Headers()
	// One field per line at most; sizing the slice once saves the regrowths.
	h.fields = make([]field, 0, min(strings.Count(head, "\r\n")-1, lim.MaxHeaders))
	cl := -1
	for pos := eol + 2; pos < len(head); {
		// A field is a line plus the continuation lines that start with SP or HTAB
		// (RFC 3261 §7.3.1).
		end := pos
		for {
			end += strings.Index(head[end:], "\r\n") + 2
			if end == len(head) || !isWS(head[end]) {
				break
			}
		}
		if len(h.fields) == lim.MaxHeaders {
			return nil, 0, &ParseError{Err: ErrTooManyHeaders}
		}
		f, err := parseField(head[pos : end-2])
		if err != nil {
			return nil, 0, err
		}
		if f.key == "content-length" {
			// Two Content-Lengths are refused, even equal ones: two elements that
			// disagree on which one counts would see different messages.
			if cl >= 0 {
				return nil, 0, headerError("Content-Length", "appears more than once")
			}
			if cl, err = parseContentLength(f.value, lim.MaxBodyBytes); err != nil {
				return nil, 0, err
			}
		}
		h.fields = append(h.fields, f)
		pos = end
	}
	return msg, cl, nil
}

func parseContentLength(v string, max int) (int, error) {
	// A sign or anything but digits is malformed (RFC 4475 §3.1.2.3).
	if !isDigits(v) {
		return 0, headerError("Content-Length", "not a decimal number")
	}
	n := 0
	for i := 0; i < len(v); i++ {
		// n*10+d > max, checked before multiplying so n cannot wrap around. d > max
		// needs its own test because (max-d)/10 truncates towards zero.
		d := int(v[i] - '0')
		if d > max || n > (max-d)/10 {
			return 0, &ParseError{Header: "Content-Length", Err: ErrBodyTooLarge}
		}
		n = n*10 + d
	}
	return n, nil
}

// parseField splits one header field, possibly folded, into name and unfolded
// value. raw is kept for the serializer.
func parseField(raw string) (field, error) {
	// The only CRLFs left in raw are line folds; any other CR or LF is bare.
	for i := 0; i < len(raw); i++ {
		switch {
		case raw[i] == '\r' && i+1 < len(raw) && raw[i+1] == '\n':
			i++
		case raw[i] == '\r' || raw[i] == '\n':
			return field{}, syntaxError("bare CR or LF in header field")
		}
	}
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return field{}, syntaxError("header field without a colon")
	}
	// HCOLON allows SP and HTAB, but no folding, before the colon (RFC 3261 §25.1).
	name := trimWS(raw[:colon])
	if !isAll(name, classToken) || isWS(raw[0]) {
		return field{}, syntaxError("invalid header field name")
	}
	value := unfold(raw[colon+1:])
	if !validFieldValue(value) {
		return field{}, syntaxError("control character or invalid UTF-8 in header field")
	}
	return field{name: name, key: headerKey(name), value: value, raw: raw}, nil
}

// unfold replaces each line fold and the whitespace around it with one SP, which
// RFC 3261 §7.3.1 makes equivalent, and trims the value.
func unfold(v string) string {
	if !strings.Contains(v, "\r\n") {
		return trimWS(v)
	}
	parts := strings.Split(v, "\r\n")
	for i := range parts {
		parts[i] = trimWS(parts[i])
	}
	return trimWS(strings.Join(parts, " "))
}

// parseStartLine parses a Request-Line or Status-Line (RFC 3261 §7.1, §7.2). The
// elements are separated by exactly one SP, so extra or trailing whitespace is an
// error (RFC 4475 §3.1.2.8 to §3.1.2.10).
func parseStartLine(line string) (Message, error) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return nil, syntaxError("invalid start line")
	}
	first, rest := line[:sp], line[sp+1:]

	// A method is a token and cannot contain "/", so this is a Status-Line.
	if strings.IndexByte(first, '/') >= 0 {
		if err := checkVersion(first); err != nil {
			return nil, err
		}
		// Status-Code is three digits, the first naming the class (RFC 3261 §7.2);
		// RFC 4475 §3.1.2.19 sends a longer one.
		if len(rest) < 4 || rest[3] != ' ' || rest[0] < '1' || rest[0] > '6' ||
			!isDigits(rest[1:3]) {
			return nil, syntaxError("invalid status code")
		}
		reason := rest[4:]
		if !validReasonPhrase(reason) {
			return nil, syntaxError("invalid reason phrase")
		}
		code := int(rest[0]-'0')*100 + int(rest[1]-'0')*10 + int(rest[2]-'0')
		return &Response{StatusCode: code, Reason: reason}, nil
	}

	if !isAll(first, classToken) {
		return nil, syntaxError("invalid method")
	}
	uriText, version, ok := strings.Cut(rest, " ")
	if !ok || strings.IndexByte(version, ' ') >= 0 {
		return nil, syntaxError("invalid request line")
	}
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	// RFC 4475 §3.1.2.7 encloses the Request-URI in <>, which ParseURI refuses.
	u, err := ParseURI(uriText)
	if err != nil {
		return nil, syntaxError("invalid Request-URI")
	}
	// Header components are not allowed in a Request-URI (RFC 3261 §19.1.1 table 1;
	// RFC 4475 §3.1.2.11).
	if len(u.Headers) > 0 {
		return nil, syntaxError("Request-URI carries header components")
	}
	return &Request{Method: first, URI: u}, nil
}

// checkVersion accepts SIP/2.0 in any case: literal strings in the RFC 3261 ABNF
// are case-insensitive.
func checkVersion(v string) error {
	if strings.EqualFold(v, "SIP/2.0") {
		return nil
	}
	if len(v) > 4 && strings.EqualFold(v[:4], "SIP/") {
		return &ParseError{Err: ErrUnsupportedVersion}
	}
	return syntaxError("invalid SIP version")
}
