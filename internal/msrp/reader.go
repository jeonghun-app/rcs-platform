package msrp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// DefaultMaxHeaderBytes bounds the start line and header section of one
// message when the caller gives no limit. Paths with a few hops and the
// usual MIME headers fit many times over.
const DefaultMaxHeaderBytes = 16 << 10

// ErrFraming reports input the Reader cannot frame: a bad start line, a
// header section over the limit, a line not ended by CRLF, or a connection
// that ended inside a message. The stream cannot be resynchronised, so the
// connection has to be closed.
var ErrFraming = errors.New("msrp: framing error")

// ErrBodyTooLarge reports a body over the caller's limit. The Reader has
// skipped the rest of it, so the stream is still in step.
var ErrBodyTooLarge = errors.New("msrp: body exceeds limit")

// MessageError reports a message that was framed correctly but is not
// acceptable. The stream is still in step. Message holds whatever parsed,
// always including the transaction id, so a request can still be answered
// with Code when its paths parsed.
type MessageError struct {
	Message *Message
	Code    int
	Err     error
}

func (e *MessageError) Error() string {
	return fmt.Sprintf("msrp: transaction %s rejected with %d: %v", e.Message.TransactionID, e.Code, e.Err)
}

func (e *MessageError) Unwrap() error { return e.Err }

// Reader reads MSRP messages from a byte stream, typically a connection.
//
// The body is found by scanning for the end-line of the transaction
// (§7.1), so bytes that merely look like an end-line, such as another
// transaction id or an end-line not preceded by CRLF, stay part of the
// body. A Reader is not safe for concurrent use.
type Reader struct {
	br        *bufio.Reader
	maxHeader int
	cur       *Message
	body      *bodyReader
}

// NewReader returns a Reader that refuses header sections larger than
// maxHeaderBytes, or DefaultMaxHeaderBytes when it is not positive.
func NewReader(r io.Reader, maxHeaderBytes int) *Reader {
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = DefaultMaxHeaderBytes
	}
	// The body scanner peeks at up to one octet more than the longest
	// end-line (7 + 32 + 1 + 2 octets), so any buffer above that works;
	// 4 KiB keeps the number of reads low.
	return &Reader{br: bufio.NewReaderSize(r, 4096), maxHeader: maxHeaderBytes}
}

func framing(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFraming, fmt.Sprintf(format, args...))
}

// truncated is the framing error of a stream that ended inside a message,
// where: it is ErrFraming, and io.ErrUnexpectedEOF too, so that a reader of
// the connection can tell that the peer has stopped sending (#240).
type truncated string

func (where truncated) Error() string {
	return ErrFraming.Error() + ": stream ended inside " + string(where)
}

func (truncated) Is(target error) bool { return target == ErrFraming || target == io.ErrUnexpectedEOF }

// ReadHeader reads the start line and header section of the next message,
// first skipping whatever is left of the previous body. For a message with
// a body it stops before the body, which is then read through Body or
// ReadBody; Continuation is filled in when the body has been read to the
// end. io.EOF means the stream ended cleanly between messages.
//
// A *MessageError comes back together with the partly filled message; any
// other error is fatal for the stream.
func (r *Reader) ReadHeader() (*Message, error) {
	if err := r.skipBody(); err != nil {
		return nil, err
	}
	r.cur = nil
	budget := r.maxHeader
	start, err := r.readLine(&budget)
	if err != nil {
		return nil, err
	}
	m, err := parseStartLine(start)
	if err != nil {
		return nil, err
	}

	var lines []string
	hasBody := false
	for {
		line, err := r.readLine(&budget)
		if errors.Is(err, io.EOF) {
			return nil, truncated("the header section")
		}
		if err != nil {
			return nil, err
		}
		if line == "" {
			hasBody = true
			break
		}
		if flag, ok := endLineFlag(line, m.TransactionID); ok {
			m.Continuation = flag
			break
		}
		lines = append(lines, line)
	}
	r.cur = m
	if hasBody {
		r.body = &bodyReader{r: r, m: m, endLine: []byte(endLinePrefix + m.TransactionID)}
	}
	err = parseHeaders(m, lines, hasBody)
	if !validIdent(m.TransactionID) {
		err = errors.New("transaction id is not 4 to 32 characters (§9 ident)")
	}
	if err != nil {
		return m, &MessageError{Message: m, Code: StatusBadRequest, Err: err}
	}
	return m, nil
}

// Body returns the body of the message ReadHeader returned last. It reads
// io.EOF at the end-line; a message without a body has an empty Body.
func (r *Reader) Body() io.Reader {
	if r.body == nil {
		return bytes.NewReader(nil)
	}
	return r.body
}

// ReadBody reads the rest of the current body into its Message, refusing
// more than limit octets with ErrBodyTooLarge.
func (r *Reader) ReadBody(limit int64) error {
	_, err := r.readBodyCharged(limit, nil)
	return err
}

// readBodyCharged is ReadBody with the memory it allocates charged to b as
// it grows, so the octets of chunks being read count against the same
// allowance as those held for reassembly. The buffer grows with what has
// arrived, never with what a header promises, and never past limit+1. It
// returns what was charged, for the caller to release once it is done with
// the body; running out of allowance is ErrBodyTooLarge as well.
func (r *Reader) readBodyCharged(limit int64, b *Budget) (int64, error) {
	if r.body == nil {
		return 0, nil
	}
	var buf []byte
	var charged int64
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) > limit {
				break
			}
			newCap := int(min(int64(max(512, 2*cap(buf))), limit+1))
			if !b.take(int64(newCap - cap(buf))) {
				return charged, r.tooLarge()
			}
			charged += int64(newCap - cap(buf))
			nb := make([]byte, len(buf), newCap)
			copy(nb, buf)
			buf = nb
		}
		n, err := r.body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return charged, err
		}
	}
	if int64(len(buf)) > limit {
		return charged, r.tooLarge()
	}
	r.cur.Body = buf
	r.body = nil
	return charged, nil
}

func (r *Reader) tooLarge() error {
	if err := r.skipBody(); err != nil {
		return err
	}
	return ErrBodyTooLarge
}

// ReadMessage reads one whole message. SEND bodies may be up to maxBody
// octets; other requests are held to the 10240 octets of §7.1. Errors are
// as for ReadHeader; an oversized body is a *MessageError with code 413
// for SEND and 400 otherwise.
func (r *Reader) ReadMessage(maxBody int64) (*Message, error) {
	m, err := r.ReadHeader()
	if err != nil {
		return m, err
	}
	limit := maxBody
	if m.Method != MethodSend && limit > maxNonSendBody {
		limit = maxNonSendBody
	}
	if err := r.ReadBody(limit); err != nil {
		if errors.Is(err, ErrBodyTooLarge) {
			code := StatusBadRequest
			if m.Method == MethodSend {
				code = StatusMessageTooLarge
			}
			return m, &MessageError{Message: m, Code: code, Err: err}
		}
		return nil, err
	}
	if err := checkBody(m, int64(len(m.Body))); err != nil {
		return m, &MessageError{Message: m, Code: StatusBadRequest, Err: err}
	}
	return m, nil
}

func (r *Reader) skipBody() error {
	if r.body == nil {
		return nil
	}
	_, err := io.Copy(io.Discard, r.body)
	r.body = nil
	return err
}

// readLine returns one CRLF-terminated line without the CRLF, charging it
// to budget.
func (r *Reader) readLine(budget *int) (string, error) {
	var line []byte
	for {
		frag, err := r.br.ReadSlice('\n')
		*budget -= len(frag)
		if *budget < 0 {
			return "", framing("header section larger than %d octets", r.maxHeader)
		}
		line = append(line, frag...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return "", io.EOF
			}
			return "", truncated("a line")
		}
		return "", err
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return "", framing("line not terminated by CRLF")
	}
	return string(line[:len(line)-2]), nil
}

func parseStartLine(line string) (*Message, error) {
	rest, ok := strings.CutPrefix(line, "MSRP ")
	if !ok {
		return nil, framing("start line does not begin with MSRP")
	}
	tid, rest, ok := strings.Cut(rest, " ")
	if !ok || !validFramingID(tid) {
		return nil, framing("bad transaction id in start line")
	}
	m := &Message{TransactionID: tid}
	if len(rest) >= 3 && isDigits(rest[:3]) && (len(rest) == 3 || rest[3] == ' ') {
		m.StatusCode, _ = strconv.Atoi(rest[:3])
		if len(rest) > 3 {
			m.Comment = rest[4:]
			if !validText(m.Comment) {
				return nil, framing("bad response comment")
			}
		}
		return m, nil
	}
	if !validMethod(rest) {
		return nil, framing("bad method in start line")
	}
	m.Method = rest
	return m, nil
}

func endLineFlag(line, tid string) (byte, bool) {
	if len(line) != len(endLinePrefix)+len(tid)+1 ||
		!strings.HasPrefix(line, endLinePrefix) || line[len(endLinePrefix):len(line)-1] != tid {
		return 0, false
	}
	switch c := line[len(line)-1]; c {
	case FlagEnd, FlagMore, FlagAbort:
		return c, true
	}
	return 0, false
}

// parseHeaders fills m from the header lines and checks the rules of §7.1
// and §9 that do not depend on the body. It keeps going after the first
// problem so that the paths are known even for a rejected request.
func parseHeaders(m *Message, lines []string, hasBody bool) error {
	var first error
	fail := func(err error) {
		if first == nil {
			first = err
		}
	}
	seen := map[string]bool{}
	for i, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !validHeaderName(name) {
			fail(fmt.Errorf("malformed header line %d", i+1))
			continue
		}
		value, ok = strings.CutPrefix(value, " ")
		if !ok || !validText(value) {
			fail(fmt.Errorf("malformed %s value", name))
			continue
		}
		if isKnownHeader(name) {
			key := strings.ToLower(name)
			if seen[key] {
				fail(fmt.Errorf("repeated %s header", name))
				continue
			}
			seen[key] = true
		}
		var err error
		switch {
		// The paths are kept even when out of place, so that the refusal
		// can still be addressed.
		case strings.EqualFold(name, hdrToPath):
			m.ToPath, err = parsePath(value)
			if err == nil && i != 0 {
				err = errors.New("To-Path must be the first header (§9)")
			}
		case strings.EqualFold(name, hdrFromPath):
			m.FromPath, err = parsePath(value)
			if err == nil && i != 1 {
				err = errors.New("From-Path must be the second header (§9)")
			}
		case strings.EqualFold(name, hdrMessageID):
			if !validIdent(value) {
				err = errors.New("malformed Message-ID")
			}
			m.MessageID = value
		case strings.EqualFold(name, hdrSuccessReport):
			m.SuccessReport, err = parseReportMode(value, false)
		case strings.EqualFold(name, hdrFailureReport):
			m.FailureReport, err = parseReportMode(value, true)
		case strings.EqualFold(name, hdrByteRange):
			m.ByteRange, err = parseByteRange(value)
		case strings.EqualFold(name, hdrStatus):
			m.Status, err = parseStatus(value)
		case strings.EqualFold(name, hdrContentType):
			if i != len(lines)-1 {
				err = errors.New("Content-Type must be the last header (§7.1)")
			} else if !validContentType(value) {
				err = errors.New("malformed Content-Type")
			}
			m.ContentType = value
		default:
			m.Header = append(m.Header, Field{Name: name, Value: value})
		}
		if err != nil {
			fail(err)
		}
	}
	if first != nil {
		return first
	}

	if m.ToPath == nil || m.FromPath == nil {
		return errors.New("To-Path and From-Path are required (§9)")
	}
	if !m.IsRequest() {
		if hasBody {
			return errors.New("a response has no body (§9)")
		}
		return nil
	}
	if hasBody && m.ContentType == "" {
		return errors.New("a body needs a Content-Type (§7.1)")
	}
	if !hasBody {
		if m.ContentType != "" {
			return errors.New("Content-Type without a body (§7.1)")
		}
		for _, f := range m.Header {
			if isMIMEHeader(f.Name) {
				return fmt.Errorf("%s without a body (§7.1)", f.Name)
			}
		}
	}
	switch m.Method {
	case MethodSend:
		if m.MessageID == "" {
			return errors.New("SEND needs a Message-ID (§7.1.1)")
		}
	case MethodReport:
		if m.MessageID == "" || m.Status == nil {
			return errors.New("REPORT needs Message-ID and Status (§7.1.2)")
		}
		if m.SuccessReport != ReportUnset || m.FailureReport != ReportUnset {
			return errors.New("REPORT must not carry report headers (§7.1.2)")
		}
	}
	return nil
}

// checkBody applies the rules that need the body length n: only SEND is
// chunked, and a chunk may fall short of its Byte-Range (an interrupted
// sender, §7.3.1) but never run past it.
func checkBody(m *Message, n int64) error {
	if m.Method != MethodSend {
		if m.flag() != FlagEnd {
			return errors.New("only SEND requests are chunked (§7.1)")
		}
		return nil
	}
	br := m.Range()
	if br.End != Unknown && n > br.End-br.Start+1 {
		return errors.New("body longer than its Byte-Range")
	}
	if br.Total != Unknown && n > br.Total-(br.Start-1) {
		return errors.New("body runs past the Byte-Range total")
	}
	return nil
}

func parsePath(v string) ([]URI, error) {
	parts := strings.Split(v, " ")
	path := make([]URI, 0, len(parts))
	for _, p := range parts {
		u, err := ParseURI(p)
		if err != nil {
			return nil, err
		}
		path = append(path, u)
	}
	return path, nil
}

func parseReportMode(v string, allowPartial bool) (ReportMode, error) {
	switch {
	case strings.EqualFold(v, "yes"):
		return ReportYes, nil
	case strings.EqualFold(v, "no"):
		return ReportNo, nil
	case allowPartial && strings.EqualFold(v, "partial"):
		return ReportPartial, nil
	}
	return ReportUnset, fmt.Errorf("bad report value %q", v)
}

func parseByteRange(v string) (*ByteRange, error) {
	startS, rest, ok1 := strings.Cut(v, "-")
	endS, totalS, ok2 := strings.Cut(rest, "/")
	if !ok1 || !ok2 {
		return nil, errors.New("malformed Byte-Range")
	}
	start, err1 := parsePosition(startS, false)
	end, err2 := parsePosition(endS, true)
	total, err3 := parsePosition(totalS, true)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("malformed Byte-Range: %w", err)
	}
	br := &ByteRange{Start: start, End: end, Total: total}
	if !br.valid() {
		return nil, errors.New("inconsistent Byte-Range")
	}
	return br, nil
}

func parsePosition(s string, allowStar bool) (int64, error) {
	if allowStar && s == "*" {
		return Unknown, nil
	}
	if !isDigits(s) {
		return 0, fmt.Errorf("bad position %q", s)
	}
	return strconv.ParseInt(s, 10, 64)
}

func parseStatus(v string) (*Status, error) {
	if len(v) < 7 || !isDigits(v[0:3]) || v[3] != ' ' || !isDigits(v[4:7]) || (len(v) > 7 && v[7] != ' ') {
		return nil, errors.New("malformed Status")
	}
	ns, _ := strconv.Atoi(v[0:3])
	code, _ := strconv.Atoi(v[4:7])
	s := &Status{Namespace: ns, Code: code}
	if len(v) > 7 {
		s.Comment = v[8:]
	}
	return s, nil
}

// bodyReader yields body octets up to the end-line of its transaction.
//
// The end-line only counts when it is a whole line directly after a CRLF,
// and that CRLF belongs to the framing, not the body (§7.1). So a trailing
// CR or CRLF is held back until the following octets show whether the
// end-line comes next, and so are the few octets after a CRLF that could
// still turn out to be the end-line. Everything else is handed out as soon
// as it has arrived, which keeps memory bounded however long the body is
// and lets a relay pass a chunk on while it is still arriving.
type bodyReader struct {
	r       *Reader
	m       *Message
	endLine []byte
	buf     []byte
	pending []byte
	held    int // 0, or 1 for a held "\r", or 2 for a held "\r\n"
	eof     bool
	err     error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	for len(b.pending) == 0 {
		if b.eof {
			return 0, io.EOF
		}
		if b.err != nil {
			return 0, b.err
		}
		b.fill()
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *bodyReader) fail(err error) {
	if errors.Is(err, io.EOF) {
		err = truncated("a body")
	}
	b.err = err
}

// fill moves the next run of octets that has arrived into pending: one
// line, or everything buffered when no line ends there.
func (b *bodyReader) fill() {
	br := b.r.br
	if br.Buffered() == 0 {
		if _, err := br.Peek(1); err != nil {
			b.fail(err)
			return
		}
	}
	run, _ := br.Peek(br.Buffered())
	complete := false
	if i := bytes.IndexByte(run, '\n'); i >= 0 {
		run, complete = run[:i+1], true
	} else if b.held == 2 && b.mayBeEndLine(run) {
		// Wait for one more octet to tell.
		if _, err := br.Peek(len(run) + 1); err != nil {
			b.fail(err)
		}
		return
	}

	if complete && b.held == 2 && b.isEndLine(run) {
		b.m.Continuation = run[len(b.endLine)]
		_, _ = br.Discard(len(run))
		b.held = 0
		b.eof = true
		return
	}
	b.buf = append(b.buf[:0], "\r\n"[:b.held]...)
	b.buf = append(b.buf, run...)
	_, _ = br.Discard(len(run))
	b.held = 0
	switch {
	case complete && bytes.HasSuffix(b.buf, []byte("\r\n")):
		b.held = 2
	case !complete && bytes.HasSuffix(b.buf, []byte("\r")):
		b.held = 1
	}
	b.pending = b.buf[:len(b.buf)-b.held]
}

func isFlag(c byte) bool { return c == FlagEnd || c == FlagMore || c == FlagAbort }

func (b *bodyReader) isEndLine(line []byte) bool {
	n := len(b.endLine)
	return len(line) == n+3 && bytes.Equal(line[:n], b.endLine) && isFlag(line[n]) &&
		line[n+1] == '\r' && line[n+2] == '\n'
}

// mayBeEndLine reports whether p, which holds no LF, could be the start of
// the end-line.
func (b *bodyReader) mayBeEndLine(p []byte) bool {
	n := len(b.endLine)
	switch {
	case len(p) <= n:
		return bytes.Equal(p, b.endLine[:len(p)])
	case len(p) == n+1:
		return bytes.Equal(p[:n], b.endLine) && isFlag(p[n])
	case len(p) == n+2:
		return bytes.Equal(p[:n], b.endLine) && isFlag(p[n]) && p[n+1] == '\r'
	}
	return false
}
