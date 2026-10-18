package sdp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// DefaultMaxSize is the size limit when Parser.MaxSize is zero. An RCS chat or
// file transfer offer is well under 2 KiB; 64 KiB leaves room for large
// multi-stream offers while bounding what a peer can make a proxy hold.
const DefaultMaxSize = 64 << 10

// ErrTooLarge is returned for a description longer than the parser's limit.
var ErrTooLarge = errors.New("sdp: description exceeds the size limit")

// SyntaxError reports a description that does not follow RFC 8866.
type SyntaxError struct {
	Line int // 1-based; 0 when the problem is not tied to one line
	Msg  string
}

func (e *SyntaxError) Error() string {
	if e.Line == 0 {
		return "sdp: " + e.Msg
	}
	return fmt.Sprintf("sdp: line %d: %s", e.Line, e.Msg)
}

// Parser parses session descriptions. The zero value is ready to use.
type Parser struct {
	// MaxSize is the largest description accepted, in bytes. Zero or a
	// negative value means DefaultMaxSize.
	MaxSize int
}

// Parse parses data with the default size limit.
func Parse(data []byte) (*Session, error) {
	return Parser{}.Parse(data)
}

// Parse parses one session description. It returns ErrTooLarge or a
// *SyntaxError; on error the partial result is discarded.
func (p Parser) Parse(data []byte) (*Session, error) {
	limit := p.MaxSize
	if limit <= 0 {
		limit = DefaultMaxSize
	}
	if len(data) > limit {
		return nil, ErrTooLarge
	}
	if len(data) == 0 {
		return nil, &SyntaxError{Msg: "empty description"}
	}
	st := state{s: &Session{}}
	for len(data) > 0 {
		st.line++
		var line []byte
		line, data = nextLine(data)
		if err := st.add(line); err != nil {
			return nil, err
		}
	}
	if err := st.finish(); err != nil {
		return nil, err
	}
	return st.s, nil
}

// nextLine splits off one line. A CR is part of the line ending only when an
// LF follows it; any other CR stays in the line and is rejected there.
func nextLine(data []byte) (line, rest []byte) {
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return data, nil
	}
	line, rest = data[:i], data[i+1:]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, rest
}

// The line types RFC 8866 §5 defines, in the order they appear in a session
// section and in a media section. A line may follow only lines of the same
// or an earlier position; the r= line shares the position of t= because the
// two interleave.
const (
	knownTypes   = "vosiuepcbtrzkam"
	sessionOrder = "vosiuepcbtzka"
	mediaOrder   = "micbka"
	// Line types that may appear more than once in their section.
	sessionRepeatable = "epbtra"
	mediaRepeatable   = "cba"
)

// state is the parser's position in the description.
type state struct {
	s    *Session
	line int
	prev byte // type of the previous line
	// last is the type of the line with the highest order position so far in
	// the current section, which is what an out-of-order line is reported
	// against.
	last      byte
	seen      [26]bool // line types seen in the current section
	inMedia   bool
	mediaLine []int // line number of each m=, for errors reported at the end
}

func (st *state) errf(format string, args ...any) error {
	return &SyntaxError{Line: st.line, Msg: fmt.Sprintf(format, args...)}
}

func (st *state) add(line []byte) error {
	if len(line) == 0 {
		return st.errf("empty line")
	}
	if i := bytes.IndexAny(line, "\x00\r"); i >= 0 {
		if line[i] == 0 {
			return st.errf("NUL byte")
		}
		return st.errf("CR not followed by LF")
	}
	if len(line) < 2 || line[1] != '=' || line[0] < 'a' || line[0] > 'z' {
		return st.errf("want <type>=<value> with a lower-case type letter and no space before '='")
	}
	typ, value := line[0], string(line[2:])
	// RFC 8866 §5: a description with a type letter the parser does not
	// understand must be ignored as a whole, so it is an error, not skipped.
	if strings.IndexByte(knownTypes, typ) < 0 {
		return st.errf("unknown line type %q", typ)
	}
	if st.prev == 0 && typ != 'v' {
		return st.errf(`description must start with a "v=" line`)
	}
	var err error
	switch {
	case typ == 'm':
		err = st.startMedia(value)
	case st.inMedia:
		err = st.addMedia(typ, value)
	default:
		err = st.addSession(typ, value)
	}
	st.prev = typ
	return err
}

// order checks that typ may follow the lines already seen in the section.
func (st *state) order(typ byte, order, repeatable string) error {
	pos := strings.IndexByte(order, typ)
	if typ == 'r' {
		if st.prev != 't' && st.prev != 'r' {
			return st.errf(`"r=" line must follow a "t=" or "r=" line`)
		}
		pos = strings.IndexByte(order, 't')
	}
	if st.last != 0 && pos < strings.IndexByte(order, st.last) {
		return st.errf("%q line must come before the %q line", string(typ)+"=", string(st.last)+"=")
	}
	if st.seen[typ-'a'] && strings.IndexByte(repeatable, typ) < 0 {
		return st.errf("more than one %q line", string(typ)+"=")
	}
	st.seen[typ-'a'] = true
	if typ != 'r' {
		st.last = typ
	}
	return nil
}

func (st *state) addSession(typ byte, v string) error {
	if err := st.order(typ, sessionOrder, sessionRepeatable); err != nil {
		return err
	}
	s := st.s
	var err error
	switch typ {
	case 'v':
		if v != "0" {
			return st.errf("unsupported protocol version %.16q", v)
		}
	case 'o':
		s.Origin, err = parseOrigin(v)
	case 's':
		s.Name, err = v, textErr(v)
	case 'i':
		s.Information, err = v, textErr(v)
	case 'u':
		s.URI, err = v, nonWSErr(v)
	case 'e':
		s.Emails, err = append(s.Emails, v), textErr(v)
	case 'p':
		s.Phones, err = append(s.Phones, v), textErr(v)
	case 'c':
		var c Connection
		c, err = parseConnection(v)
		s.Connection = &c
	case 'b':
		var b Bandwidth
		b, err = parseBandwidth(v)
		s.Bandwidths = append(s.Bandwidths, b)
	case 't':
		var t Time
		t, err = parseTime(v)
		s.Times = append(s.Times, t)
	case 'r':
		t := &s.Times[len(s.Times)-1]
		t.Repeats, err = append(t.Repeats, v), validateRepeat(v)
	case 'z':
		s.TimeZones, err = v, validateZones(v)
	case 'k':
		s.Key, err = v, textErr(v)
	case 'a':
		var a Attribute
		a, err = parseAttribute(v)
		s.Attributes = append(s.Attributes, a)
	}
	if err != nil {
		return st.errf("%c=: %v", typ, err)
	}
	return nil
}

func (st *state) startMedia(v string) error {
	if !st.inMedia {
		if err := st.requireSessionLines(); err != nil {
			return err
		}
	}
	m, err := parseMediaLine(v)
	if err != nil {
		return st.errf("m=: %v", err)
	}
	st.s.Media = append(st.s.Media, m)
	st.mediaLine = append(st.mediaLine, st.line)
	st.inMedia = true
	st.seen = [26]bool{'m' - 'a': true}
	st.last = 'm'
	return nil
}

func (st *state) addMedia(typ byte, v string) error {
	if strings.IndexByte(mediaOrder, typ) < 0 {
		return st.errf("%q line is not allowed in a media description", string(typ)+"=")
	}
	if err := st.order(typ, mediaOrder, mediaRepeatable); err != nil {
		return err
	}
	m := &st.s.Media[len(st.s.Media)-1]
	var err error
	switch typ {
	case 'i':
		m.Information, err = v, textErr(v)
	case 'c':
		var c Connection
		c, err = parseConnection(v)
		m.Connections = append(m.Connections, c)
	case 'b':
		var b Bandwidth
		b, err = parseBandwidth(v)
		m.Bandwidths = append(m.Bandwidths, b)
	case 'k':
		m.Key, err = v, textErr(v)
	case 'a':
		var a Attribute
		a, err = parseAttribute(v)
		m.Attributes = append(m.Attributes, a)
	}
	if err != nil {
		return st.errf("%c=: %v", typ, err)
	}
	return nil
}

// requireSessionLines reports the first mandatory session line that is
// missing (RFC 8866 §5). v= is not checked: the first line is always v=.
func (st *state) requireSessionLines() error {
	for _, typ := range []byte("ost") {
		if !st.seen[typ-'a'] {
			return st.errf("missing %q line", string(typ)+"=")
		}
	}
	return nil
}

func (st *state) finish() error {
	if !st.inMedia {
		st.line++ // the missing line would have been the next one
		if err := st.requireSessionLines(); err != nil {
			return err
		}
	}
	// RFC 8866 §5.7: every media description needs a c= line of its own
	// unless the session has one.
	if st.s.Connection == nil {
		for i := range st.s.Media {
			if len(st.s.Media[i].Connections) == 0 {
				return &SyntaxError{Line: st.mediaLine[i], Msg: `media description has no "c=" line and the session has none`}
			}
		}
	}
	return nil
}

func textErr(v string) error {
	if !isText(v) {
		return errors.New("value must not be empty")
	}
	return nil
}

func nonWSErr(v string) error {
	if !isNonWS(v) {
		return errors.New("value must be non-empty and contain no spaces or control characters")
	}
	return nil
}
