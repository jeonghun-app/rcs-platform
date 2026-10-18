package cpim

import (
	"errors"
	"fmt"
)

var (
	// ErrMalformed reports input outside the RFC 3862 grammar. Every *Error
	// except a ReasonTooLarge one matches it with errors.Is.
	ErrMalformed = errors.New("cpim: malformed message")
	// ErrTooLarge reports input beyond the configured Limits. A ReasonTooLarge
	// *Error matches it with errors.Is.
	ErrTooLarge = errors.New("cpim: message exceeds limits")
	// ErrMissingHeader reports that a header an accessor needs is absent.
	ErrMissingHeader = errors.New("cpim: header not present")
	// ErrUndeclaredNamespace reports that no prefix is bound to a namespace.
	ErrUndeclaredNamespace = errors.New("cpim: namespace not declared")
)

// Reason says why a message or value was rejected. The values are a small
// fixed set that never contains input, so a service can count rejections by
// reason without putting subscriber data into a metric.
type Reason string

// The reasons Parse, Marshal and the accessors report.
const (
	// ReasonTooLarge: a Limits bound was exceeded.
	ReasonTooLarge Reason = "too-large"
	// ReasonFraming: a header section does not end with an empty line, or a
	// continuation line has no header to continue.
	ReasonFraming Reason = "framing"
	// ReasonLineEnding: CRLF and bare LF line ends are mixed in the headers.
	ReasonLineEnding Reason = "line-ending"
	// ReasonEncoding: a header is not UTF-8 (RFC 3862 §2.2).
	ReasonEncoding Reason = "encoding"
	// ReasonControl: a header contains a control character other than white
	// space around its value (RFC 3862 §2.2).
	ReasonControl Reason = "control-character"
	// ReasonHeaderName: a header name is outside the §3.6 grammar.
	ReasonHeaderName Reason = "header-name"
	// ReasonParameter: header parameters are outside the §3.6 grammar.
	ReasonParameter Reason = "parameter"
	// ReasonNamespace: an NS header is invalid or a prefix is used before
	// its NS header (§3.4), so later headers cannot be interpreted.
	ReasonNamespace Reason = "namespace"
	// ReasonContentType: the content has no Content-Type (§2.4).
	ReasonContentType Reason = "content-type"
	// ReasonValue: a header value does not have the syntax its header
	// defines, or cannot be written as one canonical line.
	ReasonValue Reason = "value"
)

// Error is the error Parse, Marshal and the accessors return for invalid
// input. Its message names the line and the rule broken, never the input.
type Error struct {
	Reason Reason
	// Line is the 1-based line in the header block, or 0 when the problem is
	// not tied to one line.
	Line int
	msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("cpim: line %d: %s", e.Line, e.msg)
	}
	return "cpim: " + e.msg
}

// Unwrap makes errors.Is(err, ErrMalformed) and errors.Is(err, ErrTooLarge)
// work on an *Error.
func (e *Error) Unwrap() error {
	if e.Reason == ReasonTooLarge {
		return ErrTooLarge
	}
	return ErrMalformed
}

// ReasonOf returns the Reason carried by err, or "" when err is not an *Error.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func reject(r Reason, msg string) *Error {
	return &Error{Reason: r, msg: msg}
}

// atLine sets the line of err if it is an *Error without one.
func atLine(err error, line int) error {
	var e *Error
	if errors.As(err, &e) && e.Line == 0 {
		e.Line = line
	}
	return err
}
