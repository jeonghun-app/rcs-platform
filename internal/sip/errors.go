package sip

import "errors"

// Sentinel errors. A parse failure is a *ParseError that wraps one of them, so
// callers test with errors.Is and can still report which header was at fault.
var (
	// ErrMalformed means the input does not follow the RFC 3261 §25 grammar.
	ErrMalformed = errors.New("sip: malformed message")
	// ErrUnsupportedVersion means the start line names a SIP version other than
	// SIP/2.0, which a server answers with 505 (RFC 3261 §21.5.6). It is kept
	// apart from ErrMalformed so a transport can count it separately.
	ErrUnsupportedVersion = errors.New("sip: unsupported SIP version")
	// ErrHeaderTooLarge means the start line and header fields exceed
	// Limits.MaxHeaderBytes.
	ErrHeaderTooLarge = errors.New("sip: header section too large")
	// ErrTooManyHeaders means the message has more than Limits.MaxHeaders fields.
	ErrTooManyHeaders = errors.New("sip: too many header fields")
	// ErrBodyTooLarge means Content-Length, or the rest of a datagram, exceeds
	// Limits.MaxBodyBytes.
	ErrBodyTooLarge = errors.New("sip: body too large")
	// ErrMissingContentLength means a message on a stream transport has no
	// Content-Length, without which the end of the message cannot be found
	// (RFC 3261 §18.3).
	ErrMissingContentLength = errors.New("sip: Content-Length required on stream transports")
	// ErrKeepAlive means a datagram held only CRLF keep-alives (or nothing), which
	// is not an error worth logging.
	ErrKeepAlive = errors.New("sip: keep-alive, not a message")
	// ErrMissingHeader means a header field a typed accessor was asked for is
	// absent.
	ErrMissingHeader = errors.New("sip: header field not present")
)

// ParseError describes why a message, a header field value or a URI was refused.
//
// Reason is a fixed description and Header a canonical header name: neither ever
// contains bytes from the input, so a ParseError is safe to log.
type ParseError struct {
	Header string // canonical name of the offending header field; empty for the start line or framing
	Reason string // what was wrong
	Err    error  // one of the sentinel errors of this package
}

func (e *ParseError) Error() string {
	msg := e.Err.Error()
	if e.Header != "" {
		msg += ": " + e.Header
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

func (e *ParseError) Unwrap() error { return e.Err }

func syntaxError(reason string) error {
	return &ParseError{Reason: reason, Err: ErrMalformed}
}

func headerError(header, reason string) error {
	return &ParseError{Header: header, Reason: reason, Err: ErrMalformed}
}

// inHeader attributes an error from a value parser to the header field it came
// from, leaving errors that already name a field alone.
func inHeader(name string, err error) error {
	var pe *ParseError
	if err == nil || !errors.As(err, &pe) || pe.Header != "" {
		return err
	}
	cp := *pe
	cp.Header = name
	return &cp
}
