package msrp

import (
	"errors"
	"os"
)

// EventKind says what an Event reports.
type EventKind uint8

// Kinds of Event.
const (
	// EventRefused: a request was refused with Code, whether or not
	// Failure-Report let the answer go out.
	EventRefused EventKind = iota + 1
	// EventDropped: something was dropped without an answer; Err says
	// what (ErrMalformedResponse, ErrHandlerBusy, ErrReassemblyTimeout),
	// or a keep-alive that could not be sent (ErrKeepAliveNotSent).
	EventDropped
	// EventClosed: the connection ended; Err says why.
	EventClosed
)

// Event tells Config.OnEvent what a connection refused, dropped or gave
// up on, so a service can count it (architecture §8).
//
// Every field takes its value from a small fixed set, whatever the peer
// sends, so all of them can be metric dimensions and logged as they are:
// Method is "", SEND, REPORT, NICKNAME or "other"; Code is an MSRP status
// code; Err is nil or one of this package's sentinel errors, compared with
// errors.Is or ==. Peer-chosen text and network errors, which carry
// addresses, never reach an Event.
type Event struct {
	Kind   EventKind
	Method string
	Code   int
	Err    error
}

// Reasons in an Event, beside the errors of the connection layer.
var (
	ErrHandlerBusy            = errors.New("msrp: handler queue is full")
	ErrReassemblyTimeout      = errors.New("msrp: incomplete message timed out")
	ErrMalformedResponse      = errors.New("msrp: malformed response")
	ErrTooManyUnknownSessions = errors.New("msrp: too many requests for unknown sessions")
	ErrWriteTimeout           = errors.New("msrp: write deadline passed")
	ErrPeerGone               = errors.New("msrp: connection lost")
	// ErrKeepAliveNotSent: a keep-alive could not be built, for want of
	// random bytes for its ids; the next interval tries again.
	ErrKeepAliveNotSent = errors.New("msrp: keep-alive could not be sent")
)

// eventErrs are the errors an Event may carry as they are, most specific
// first.
var eventErrs = []error{
	ErrHandlerBusy, ErrReassemblyTimeout, ErrMalformedResponse, ErrTooManyUnknownSessions, ErrKeepAliveNotSent,
	ErrPeerNotReading, ErrKeepAliveTimeout, ErrUnbound, ErrFraming, ErrWriteTimeout, ErrConnClosed,
}

func eventErr(err error) error {
	if err == nil {
		return nil
	}
	for _, e := range eventErrs {
		if errors.Is(err, e) {
			return e
		}
	}
	// Write deadlines are the only deadlines this package sets.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return ErrWriteTimeout
	}
	return ErrPeerGone
}

func eventMethod(m string) string {
	switch m {
	case "", MethodSend, MethodReport, MethodNickname:
		return m
	}
	return "other"
}

func (c *Conn) emit(e Event) {
	if c.cfg.OnEvent == nil {
		return
	}
	e.Method = eventMethod(e.Method)
	e.Err = eventErr(e.Err)
	c.cfg.OnEvent(e)
}
