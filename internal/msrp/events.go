package msrp

import "errors"

// EventKind says what an Event reports.
type EventKind uint8

// Kinds of Event.
const (
	// EventRefused: a request was refused with Code, whether or not
	// Failure-Report let the answer go out.
	EventRefused EventKind = iota + 1
	// EventDropped: something was dropped without an answer; Err says
	// what (a malformed response, ErrHandlerBusy, ErrReassemblyTimeout).
	EventDropped
	// EventClosed: the connection ended; Err says why, for example
	// ErrPeerNotReading, ErrFraming, ErrUnbound or ErrKeepAliveTimeout.
	EventClosed
)

// Event tells Config.OnEvent what a connection refused, dropped or gave
// up on, so a service can count it (architecture §8). It carries no
// identifier, URI or content, so it is safe to log and to use in metrics.
type Event struct {
	Kind   EventKind
	Method string // the request concerned, if any
	Code   int    // the status answered, for EventRefused
	Err    error
}

// Reasons for EventDropped.
var (
	ErrHandlerBusy       = errors.New("msrp: handler queue is full")
	ErrReassemblyTimeout = errors.New("msrp: incomplete message timed out")
)

func (c *Conn) emit(e Event) {
	if c.cfg.OnEvent != nil {
		c.cfg.OnEvent(e)
	}
}
