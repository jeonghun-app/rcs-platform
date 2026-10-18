package diameter

import "time"

// Clock is the time source for every protocol timer (watchdog, request
// timeout, capabilities exchange, reconnect backoff), so tests can drive the
// timers without waiting for them.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine, or synchronously for a test
	// clock, once d has elapsed. f must not block.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending call scheduled with [Clock.AfterFunc].
type Timer interface {
	// Stop prevents the call if it has not happened yet and reports whether
	// it did so.
	Stop() bool
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
