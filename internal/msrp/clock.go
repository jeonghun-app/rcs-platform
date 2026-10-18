package msrp

import "time"

// Clock is the time source for transaction timeouts, keep-alives and the
// unbound-connection timeout. Tests inject a fake one so that no test waits
// for a real timer.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine once d has passed.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending AfterFunc call.
type Timer interface {
	// Stop prevents the call if it has not happened yet.
	Stop() bool
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
