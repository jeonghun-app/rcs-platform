package messaging

import (
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
)

// A registration says the recipient can be reached now, but a message
// another task is trying to deliver at that moment is claimed, so the pass
// the registration runs does not see it (store.Store.Pending), or loses
// its claim. That attempt may have gone where the recipient no longer is,
// on the flow it just left, and fail: the other task then holds the queue
// until its retry timer, up to MaxRetryInterval, and nothing else reads it
// (#632). So a pass that a registration here asked for, and that passed
// over such a message, reads the queue again soon after, and again with
// backoff while the message is still held, until the waits reach a lease.
// By then any attempt begun before the registration is over; one begun
// after it went to the new flow. The holder's own retry timer still runs,
// and finds nothing. A recipient has one look waiting at a time, and a
// registration starts the backoff over, so registrations that come often
// cost a read or two each, not a series each.

// heldRetry is the first wait before the queue is read again for a message
// held elsewhere; it doubles from there.
const heldRetry = time.Second

// lease is how long a claim lasts: it outlasts a whole attempt, so that it
// never runs out while the attempt is still going and another task
// delivers the message a second time.
func (e *Engine) lease() time.Duration { return 3 * e.cfg.DeliveryTimeout }

// registeredLook has the pass a registration runs look for messages held
// elsewhere, starting the backoff over: the look already waiting is
// dropped, so that a recipient has one series of looks however often it
// registers. It needs e.mu.
func (e *Engine) registeredLook(user string) {
	e.state(user).lookTimer = nil
	e.lookOut(user, 0)
}

// lookOut has the next pass over user's whole queue look for messages held
// elsewhere, wait being the wait that led to it. The shortest wait asked
// for counts. It needs e.mu.
func (e *Engine) lookOut(user string, wait time.Duration) {
	r := e.state(user)
	if !r.look || wait < r.lookWait {
		r.lookWait = wait
	}
	r.look = true
}

// takeLook reports whether this pass over user's whole queue looks for
// messages held elsewhere, and the wait that led to it, and clears it for
// the next pass.
func (e *Engine) takeLook(user string) (bool, time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.recipients[user]
	if r == nil || !r.look {
		return false, 0
	}
	r.look = false
	return true, r.lookWait
}

// lookAgain reads user's queue again, looking again, after twice the last
// wait, unless that wait had reached a lease. The look replaces any other
// waiting for user, and keeps user's state until it is made.
func (e *Engine) lookAgain(user string, wait time.Duration) {
	if wait >= e.lease() {
		return
	}
	next := max(2*wait, heldRetry)
	e.metrics.Count("delivery.held_elsewhere", 1)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	r := e.state(user)
	var t msrp.Timer
	t = e.clock.AfterFunc(next, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		r := e.recipients[user]
		// Only the look waiting now counts; one replaced, or dropped by a
		// registration, does nothing when it fires. This check, not Stop,
		// keeps one series: Stop cannot hold back a callback already
		// under way.
		if e.closed || r == nil || r.lookTimer != t {
			return
		}
		r.lookTimer = nil
		e.lookOut(user, next)
		r.full = true
		e.schedule(user, r)
	})
	r.lookTimer = t
}
