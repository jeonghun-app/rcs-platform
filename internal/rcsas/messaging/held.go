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

// A task can die while its attempt holds a message. The claim outlives it
// for the rest of its lease, and every pass meanwhile passes the message
// over (store.Store.PendingHeld) or loses its claim to it. The dead task's
// retry timer died with it, and nothing else reads the queue until the
// next message, registration or takeover (#651). So a pass that left a
// message another task held has the queue read again once that claim is
// over. The store tests a lease against the reader's clock, so for a
// lease the read passed over that is the lease's own end. A live holder's
// attempt is over long before. If it delivered the message, the read costs
// one query that finds it gone. If the attempt failed and put the message
// back, the read tries it as any pass would, and one that finds the
// recipient unreachable holds the queue here with a retry timer of this
// task's own, beside the holder's. A recipient has one such read waiting,
// the earliest asked for; its pass asks for the next if a message is still
// held. Only a pass meets the claim: a 1-to-1 queue no surviving task reads
// during the lease still waits for the recipient's next event (#663).

// lostClaimEnd is when a claim another task won from this one is over at
// the latest: that claim was made no later than now by its holder's clock,
// which may be ClockSkew ahead of this one's.
func (e *Engine) lostClaimEnd() time.Time {
	return e.clock.Now().Add(e.lease() + e.cfg.ClockSkew)
}

// leaseRead has user's whole queue read at until, when a claim a pass left
// is over, unless a read is set for no later. It needs e.mu.
func (e *Engine) leaseRead(user string, r *recipient, until time.Time) {
	if e.closed || r.leaseTimer != nil && !until.Before(r.leaseAt) {
		return
	}
	if r.leaseTimer != nil {
		r.leaseTimer.Stop()
	}
	e.metrics.Count("delivery.lease_read", 1)
	var t msrp.Timer
	t = e.clock.AfterFunc(until.Sub(e.clock.Now()), func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		r := e.recipients[user]
		// As for a look: only the read waiting now counts.
		if e.closed || r == nil || r.leaseTimer != t {
			return
		}
		r.leaseTimer = nil
		r.full = true
		e.schedule(user, r)
	})
	r.leaseTimer, r.leaseAt = t, until
}
