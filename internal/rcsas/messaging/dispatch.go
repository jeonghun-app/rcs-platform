package messaging

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// A recipient's queue is delivered by one worker at a time within a task;
// store.Claim keeps workers of different tasks from delivering one message
// twice. What a worker did last decides what makes it read the queue again:
//
//   - Everything went (holdNone): any new message, registration or leg
//     reads it again, which costs one store read when there is nothing
//     waiting.
//   - Messages wait for a session of their own (holdWaiting): reading the
//     queue again would find them waiting still, so a new message is tried
//     on its own. The whole queue is read on what can let them go: a leg
//     opening, a registration on a new flow, a failed invitation that makes
//     pager mode the way, or the retry timer.
//   - The recipient could not be reached (holdBlocked): a new message
//     waits too. Any registration, a leg, or the retry timer reads the
//     queue.
//
// The retry timer starts at RetryInterval and doubles up to
// MaxRetryInterval while a queue stays held, so a recipient that never
// comes back costs a read an hour, not one per message sent to it.
type hold uint8

const (
	holdNone hold = iota
	holdWaiting
	holdBlocked
)

type runState uint8

const (
	runIdle runState = iota
	runQueued
	running
)

type recipient struct {
	run runState
	// full asks for the whole queue to be read; single holds new messages
	// to try on their own.
	full   bool
	single []store.Message
	hold   hold
	retry  msrp.Timer
	wait   time.Duration
}

// state needs e.mu.
func (e *Engine) state(user string) *recipient {
	r := e.recipients[user]
	if r == nil {
		r = &recipient{}
		e.recipients[user] = r
	}
	return r
}

// schedule needs e.mu.
func (e *Engine) schedule(user string, r *recipient) {
	if r.run == runIdle {
		r.run = runQueued
		e.queue = append(e.queue, user)
		e.wake.Signal()
	}
}

// kickEvent reads user's queue after something that may let its messages
// go; it also restarts the retry timer's backoff.
func (e *Engine) kickEvent(user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	r := e.state(user)
	if r.retry != nil {
		r.retry.Stop()
		r.retry = nil
	}
	r.wait = 0
	r.full = true
	e.schedule(user, r)
}

// kickNew has a newly queued message delivered (see hold).
func (e *Engine) kickNew(m store.Message) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	r := e.state(m.Recipient)
	switch r.hold {
	case holdNone:
		r.full = true
	case holdWaiting:
		if len(r.single) < e.cfg.Batch {
			r.single = append(r.single, m)
		}
	case holdBlocked:
		return
	}
	e.schedule(m.Recipient, r)
}

// kickRetry is the retry timer.
func (e *Engine) kickRetry(user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.recipients[user]
	if e.closed || r == nil {
		return
	}
	r.retry = nil
	r.full = true
	e.schedule(user, r)
}

// work is one delivery worker. Workers are a fixed pool, so a burst of
// registrations queues recipients rather than starting a goroutine each.
func (e *Engine) work() {
	defer e.wg.Done()
	for {
		e.mu.Lock()
		for len(e.queue) == 0 && !e.closed {
			e.wake.Wait()
		}
		if e.closed {
			e.mu.Unlock()
			return
		}
		user := e.queue[0]
		e.queue = e.queue[1:]
		r := e.recipients[user]
		r.run = running
		for r.full || len(r.single) > 0 {
			full, single := r.full, r.single
			r.full, r.single = false, nil
			e.mu.Unlock()
			var res passResult
			if full {
				res = e.drain(e.ctx, user)
			} else {
				res = e.trySingles(e.ctx, single)
			}
			e.mu.Lock()
			if res.again {
				r.full = true
			}
			e.settle(user, r, res, full)
			if e.closed {
				break
			}
		}
		r.run = runIdle
		if r.hold == holdNone && r.retry == nil {
			delete(e.recipients, user)
		}
		e.mu.Unlock()
	}
}

// passResult is what one pass over a queue found; again asks for the
// whole queue to be read.
type passResult struct{ stopped, skipped, again bool }

// settle needs e.mu. It records what a pass found and arms the retry timer
// of a queue left held.
func (e *Engine) settle(user string, r *recipient, res passResult, full bool) {
	switch {
	case res.stopped:
		r.hold = holdBlocked
	case res.skipped:
		r.hold = holdWaiting
	case full:
		// The whole queue went: nothing is held.
		r.hold = holdNone
	}
	if r.hold == holdNone {
		if r.retry != nil {
			r.retry.Stop()
			r.retry = nil
		}
		r.wait = 0
		return
	}
	if r.retry == nil && !e.closed {
		r.wait = min(max(2*r.wait, e.cfg.RetryInterval), e.cfg.MaxRetryInterval)
		r.retry = e.clock.AfterFunc(r.wait, func() { e.kickRetry(user) })
	}
}

type outcome uint8

const (
	// done: delivered, given up on, or taken by another task.
	done outcome = iota
	// skip: m stays queued for a reason of its own (it waits for a
	// session), which says nothing about the messages after it.
	skip
	// stop: m stays queued because the recipient cannot be reached now,
	// which holds for the messages after it too.
	stop
	// whole: m found a leg that older messages wait for, and was not
	// sent ahead of them; the queue is to be read again, in order.
	whole
)

// drain delivers recipient's queue, oldest first, until a message finds the
// recipient unreachable or the engine closes.
func (e *Engine) drain(ctx context.Context, recipient string) passResult {
	var res passResult
	after := ""
	// waited holds the senders whose chat messages this pass left waiting
	// for a session. If that session opens part-way through the pass, a
	// later message from the same sender must not go before them.
	waited := map[string]bool{}
	for ctx.Err() == nil && !e.isClosed() {
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		batch, err := e.store.Pending(sctx, recipient, after, e.clock.Now(), e.cfg.Batch)
		cancel()
		if err != nil {
			e.storeFailed("pending", recipient, err)
			return passResult{stopped: true}
		}
		for _, m := range batch {
			switch e.deliver(ctx, m, waited[m.Sender]) {
			case stop:
				res.stopped = true
				return res
			case skip:
				res.skipped = true
				if m.Mode == store.Chat || m.Notification {
					waited[m.Sender] = true
				}
			case whole:
				res.again = true
				return res
			}
			after = m.ID
			if e.isClosed() {
				return res
			}
		}
		if len(batch) < e.cfg.Batch {
			return res
		}
	}
	return res
}

// trySingles tries new messages of a held queue on their own. A message
// that finds a chat leg open has older ones waiting for that same leg: the
// whole queue is read instead, so that they go first.
func (e *Engine) trySingles(ctx context.Context, ms []store.Message) passResult {
	var res passResult
	for _, m := range ms {
		switch e.deliver(ctx, m, true) {
		case whole:
			res.again = true
			return res
		case stop:
			res.stopped = true
			return res
		case skip:
			res.skipped = true
		}
	}
	return res
}

// deliver makes one attempt at m. A chat message or a notification goes
// on an open chat leg if there is one; a notification, a standalone
// message within the pager limit, and a chat message within it to a client
// that takes no sessions go in pager mode; anything else waits for a
// terminating session, a chat session or a large-mode session of its own.
// behind says older messages from m's sender wait for a chat leg: if one
// is open now, m is not sent ahead of them (whole).
func (e *Engine) deliver(ctx context.Context, m store.Message, behind bool) outcome {
	fits := len(m.CPIM) <= e.cfg.PagerLimit
	if m.Mode == store.Chat || m.Notification {
		if l := e.chatLeg(m.Recipient, m.Sender); l != nil {
			if behind {
				return whole
			}
			return e.viaLeg(ctx, l, m)
		}
	}
	e.mu.Lock()
	_, pagerOnly := e.pagerOnly[m.Recipient]
	e.mu.Unlock()
	switch {
	case m.Notification && fits, fits && (m.Mode == store.Standalone || pagerOnly):
		return e.viaPager(ctx, m)
	case m.Notification:
		// Submit refuses these; a notification queued by an earlier
		// version could still be one.
		if c, ok := e.claim(ctx, m); ok {
			e.giveUp(c, "delivery.notification_too_large")
		}
		return done
	case pagerOnly:
		// ADR 0004: larger content waits for a session the client opens
		// itself, or expires.
		return skip
	}
	e.invite(ctx, m)
	return skip
}

// chatLeg returns the newest open chat leg of user with peer.
func (e *Engine) chatLeg(user, peer string) *Leg {
	e.mu.Lock()
	defer e.mu.Unlock()
	legs := e.legs[legKey{user, peer}]
	for i := len(legs) - 1; i >= 0; i-- {
		select {
		case <-legs[i].Done():
		default:
			return legs[i]
		}
	}
	return nil
}

// claim takes m for this task and returns it whole; false when another
// task holds it, or it is gone.
func (e *Engine) claim(ctx context.Context, m store.Message) (store.Message, bool) {
	now := e.clock.Now()
	ctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	// The lease outlasts a whole attempt, so that it never runs out while
	// the attempt is still going and another task delivers m a second time.
	c, err := e.store.Claim(ctx, m.Recipient, m.ID, e.cfg.InstanceID, now, now.Add(3*e.cfg.DeliveryTimeout))
	switch {
	case err == nil:
		return c, true
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		e.metrics.Count("delivery.claimed_elsewhere", 1)
	default:
		e.storeFailed("claim", m.Recipient, err)
	}
	return store.Message{}, false
}

func (e *Engine) viaLeg(ctx context.Context, l *Leg, m store.Message) outcome {
	c, ok := e.claim(ctx, m)
	if !ok {
		return done
	}
	return e.sendClaimed(ctx, l, c)
}

// sendClaimed delivers a claimed message on l and records the outcome.
func (e *Engine) sendClaimed(ctx context.Context, l *Leg, m store.Message) outcome {
	ctx, cancel := e.withTimeout(ctx, e.cfg.DeliveryTimeout)
	code, err := l.send(ctx, m.CPIM)
	cancel()
	switch {
	case err == nil && code == msrp.StatusOK:
		e.metrics.Count("delivery.msrp", 1)
		e.remove(m)
		return done
	case err == nil && permanent(code):
		e.giveUp(m, "delivery.refused")
		return done
	}
	e.metrics.Count("delivery.msrp_failed", 1)
	e.release(m)
	return stop
}

// permanent reports whether a recipient's failure report means the
// message will never be taken (RFC 4975 §10): it is malformed, refused,
// too large or of a type the recipient does not accept.
func permanent(code int) bool {
	switch code {
	case msrp.StatusBadRequest, msrp.StatusForbidden, msrp.StatusMessageTooLarge, msrp.StatusUnsupportedMediaType:
		return true
	}
	return false
}

func (e *Engine) viaPager(ctx context.Context, m store.Message) outcome {
	m, ok := e.claim(ctx, m)
	if !ok {
		return done
	}
	d := Delivery{
		Recipient: m.Recipient, Sender: m.Sender, Mode: m.Mode, Notification: m.Notification, CPIM: m.CPIM,
		Conversation: Conversation{ID: m.Conversation, Contribution: m.Contribution, InReplyTo: m.InReplyTo},
	}
	if c, err := e.parseCPIM(m.CPIM); err == nil {
		if from, err := c.From(); err == nil {
			d.SenderName = EscapeDisplayName(from.Name)
		}
	}
	if m.Notification {
		d.Route = e.nextRoute(m.CPIM)
	}
	ctx, cancel := e.withTimeout(ctx, e.cfg.DeliveryTimeout)
	err := e.deliverer.Pager(ctx, d)
	cancel()
	switch {
	case err == nil:
		e.metrics.Count("delivery.pager", 1)
		e.remove(m)
		return done
	case errors.Is(err, ErrUndeliverable):
		e.giveUp(m, "delivery.undeliverable")
		return done
	}
	e.metrics.Count("delivery.pager_failed", 1)
	e.release(m)
	return stop
}

// invite asks for a session to deliver m on, unless one was asked for
// within InviteTimeout: a chat session for a chat message, a large-mode
// session for this message alone for a standalone one.
func (e *Engine) invite(ctx context.Context, m store.Message) {
	inv := Invitation{
		Recipient: m.Recipient, Peer: m.Sender, Mode: m.Mode,
		Conversation: Conversation{ID: m.Conversation, Contribution: m.Contribution, InReplyTo: m.InReplyTo},
	}
	if m.Mode == store.Standalone {
		inv.QueueID = m.ID
	}
	key := inviteKey{inv.Recipient, inv.Peer, inv.Mode, inv.QueueID}
	now := e.clock.Now()
	e.mu.Lock()
	if until, ok := e.invites[key]; ok && now.Before(until) {
		e.mu.Unlock()
		return
	}
	if len(e.invites) >= e.cfg.MaxTracked {
		for k, until := range e.invites {
			if !now.Before(until) {
				delete(e.invites, k)
			}
		}
	}
	if len(e.invites) >= e.cfg.MaxTracked {
		e.mu.Unlock()
		e.metrics.Count("invite.untracked", 1)
		return
	}
	e.invites[key] = now.Add(e.cfg.InviteTimeout)
	e.mu.Unlock()
	ctx, cancel := e.withTimeout(ctx, e.cfg.DeliveryTimeout)
	err := e.deliverer.Invite(ctx, inv)
	cancel()
	if err == nil {
		e.metrics.Count("invite.sent", 1)
		return
	}
	e.InviteFailed(inv, err)
}

func (e *Engine) remove(m store.Message) {
	ctx, cancel := e.recordCtx()
	defer cancel()
	if err := e.store.Remove(ctx, m, e.cfg.InstanceID); err != nil {
		// The lease ran out and another task took the message: it may be
		// delivered twice, which clients absorb by Message-ID.
		e.storeFailed("remove", m.Recipient, err)
	}
}

func (e *Engine) release(m store.Message) {
	ctx, cancel := e.recordCtx()
	defer cancel()
	if err := e.store.Release(ctx, m.Recipient, m.ID, e.cfg.InstanceID); err != nil {
		e.storeFailed("release", m.Recipient, err)
	}
}

// giveUp ends a claimed message that will not be delivered, telling its
// sender if it asked for negative delivery notifications (RFC 5438
// §7.1.1.3), and reports whether m is gone. The notification is queued
// before m is removed, so a failure in between repeats it rather than loses
// it; its ID derives from m's, so the repeat is the same queue item.
func (e *Engine) giveUp(m store.Message, metric string) bool {
	if !m.Notification {
		n, err := e.notification(m, failedDelivery, m.ID+"-f", e.clock.Now())
		switch {
		case err == nil:
			ctx, cancel := e.recordCtx()
			err := e.enqueueNotification(ctx, n, failedDelivery.status)
			cancel()
			if err != nil {
				e.storeFailed("enqueue notification", m.Sender, err)
				e.release(m)
				return false
			}
		case !errors.Is(err, imdn.ErrNotRequested):
			// The message was parsed when it was accepted; a body that
			// no longer parses (a lowered size limit) cannot be answered.
			e.metrics.Count("imdn.generate_failed", 1)
		}
	}
	e.metrics.Count(metric, 1)
	e.remove(m)
	return true
}

// Sweep gives up on up to Batch expired messages and reports how many it
// handled; Run calls it. Each call goes on where the last one stopped, so
// messages that cannot be handled (another task holds them) do not keep
// the sweep from the ones after them; what a failing read found is still
// handled.
func (e *Engine) Sweep(ctx context.Context) (int, error) {
	now := e.clock.Now()
	e.mu.Lock()
	cursor := e.sweepAt
	e.mu.Unlock()
	sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	expired, next, err := e.store.Expired(sctx, now, cursor, e.cfg.Batch)
	cancel()
	e.mu.Lock()
	e.sweepAt = next
	e.mu.Unlock()
	n := 0
	for _, m := range expired {
		if c, ok := e.claim(ctx, m); ok && e.giveUp(c, "message.expired") {
			n++
		}
	}
	return n, err
}

// Run sweeps expired messages every SweepInterval until ctx ends; a sweep
// that found a full batch, or stopped part-way through the store, is
// followed by another at once.
func (e *Engine) Run(ctx context.Context) error {
	tick := make(chan struct{}, 1)
	for {
		for ctx.Err() == nil {
			n, err := e.Sweep(ctx)
			if err != nil {
				e.storeFailed("expired", "", err)
				break
			}
			e.mu.Lock()
			more := e.sweepAt != ""
			e.mu.Unlock()
			if n < e.cfg.Batch && !more {
				break
			}
		}
		t := e.clock.AfterFunc(e.cfg.SweepInterval, func() {
			select {
			case tick <- struct{}{}:
			default:
			}
		})
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-tick:
		}
	}
}

func (e *Engine) storeFailed(op, identity string, err error) {
	e.metrics.Count("store.failed", 1)
	attrs := []any{slog.String("op", op), slog.String("error", err.Error())}
	if identity != "" {
		attrs = append(attrs, pii.URI("identity", identity))
	}
	e.log.Warn("message store operation failed", attrs...)
}
