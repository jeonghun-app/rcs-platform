package messaging

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// kick asks for recipient's queue to be delivered. A queue is delivered by
// one worker at a time within a task; a kick while it runs makes it run
// once more, so nothing enqueued meanwhile waits for the next event.
// Across tasks, store.Claim keeps two workers from delivering one message.
func (e *Engine) kick(recipient string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	switch e.state[recipient] {
	case queued, runAgain:
	case running:
		e.state[recipient] = runAgain
	default:
		e.state[recipient] = queued
		e.queue = append(e.queue, recipient)
		e.wake.Signal()
	}
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
		r := e.queue[0]
		e.queue = e.queue[1:]
		e.state[r] = running
		e.mu.Unlock()
		for {
			e.drain(e.ctx, r)
			e.mu.Lock()
			again := e.state[r] == runAgain
			if again {
				e.state[r] = running
			} else {
				delete(e.state, r)
			}
			e.mu.Unlock()
			if !again {
				break
			}
		}
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
)

// drain delivers recipient's queue, oldest first, until a message finds the
// recipient unreachable.
func (e *Engine) drain(ctx context.Context, recipient string) {
	after := ""
	for ctx.Err() == nil {
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		batch, err := e.store.Pending(sctx, recipient, after, e.clock.Now(), e.cfg.Batch)
		cancel()
		if err != nil {
			e.storeFailed("pending", recipient, err)
			return
		}
		for _, m := range batch {
			if e.deliver(ctx, m) == stop {
				return
			}
			after = m.ID
		}
		if len(batch) < e.cfg.Batch {
			return
		}
	}
}

// deliver makes one attempt at m: on an open leg if there is one, else in
// pager mode if m may go that way, else by asking for a session.
func (e *Engine) deliver(ctx context.Context, m store.Message) outcome {
	fits := len(m.CPIM) <= e.cfg.PagerLimit
	if l := e.legFor(m); l != nil {
		return e.viaLeg(ctx, l, m)
	}
	e.mu.Lock()
	_, pagerOnly := e.pagerOnly[m.Recipient]
	e.mu.Unlock()
	switch {
	case m.Notification, fits && (m.Mode == store.Standalone || pagerOnly):
		return e.viaPager(ctx, m)
	case pagerOnly:
		// ADR 0004: larger content waits for a session the client opens
		// itself, or expires.
		return skip
	}
	e.invite(ctx, m)
	return skip
}

// legFor returns the newest open leg m can go on. A notification may go on
// a chat leg or a standalone one, since it carries no content of its own.
func (e *Engine) legFor(m store.Message) *Leg {
	modes := []store.Mode{m.Mode}
	if m.Notification {
		modes = []store.Mode{store.Chat, store.Standalone}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, mode := range modes {
		legs := e.legs[legKey{m.Recipient, m.Sender, mode}]
		for i := len(legs) - 1; i >= 0; i-- {
			select {
			case <-legs[i].Done():
			default:
				return legs[i]
			}
		}
	}
	return nil
}

// claim takes m for this task; false when another task holds it, or it is
// gone.
func (e *Engine) claim(ctx context.Context, m store.Message) bool {
	now := e.clock.Now()
	// The lease outlasts a whole attempt, so that it never runs out while
	// the attempt is still going and another task delivers m a second time.
	ctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	_, err := e.store.Claim(ctx, m.Recipient, m.ID, e.cfg.InstanceID, now, now.Add(3*e.cfg.DeliveryTimeout))
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
		e.metrics.Count("delivery.claimed_elsewhere", 1)
	default:
		e.storeFailed("claim", m.Recipient, err)
	}
	return false
}

func (e *Engine) viaLeg(ctx context.Context, l *Leg, m store.Message) outcome {
	if !e.claim(ctx, m) {
		return done
	}
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
	if !e.claim(ctx, m) {
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
// within InviteTimeout.
func (e *Engine) invite(ctx context.Context, m store.Message) {
	key := legKey{m.Recipient, m.Sender, m.Mode}
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
	inv := Invitation{
		Recipient: m.Recipient, Peer: m.Sender, Mode: m.Mode,
		Conversation: Conversation{ID: m.Conversation, Contribution: m.Contribution, InReplyTo: m.InReplyTo},
	}
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
	ctx, cancel := e.withTimeout(e.ctx, e.cfg.StoreTimeout)
	defer cancel()
	if err := e.store.Remove(ctx, m.Recipient, m.ID, e.cfg.InstanceID); err != nil {
		// The lease ran out and another task took the message: it may be
		// delivered twice, which clients absorb by Message-ID.
		e.storeFailed("remove", m.Recipient, err)
	}
}

func (e *Engine) release(m store.Message) {
	ctx, cancel := e.withTimeout(e.ctx, e.cfg.StoreTimeout)
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
		n, err := e.notification(m, imdn.DeliveryNotification, imdn.Failed, m.ID+"-f", e.clock.Now())
		switch {
		case err == nil:
			ctx, cancel := e.withTimeout(e.ctx, e.cfg.StoreTimeout)
			err := e.enqueueNotification(ctx, n, imdn.Failed)
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
// handled; Run calls it.
func (e *Engine) Sweep(ctx context.Context) (int, error) {
	now := e.clock.Now()
	sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	expired, err := e.store.Expired(sctx, now, e.cfg.Batch)
	cancel()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range expired {
		if e.claim(ctx, m) && e.giveUp(m, "message.expired") {
			n++
		}
	}
	return n, nil
}

// Run sweeps expired messages every SweepInterval until ctx ends; a full
// batch is followed by another at once.
func (e *Engine) Run(ctx context.Context) error {
	tick := make(chan struct{}, 1)
	for {
		for {
			n, err := e.Sweep(ctx)
			if err != nil {
				e.storeFailed("expired", "", err)
			}
			if err != nil || n < e.cfg.Batch {
				break
			}
		}
		t := e.clock.AfterFunc(e.cfg.SweepInterval, func() { tick <- struct{}{} })
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
