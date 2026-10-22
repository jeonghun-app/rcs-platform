package messaging

import (
	"context"
	"errors"
	"log/slog"
	"maps"
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
//     queue. A message that comes in while such a pass runs is noted:
//     should the pass get through, the queue is read again for it, since
//     the pass may have read past where it sorts (#214).
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
	// waiting holds the senders with chat messages or notifications the
	// last passes left waiting for a session: a new message from one of
	// them must not go ahead of those, from anyone else it may.
	waiting map[string]bool
	// arrived notes a message queued while a pass ran with the queue
	// blocked (see hold).
	arrived bool
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
		} else {
			// No room to try it on its own: the queue is read in order
			// instead, and until then its sender counts as waiting, so
			// that no later message of its goes first.
			r.full = true
			if r.waiting == nil {
				r.waiting = map[string]bool{}
			}
			r.waiting[m.Sender] = true
		}
	case holdBlocked:
		if r.run == running {
			r.arrived = true
		}
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
			full, single, waiting := r.full, r.single, maps.Clone(r.waiting)
			r.full, r.single = false, nil
			e.mu.Unlock()
			var res passResult
			if full {
				res = e.drain(e.ctx, user)
			} else {
				res = e.trySingles(e.ctx, single, waiting)
			}
			e.mu.Lock()
			if res.again {
				r.full = true
			}
			if full && !res.stopped && !res.again {
				// A pass that read the whole queue knows who waits.
				r.waiting = res.waited
			} else {
				for s := range res.waited {
					if r.waiting == nil {
						r.waiting = map[string]bool{}
					}
					r.waiting[s] = true
				}
			}
			e.settle(user, r, res, full)
			if r.arrived {
				// A pass that stopped leaves it to wait like the rest. One
				// that got through, full or of single messages, has the
				// queue read again for it: a pass of singles leaves the
				// hold as it was, so the hold cannot tell.
				r.arrived = false
				if !res.stopped {
					r.full = true
				}
			}
			if !full && !res.stopped && r.hold == holdBlocked {
				// A pass of singles got through to a queue an earlier
				// pass left blocked: the recipient is reachable, and only
				// a pass over the whole queue says what holds it now.
				// Left blocked, a message that comes in after this run
				// would wait for the retry timer, up to MaxRetryInterval.
				r.full = true
			}
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
// whole queue to be read; waited are the senders whose chat messages or
// notifications it left waiting for a session.
type passResult struct {
	stopped, skipped, again bool
	waited                  map[string]bool
}

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
	res := passResult{waited: map[string]bool{}}
	after := ""
	// If the session the waited senders' messages wait for opens part-way
	// through the pass, a later message from the same sender must not go
	// before them.
	waited := res.waited
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
				if sessionBound(m) {
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
// from a sender with messages waiting (waiting) that finds a chat leg open
// has older ones waiting for that same leg: the whole queue is read
// instead, so that they go first. Anyone else's goes at once.
func (e *Engine) trySingles(ctx context.Context, ms []store.Message, waiting map[string]bool) passResult {
	res := passResult{waited: map[string]bool{}}
	for _, m := range ms {
		switch e.deliver(ctx, m, waiting[m.Sender] || res.waited[m.Sender]) {
		case whole:
			res.again = true
			return res
		case stop:
			res.stopped = true
			return res
		case skip:
			res.skipped = true
			if sessionBound(m) {
				res.waited[m.Sender] = true
			}
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
	if m.Mode == store.Group {
		return e.deliverGroup(ctx, m, behind)
	}
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

// sessionBound reports whether m waits for a session with its sender: a
// chat or group message, or a notification.
func sessionBound(m store.Message) bool {
	return m.Mode == store.Chat || m.Mode == store.Group || m.Notification
}

// deliverGroup makes one attempt at a group message or notification: on
// the recipient's open session with the group, or by asking the SIP layer
// to bring the recipient back into the group. Pager mode is never used: a
// group message out of the group's session would reach a client that
// cannot place it in the group (RCC.07 Group Chat). Messages for a client
// that takes no sessions wait until it opens one itself.
//
// Before inviting, and for a recipient that left the group on this task
// (ParticipantLeft) whether its session is still open or not, the
// GroupHandler says whether the recipient is still a participant: if not,
// the message is given up, so that a copy queued before someone left or
// was removed neither reaches them nor brings them back, at every retry,
// into a group they are not in.
func (e *Engine) deliverGroup(ctx context.Context, m store.Message, behind bool) outcome {
	key := legKey{m.Recipient, m.Sender}
	if e.chatLeg(m.Recipient, m.Sender) == nil && e.marked(e.unreachable, key) {
		// The group's invitation will never reach the recipient: an
		// address that does not exist, or one that comes back to rcs-as
		// (security review on #279). Its copies are given up, rather
		// than kept, and retried, for StoreTTL.
		if c, ok := e.claim(ctx, m); ok {
			e.giveUp(c, "delivery.undeliverable")
		}
		return done
	}
	asked := false
	if e.hasDeparted(key) {
		if o, member := e.stillMember(ctx, m); !member {
			return o
		}
		// Added again since: the mark is stale.
		e.ParticipantAdded(m.Sender, m.Recipient)
		asked = true
	}
	if l := e.chatLeg(m.Recipient, m.Sender); l != nil {
		if behind {
			return whole
		}
		return e.viaLeg(ctx, l, m)
	}
	e.mu.Lock()
	_, pagerOnly := e.pagerOnly[m.Recipient]
	e.mu.Unlock()
	if pagerOnly || !e.inviteDue(m) {
		return skip
	}
	if !asked {
		if o, member := e.stillMember(ctx, m); !member {
			return o
		}
	}
	if !e.ownsGroup(ctx, m) {
		// Another task owns the group and invites for its copies; an
		// invitation from here would open the session on this task
		// instead, and the next message would invite back (#121).
		e.metrics.Count("delivery.group_not_owned", 1)
		e.wakeOwner(m)
		return skip
	}
	e.invite(ctx, m)
	return skip
}

// maxWakesOut bounds the wakes on their way at once, and wakeRetry is when
// a queue whose wake found no room is read again for it.
const (
	maxWakesOut = 64
	wakeRetry   = time.Second
)

// wakeOwner asks the owner of m's group to read m's recipient's queue
// (GroupHandler.WakeOwner), once per InviteTimeout, as often as the owner
// would invite the recipient for it, and at once after the recipient
// registered on a new flow here, which the wake tells (Engine.Wake). It
// goes off the queue pass, which a connection to the owner still to be
// made would hold up (code review on #464); beyond maxWakesOut on their
// way it is counted (group.wake_skipped) and the queue read again after
// wakeRetry, rather than at its own next retry, up to an hour away (QA on
// #464).
func (e *Engine) wakeOwner(m store.Message) {
	h := e.groupHandler()
	if h == nil {
		return
	}
	k := legKey{m.Recipient, m.Sender}
	e.mu.Lock()
	until, asked := e.woken[k]
	if e.closed || asked && e.clock.Now().Before(until) {
		e.mu.Unlock()
		return
	}
	if e.wakesOut >= maxWakesOut {
		retry := !e.wakeRetries[k.user]
		if retry {
			e.wakeRetries[k.user] = true
		}
		e.mu.Unlock()
		e.metrics.Count("group.wake_skipped", 1)
		if retry {
			e.clock.AfterFunc(wakeRetry, func() {
				e.mu.Lock()
				delete(e.wakeRetries, k.user)
				e.mu.Unlock()
				e.kickEvent(k.user)
			})
		}
		return
	}
	e.markFor(e.woken, k, e.cfg.InviteTimeout)
	flow := e.flows[k.user]
	registered := flow != 0 && e.wokeFlow[k] != flow
	if len(e.wokeFlow) >= e.cfg.MaxTracked {
		clear(e.wokeFlow)
	}
	e.wokeFlow[k] = flow
	e.wakesOut++
	e.wg.Add(1)
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		ctx, cancel := context.WithTimeout(e.ctx, e.cfg.DeliveryTimeout)
		defer cancel()
		h.WakeOwner(ctx, m.Sender, m.Recipient, registered)
		e.mu.Lock()
		e.wakesOut--
		e.mu.Unlock()
	}()
}

// ownsGroup asks the GroupHandler whether this task owns m's group; when
// it cannot tell, it does not.
func (e *Engine) ownsGroup(ctx context.Context, m store.Message) bool {
	h := e.groupHandler()
	if h == nil {
		return false
	}
	owns, err := h.Owns(ctx, m.Sender)
	if err != nil {
		e.storeFailed("group owner", m.Recipient, err)
		return false
	}
	return owns
}

// stillMember asks the GroupHandler whether m's recipient is still a
// participant of m's group, and gives m up if not. When it is not, or
// cannot tell, it returns the outcome of the attempt.
func (e *Engine) stillMember(ctx context.Context, m store.Message) (outcome, bool) {
	h := e.groupHandler()
	if h == nil {
		return skip, false
	}
	member, err := h.Member(ctx, m.Sender, m.Recipient)
	switch {
	case err != nil:
		e.storeFailed("group member", m.Recipient, err)
		return skip, false
	case !member:
		if c, ok := e.claim(ctx, m); ok {
			e.giveUp(c, "delivery.not_participant")
		}
		return done, false
	}
	return done, true
}

// chatLeg returns the newest open chat leg of user with peer.
func (e *Engine) chatLeg(user, peer string) *Leg {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.chatLegLocked(user, peer)
}

// chatLegLocked is chatLeg for a caller holding e.mu.
func (e *Engine) chatLegLocked(user, peer string) *Leg {
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
	if c.Summary {
		return e.sendSummary(ctx, l, c)
	}
	return e.sendClaimed(ctx, l, c)
}

// sendClaimed delivers a claimed message on l and records the outcome.
func (e *Engine) sendClaimed(ctx context.Context, l *Leg, m store.Message) outcome {
	return e.sendClaimedThen(ctx, l, m, nil)
}

// sendClaimedThen is sendClaimed with over, when not nil, run as soon as
// the attempt is over and before its outcome is recorded: m is still
// claimed then, so no pass sees it in between.
func (e *Engine) sendClaimedThen(ctx context.Context, l *Leg, m store.Message, over func()) outcome {
	ctx, cancel := e.withTimeout(ctx, e.cfg.DeliveryTimeout)
	code, err := l.send(ctx, m.CPIM)
	cancel()
	if over != nil {
		over()
	}
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

// inviteMark is an invitation asked for, waited for until until. by is
// the terminating large-mode leg that marked it while it makes its attempt
// (activate), so that it deletes its own mark and never a newer one;
// nil for the invitations invite asks for.
type inviteMark struct {
	until time.Time
	by    *Leg
}

// invitation is the session m waits for, and its key in e.invites.
func invitation(m store.Message) (Invitation, inviteKey) {
	inv := Invitation{
		Recipient: m.Recipient, Peer: m.Sender, Mode: m.Mode,
		Conversation: Conversation{ID: m.Conversation, Contribution: m.Contribution, InReplyTo: m.InReplyTo},
	}
	switch m.Mode {
	case store.Standalone:
		inv.QueueID = m.ID
	case store.Group:
		inv.Referrer = m.Author
	}
	return inv, inviteKey{inv.Recipient, inv.Peer, inv.Mode, inv.QueueID}
}

// inviteDue reports whether invite would ask for m's session now, none
// having been asked for within InviteTimeout.
func (e *Engine) inviteDue(m store.Message) bool {
	_, key := invitation(m)
	e.mu.Lock()
	defer e.mu.Unlock()
	mark, ok := e.invites[key]
	return !ok || !e.clock.Now().Before(mark.until)
}

// invite asks for a session to deliver m on, unless one was asked for
// within InviteTimeout: a chat session for a chat message, a large-mode
// session for this message alone for a standalone one.
func (e *Engine) invite(ctx context.Context, m store.Message) {
	inv, key := invitation(m)
	e.ask(ctx, inv, key)
}

// Invite asks the Deliverer for inv's session as the engine asks for the
// sessions of what it queues, unless one was asked for within
// InviteTimeout or the recipient takes no sessions from the network: the
// SIP layer's way to invite a group's new participants, for whom nothing
// is queued yet. A message queued for one meanwhile then waits for that
// session rather than ringing its client a second time.
func (e *Engine) Invite(ctx context.Context, inv Invitation) {
	e.mu.Lock()
	_, pagerOnly := e.pagerOnly[inv.Recipient]
	e.mu.Unlock()
	if pagerOnly {
		return
	}
	e.ask(ctx, inv, inviteKey{inv.Recipient, inv.Peer, inv.Mode, inv.QueueID})
}

func (e *Engine) ask(ctx context.Context, inv Invitation, key inviteKey) {
	now := e.clock.Now()
	e.mu.Lock()
	if mark, ok := e.invites[key]; ok && now.Before(mark.until) {
		e.mu.Unlock()
		return
	}
	// The pass that found no chat leg for m may have looked just before
	// one opened: the session asked for earlier was answered, and its leg
	// took the key out of e.invites (activate). Asking again would open a
	// second session, and the newer leg, which the client may never bind,
	// is the one chatLeg gives every delivery after (#260). The leg's
	// activation has the queue read again, and m goes on it. The check
	// stays under e.mu with the key's: activate adds the leg and deletes
	// the key in one critical section, so no pass falls between the two
	// at that handoff. (A key can also go without a leg, as on a
	// registration on a new flow or past InviteTimeout; asking again is
	// meant then.) It records nothing, so once the leg ends the next pass
	// may ask again at once.
	if (inv.Mode == store.Chat || inv.Mode == store.Group) && e.chatLegLocked(inv.Recipient, inv.Peer) != nil {
		e.mu.Unlock()
		return
	}
	if len(e.invites) >= e.cfg.MaxTracked {
		for k, mark := range e.invites {
			if !now.Before(mark.until) {
				delete(e.invites, k)
			}
		}
	}
	if len(e.invites) >= e.cfg.MaxTracked {
		e.mu.Unlock()
		e.metrics.Count("invite.untracked", 1)
		return
	}
	e.invites[key] = inviteMark{until: now.Add(e.cfg.InviteTimeout)}
	inv.flow, inv.asked = e.flows[inv.Recipient], e.flowSeq
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
