package messaging

import (
	"context"
	"errors"
	"maps"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// A group chat (RCC.07 Group Chat) runs through the same queues and
// delivery as 1-to-1 chat. Each participant has a session with the group,
// a leg of Mode store.Group whose peer is the group's conference URI. A
// message a participant writes there is queued once per other participant
// with Sender set to the group, so it goes out on that participant's own
// session with the group, and with Author set to the writer. Who belongs
// to a group, and what a sender may do in it, is the group package's
// business (GroupHandler); the engine moves the messages.

// GroupKind says what a participant sent in a group, for the limits the
// GroupHandler applies.
type GroupKind uint8

const (
	// GroupText is a message for the other participants.
	GroupText GroupKind = iota + 1
	// GroupNotification is a disposition notification about a message
	// of the group, for its author.
	GroupNotification
	// GroupComposing is an is-composing indication (RFC 3994).
	GroupComposing
)

// GroupHandler decides who a participant's message in a group goes to.
type GroupHandler interface {
	// Recipients returns who a kind of message from sender in group goes
	// to, sender left out, or a *Rejection when sender may not send it
	// there now. For a notification, only the refusal matters: it goes to
	// the author of the message it reports on.
	Recipients(ctx context.Context, group, sender string, kind GroupKind) (Audience, error)
	// Member reports whether user is a current participant of group, one
	// that messages are kept for; false, without an error, when the group
	// has ended.
	Member(ctx context.Context, group, user string) (bool, error)
	// Owns reports whether this task owns group (#121), taking it over if
	// its owner has stopped: false when another task, alive, does. Only
	// the owner invites a group's participants for their queued copies,
	// so that a group's sessions all open on one task.
	Owns(ctx context.Context, group string) (bool, error)
}

// Audience is who a participant's message in a group goes to, and the
// name the group knows the participant by.
type Audience struct {
	Recipients []string
	// SenderName is the sender's display name in the group's roster, or
	// empty. It replaces the name the sender's client wrote in the CPIM
	// From, which could be another participant's.
	SenderName string
	// Fence, when set, is the group's owner the message's copies are
	// queued under (store.Message.Fence, #121).
	Fence *store.Fence
}

// Wake has the engine read user's queue again, as a registration on a new
// flow does: for the owner of a group whose copies wait in it, told by
// the task that saw the registration (#121).
func (e *Engine) Wake(user string) {
	e.metrics.Count("group.wake", 1)
	e.kickEvent(user)
}

// SetGroupHandler gives the engine the group package that runs the
// groups. Without one, every group message is refused.
func (e *Engine) SetGroupHandler(h GroupHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.groups = h
}

func (e *Engine) groupHandler() GroupHandler {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.groups
}

// ParticipantLeft tells the engine that user is no longer a participant
// of group: it left, declined or was removed, or tried to join without
// being one. What is queued for it from the group is not delivered on a
// session that is still open, nor used to invite it back: the next
// attempt, made now, asks the GroupHandler and gives up on each message
// if user is still not a participant. The mark is per task; elsewhere the
// GroupHandler is asked before every invitation.
func (e *Engine) ParticipantLeft(group, user string) {
	e.mu.Lock()
	e.mark(e.departed, legKey{user, group})
	delete(e.invites, inviteKey{user, group, store.Group, ""})
	e.mu.Unlock()
	e.kickEvent(user)
}

// mark records k in marks for as long as a copy could be queued for it,
// within MaxTracked marks; it needs e.mu.
func (e *Engine) mark(marks map[legKey]time.Time, k legKey) {
	now := e.clock.Now()
	if len(marks) >= e.cfg.MaxTracked {
		for k, until := range marks {
			if !now.Before(until) {
				delete(marks, k)
			}
		}
		for k := range marks {
			if len(marks) < e.cfg.MaxTracked {
				break
			}
			delete(marks, k)
		}
	}
	// Nothing queued outlives StoreTTL, so neither need the mark.
	marks[k] = now.Add(e.cfg.StoreTTL)
}

// ParticipantAdded tells the engine that user is a participant of group
// again, after ParticipantLeft, or one the group's invitation may reach
// again after it found it unreachable.
func (e *Engine) ParticipantAdded(group, user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.departed, legKey{user, group})
	delete(e.unreachable, legKey{user, group})
}

func (e *Engine) hasDeparted(k legKey) bool { return e.marked(e.departed, k) }

func (e *Engine) marked(marks map[legKey]time.Time, k legKey) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := marks[k]
	return ok && e.clock.Now().Before(until)
}

// GroupOrigin describes a message a participant wrote in a group.
type GroupOrigin struct {
	// Group is the group's conference URI.
	Group string
	// Sender is the participant's asserted identity, and Identities the
	// others it may name in the CPIM From.
	Sender       string
	Identities   []string
	Conversation Conversation
	CPIM         []byte
}

// SubmitGroup runs a participant's message in a group through the
// pipeline: the same checks as Submit, the GroupHandler's say on who may
// send and to whom, and then one queue item per recipient, or for a
// notification one for the author of the message it reports on. It
// returns a *Rejection for a message refused, and another error when
// rcs-as could not take it for every recipient, which the client may retry
// (each recipient's client drops a duplicate by its Message-ID).
//
// rcs-as rewrites the CPIM From to the sender's asserted identity, under
// the name the roster gives it, and the To to the group (groupView).
// Clients take the author of a group message from its From (rcsjta
// GroupChatSession), and the sender's own client writes its own address
// and name there, which nothing else checks.
func (e *Engine) SubmitGroup(ctx context.Context, o GroupOrigin) error {
	err := e.submitGroup(ctx, o)
	var r *Rejection
	if errors.As(err, &r) {
		e.metrics.Count("message.rejected."+string(r.Reason), 1)
		if c := r.cpimReason(); c != "" {
			e.metrics.Count("cpim.rejected."+string(c), 1)
		}
	} else if err != nil {
		e.metrics.Count("store.failed", 1)
	}
	return err
}

func (e *Engine) submitGroup(ctx context.Context, o GroupOrigin) error {
	h := e.groupHandler()
	if h == nil {
		return reject(ReasonNoGroup, nil)
	}
	for _, id := range append([]string{o.Group, o.Sender}, o.Identities...) {
		if id == "" || len(id) > MaxIdentityLength {
			return reject(ReasonMalformed, errors.New("identity empty or too long"))
		}
	}
	// The author is named as the group names it, so that its share, its
	// sent records and the notifications for it meet its own legs. The
	// identity as asserted stays one the client may name itself by, as it
	// was provisioned (namesSender).
	sender, ok := UserOf(o.Sender, e.cfg.HomeDomain)
	if !ok {
		return reject(ReasonNotParticipant, nil)
	}
	o.Identities = append(slices.Clip(o.Identities), o.Sender)
	o.Sender = sender
	m, err := ParseMessage(o.CPIM, e.cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	e.countDeviations(m.CPIM.Deviations())
	if !namesSender(m.From.URI, o.Sender, o.Identities, e.cfg.HomeDomain) {
		return reject(ReasonFromMismatch, nil)
	}
	now := e.clock.Now()
	switch {
	case isComposing(m.CPIM):
		return e.groupComposing(ctx, h, o, m, now)
	case m.Notification != nil:
		if len(o.CPIM) > e.cfg.PagerLimit {
			return reject(ReasonTooLarge, nil)
		}
		if !e.notifiers.allow(o.Sender, now) {
			return reject(ReasonRateLimited, nil)
		}
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		defer cancel()
		return e.submitGroupNotification(sctx, h, o, m, "", now)
	}
	if !e.senders.allow(o.Sender, now) {
		return reject(ReasonRateLimited, nil)
	}
	aud, err := h.Recipients(ctx, o.Group, o.Sender, GroupText)
	if err != nil {
		return err
	}
	return e.submitGroupMessage(ctx, o, m, aud, now)
}

// isComposing reports whether a CPIM message carries an is-composing
// indication, as a group session sends them (rcsjta GroupChatSession), so
// that the From tells the others who is typing.
func isComposing(c *cpim.Message) bool {
	t, _, err := mime.ParseMediaType(c.ContentType())
	return err == nil && t == IsComposingType
}

// groupView is c as the group's participants see it. Its header block is
// built anew: From, the sender's asserted identity under its roster name,
// then To, the group for a message or the author for a notification, then
// every other header of c in its order. A header that a receiver could take for a From or To
// (addressHeader) is left out wherever it was, in whatever case, prefix or
// namespace, so that every receiver reads the author rcs-as checked, and
// so are content headers that look like one. The two come before any NS
// header, so they are in the core namespace (RFC 3862 §3.4).
func groupView(c *cpim.Message, from cpim.Address, to string) ([]byte, error) {
	out := &cpim.Message{Headers: []cpim.Header{
		{Name: cpim.HeaderFrom, Value: from.String()},
		{Name: cpim.HeaderTo, Value: cpim.Address{URI: to}.String()},
	}, Body: c.Body}
	for _, h := range c.Headers {
		if addressHeader(h.Name) == "" {
			out.Headers = append(out.Headers, h)
		}
	}
	for _, f := range c.ContentHeaders {
		if addressHeader(f.Name) == "" {
			out.ContentHeaders = append(out.ContentHeaders, f)
		}
	}
	return out.Marshal()
}

func (e *Engine) submitGroupMessage(ctx context.Context, o GroupOrigin, m *Message, aud Audience, now time.Time) error {
	recipients := aud.Recipients
	body, err := groupView(m.CPIM, cpim.Address{Name: aud.SenderName, URI: o.Sender}, o.Group)
	if err != nil {
		return reject(ReasonMalformed, err)
	}
	if len(body) > e.cfg.MaxMessageSize {
		return reject(ReasonTooLarge, nil)
	}
	if m.IncompleteRequest {
		e.metrics.Count("imdn.incomplete_request", 1)
	}
	if req := m.Request; req.Dispositions != 0 {
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		err := e.recordGroupSent(sctx, o, req, recipients, now)
		cancel()
		if err != nil {
			return err
		}
	}
	// Each recipient's queue is its own: one that is full, or a store
	// call that fails, costs that recipient the message and nobody else.
	// The calls run one after another on the sender's session, so all of
	// them together are bounded too: past FanoutTimeout the rest are left
	// out and the sender is answered as for a store failure. The reference
	// client does not resend by itself: it marks the message failed and
	// ends the session, and its user may send it again (recipients drop
	// the repeats by Message-ID).
	//
	// Each message starts at a random recipient: with a store too slow for
	// the whole list, the ones left out differ from one message, or one
	// resend, to the next, rather than always being those at its end.
	fctx, done := e.withTimeout(ctx, e.cfg.FanoutTimeout)
	defer done()
	start, err := e.randomIndex(len(recipients))
	if err != nil {
		return err
	}
	var failed error
	for i := range recipients {
		r := recipients[(start+i)%len(recipients)]
		if err := fctx.Err(); err != nil {
			e.metrics.Count("group.fanout.timed_out", int64(len(recipients)-i))
			if failed == nil {
				failed = err
			}
			break
		}
		id, err := e.newID(now)
		if err != nil {
			return err
		}
		q := store.Message{
			Recipient: r, ID: id, Sender: o.Group, Author: o.Sender, Mode: store.Group, MessageID: m.Request.MessageID,
			Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
			CPIM: body, Enqueued: now, Expires: now.Add(e.cfg.StoreTTL), Fence: aud.Fence,
		}
		sctx, cancel := e.withTimeout(fctx, e.cfg.StoreTimeout)
		err = e.enqueue(sctx, q)
		if errors.Is(err, store.ErrNotOwner) {
			// Another task took the group over: it queues nothing more of
			// this message, and the sender's client sends it again, to
			// the new owner (#121).
			cancel()
			e.metrics.Count("group.fanout.not_owner", 1)
			return err
		}
		if errors.Is(err, store.ErrQueueFull) || errors.Is(err, store.ErrSenderShareFull) {
			e.metrics.Count("group.fanout.queue_full", 1)
			if n, nerr := e.notification(q, failedDelivery, q.ID+"-f", now); nerr == nil {
				_ = e.enqueueNotification(sctx, n, failedDelivery.status)
			}
			err = nil
		}
		cancel()
		if err != nil && failed == nil {
			failed = err
		}
	}
	e.metrics.Count("group.message.accepted", 1)
	e.metrics.Count("group.fanout.deliveries", int64(len(recipients)))
	return failed
}

// recordGroupSent records a group message that asks for notifications,
// twice. The group's record (Sender the group) matches a notification sent
// in the group to its message whatever form of the author's identity the
// notifier writes in its To, and holds the marks of the notifications
// accepted. The author's own record (Sender the author, naming the group)
// is what a notification sent to the author outside the group finds
// (submitNotification). The author's comes first: it is the one a 1-to-1
// message could already hold under the same Message-ID, which makes the
// group message a reuse rather than a resend (RFC 5438 §6.3).
func (e *Engine) recordGroupSent(ctx context.Context, o GroupOrigin, req imdn.Request, recipients []string, now time.Time) error {
	resent := false
	for _, r := range []store.Sent{
		{Sender: o.Sender, MessageID: req.MessageID, Group: o.Group},
		{Sender: o.Group, MessageID: req.MessageID, Author: o.Sender},
	} {
		r.Recipients, r.Dispositions, r.DateTime, r.Expires = recipients, req.Dispositions, req.DateTime, now.Add(e.cfg.SentTTL)
		err := e.store.RecordSent(ctx, r, now)
		if !errors.Is(err, store.ErrExists) {
			if err != nil {
				return err
			}
			continue
		}
		s, err := e.store.Sent(ctx, r.Sender, req.MessageID, now)
		switch {
		case err != nil:
			return err
		case s.Group != r.Group || s.Author != r.Author:
			return reject(ReasonMessageIDReused, nil)
		}
		resent = true
	}
	if resent {
		e.metrics.Count("message.resent", 1)
	}
	return nil
}

// submitGroupNotification accepts a notification about a group's message
// on the same terms as submitNotification: the message must be the
// group's, the notifier one of the participants it went to, and the kind
// one its author asked for, once. A recipient-uri in it, if any, must name
// the notifier, so that no participant reports for another.
//
// It arrives in the notifier's session with the group, where h checks that
// the notifier may send there, or outside it, in a SIP MESSAGE to author,
// whose own record of the message named the group: rcsjta sends display
// notifications that way once the group session is gone
// (ChatServiceImpl.sendGroupChatDisplayedDeliveryReport). Either way it
// goes to the author in the group, From the notifier and To the author,
// as the group's record names it: a client takes a notification in a group
// only when it is To itself (rcsjta), and what the notifier wrote there
// (the anonymous URI from outside the group) is not rcs-as's to pass on.
//
// The record is read before the group: a notification about nothing costs
// one small read, not one of the group's item.
func (e *Engine) submitGroupNotification(ctx context.Context, h GroupHandler, o GroupOrigin, m *Message, author string, now time.Time) error {
	n := m.Notification
	sent, err := e.store.Sent(ctx, o.Group, n.MessageID, now)
	if errors.Is(err, store.ErrNotFound) || err == nil && (sent.Author == "" || author != "" && sent.Author != author) {
		return reject(ReasonIMDNUnknown, nil)
	}
	if err != nil {
		return err
	}
	switch {
	case !slices.Contains(sent.Recipients, o.Sender):
		return reject(ReasonIMDNForged, nil)
	case n.RecipientURI != "" && !namesSender(n.RecipientURI, o.Sender, o.Identities, e.cfg.HomeDomain):
		return reject(ReasonIMDNForged, nil)
	case !sent.Dispositions.Wants(n.Kind, n.Status):
		return reject(ReasonIMDNNotRequested, nil)
	}
	if h != nil {
		if _, err := h.Recipients(ctx, o.Group, o.Sender, GroupNotification); err != nil {
			return err
		}
	}
	body, err := groupView(m.CPIM, cpim.Address{URI: o.Sender}, sent.Author)
	if err != nil {
		return reject(ReasonIMDNMalformed, err)
	}
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	mark := string(n.Kind) + " " + o.Sender
	err = e.store.MarkNotified(ctx, o.Group, n.MessageID, mark, string(n.Status), id, now)
	switch {
	case errors.Is(err, store.ErrExists):
		e.metrics.Count("imdn.duplicate", 1)
		return nil
	case errors.Is(err, store.ErrNotFound):
		return reject(ReasonIMDNUnknown, nil)
	case err != nil:
		return err
	}
	q := store.Message{
		Recipient: sent.Author, ID: id, Sender: o.Group, Author: o.Sender, Mode: store.Group, Notification: true,
		Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
		CPIM: body, Enqueued: now, Expires: now.Add(e.cfg.StoreTTL),
	}
	err = e.enqueue(ctx, q)
	switch {
	case errors.Is(err, store.ErrQueueFull), errors.Is(err, store.ErrSenderShareFull):
		// Taken, the mark kept, and summarized: a refusal would not make
		// room, and the reference client ends its session with the group
		// on one (rcsjta GroupChatSession.msrpTransferError).
		e.summarize(ctx, sent, o, now)
		return nil
	case err != nil:
		rctx, cancel := e.recordCtx()
		_ = e.store.UnmarkNotified(rctx, o.Group, n.MessageID, mark, id)
		cancel()
		return err
	}
	e.metrics.Count("group.notification.accepted", 1)
	return nil
}

// SummaryIDPrefix begins the queue ID of a group notification summary,
// which is this followed by the Message-ID it summarizes: one per message
// in its author's queue, since an author's Message-IDs are its own
// (recordGroupSent).
const SummaryIDPrefix = "r-"

// summarize stands in for a notification about the group message sent
// that its author's queue had no room for, the group's share or the total
// of group notifications being full: it makes sure the queue holds the
// message's summary (store.Message.Summary), which, delivered, sends the
// author every participant's notification from the marks (#166). The
// reference client marks a group message read by all only once each
// participant's display notification is in (rcsjta
// GroupChatImpl.isDisplayedByAllRecipients), and does not take aggregated
// ones (RFC 5438 §8.3), so they go out one per participant. A summary
// there already, waiting or being sent, covers this one too: see
// sendSummary.
func (e *Engine) summarize(ctx context.Context, sent store.Sent, o GroupOrigin, now time.Time) {
	q := store.Message{
		Recipient: sent.Author, ID: SummaryIDPrefix + sent.MessageID, Sender: o.Group, Mode: store.Group,
		Notification: true, Summary: true, MessageID: sent.MessageID,
		Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
		Enqueued: now, Expires: sent.Expires,
	}
	err := e.store.Enqueue(ctx, q, e.limit)
	switch {
	case err == nil:
		e.kickNew(q)
	case errors.Is(err, store.ErrExists):
	default:
		// The whole queue is full, or the store failed: the
		// notification is dropped as before summaries.
		e.metrics.Count("group.notification.dropped", 1)
		return
	}
	e.metrics.Count("group.notification.summarized", 1)
}

// sendSummary delivers a claimed summary on the author's leg l: from the
// group's sent record, for each participant that reported, its strongest
// notification (display before delivery before processing), as a
// notification of its own From the participant To the author. All but the
// last go without reports (Failure-Report: no, no Success-Report); the
// last asks for a success report (Leg.send). One session delivers in order
// over one connection, so its 200 says every one of them reached the
// client: a transport guarantee, not that the client took each, since one
// it refuses under Failure-Report: no is not reported. Only then is the
// summary removed, and only if no notification was marked since the
// record was read (store.Store.RemoveSummary); otherwise it is released
// and the queue read again, so that it goes out once more with the new
// ones, to the participants whose notification changed. A removal that
// fails otherwise is tried again at the next delivery: a busy store
// (store.ErrBusy) for as long as it takes, any other failure
// MaxSummaryFailures times in a row at most, after which the summary is
// given up unless notifications were merged into it meanwhile.
func (e *Engine) sendSummary(ctx context.Context, l *Leg, m store.Message) outcome {
	now := e.clock.Now()
	sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	sent, err := e.store.Sent(sctx, m.Sender, m.MessageID, now)
	cancel()
	switch {
	case errors.Is(err, store.ErrNotFound):
		// The record expired: there is nothing left to send.
		e.forgetSummary(m)
		e.remove(m)
		return done
	case err != nil:
		e.storeFailed("sent", m.Recipient, err)
		e.release(m)
		return stop
	}
	notes, err := e.summaryNotifications(sent, now)
	if err != nil {
		e.metrics.Count("imdn.generate_failed", 1)
		e.forgetSummary(m)
		e.remove(m)
		return done
	}
	confirmed := e.summarySent(m)
	var send []summaryNote
	for _, n := range notes {
		if confirmed[n.notifier] != n.state {
			send = append(send, n)
		}
	}
	for i, n := range send {
		dctx, cancel := e.withTimeout(ctx, e.cfg.DeliveryTimeout)
		if i < len(send)-1 {
			l.carried.Store(true)
			_, err = l.session.Send(dctx, msrp.Outgoing{ContentType: cpim.ContentType, Body: n.body, FailureReport: msrp.ReportNo})
			cancel()
			if err != nil {
				e.metrics.Count("delivery.msrp_failed", 1)
				e.release(m)
				return stop
			}
			e.metrics.Count("group.summary.sent", 1)
			continue
		}
		code, err := l.send(dctx, n.body)
		cancel()
		switch {
		case err == nil && code == msrp.StatusOK:
			e.metrics.Count("group.summary.sent", 1)
		case err == nil && permanent(code):
			e.forgetSummary(m)
			e.giveUp(m, "delivery.refused")
			return done
		default:
			e.metrics.Count("delivery.msrp_failed", 1)
			e.release(m)
			return stop
		}
	}
	// The client has every one of them now.
	states := make(map[string]string, len(notes))
	for _, n := range notes {
		states[n.notifier] = n.state
	}
	e.rememberSummary(m, states)
	rctx, cancel := e.recordCtx()
	err = e.store.RemoveSummary(rctx, m, e.cfg.InstanceID, sent.MarkCount)
	cancel()
	switch {
	case err == nil:
		e.forgetSummary(m)
		e.metrics.Count("group.summary.expanded", 1)
		return done
	case errors.Is(err, store.ErrMarksChanged):
		e.summaryProgressed(m)
		e.release(m)
		return whole
	}
	e.storeFailed("remove summary", m.Recipient, err)
	if errors.Is(err, store.ErrBusy) {
		// Other writes to the record, the marks themselves among them,
		// held it: that passes, and is no reason to give up.
		e.release(m)
		return stop
	}
	if e.summaryFailed(m) >= MaxSummaryFailures {
		// Notifications merged into the summary since the record was read
		// were not sent: they are not given up with it.
		if e.marksGrew(ctx, m, sent.MarkCount) {
			e.summaryProgressed(m)
			e.release(m)
			return whole
		}
		// Nothing left to send: giving it up is better than trying the
		// removal at every retry for as long as the store refuses.
		e.forgetSummary(m)
		e.giveUp(m, "group.summary.abandoned")
		return done
	}
	e.release(m)
	return stop
}

// marksGrew reports whether the sent record of summary m now counts more
// marks than read did. A record it cannot read counts as grown, so that
// the summary is kept rather than given up on a guess.
func (e *Engine) marksGrew(ctx context.Context, m store.Message, read int64) bool {
	sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	sent, err := e.store.Sent(sctx, m.Sender, m.MessageID, e.clock.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false
	case err != nil:
		e.storeFailed("sent", m.Recipient, err)
		return true
	}
	return sent.MarkCount > read
}

// MaxSummaryFailures is how many times in a row a summary's removal may
// fail, other than for new marks, before it is given up.
const MaxSummaryFailures = 3

// summaryState is what the engine remembers of a summary between
// deliveries on this task: the notification state each participant was
// last sent in a pass the client confirmed, and how many removals have
// failed in a row.
type summaryState struct {
	sent     map[string]string
	failures int
}

func summaryKey(m store.Message) legKey { return legKey{m.Recipient, m.ID} }

func (e *Engine) summarySent(m store.Message) map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if st := e.summaries[summaryKey(m)]; st != nil {
		return st.sent
	}
	return nil
}

// summaryFor needs e.mu.
func (e *Engine) summaryFor(m store.Message) *summaryState {
	k := summaryKey(m)
	st := e.summaries[k]
	if st == nil {
		if len(e.summaries) >= e.cfg.MaxTracked {
			for x := range e.summaries {
				delete(e.summaries, x)
				break
			}
		}
		st = &summaryState{}
		e.summaries[k] = st
	}
	return st
}

func (e *Engine) rememberSummary(m store.Message, sent map[string]string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.summaryFor(m).sent = sent
}

func (e *Engine) summaryFailed(m store.Message) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.summaryFor(m)
	st.failures++
	return st.failures
}

// summaryProgressed restarts the count of failed removals: new marks are
// not a failure.
func (e *Engine) summaryProgressed(m store.Message) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.summaryFor(m).failures = 0
}

func (e *Engine) forgetSummary(m store.Message) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.summaries, summaryKey(m))
}

// kindRank orders notification kinds by strength: what a participant
// displayed it has had delivered.
var kindRank = map[imdn.Kind]int{imdn.ProcessingNotification: 1, imdn.DeliveryNotification: 2, imdn.DisplayNotification: 3}

// summaryNote is one notification a summary sends: from notifier, in
// state (kind and status), as body.
type summaryNote struct {
	notifier, state string
	body            []byte
}

// summaryNotifications builds the notifications a summary stands for, in
// the order of the participants' identities.
func (e *Engine) summaryNotifications(sent store.Sent, now time.Time) ([]summaryNote, error) {
	type best struct {
		kind   imdn.Kind
		status imdn.Status
	}
	strongest := map[string]best{}
	for key, status := range sent.Marks {
		k, notifier, ok := strings.Cut(key, " ")
		kind := imdn.Kind(k)
		if !ok || kindRank[kind] == 0 || !slices.Contains(sent.Recipients, notifier) {
			continue
		}
		if b, ok := strongest[notifier]; !ok || kindRank[kind] > kindRank[b.kind] {
			strongest[notifier] = best{kind, imdn.Status(status)}
		}
	}
	notifiers := slices.Sorted(maps.Keys(strongest))
	notes := make([]summaryNote, 0, len(notifiers))
	for _, notifier := range notifiers {
		b := strongest[notifier]
		id, err := imdn.NewMessageID(e.rand)
		if err != nil {
			return nil, err
		}
		n := imdn.Notification{MessageID: sent.MessageID, DateTime: sent.DateTime, Kind: b.kind, Status: b.status}
		msg, err := n.Message(imdn.Envelope{From: cpim.Address{URI: notifier}, To: cpim.Address{URI: sent.Author}, MessageID: id, DateTime: now})
		if err != nil {
			return nil, err
		}
		body, err := msg.Marshal()
		if err != nil {
			return nil, err
		}
		notes = append(notes, summaryNote{notifier: notifier, state: string(b.kind) + " " + string(b.status), body: body})
	}
	return notes, nil
}

// groupComposing passes an is-composing indication to the open sessions
// of the other participants on this task, without storing it, under
// IsComposingRate per sender and group. With no other session of the
// group open here there is nobody to pass it to, and the group's item is
// not read.
func (e *Engine) groupComposing(ctx context.Context, h GroupHandler, o GroupOrigin, m *Message, now time.Time) error {
	if len(o.CPIM) > MaxIsComposingSize || !e.composing.allow(o.Group+"\x00"+o.Sender, now) || !e.othersHere(o.Group, o.Sender) {
		e.metrics.Count("iscomposing.dropped", 1)
		return nil
	}
	aud, err := h.Recipients(ctx, o.Group, o.Sender, GroupComposing)
	if err != nil {
		return err
	}
	body, err := groupView(m.CPIM, cpim.Address{Name: aud.SenderName, URI: o.Sender}, o.Group)
	if err != nil {
		return reject(ReasonMalformed, err)
	}
	for _, r := range aud.Recipients {
		to := e.chatLeg(r, o.Group)
		if to == nil || !to.composing.CompareAndSwap(false, true) {
			e.metrics.Count("iscomposing.dropped", 1)
			continue
		}
		go func() {
			ctx, cancel := e.withTimeout(e.ctx, e.cfg.DeliveryTimeout)
			to.carried.Store(true)
			_, err := to.session.Send(ctx, msrp.Outgoing{ContentType: cpim.ContentType, Body: body, FailureReport: msrp.ReportNo})
			cancel()
			to.composing.Store(false)
			if err != nil {
				e.metrics.Count("iscomposing.dropped", 1)
				return
			}
			e.metrics.Count("iscomposing.forwarded", 1)
		}()
	}
	return nil
}

// othersHere reports whether a participant of group other than sender
// has a session with it open on this task.
func (e *Engine) othersHere(group, sender string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	own := 0
	for _, l := range e.legs[legKey{sender, group}] {
		select {
		case <-l.Done():
		default:
			own++
		}
	}
	return e.groupLegs[group] > own
}

// groupReceived is HandleMessage for a group session. A bare is-composing
// indication, which a client may also send there, is wrapped in CPIM so
// that the others learn who is typing.
func (e *Engine) groupReceived(l *Leg, m *msrp.Message) error {
	body := m.Body
	switch m.MediaType() {
	case cpim.ContentType:
	case IsComposingType:
		if len(body) > MaxIsComposingSize {
			e.metrics.Count("iscomposing.dropped", 1)
			return nil
		}
		c := &cpim.Message{
			Headers: []cpim.Header{
				{Name: cpim.HeaderFrom, Value: cpim.Address{URI: l.p.User}.String()},
				{Name: cpim.HeaderTo, Value: cpim.Address{URI: l.p.Peer}.String()},
				{Name: cpim.HeaderDateTime, Value: cpim.FormatDateTime(e.clock.Now())},
			},
			ContentHeaders: []cpim.Field{{Name: "Content-Type", Value: IsComposingType}},
			Body:           body,
		}
		var err error
		if body, err = c.Marshal(); err != nil {
			e.metrics.Count("iscomposing.dropped", 1)
			return nil
		}
	default:
		e.metrics.Count("message.rejected."+string(ReasonContentType), 1)
		return &msrp.StatusError{Code: msrp.StatusUnsupportedMediaType}
	}
	err := e.SubmitGroup(e.ctx, GroupOrigin{
		Group: l.p.Peer, Sender: l.p.User, Identities: l.p.Identities, Conversation: l.p.Conversation, CPIM: body,
	})
	var r *Rejection
	switch {
	case errors.As(err, &r):
		return &msrp.StatusError{Code: r.MSRPStatus()}
	case err != nil:
		return notStored(err)
	}
	return nil
}
