package messaging

import (
	"context"
	"errors"
	"mime"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
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
}

// Audience is who a participant's message in a group goes to, and the
// name the group knows the participant by.
type Audience struct {
	Recipients []string
	// SenderName is the sender's display name in the group's roster, or
	// empty. It replaces the name the sender's client wrote in the CPIM
	// From, which could be another participant's.
	SenderName string
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
	m, err := ParseMessage(o.CPIM, e.cfg.MaxMessageSize)
	if err != nil {
		return err
	}
	e.countDeviations(m.CPIM.Deviations())
	if m.From.URI != AnonymousURI && m.From.URI != o.Sender && !slices.Contains(o.Identities, m.From.URI) {
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
		if _, err := h.Recipients(ctx, o.Group, o.Sender, GroupNotification); err != nil {
			return err
		}
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		defer cancel()
		return e.submitGroupNotification(sctx, o, m, now)
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
// then To, the group, or when to is empty the To the sender wrote (a
// notification's, which names the author), then every other header of c
// in its order. A header that a receiver could take for a From or To
// (addressHeader) is left out wherever it was, in whatever case, prefix or
// namespace, so that every receiver reads the author rcs-as checked, and
// so are content headers that look like one. The two come before any NS
// header, so they are in the core namespace (RFC 3862 §3.4).
func groupView(c *cpim.Message, from cpim.Address, to string) ([]byte, error) {
	out := &cpim.Message{Headers: []cpim.Header{{Name: cpim.HeaderFrom, Value: from.String()}}, Body: c.Body}
	switch h, ok := c.Get(cpim.CoreNamespace, cpim.HeaderTo); {
	case to != "":
		out.Headers = append(out.Headers, cpim.Header{Name: cpim.HeaderTo, Value: cpim.Address{URI: to}.String()})
	case ok:
		out.Headers = append(out.Headers, cpim.Header{Name: cpim.HeaderTo, Params: h.Params, Value: h.Value})
	}
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
		// Keyed by the group, so that a notification is matched to its
		// message whatever form of the author's identity the notifier
		// writes in its To.
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		err := e.store.RecordSent(sctx, store.Sent{
			Sender: o.Group, MessageID: req.MessageID, Author: o.Sender, Recipients: recipients,
			Dispositions: req.Dispositions, Expires: now.Add(e.cfg.SentTTL),
		}, now)
		if errors.Is(err, store.ErrExists) {
			var s store.Sent
			s, err = e.store.Sent(sctx, o.Group, req.MessageID, now)
			switch {
			case err != nil:
			case s.Author != o.Sender:
				err = reject(ReasonMessageIDReused, nil)
			default:
				e.metrics.Count("message.resent", 1)
			}
		}
		cancel()
		if err != nil {
			return err
		}
	}
	// Each recipient's queue is its own: one that is full, or a store
	// call that fails, costs that recipient the message and nobody else.
	var failed error
	for _, r := range recipients {
		id, err := e.newID(now)
		if err != nil {
			return err
		}
		q := store.Message{
			Recipient: r, ID: id, Sender: o.Group, Author: o.Sender, Mode: store.Group, MessageID: m.Request.MessageID,
			Conversation: o.Conversation.ID, Contribution: o.Conversation.Contribution, InReplyTo: o.Conversation.InReplyTo,
			CPIM: body, Enqueued: now, Expires: now.Add(e.cfg.StoreTTL),
		}
		sctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
		err = e.enqueue(sctx, q)
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

// submitGroupNotification accepts a notification about a group's message
// on the same terms as submitNotification: the message must be the
// group's, the notifier one of the participants it went to, and the kind
// one its author asked for, once.
func (e *Engine) submitGroupNotification(ctx context.Context, o GroupOrigin, m *Message, now time.Time) error {
	n := m.Notification
	sent, err := e.store.Sent(ctx, o.Group, n.MessageID, now)
	if errors.Is(err, store.ErrNotFound) {
		return reject(ReasonIMDNUnknown, nil)
	}
	if err != nil {
		return err
	}
	switch {
	case sent.Author == "" || !slices.Contains(sent.Recipients, o.Sender):
		return reject(ReasonIMDNForged, nil)
	case !sent.Dispositions.Wants(n.Kind, n.Status):
		return reject(ReasonIMDNNotRequested, nil)
	}
	body, err := groupView(m.CPIM, cpim.Address{URI: o.Sender}, "")
	if err != nil {
		return reject(ReasonIMDNMalformed, err)
	}
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	mark := string(n.Kind) + " " + o.Sender
	err = e.store.MarkNotified(ctx, o.Group, n.MessageID, mark, id, now)
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
		// Taken and dropped, the mark kept: a refusal would not make
		// room, and the reference client ends its session with the group
		// on one (rcsjta GroupChatSession.msrpTransferError).
		e.metrics.Count("group.notification.dropped", 1)
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

// groupComposing passes an is-composing indication to the open sessions
// of the other participants on this task, without storing it, under
// IsComposingRate per sender and group.
func (e *Engine) groupComposing(ctx context.Context, h GroupHandler, o GroupOrigin, m *Message, now time.Time) error {
	if len(o.CPIM) > MaxIsComposingSize || !e.composing.allow(o.Group+"\x00"+o.Sender, now) {
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
		return &msrp.StatusError{Code: StatusTryAgain, Comment: "Try again later"}
	}
	return nil
}
