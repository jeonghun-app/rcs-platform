package messaging

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// disposition is what a notification reports.
type disposition struct {
	kind   imdn.Kind
	status imdn.Status
}

var failedDelivery = disposition{imdn.DeliveryNotification, imdn.Failed}

// submitNotification accepts a disposition notification only if it answers
// a message its recipient (o.Recipient) sent to its sender (o.Sender), or
// comes from an allowed intermediary, and reports something that message
// asked for, once per notifier and kind. Without that check anyone could
// tell a sender that its message was read or failed (threat model T10;
// RFC 5438 §6.3 makes the Message-ID unguessable for the same reason).
//
// Who sent the notification is o.Sender, the identity the network asserted;
// the CPIM From has already been checked against it, or is the anonymous
// URI clients use in 1-to-1 chat.
func (e *Engine) submitNotification(ctx context.Context, o Origin, m *Message, now time.Time) error {
	n := m.Notification
	sent, err := e.store.Sent(ctx, o.Recipient, n.MessageID, now)
	if errors.Is(err, store.ErrNotFound) {
		return reject(ReasonIMDNUnknown, nil)
	}
	if err != nil {
		return err
	}
	if sent.Group != "" {
		// About a group message: matched and marked in the group.
		g := GroupOrigin{Group: sent.Group, Sender: o.Sender, Identities: o.Identities, Conversation: o.Conversation, CPIM: o.CPIM}
		return e.submitGroupNotification(ctx, nil, g, m, o.Recipient, now)
	}
	switch {
	case slices.Contains(sent.Recipients, o.Sender):
	case slices.Contains(e.cfg.Intermediaries, o.Sender) && intermediaryMay(n.Kind, n.Status):
	default:
		return reject(ReasonIMDNForged, nil)
	}
	if !sent.Dispositions.Wants(n.Kind, n.Status) {
		return reject(ReasonIMDNNotRequested, nil)
	}
	body, err := e.dropOwnRoute(m)
	if err != nil {
		return reject(ReasonIMDNMalformed, err)
	}
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	mark := string(n.Kind) + " " + o.Sender
	err = e.store.MarkNotified(ctx, o.Recipient, n.MessageID, mark, string(n.Status), id, now)
	switch {
	case errors.Is(err, store.ErrExists):
		e.metrics.Count("imdn.duplicate", 1)
		return nil
	case errors.Is(err, store.ErrNotFound):
		return reject(ReasonIMDNUnknown, nil)
	case err != nil:
		return err
	}
	err = e.enqueue(ctx, queued(o, id, body, true, "", now, e.cfg.StoreTTL))
	if err != nil {
		// Let the client's retry through: what the mark stood for did
		// not happen.
		rctx, cancel := e.recordCtx()
		_ = e.store.UnmarkNotified(rctx, o.Recipient, n.MessageID, mark, id)
		cancel()
		switch {
		case errors.Is(err, store.ErrQueueFull):
			return reject(ReasonQueueFull, nil)
		case errors.Is(err, store.ErrSenderShareFull):
			return reject(ReasonQueueShareFull, nil)
		}
	}
	return err
}

// intermediaryMay reports whether an intermediary may send a notification
// of kind k and status s. RFC 5438 §8.2 lets it send processing
// notifications and say that delivery failed; only the recipient can say a
// message was delivered or displayed.
func intermediaryMay(k imdn.Kind, s imdn.Status) bool {
	return k == imdn.ProcessingNotification || k == imdn.DeliveryNotification && s != imdn.Delivered
}

// dropOwnRoute removes the top IMDN-Route of a notification when it names
// rcs-as (RFC 5438 §8): the notification has reached that hop. It returns
// the body to forward, which is the original unless an entry was removed.
func (e *Engine) dropOwnRoute(m *Message) ([]byte, error) {
	routes := m.CPIM.All(imdn.Namespace, imdn.HeaderRoute)
	if len(routes) == 0 {
		return m.Raw, nil
	}
	a, err := cpim.ParseAddress(routes[0].Value)
	if err != nil || !slices.Contains(e.cfg.Self, a.URI) {
		return m.Raw, err
	}
	i := slices.Index(m.CPIM.Headers, routes[0])
	m.CPIM.Headers = slices.Delete(m.CPIM.Headers, i, i+1)
	return m.CPIM.Marshal()
}

// nextRoute is the URI a stored notification is sent through: its top
// IMDN-Route, if that is one of TrustedRoutes and not rcs-as itself. A client
// writes these headers, so anything else would let it pick where rcs-as
// sends a request from inside the network.
func (e *Engine) nextRoute(body []byte) string {
	c, err := e.parseCPIM(body)
	if err != nil {
		return ""
	}
	h, ok := c.Get(imdn.Namespace, imdn.HeaderRoute)
	if !ok {
		return ""
	}
	a, err := cpim.ParseAddress(h.Value)
	if err != nil || slices.Contains(e.cfg.Self, a.URI) {
		return ""
	}
	if !e.trusted(a.URI) {
		e.metrics.Count("imdn.route_untrusted", 1)
		return ""
	}
	return a.URI
}

// trusted reports whether uri is one of TrustedRoutes, exactly. Reading a
// host out of a client's URI would have to agree with every SIP parser the
// request later meets on where the user part ends, which parameters
// redirect it (maddr) and what its headers add (?Route=); comparing whole
// URIs leaves nothing to interpret.
func (e *Engine) trusted(uri string) bool {
	return slices.Contains(e.cfg.TrustedRoutes, uri)
}

// Report generates the notification the recipient of d reported in a way
// other than an IMDN of its own, for example a network that confirms
// delivery of a pager-mode MESSAGE, and queues it for d.Sender. It returns
// imdn.ErrNotRequested when the sender did not ask for it.
func (e *Engine) Report(ctx context.Context, d Delivery, k imdn.Kind, s imdn.Status) error {
	if d.Notification {
		return imdn.ErrNotRequested
	}
	now := e.clock.Now()
	id, err := e.newID(now)
	if err != nil {
		return err
	}
	q := store.Message{
		Recipient: d.Recipient, Sender: d.Sender, Mode: d.Mode, CPIM: d.CPIM,
		Conversation: d.Conversation.ID, Contribution: d.Conversation.Contribution, InReplyTo: d.Conversation.InReplyTo,
	}
	n, err := e.notification(q, disposition{k, s}, id, now)
	if err != nil {
		return err
	}
	ctx, cancel := e.withTimeout(ctx, e.cfg.StoreTimeout)
	defer cancel()
	return e.enqueueNotification(ctx, n, s)
}

// notification builds the notification d about m, sent on behalf of
// m.Recipient, as a queue item for m.Sender with the given ID. It returns
// imdn.ErrNotRequested when the sender did not ask for it, which includes
// a message that asked without the Message-ID and DateTime to answer with.
//
// A notification generated by the network is from the recipient: that is
// the conversation a client files it under (an assumption docs/rcs-as.md
// records). IMDN-Route is copied from IMDN-Record-Route, as RFC 5438
// §7.2.1 has a recipient do, keeping only TrustedRoutes.
func (e *Engine) notification(m store.Message, d disposition, id string, now time.Time) (store.Message, error) {
	c, err := e.parseCPIM(m.CPIM)
	if err != nil {
		return store.Message{}, err
	}
	req, err := imdn.ParseRequest(c)
	if errors.Is(err, imdn.ErrIncompleteRequest) {
		return store.Message{}, imdn.ErrNotRequested
	}
	if err != nil {
		return store.Message{}, err
	}
	n, err := req.Notification(d.kind, d.status, m.Recipient)
	if err != nil {
		return store.Message{}, err
	}
	var route []cpim.Address
	for _, a := range req.RecordRoute {
		if e.trusted(a.URI) {
			route = append(route, a)
		} else {
			e.metrics.Count("imdn.route_dropped", 1)
		}
	}
	mid, err := imdn.NewMessageID(e.rand)
	if err != nil {
		return store.Message{}, err
	}
	// It goes to whoever wrote m, from m's recipient. In a group that is
	// m's author, in the author's session with the group.
	to, sender, author := m.Sender, m.Recipient, ""
	if m.Mode == store.Group {
		to, sender, author = m.Author, m.Sender, m.Recipient
	}
	out, err := n.Message(imdn.Envelope{
		From: cpim.Address{URI: m.Recipient}, To: cpim.Address{URI: to},
		Route: route, MessageID: mid, DateTime: now,
	})
	if err != nil {
		return store.Message{}, err
	}
	body, err := out.Marshal()
	if err != nil {
		return store.Message{}, err
	}
	return store.Message{
		Recipient: to, ID: id, Sender: sender, Author: author,
		Conversation: m.Conversation, Contribution: m.Contribution, InReplyTo: m.InReplyTo,
		Mode: m.Mode, Notification: true, CPIM: body, Enqueued: now, Expires: now.Add(e.cfg.StoreTTL),
	}, nil
}

// enqueueNotification queues n, which notification built. ErrExists means
// an earlier attempt already did. A full queue drops it: the sender has
// more waiting than it can take, and a notification is not worth refusing
// anything for.
func (e *Engine) enqueueNotification(ctx context.Context, n store.Message, s imdn.Status) error {
	err := e.store.Enqueue(ctx, n, e.limit)
	switch {
	case errors.Is(err, store.ErrQueueFull), errors.Is(err, store.ErrSenderShareFull):
		e.metrics.Count("imdn.dropped.queue_full", 1)
		return nil
	case err != nil && !errors.Is(err, store.ErrExists):
		return err
	}
	e.metrics.Count("imdn.generated."+string(s), 1)
	if err == nil {
		e.kickNew(n)
	}
	return nil
}
