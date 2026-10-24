package bridge

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// maxMessageIDLength is the longest IMDN Message-ID rcs-as takes
// (docs/rcs-as.md, The pipeline).
const maxMessageIDLength = 128

// defaultContentType is a message's when the application names none.
const defaultContentType = "text/plain;charset=utf-8"

// recentLength bounds the received messages an endpoint remembers, for a
// display notification the application may send about one.
const recentLength = 1024

// outgoing is a message the application sends.
type outgoing struct {
	target      sip.URI
	contentType string
	body        string
	messageID   string
	asked       imdn.Disposition
}

// cpimMessage is m as the CPIM body of a pager-mode MESSAGE (RCC.07,
// RFC 3862) from e: From, To and DateTime, the IMDN Message-ID always, and
// the notifications asked for (RFC 5438 §6.3, §7.1.1).
func (e *endpoint) cpimMessage(m outgoing) ([]byte, error) {
	c := &cpim.Message{}
	for _, h := range [][2]string{
		{cpim.HeaderFrom, e.self.String()},
		{cpim.HeaderTo, cpim.Address{URI: m.target.String()}.String()},
		{cpim.HeaderDateTime, cpim.FormatDateTime(e.b.cfg.Now())},
	} {
		if err := c.Add(cpim.CoreNamespace, h[0], h[1]); err != nil {
			return nil, err
		}
	}
	var err error
	if m.asked != 0 {
		err = imdn.AddRequest(c, m.messageID, m.asked)
	} else if err = c.Declare(imdn.Prefix, imdn.Namespace); err == nil {
		// RCC.07 standalone messages carry a Message-ID whether or not
		// they ask for a notification.
		err = c.Add(imdn.Namespace, imdn.HeaderMessageID, m.messageID)
	}
	if err != nil {
		return nil, err
	}
	c.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: m.contentType}}
	c.Body = content.BodyOf([]byte(m.body))
	return c.Marshal()
}

// validContentType reports whether v is a media type that can stand in a
// CPIM Content-Type field.
func validContentType(v string) bool {
	if strings.ContainsAny(v, "\r\n") {
		return false
	}
	_, _, err := mime.ParseMediaType(v)
	return err == nil
}

// validMessageID reports whether id can be an IMDN Message-ID.
func validMessageID(id string) bool {
	return id != "" && len(id) <= maxMessageIDLength && cpim.IsToken(id)
}

// inbound is a MESSAGE the endpoint has accepted, for its worker.
type inbound struct {
	from sip.URI
	line Line
	msg  *cpim.Message
	// notification is set for an IMDN, request for a message.
	notification *imdn.Notification
	request      imdn.Request
	at           time.Time
}

// receive takes a MESSAGE on the line's reading goroutine: it checks and
// parses it, queues it for the worker and returns the status to answer
// with. 200 says the endpoint has it; a message the endpoint cannot read is
// refused, as a device refuses it, so that the network does not take it
// for delivered.
func (e *endpoint) receive(in Incoming) int {
	if in.ContentType != cpim.ContentType {
		return 415
	}
	m, err := cpim.Parse(in.Body)
	if err != nil {
		return 400
	}
	ib := inbound{from: in.From, line: in.Line, msg: m, at: e.b.cfg.Now()}
	if imdn.IsNotification(m) {
		n, err := imdn.ParseNotificationMessage(m)
		if err != nil {
			return 400
		}
		ib.notification = &n
	} else if ib.request, err = imdn.ParseRequest(m); err != nil {
		return 400
	}
	select {
	case e.inbox <- ib:
		return 200
	default:
		// RFC 3261 §21.4.7: busy now; rcs-as tries again later.
		return 486
	}
}

// work turns what the endpoint received into events, in the order it came,
// and sends the delivery notifications messages asked for.
func (e *endpoint) work() {
	for {
		select {
		case ib := <-e.inbox:
			e.handle(ib)
		case <-e.done:
			return
		}
	}
}

func (e *endpoint) handle(ib inbound) {
	from := e.b.nameOf(ib.from)
	if n := ib.notification; n != nil {
		e.b.hub.publish(imdnEvent{Type: "imdn", Endpoint: e.name, FromEndpoint: from, MessageID: n.MessageID, Status: string(n.Status)})
		return
	}
	at := ib.at
	if t, err := ib.msg.DateTime(); err == nil {
		at = t
	}
	if ib.request.MessageID != "" {
		e.received.put(ib.request.MessageID, received{from: ib.from, msg: ib.msg, request: ib.request})
	}
	e.b.hub.publish(messageEvent{
		Type: "message", Endpoint: e.name, From: ib.from.String(), FromEndpoint: from,
		MessageID: ib.request.MessageID, ContentType: ib.msg.ContentType(),
		Body: string(ib.msg.Body.Bytes()), At: at.UTC().Format(time.RFC3339Nano),
	})
	// The bridge is the device: it says the message was delivered once it
	// is on its way to the application (RFC 5438 §5.1).
	if ib.request.Dispositions.Wants(imdn.DeliveryNotification, imdn.Delivered) {
		ctx, cancel := e.b.opContext()
		defer cancel()
		status, err := e.notify(ctx, ib.line, received{from: ib.from, msg: ib.msg, request: ib.request}, imdn.DeliveryNotification, imdn.Delivered)
		switch {
		case err != nil:
			e.b.log.Warn("delivery notification not sent", pii.Identity("endpoint", e.name), slog.String("reason", safeerr.Reason(err).Error()))
		case status >= 300:
			e.b.log.Warn("delivery notification refused", pii.Identity("endpoint", e.name), slog.Int("sip_status", status))
		}
	}
}

// received is what a notification about a received message needs.
type received struct {
	from    sip.URI
	msg     *cpim.Message
	request imdn.Request
}

// errOffline is a send while the endpoint has no registered flow.
var errOffline = errors.New("bridge: the endpoint is not registered")

// notify sends the notification of kind k and status s about r on line,
// as a MESSAGE of its own (RFC 5438 §12.1.3.1) to the message's SIP From.
// Its CPIM To is the message's IMDN-Record-Route, or else its CPIM From
// (§7.2.1), as rcs-sim's pager scenario sends it. A nil line is the
// endpoint's current one.
func (e *endpoint) notify(ctx context.Context, line Line, r received, k imdn.Kind, s imdn.Status) (int, error) {
	if line == nil {
		line = e.currentLine()
	}
	if line == nil {
		return 0, errOffline
	}
	n, err := r.request.Notification(k, s, e.self.URI)
	if err != nil {
		return 0, err
	}
	to, err := r.msg.From()
	if err != nil {
		return 0, err
	}
	id, err := imdn.NewMessageID(e.b.cfg.Rand)
	if err != nil {
		return 0, err
	}
	m, err := n.Message(imdn.Envelope{From: e.self, To: to, Route: r.request.RecordRoute, MessageID: id, DateTime: e.b.cfg.Now()})
	if err != nil {
		return 0, err
	}
	body, err := m.Marshal()
	if err != nil {
		return 0, err
	}
	return line.Send(ctx, r.from, body)
}

// recent holds the last received messages by Message-ID, the oldest
// forgotten first.
type recent struct {
	mu    sync.Mutex
	max   int
	byID  map[string]received
	order []string
}

func newRecent(n int) *recent { return &recent{max: n, byID: map[string]received{}} }

func (r *recent) put(id string, m received) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[id]; !ok {
		r.order = append(r.order, id)
	}
	r.byID[id] = m
	for len(r.order) > r.max {
		delete(r.byID, r.order[0])
		r.order = r.order[1:]
	}
}

func (r *recent) get(id string) (received, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.byID[id]
	return m, ok
}
