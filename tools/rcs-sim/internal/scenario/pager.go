package scenario

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// queueLength bounds the messages a SIP client holds unread.
const queueLength = 16

// pagerText is what the pager-message scenario sends.
const pagerText = "rcs-sim pager-mode message"

// errNoSIP fails a SIP scenario that has no client configuration, and
// errNoPeer one with two clients that has no peer.
var (
	errNoSIP  = errors.New("no SIP client configured (-sip-proxy)")
	errNoPeer = errors.New("no SIP peer configured (-sip-peer-impi)")
)

// sipClient is one simulated client in a SIP scenario: its UA and what the
// network sends it.
type sipClient struct {
	ua       *sipua.UA
	self     cpim.Address
	messages chan *sip.Request
}

// newSIPClient dials and registers cfg as self. Every MESSAGE the network
// sends it is answered 200 at once and queued for the scenario, as a
// device's messaging stack accepts a message before the user sees it.
func (r *run) newSIPClient(ctx context.Context, cfg sipua.Config, self cpim.Address) (*sipClient, error) {
	c := &sipClient{self: self, messages: make(chan *sip.Request, queueLength)}
	ids := sip.IDGenerator{Rand: r.cfg.Rand}
	cfg.OnRequest = func(tx *transaction.ServerTransaction) {
		if res := c.answer(tx.Request(), ids); res != nil {
			_ = tx.Respond(res)
		}
	}
	if cfg.Rand == nil {
		cfg.Rand = r.cfg.Rand
	}
	ua, err := sipua.Dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	r.onEnd(func() { ua.Close() })
	c.ua = ua
	if _, err := ua.Register(ctx); err != nil {
		return nil, err
	}
	r.onEnd(func() {
		// Leave no binding behind; a client that failed has none to leave.
		ctx, cancel := context.WithTimeout(context.Background(), r.cfg.StepTimeout)
		defer cancel()
		_, _ = ua.Unregister(ctx)
	})
	return c, nil
}

// answer answers a request outside any dialog sipua knows: a MESSAGE with
// 200, once queued (486 when the queue is full); one with a To tag, in a
// dialog the client does not have, with 481 (RFC 3261 §12.2.2); any other
// with 405 and the Allow it requires (§8.2.1).
func (c *sipClient) answer(req *sip.Request, ids sip.IDGenerator) *sip.Response {
	code := 200
	to, err := req.Header.To()
	switch {
	case err != nil:
		code = 400
	case to.Tag() != "":
		code = 481
	case req.Method != "MESSAGE":
		code = 405
	default:
		select {
		case c.messages <- req:
		default:
			code = 486
		}
	}
	tag, err := ids.Tag()
	if err != nil {
		return nil
	}
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		return nil
	}
	if code == 405 && res.Header.Add("Allow", "MESSAGE") != nil {
		return nil
	}
	return res
}

// next waits for the next MESSAGE the network sends c.
func (c *sipClient) next(ctx context.Context) (*sip.Request, error) {
	select {
	case m := <-c.messages:
		return m, nil
	case <-c.ua.Done():
		return nil, c.ua.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// pagerMessage is the pager-message scenario (#135 AC 5, RCC.07 standalone
// messaging in pager mode): the client sends a MESSAGE with CPIM and an IMDN
// request to the peer's IMPU, the peer receives it on its flow and answers
// 200, and the delivery notification comes back as a MESSAGE carrying
// message/imdn+xml.
func pagerMessage(r *run) error {
	switch {
	case r.cfg.SIP == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoSIP })
	case r.cfg.SIPPeer == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoPeer })
	}
	var a, b *sipClient
	if err := r.step("register", func(ctx context.Context) (map[string]int64, error) {
		var err error
		if a, err = r.newSIPClient(ctx, *r.cfg.SIP, r.cfg.Self); err != nil {
			return nil, sipError(err)
		}
		if b, err = r.newSIPClient(ctx, *r.cfg.SIPPeer, r.cfg.Peer); err != nil {
			return nil, fmt.Errorf("peer: %w", sipError(err))
		}
		return nil, nil
	}); err != nil {
		return err
	}
	var id string
	if err := r.step("message", func(ctx context.Context) (map[string]int64, error) {
		body, msgID, err := r.pagerBody(a.self, b.self)
		if err != nil {
			return nil, err
		}
		id = msgID
		req, err := a.ua.NewMessage(r.cfg.SIPPeer.IMPU, cpim.ContentType, body)
		if err != nil {
			return nil, err
		}
		res, err := a.ua.Send(ctx, req)
		if err != nil {
			return nil, sipError(err)
		}
		detail := map[string]int64{"status": int64(res.StatusCode), "bytes": int64(len(body))}
		if res.StatusCode != 200 && res.StatusCode != 202 {
			return detail, fmt.Errorf("MESSAGE answered %d", res.StatusCode)
		}
		return detail, nil
	}); err != nil {
		return err
	}
	var request imdn.Request
	var from cpim.Address
	var sender sip.URI
	if err := r.step("receive", func(ctx context.Context) (map[string]int64, error) {
		m, err := b.next(ctx)
		if err != nil {
			return nil, sipError(err)
		}
		f, err := m.Header.From()
		if err != nil {
			return nil, errors.New("the message has no From")
		}
		sender = f.URI
		c, err := readCPIM(m)
		if err != nil {
			return nil, err
		}
		if request, err = imdn.ParseRequest(c); err != nil {
			return nil, errors.New("the message carries no IMDN request")
		}
		from, _ = c.From()
		switch {
		case request.MessageID != id:
			return nil, errors.New("the message received is not the one sent")
		case string(c.Body) != pagerText:
			return nil, errors.New("the message's text changed on the way")
		case !request.Dispositions.Wants(imdn.DeliveryNotification, imdn.Delivered):
			return nil, errors.New("the delivery notification request was lost")
		}
		return map[string]int64{"bytes": int64(len(m.Body))}, nil
	}); err != nil {
		return err
	}
	return r.step("delivery-notification", func(ctx context.Context) (map[string]int64, error) {
		n, err := request.Notification(imdn.DeliveryNotification, imdn.Delivered, b.self.URI)
		if err != nil {
			return nil, err
		}
		nid, err := imdn.NewMessageID(r.cfg.Rand)
		if err != nil {
			return nil, err
		}
		cm, err := n.Message(imdn.Envelope{From: b.self, To: from, Route: request.RecordRoute, MessageID: nid, DateTime: time.Now()})
		if err != nil {
			return nil, err
		}
		body, err := cm.Marshal()
		if err != nil {
			return nil, err
		}
		// In pager mode the notification is a MESSAGE of its own (RFC 5438
		// §12.1.3.1), to the SIP From of the message, and its CPIM To is the
		// message's IMDN-Record-Route or else its CPIM From (§7.2.1).
		req, err := b.ua.NewMessage(sender, cpim.ContentType, body)
		if err != nil {
			return nil, err
		}
		res, err := b.ua.Send(ctx, req)
		if err != nil {
			return nil, sipError(err)
		}
		if res.StatusCode != 200 && res.StatusCode != 202 {
			return map[string]int64{"status": int64(res.StatusCode)}, fmt.Errorf("the notification's MESSAGE answered %d", res.StatusCode)
		}
		got, err := a.next(ctx)
		if err != nil {
			return nil, sipError(err)
		}
		c, err := readCPIM(got)
		if err != nil {
			return nil, err
		}
		if !imdn.IsNotification(c) {
			return nil, errors.New("the sender received something other than a notification")
		}
		back, err := imdn.ParseNotificationMessage(c)
		switch {
		case err != nil:
			return nil, errors.New("the notification does not parse")
		case back.MessageID != id || back.Kind != imdn.DeliveryNotification || back.Status != imdn.Delivered:
			return nil, errors.New("the notification is not the delivery of the message sent")
		}
		return map[string]int64{"bytes": int64(len(got.Body))}, nil
	})
}

// pagerBody is the CPIM message from self to peer with a delivery
// notification request (RFC 5438 §6.3), and its IMDN Message-ID.
func (r *run) pagerBody(self, peer cpim.Address) ([]byte, string, error) {
	m := &cpim.Message{}
	for _, h := range [][2]string{
		{cpim.HeaderFrom, self.String()},
		{cpim.HeaderTo, peer.String()},
		{cpim.HeaderDateTime, cpim.FormatDateTime(time.Now())},
	} {
		if err := m.Add(cpim.CoreNamespace, h[0], h[1]); err != nil {
			return nil, "", err
		}
	}
	id, err := imdn.NewMessageID(r.cfg.Rand)
	if err != nil {
		return nil, "", err
	}
	if err := imdn.AddRequest(m, id, imdn.PositiveDelivery); err != nil {
		return nil, "", err
	}
	m.ContentHeaders = []cpim.Field{{Name: "Content-Type", Value: "text/plain;charset=utf-8"}}
	m.Body = []byte(pagerText)
	body, err := m.Marshal()
	return body, id, err
}

// readCPIM reads a MESSAGE's CPIM body. RCS standalone messages are always
// CPIM (RCC.07).
func readCPIM(m *sip.Request) (*cpim.Message, error) {
	ct, err := m.Header.ContentType()
	if err != nil || ct.Type+"/"+ct.Subtype != cpim.ContentType {
		return nil, errors.New("the MESSAGE is not message/cpim")
	}
	c, err := cpim.Parse(m.Body)
	if err != nil {
		return nil, errors.New("the MESSAGE's CPIM does not parse")
	}
	return c, nil
}

// sipError reduces a SIP client error for a result line: sipua's own are
// fixed strings already, network ones lose their addresses.
func sipError(err error) error { return safeerr.Reason(err) }
