package scenario

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// pagerText is what the pager-message scenario sends, followed by a token
// of the run, which tells its messages from those an earlier run left in
// the network.
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

// await waits for the MESSAGE whose CPIM message has the IMDN Message-ID
// id, and returns it with its CPIM and how many it skipped. A store-and-
// forward network may first deliver what an earlier run left: a CPIM
// message with another Message-ID that does not carry token cannot be this
// run's, so it is skipped. Anything else is returned for the step to judge:
// one that is not CPIM, or this run's (token) with another Message-ID.
func (c *sipClient) await(ctx context.Context, id, token string) (*sip.Request, *cpim.Message, int, error) {
	for skipped := 0; ; skipped++ {
		m, err := c.next(ctx)
		if err != nil {
			return nil, nil, skipped, err
		}
		cm, err := readCPIM(m)
		if err != nil {
			return m, nil, skipped, err
		}
		h, _ := cm.Get(imdn.Namespace, imdn.HeaderMessageID)
		if h.Value == id || (token != "" && strings.Contains(string(cm.Body), token)) {
			return m, cm, skipped, nil
		}
	}
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
	token, err := imdn.NewMessageID(r.cfg.Rand)
	if err != nil {
		return err
	}
	text := pagerText + " " + token
	var id string
	if err := r.step("message", func(ctx context.Context) (map[string]int64, error) {
		body, msgID, err := r.pagerBody(a.self, b.self, text)
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
		m, c, skipped, err := b.await(ctx, id, token)
		if err != nil {
			return nil, sipError(err)
		}
		detail := map[string]int64{"bytes": int64(len(m.Body)), "skipped": int64(skipped)}
		f, err := m.Header.From()
		if err != nil {
			return detail, errors.New("the message has no From")
		}
		sender = f.URI
		if request, err = imdn.ParseRequest(c); err != nil {
			return detail, errors.New("the message carries no IMDN request")
		}
		from, _ = c.From()
		switch {
		case request.MessageID != id:
			return detail, errors.New("the message received is not the one sent")
		case string(c.Body) != text:
			return detail, errors.New("the message's text changed on the way")
		case !request.Dispositions.Wants(imdn.DeliveryNotification, imdn.Delivered):
			return detail, errors.New("the delivery notification request was lost")
		}
		return detail, nil
	}); err != nil {
		return err
	}
	if err := r.step("delivery-notification", func(ctx context.Context) (map[string]int64, error) {
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
		// The notification is told by its own Message-ID, which no
		// earlier run's can have.
		got, c, skipped, err := a.await(ctx, nid, "")
		if err != nil {
			return nil, sipError(err)
		}
		detail := map[string]int64{"bytes": int64(len(got.Body)), "skipped": int64(skipped)}
		if !imdn.IsNotification(c) {
			return detail, errors.New("the sender received something other than a notification")
		}
		back, err := imdn.ParseNotificationMessage(c)
		switch {
		case err != nil:
			return detail, errors.New("the notification does not parse")
		case back.MessageID != id || back.Kind != imdn.DeliveryNotification || back.Status != imdn.Delivered:
			return detail, errors.New("the notification is not the delivery of the message sent")
		}
		return detail, nil
	}); err != nil {
		return err
	}
	return r.step("peer-offline", func(ctx context.Context) (map[string]int64, error) {
		// #135 AC 5: B is not registered. Today the platform answers 480
		// (TS 24.229 §5.4.3.3): pager mode has no store-and-forward yet,
		// which comes with rcs-as's SIP side. A network that stores the
		// message instead (200 or 202) passes only if it delivers it once
		// B registers again; one that accepts it and drops it fails.
		if _, err := b.ua.Unregister(ctx); err != nil {
			return nil, fmt.Errorf("peer: %w", sipError(err))
		}
		body, msgID, err := r.pagerBody(a.self, b.self, text)
		if err != nil {
			return nil, err
		}
		req, err := a.ua.NewMessage(r.cfg.SIPPeer.IMPU, cpim.ContentType, body)
		if err != nil {
			return nil, err
		}
		res, err := a.ua.Send(ctx, req)
		if err != nil {
			return nil, sipError(err)
		}
		detail := map[string]int64{"status": int64(res.StatusCode)}
		switch res.StatusCode {
		case 480:
			return detail, nil
		case 200, 202:
		default:
			return detail, fmt.Errorf("MESSAGE to the unregistered peer answered %d, want 480 or store-and-forward", res.StatusCode)
		}
		if _, err := b.ua.Register(ctx); err != nil {
			return detail, fmt.Errorf("peer: %w", sipError(err))
		}
		_, c, skipped, err := b.await(ctx, msgID, "")
		detail["skipped"] = int64(skipped)
		if err != nil {
			return detail, fmt.Errorf("MESSAGE to the unregistered peer answered %d, and it never arrived after the peer registered again", res.StatusCode)
		}
		if got, err := imdn.ParseRequest(c); err != nil || got.MessageID != msgID || string(c.Body) != text {
			return detail, errors.New("the stored message changed on the way")
		}
		detail["stored"] = 1
		return detail, nil
	})
}

// pagerBody is the CPIM message from self to peer with text and a delivery
// notification request (RFC 5438 §6.3), and its IMDN Message-ID.
func (r *run) pagerBody(self, peer cpim.Address, text string) ([]byte, string, error) {
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
	m.Body = []byte(text)
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
