package sipua

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// ErrCallEnded refuses an answer to an incoming INVITE that has had its
// final response already: the UA's own, or the 487 after a CANCEL.
var ErrCallEnded = errors.New("sipua: the incoming INVITE has been answered")

// IncomingCall is an INVITE the network sent this UA, the called party, that
// is not yet answered (RFC 3261 §13.3). Config.OnInvite receives it; Ring,
// Accept and Reject answer it, from any goroutine. Its methods are safe for
// concurrent use.
type IncomingCall struct {
	ua  *UA
	tx  *transaction.ServerTransaction
	req *sip.Request
	// tag is this side's To tag, the same in every response (§12.1.1).
	tag string

	mu        sync.Mutex
	final     bool
	cancelled chan struct{}
}

// Request is the INVITE; its body is the SDP offer.
func (c *IncomingCall) Request() *sip.Request { return c.req }

// Cancelled is closed when a CANCEL ended the call before it was answered:
// the INVITE has then been answered 487 (§9.2).
func (c *IncomingCall) Cancelled() <-chan struct{} { return c.cancelled }

// Ring answers 180 Ringing.
func (c *IncomingCall) Ring() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final {
		return ErrCallEnded
	}
	res, err := c.response(180, nil)
	if err != nil {
		return err
	}
	return c.tx.Respond(res)
}

// Reject answers code, a 3xx to 6xx: 486 Busy Here, 480, 603 Decline.
func (c *IncomingCall) Reject(code int) error {
	if code < 300 || code > 699 {
		return errors.New("sipua: a rejection is a 3xx to 6xx")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final {
		return ErrCallEnded
	}
	c.final = true
	c.ua.forgetCall(c.tx)
	res, err := sip.NewResponse(c.req, code, "", c.tag)
	if err != nil {
		return err
	}
	return c.tx.Respond(res)
}

// Accept answers 200 with answer as the SDP body and returns the dialog.
// The 200 is sent again, at T1 then doubling up to T2, until its ACK comes
// (§13.3.1.4); Dialog.Confirmed is closed then. Without an ACK in 64*T1 the
// dialog is ended with BYE.
func (c *IncomingCall) Accept(answer []byte) (*Dialog, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final {
		return nil, ErrCallEnded
	}
	res, err := c.response(200, answer)
	if err != nil {
		return nil, err
	}
	d, err := c.ua.newUASDialog(c.req, res)
	if err != nil {
		return nil, err
	}
	c.final = true
	c.ua.forgetCall(c.tx)
	if err := c.tx.Respond(res); err != nil {
		d.mu.Lock()
		d.endLocked()
		d.mu.Unlock()
		return nil, err
	}
	d.retransmit(c.tx, res)
	return d, nil
}

// response builds a response that sets up the dialog: the To tag, the
// Record-Route of the request (§12.1.1), and for a 2xx this UA's Contact
// with the chat ICSI and the SDP answer.
func (c *IncomingCall) response(code int, answer []byte) (*sip.Response, error) {
	res, err := sip.NewResponse(c.req, code, "", c.tag)
	if err != nil {
		return nil, err
	}
	for _, rr := range c.req.Header.Values("Record-Route") {
		if err := res.Header.Add("Record-Route", rr); err != nil {
			return nil, err
		}
	}
	if code >= 200 {
		contact := sip.Contact{Address: sip.Address{URI: c.ua.contact.URI}}
		contact.URI.Params = slices.Clone(c.ua.contact.URI.Params)
		contact.URI.Params.SetFlag("ob")
		contact.Params.Set("+g.3gpp.icsi-ref", ICSIChat)
		if err := res.Header.Add("Contact", contact.String()); err != nil {
			return nil, err
		}
		if len(answer) > 0 {
			if err := res.Header.Add("Content-Type", "application/sdp"); err != nil {
				return nil, err
			}
			res.Body = slices.Clone(answer)
		}
	}
	return res, nil
}

// incoming hands an INVITE outside any dialog to Config.OnInvite.
func (ua *UA) incoming(tx *transaction.ServerTransaction) {
	tag, err := ua.ids.Tag()
	if err != nil {
		return
	}
	c := &IncomingCall{ua: ua, tx: tx, req: tx.Request(), tag: tag, cancelled: make(chan struct{})}
	ua.mu.Lock()
	ua.calls[tx] = c
	ua.mu.Unlock()
	ua.cfg.OnInvite(c)
}

func (ua *UA) forgetCall(tx *transaction.ServerTransaction) {
	ua.mu.Lock()
	delete(ua.calls, tx)
	ua.mu.Unlock()
}

// cancel answers a CANCEL (§9.2): 200, and 487 to the INVITE it names if
// that has no final response yet. A CANCEL that names no INVITE gets 481.
func (ua *UA) cancel(tx *transaction.ServerTransaction) {
	code := 481
	var c *IncomingCall
	if inv, ok := ua.layer.InviteFor(tx.Request()); ok {
		code = 200
		ua.mu.Lock()
		c = ua.calls[inv]
		ua.mu.Unlock()
	}
	if tag, err := ua.ids.Tag(); err == nil {
		if res, err := sip.NewResponse(tx.Request(), code, "", tag); err == nil {
			_ = tx.Respond(res)
		}
	}
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final {
		return
	}
	c.final = true
	ua.forgetCall(c.tx)
	if res, err := sip.NewResponse(c.req, 487, "", c.tag); err == nil {
		_ = c.tx.Respond(res)
	}
	close(c.cancelled)
}

// newUASDialog makes the called party's dialog of invite and its 2xx res
// (§12.1.1): the route set is the request's Record-Route in order, the
// remote target its Contact.
func (ua *UA) newUASDialog(invite *sip.Request, res *sip.Response) (*Dialog, error) {
	from, err := invite.Header.From()
	if err != nil {
		return nil, err
	}
	to, err := res.Header.To()
	if err != nil {
		return nil, err
	}
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	rr, err := invite.Header.RecordRoute()
	if err != nil {
		return nil, errors.New("sipua: Record-Route of the INVITE is malformed")
	}
	target := from.URI
	if cs, err := invite.Header.Contact(); err == nil && len(cs) > 0 && !cs[0].Star {
		target = cs[0].URI
	}
	callID := invite.Header.Get("Call-ID")
	d := &Dialog{
		ua:           ua,
		key:          dialogKey(callID, to.Tag(), from.Tag()),
		callID:       callID,
		local:        res.Header.Get("To"),
		remote:       invite.Header.Get("From"),
		remoteTarget: target,
		answer:       res,
		remoteCSeq:   cseq.Seq,
		done:         make(chan struct{}),
		confirmed:    make(chan struct{}),
	}
	for _, a := range rr {
		d.routes = append(d.routes, a.String())
	}
	ua.mu.Lock()
	ua.dialogs[d.key] = d
	ua.mu.Unlock()
	return d, nil
}

// retransmit sends the 2xx again until its ACK comes, at T1 doubling up to
// T2, and ends the dialog with BYE if none has come after 64*T1 (RFC 3261
// §13.3.1.4). It runs on Config.Clock.
func (d *Dialog) retransmit(tx *transaction.ServerTransaction, res *sip.Response) {
	clock := d.ua.cfg.Clock
	interval, waited := transaction.DefaultT1, time.Duration(0)
	var again func()
	again = func() {
		select {
		case <-d.confirmed:
			return
		case <-d.done:
			return
		default:
		}
		waited += interval
		if waited >= 64*transaction.DefaultT1 {
			go func() { _, _ = d.Bye(context.Background()) }()
			return
		}
		_ = tx.Respond(res)
		interval = min(2*interval, transaction.DefaultT2)
		d.mu.Lock()
		d.retransmitTimer = clock.AfterFunc(interval, again)
		d.mu.Unlock()
	}
	d.mu.Lock()
	d.retransmitTimer = clock.AfterFunc(interval, again)
	d.mu.Unlock()
}

// confirm takes the ACK of the dialog's 2xx (§13.3.1.4).
func (d *Dialog) confirm() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.confirmed == nil {
		return
	}
	select {
	case <-d.confirmed:
	default:
		close(d.confirmed)
		if d.retransmitTimer != nil {
			d.retransmitTimer.Stop()
		}
	}
}
