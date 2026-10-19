package sipua

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// RCS service identifiers in the escaped form feature tags carry them in
// (RFC 3840, TS 24.229 §5.1.1.2.1, RCC.07).
const (
	ICSIChat            = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"
	ICSIStandalone      = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"
	ICSIStandaloneLarge = "urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg"
	IARIFileTransfer    = "urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp"
)

// chatService is the 1-to-1 chat ICSI unescaped, as P-Preferred-Service
// carries it (RFC 6050).
const chatService = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session"

// ErrDialogEnded refuses a request in a dialog that a BYE has ended.
var ErrDialogEnded = errors.New("sipua: the dialog has ended")

// NewInvite returns an INVITE for a 1-to-1 chat with target (RCC.07, TS
// 24.229 §5.1.2A.1): NewRequest's fields, a Contact with the chat ICSI and
// "ob", so that the dialog's requests come back over this flow (RFC 5626
// §4.3), the same ICSI in Accept-Contact and P-Preferred-Service, and offer
// as the SDP body.
func (ua *UA) NewInvite(target sip.URI, offer []byte) (*sip.Request, error) {
	req, err := ua.NewRequest("INVITE", target)
	if err != nil {
		return nil, err
	}
	contact := sip.Contact{Address: sip.Address{URI: ua.contact.URI}}
	contact.URI.Params = slices.Clone(ua.contact.URI.Params)
	contact.URI.Params.SetFlag("ob")
	contact.Params.Set("+g.3gpp.icsi-ref", ICSIChat)
	add(req, &err, "Contact", contact.String())
	add(req, &err, "Accept-Contact", `*;+g.3gpp.icsi-ref="`+ICSIChat+`"`)
	add(req, &err, "P-Preferred-Service", chatService)
	add(req, &err, "Allow", "INVITE, ACK, CANCEL, BYE")
	if len(offer) > 0 {
		add(req, &err, "Content-Type", "application/sdp")
		req.Body = slices.Clone(offer)
	}
	if err != nil {
		return nil, err
	}
	return req, nil
}

// Invite sends req, an INVITE from NewInvite, and returns its final
// response and, for a 2xx, the dialog it made, already ACKed (RFC 3261
// §13.2.2.4). Any other final response returns no dialog and no error: a
// 486 or a 480 is an answer a scenario checks. progress, if not nil, gets
// each provisional response, on the connection's reading goroutine, so it
// must not block.
//
// Cancelling ctx sends CANCEL, as soon as a provisional response shows the
// INVITE has arrived (RFC 3261 §9.1), and waits for the INVITE's final
// response, normally 487, which is returned with ctx's error. A 2xx that
// crosses the CANCEL is ACKed and its dialog ended with BYE.
func (ua *UA) Invite(ctx context.Context, req *sip.Request, progress func(*sip.Response)) (*Dialog, *sip.Response, error) {
	if req.Method != "INVITE" {
		return nil, nil, errors.New("sipua: Invite sends INVITE only")
	}
	if err := ua.Err(); err != nil {
		return nil, nil, err
	}
	// At most one final response or error, and the 2xx: room for all, so
	// the handler never waits.
	inv := &invite{ua: ua, req: req, progress: progress, events: make(chan result, 4), provisional: make(chan struct{})}
	tx, err := ua.layer.Request(req, ua.destination(), inv.handle)
	if err != nil {
		return nil, nil, ua.sendError(err)
	}
	cancelled, cancelSent := false, false
	ctxDone, provisional := ctx.Done(), inv.provisional
	for {
		select {
		case <-provisional:
			provisional = nil
			if cancelled && !cancelSent {
				inv.cancel()
				cancelSent = true
			}
		case ev := <-inv.events:
			if ev.err != nil {
				return nil, nil, ua.sendError(ev.err)
			}
			res := ev.res
			d := inv.dialog()
			if !cancelled {
				return d, res, nil
			}
			if d != nil {
				// The 2xx crossed the CANCEL: the call was set up, and is
				// taken down at once.
				_, _ = d.Bye(context.WithoutCancel(ctx))
			}
			return nil, res, ctx.Err()
		case <-ctxDone:
			ctxDone, cancelled = nil, true
			if provisional == nil && !cancelSent {
				inv.cancel()
				cancelSent = true
			}
		case <-ua.done:
			tx.Terminate()
			return nil, nil, ua.Err()
		}
	}
}

// invite is one INVITE's client side, from its sending to the end of its
// transaction's life.
type invite struct {
	ua       *UA
	req      *sip.Request
	progress func(*sip.Response)
	// events carries the final response or the error; provisional is
	// closed at the first provisional response.
	events          chan result
	provisional     chan struct{}
	provisionalOnce sync.Once

	mu sync.Mutex
	// d is the dialog the first 2xx made.
	d *Dialog
}

// handle is the INVITE transaction's response handler. It runs on the
// connection's reading goroutine, so the 2xx is ACKed here, before the
// next message is read: a retransmission then always finds the dialog.
func (inv *invite) handle(res *sip.Response, err error) {
	switch {
	case err == nil && res.StatusCode < 200:
		if inv.progress != nil {
			inv.progress(res)
		}
		inv.provisionalOnce.Do(func() { close(inv.provisional) })
		return
	case err != nil || res.StatusCode >= 300:
		select {
		case inv.events <- result{res, err}:
		default:
		}
		return
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.d != nil {
		inv.ua.ackAgain(inv.d, res)
		return
	}
	d, err := inv.ua.newDialog(inv.req, res)
	if err != nil {
		select {
		case inv.events <- result{nil, err}:
		default:
		}
		return
	}
	inv.d = d
	d.sendACK()
	select {
	case inv.events <- result{res, nil}:
	default:
	}
}

func (inv *invite) dialog() *Dialog {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return inv.d
}

// cancel sends CANCEL for the INVITE (RFC 3261 §9.1): its Request-URI,
// Call-ID, From, To, Route and top Via, branch included, with the CSeq
// number and the method CANCEL. Its answer does not matter: the INVITE's
// final response is what ends the wait.
func (inv *invite) cancel() {
	h := &inv.req.Header
	vias, err := h.Elements("Via")
	if err != nil || len(vias) == 0 {
		return
	}
	cseq, err := h.CSeq()
	if err != nil {
		return
	}
	c := &sip.Request{Method: "CANCEL", URI: inv.req.URI}
	add(c, &err, "Via", vias[0])
	add(c, &err, "Max-Forwards", "70")
	for _, name := range []string{"From", "To", "Call-ID"} {
		add(c, &err, name, h.Get(name))
	}
	add(c, &err, "CSeq", strconv.FormatUint(uint64(cseq.Seq), 10)+" CANCEL")
	for _, r := range h.Values("Route") {
		add(c, &err, "Route", r)
	}
	if err != nil {
		return
	}
	go func() { _, _ = inv.ua.Send(context.Background(), c) }()
}

// Dialog is an INVITE dialog this UA set up (RFC 3261 §12). Its methods are
// safe for concurrent use.
type Dialog struct {
	ua  *UA
	key string
	// local and remote are the From and To of this side's requests, tags
	// included.
	callID        string
	local, remote string
	remoteTarget  sip.URI
	// routes is the route set, the 2xx's Record-Route reversed (§12.1.2).
	routes []string
	answer *sip.Response
	ack    *sip.Request

	mu         sync.Mutex
	cseq       uint32
	remoteCSeq uint32
	ended      bool
	done       chan struct{}
}

// newDialog makes the dialog of a 2xx to invite (RFC 3261 §12.1.2) and
// keeps it, so that the network's requests in it find it.
func (ua *UA) newDialog(invite *sip.Request, res *sip.Response) (*Dialog, error) {
	from, err := invite.Header.From()
	if err != nil {
		return nil, err
	}
	to, err := res.Header.To()
	if err != nil {
		return nil, err
	}
	if to.Tag() == "" {
		return nil, errors.New("sipua: the 2xx to INVITE has no To tag")
	}
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	rr, err := res.Header.RecordRoute()
	if err != nil {
		return nil, errors.New("sipua: Record-Route of the 2xx to INVITE is malformed")
	}
	// The remote target is the 2xx's Contact; one without is answered as
	// the Request-URI, which a UAS that broke RFC 3261 §12.1.1 leaves.
	target := invite.URI
	if cs, err := res.Header.Contact(); err == nil && len(cs) > 0 && !cs[0].Star {
		target = cs[0].URI
	}
	callID := invite.Header.Get("Call-ID")
	d := &Dialog{
		ua:           ua,
		key:          dialogKey(callID, from.Tag(), to.Tag()),
		callID:       callID,
		local:        invite.Header.Get("From"),
		remote:       res.Header.Get("To"),
		remoteTarget: target,
		answer:       res,
		cseq:         cseq.Seq,
		done:         make(chan struct{}),
	}
	// The route set is used as RFC 3261 §12.2.1.1 says for one whose first
	// entry has lr: IMS proxies all route loosely, and strict routing is
	// not supported.
	for _, a := range slices.Backward(rr) {
		d.routes = append(d.routes, a.String())
	}
	if d.ack, err = d.request("ACK", cseq.Seq); err != nil {
		return nil, err
	}
	ua.mu.Lock()
	ua.dialogs[d.key] = d
	ua.mu.Unlock()
	return d, nil
}

func dialogKey(callID, localTag, remoteTag string) string {
	return callID + "\x00" + localTag + "\x00" + remoteTag
}

// dialogOf returns the dialog a request from the network belongs to: its
// To tag is ours, its From tag the other side's.
func (ua *UA) dialogOf(req *sip.Request) *Dialog {
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	if err1 != nil || err2 != nil || to.Tag() == "" {
		return nil
	}
	ua.mu.Lock()
	defer ua.mu.Unlock()
	return ua.dialogs[dialogKey(req.Header.Get("Call-ID"), to.Tag(), from.Tag())]
}

// strayResponse ACKs again a 2xx to an INVITE whose transaction has ended.
func (ua *UA) strayResponse(res *sip.Response) {
	cseq, err := res.Header.CSeq()
	if err != nil || cseq.Method != "INVITE" || res.StatusCode < 200 || res.StatusCode >= 300 {
		return
	}
	from, err1 := res.Header.From()
	to, err2 := res.Header.To()
	if err1 != nil || err2 != nil {
		return
	}
	ua.mu.Lock()
	d := ua.dialogs[dialogKey(res.Header.Get("Call-ID"), from.Tag(), to.Tag())]
	ua.mu.Unlock()
	if d != nil {
		d.sendACK()
	}
}

// ackAgain answers a further 2xx to an INVITE whose dialog is d. The same
// 2xx again means the ACK was lost, so it is sent again. A 2xx with another
// To tag comes from another branch of a fork: it is ACKed and that dialog
// ended at once, since the call is already up (RFC 3261 §13.2.2.4).
func (ua *UA) ackAgain(d *Dialog, res *sip.Response) {
	if res.Header.Get("To") != d.remote {
		other := &Dialog{ua: ua, callID: d.callID, local: d.local, remote: res.Header.Get("To"),
			remoteTarget: d.remoteTarget, cseq: d.cseq, done: make(chan struct{})}
		if cs, err := res.Header.Contact(); err == nil && len(cs) > 0 && !cs[0].Star {
			other.remoteTarget = cs[0].URI
		}
		if rr, err := res.Header.RecordRoute(); err == nil {
			for _, a := range slices.Backward(rr) {
				other.routes = append(other.routes, a.String())
			}
		}
		if ack, err := other.request("ACK", d.cseq); err == nil {
			other.ack = ack
			other.sendACK()
			go func() { _, _ = other.Bye(context.Background()) }()
		}
		return
	}
	d.sendACK()
}

// sendACK sends the 2xx's ACK, straight through the transport: an ACK to a
// 2xx is no transaction (§13.2.2.4). A copy each time, since the transport
// writes its Via. It is not waited for: this may run on the reading
// goroutine.
func (d *Dialog) sendACK() {
	_, _ = d.ua.tr.SendRequest(d.ack.Clone(), d.ua.destination(), transport.NoWait)
}

// request builds a request in the dialog (RFC 3261 §12.2.1.1).
func (d *Dialog) request(method string, cseq uint32) (*sip.Request, error) {
	branch, err := d.ua.ids.Branch()
	if err != nil {
		return nil, err
	}
	req := &sip.Request{Method: method, URI: d.remoteTarget}
	add(req, &err, "Via", "SIP/2.0/"+string(d.ua.cfg.Network)+" "+d.ua.local.String()+";branch="+branch)
	add(req, &err, "Max-Forwards", "70")
	add(req, &err, "From", d.local)
	add(req, &err, "To", d.remote)
	add(req, &err, "Call-ID", d.callID)
	add(req, &err, "CSeq", strconv.FormatUint(uint64(cseq), 10)+" "+method)
	for _, r := range d.routes {
		add(req, &err, "Route", r)
	}
	if err != nil {
		return nil, err
	}
	return req, nil
}

// Answer is the 2xx that made the dialog; its body is the SDP answer.
func (d *Dialog) Answer() *sip.Response { return d.answer }

// Done is closed when the dialog has ended, by a BYE from either side.
func (d *Dialog) Done() <-chan struct{} { return d.done }

// Bye ends the dialog and sends BYE, returning its final response. The
// session is over as BYE goes out, whatever the answer (RFC 3261 §15.1.1).
func (d *Dialog) Bye(ctx context.Context) (*sip.Response, error) {
	d.mu.Lock()
	if d.ended {
		d.mu.Unlock()
		return nil, ErrDialogEnded
	}
	d.cseq++
	bye, err := d.request("BYE", d.cseq)
	d.endLocked()
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return d.ua.Send(ctx, bye)
}

func (d *Dialog) endLocked() {
	if d.ended {
		return
	}
	d.ended = true
	close(d.done)
	d.ua.mu.Lock()
	delete(d.ua.dialogs, d.key)
	d.ua.mu.Unlock()
}

// receive answers a request the network sent in the dialog. A lower CSeq
// than the last one is out of order (500, RFC 3261 §12.2.2). BYE ends the
// dialog (§15.1.2). A re-INVITE is refused with 488: the simulator keeps
// the session it negotiated, and RCS chat needs no other (§14.2). Anything
// else goes to Config.OnRequest, or is answered 501.
func (d *Dialog) receive(tx *transaction.ServerTransaction) {
	req := tx.Request()
	code := 0
	cseq, err := req.Header.CSeq()
	d.mu.Lock()
	switch {
	case err != nil:
		code = 400
	case d.remoteCSeq != 0 && cseq.Seq < d.remoteCSeq:
		code = 500
	default:
		d.remoteCSeq = cseq.Seq
		switch req.Method {
		case "BYE":
			d.endLocked()
			code = 200
		case "INVITE":
			code = 488
		}
	}
	d.mu.Unlock()
	if code == 0 {
		if d.ua.cfg.OnRequest != nil {
			d.ua.cfg.OnRequest(tx)
			return
		}
		code = 501
	}
	// The To tag is the dialog's, already in the request.
	if res, err := sip.NewResponse(req, code, "", ""); err == nil {
		_ = tx.Respond(res)
	}
}
