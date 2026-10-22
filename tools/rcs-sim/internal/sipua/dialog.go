package sipua

import (
	"context"
	"errors"
	"fmt"
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
	if len(offer) == 0 {
		// An offer in the 2xx would need its answer in the ACK (§13.2.1),
		// which this UA does not send.
		return nil, errors.New("sipua: an INVITE needs an SDP offer")
	}
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
	// TS 24.229 §5.1.2A.1.1: a UE that registers with outbound says so.
	add(req, &err, "Supported", "outbound")
	add(req, &err, "Content-Type", "application/sdp")
	req.Body = slices.Clone(offer)
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
	from, err := req.Header.From()
	if err != nil {
		return nil, nil, err
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return nil, nil, err
	}
	// At most one final response or error, and the 2xx: room for all, so
	// the handler never waits.
	inv := &invite{
		ua: ua, req: req, progress: progress, cseq: cseq.Seq, key: dialogKey(req.Header.Get("Call-ID"), from.Tag(), ""),
		events: make(chan result, 4), provisional: make(chan struct{}), forks: map[string]*Dialog{},
	}
	// Kept for 64*T1 after Invite returns, so that a 2xx arriving as a
	// stray, after the transaction has ended, is still ACKed (§13.2.2.4).
	ua.mu.Lock()
	ua.invites[inv.key] = inv
	ua.mu.Unlock()
	defer ua.cfg.Clock.AfterFunc(64*transaction.DefaultT1, func() {
		ua.mu.Lock()
		delete(ua.invites, inv.key)
		ua.mu.Unlock()
	})
	// Once Invite has returned, nobody holds a dialog a 2xx makes: from
	// then on a 2xx takes the fork route, ACK and BYE, as one after a
	// failure response does. A dialog made just before, by a 2xx that
	// raced the return, is ended too.
	var handed *Dialog
	defer func() {
		inv.mu.Lock()
		inv.final = true
		d := inv.d
		inv.mu.Unlock()
		if d != nil && d != handed {
			ua.byes.Go(func() { _, _ = d.Bye(context.Background()) })
		}
	}()
	tx, err := ua.layer.Request(req, ua.destination(), inv.handle)
	if err != nil {
		return nil, nil, ua.sendError(err)
	}
	var cancelTimer transaction.Timer
	defer func() {
		if cancelTimer != nil {
			cancelTimer.Stop()
		}
	}()
	cancelled := false
	sendCancel := func() {
		inv.cancel()
		// §9.1: without a final response 64*T1 after the CANCEL, the
		// INVITE is given up. The client transaction leaves that to its TU.
		cancelTimer = ua.cfg.Clock.AfterFunc(64*transaction.DefaultT1, tx.Terminate)
	}
	ctxDone, provisional := ctx.Done(), inv.provisional
	for {
		select {
		case <-provisional:
			provisional = nil
			if cancelled && cancelTimer == nil {
				sendCancel()
			}
		case ev := <-inv.events:
			if ev.err != nil {
				if cancelled && errors.Is(ev.err, transaction.ErrTerminated) {
					return nil, nil, fmt.Errorf("sipua: no final response to the INVITE 64*T1 after its CANCEL: %w", ctx.Err())
				}
				return nil, nil, ua.sendError(ev.err)
			}
			res := ev.res
			d := inv.dialog()
			if !cancelled {
				handed = d
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
			if provisional == nil && cancelTimer == nil {
				sendCancel()
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
	// cseq is the INVITE's CSeq number, which every ACK to a 2xx carries
	// (§13.2.2.4); key its Call-ID and From tag.
	cseq uint32
	key  string
	// events carries the final response or the error; provisional is
	// closed at the first provisional response.
	events          chan result
	provisional     chan struct{}
	provisionalOnce sync.Once

	mu sync.Mutex
	// d is the dialog the first 2xx made; forks are the other branches'
	// 2xx, ACKed and ended, by To tag. final is set once the transaction
	// has passed a final response on.
	d     *Dialog
	forks map[string]*Dialog
	final bool
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
		if err == nil {
			inv.mu.Lock()
			inv.final = true
			inv.mu.Unlock()
		}
		select {
		case inv.events <- result{res, err}:
		default:
		}
		return
	}
	inv.ok(res)
}

// ok takes a 2xx to the INVITE, from the transaction or as a stray after
// it (§13.2.2.4). The first, before any other final response, makes the
// dialog. The same 2xx again, by its To tag, is ACKed again. A 2xx from
// another branch of a fork, or one after a failure response, is ACKed and
// its dialog ended with BYE, once per branch: the call is up already, or
// was refused.
func (inv *invite) ok(res *sip.Response) {
	to, err := res.Header.To()
	if err != nil {
		return
	}
	tag := to.Tag()
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.d != nil && tag == inv.d.remoteTag {
		inv.d.sendACK()
		return
	}
	if f := inv.forks[tag]; f != nil {
		f.sendACK()
		return
	}
	if inv.d == nil && !inv.final {
		d, err := inv.ua.newDialog(inv.req, res)
		if err != nil {
			select {
			case inv.events <- result{nil, err}:
			default:
			}
			return
		}
		inv.d, inv.final = d, true
		d.sendACK()
		select {
		case inv.events <- result{res, nil}:
		default:
		}
		return
	}
	f, err := inv.ua.buildDialog(inv.req, res)
	if err != nil {
		return
	}
	inv.forks[tag] = f
	// Counted before the ACK goes, so that whoever sees the ACK can wait
	// for the BYE.
	inv.ua.byes.Add(1)
	f.sendACK()
	go func() {
		defer inv.ua.byes.Done()
		_, _ = f.Bye(context.Background())
	}()
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
	// remoteTag is the other side's tag, which tells a retransmitted 2xx
	// from another branch's (§13.2.2.4).
	remoteTag    string
	remoteTarget sip.URI
	// routes is the route set, the 2xx's Record-Route reversed (§12.1.2).
	routes []string
	answer *sip.Response
	ack    *sip.Request

	mu         sync.Mutex
	cseq       uint32
	remoteCSeq uint32
	ended      bool
	done       chan struct{}
	// confirmed is closed when the ACK of the 2xx this UA sent arrives;
	// nil for a dialog this UA made with Invite, confirmed by its own ACK.
	// retransmitTimer sends that 2xx again meanwhile (uas.go).
	confirmed       chan struct{}
	retransmitTimer transaction.Timer
	// ackGiveUp is closed when 64*T1 have passed without that ACK, by
	// giveUpTimer.
	ackGiveUp   chan struct{}
	giveUpTimer transaction.Timer
	// byeQueued is set once a Bye whose context ended has left the BYE to
	// byeLater.
	byeQueued bool
}

// closed is a channel that is always closed.
var closed = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// Confirmed is closed once the dialog is confirmed (RFC 3261 §12): at once
// for a dialog Invite made, when the ACK of its 2xx arrives for one
// IncomingCall.Accept made.
func (d *Dialog) Confirmed() <-chan struct{} {
	if d.confirmed == nil {
		return closed
	}
	return d.confirmed
}

// newDialog makes the dialog of a 2xx to invite (RFC 3261 §12.1.2) and
// keeps it, so that the network's requests in it find it.
func (ua *UA) newDialog(invite *sip.Request, res *sip.Response) (*Dialog, error) {
	d, err := ua.buildDialog(invite, res)
	if err != nil {
		return nil, err
	}
	ua.mu.Lock()
	ua.dialogs[d.key] = d
	ua.mu.Unlock()
	return d, nil
}

// buildDialog makes the dialog of a 2xx to invite without keeping it, with
// the ACK for that 2xx, which carries the INVITE's CSeq number.
func (ua *UA) buildDialog(invite *sip.Request, res *sip.Response) (*Dialog, error) {
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
		remoteTag:    to.Tag(),
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

// strayResponse takes a 2xx to an INVITE whose transaction has ended: the
// invite, if it is recent, handles it as any 2xx; a dialog that outlived
// it ACKs it again.
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
	callID := res.Header.Get("Call-ID")
	ua.mu.Lock()
	inv := ua.invites[dialogKey(callID, from.Tag(), "")]
	d := ua.dialogs[dialogKey(callID, from.Tag(), to.Tag())]
	ua.mu.Unlock()
	switch {
	case inv != nil:
		inv.ok(res)
	case d != nil:
		d.sendACK()
	}
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
//
// On the called side the BYE waits for the ACK of the 200, or for 64*T1
// to have passed without it (§15): a BYE that overtook the ACK could reach
// a caller that has not yet confirmed the dialog. If ctx ends during that
// wait, Bye returns its error and the BYE still goes, in the background,
// when the wait is over: the dialog never stays up.
func (d *Dialog) Bye(ctx context.Context) (*sip.Response, error) {
	if d.confirmed != nil {
		select {
		case <-d.confirmed:
		case <-d.ackGiveUp:
		case <-d.done:
		case <-ctx.Done():
			d.byeLater()
			return nil, ctx.Err()
		}
	}
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

// byeLater sends, once, the BYE of a called-side Bye whose context ended
// before the ACK came: when the ACK comes, or at 64*T1 without it.
func (d *Dialog) byeLater() {
	d.mu.Lock()
	queued := d.byeQueued || d.ended
	d.byeQueued = true
	d.mu.Unlock()
	if queued {
		return
	}
	d.ua.byes.Go(func() {
		select {
		case <-d.confirmed:
		case <-d.ackGiveUp:
		case <-d.done:
			return
		case <-d.ua.done:
			return
		}
		_, _ = d.Bye(context.Background())
	})
}

func (d *Dialog) endLocked() {
	if d.ended {
		return
	}
	d.ended = true
	close(d.done)
	for _, t := range []transaction.Timer{d.retransmitTimer, d.giveUpTimer} {
		if t != nil {
			t.Stop()
		}
	}
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

// NewOptions returns a capability query to target (RCC.07 capability
// discovery over OPTIONS): NewRequest's fields with the UA's Contact, whose
// feature tags name the services it offers, as a device's query carries
// them. The far end's 200 names its own in its Contact. Send sends it.
func (ua *UA) NewOptions(target sip.URI) (*sip.Request, error) {
	req, err := ua.NewRequest("OPTIONS", target)
	if err != nil {
		return nil, err
	}
	add(req, &err, "Contact", ua.contact.String())
	add(req, &err, "Accept", "application/sdp")
	if err != nil {
		return nil, err
	}
	return req, nil
}

// ICSI of standalone messaging, pager mode, unescaped as P-Preferred-Service
// carries it (RCC.07, RFC 6050).
const standaloneService = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg"

// NewMessage returns a pager-mode MESSAGE to target (RFC 3428, RCC.07
// standalone messaging): NewRequest's fields, the standalone messaging ICSI
// in Accept-Contact and P-Preferred-Service, and body of contentType,
// normally message/cpim. Send sends it.
func (ua *UA) NewMessage(target sip.URI, contentType string, body []byte) (*sip.Request, error) {
	req, err := ua.NewRequest("MESSAGE", target)
	if err != nil {
		return nil, err
	}
	add(req, &err, "Accept-Contact", `*;+g.3gpp.icsi-ref="`+ICSIStandalone+`"`)
	add(req, &err, "P-Preferred-Service", standaloneService)
	add(req, &err, "Content-Type", contentType)
	if err != nil {
		return nil, err
	}
	req.Body = slices.Clone(body)
	return req, nil
}
