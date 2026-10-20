package sipas

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// cancelWait is how long an INVITE rcs-as cancelled may take to end, 64*T1
// (RFC 3261 §9.1), after which its transaction is ended.
const cancelWait = 32 * time.Second

var errGroupNotServed = errors.New("sipas: group sessions are not served yet")

// Invite implements messaging.Deliverer: it starts a terminating session
// to inv.Recipient and returns once the INVITE is on its way. The INVITE
// goes to the core as a terminating request, as a pager MESSAGE does (no
// orig, and P-Served-User), with an actpass offer of the leg's path at this
// task (ADR 0004). Its 2xx gives the leg the path of msrp-relay, which
// pcscf answers for active; any other end of it goes to
// Engine.InviteFailed. A leg that ends before the INVITE is answered, as
// one that waited AnswerTimeout does, cancels it.
func (s *Server) Invite(ctx context.Context, inv messaging.Invitation) error {
	if inv.Mode == store.Group {
		return errGroupNotServed
	}
	s.mu.Lock()
	err := s.roomFor(inv.Recipient)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %w", err, messaging.ErrOffline)
	}
	leg, err := s.engine.Offer(messaging.LegParams{
		User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation, Mode: inv.Mode,
		Direction: messaging.Terminating, QueueID: inv.QueueID,
	})
	if err != nil {
		return err
	}
	ss := &session{s: s, leg: leg, user: inv.Recipient, mode: inv.Mode, inv: inv}
	ss.origin = s.newOrigin(leg.Local().Host)
	req, err := s.inviteRequest(ss)
	if err != nil {
		_ = leg.Close()
		return err
	}
	dst, err := s.cfg.Resolver.Resolve(ctx, s.cfg.Core)
	if err != nil {
		_ = leg.Close()
		s.cfg.Metrics.Count("sip.invite.unresolved", 1)
		return fmt.Errorf("sipas: next hop: %w", messaging.ErrOffline)
	}
	dst.Listener = s.cfg.Listener
	// The CANCEL is built before the INVITE is sent, from which the
	// transport owns it.
	cancel, err := cancelOf(req)
	if err != nil {
		_ = leg.Close()
		return err
	}
	tx, err := s.layer.Request(req.Clone(), dst, func(res *sip.Response, err error) { s.inviteAnswered(ss, req, res, err) })
	if err != nil {
		_ = leg.Close()
		s.cfg.Metrics.Count("sip.invite.unsent", 1)
		return fmt.Errorf("sipas: send: %w", messaging.ErrOffline)
	}
	s.cfg.Metrics.Count("sip.invite.sent", 1)
	go ss.ring(tx, cancel, dst)
	return nil
}

// ring cancels rcs-as's INVITE if its leg ends before a final answer: the
// leg's AnswerTimeout, since an INVITE with a provisional answer has no
// timer of its own (RFC 3261 §17.1.1.2). An INVITE that is not answered
// even then is ended 64*T1 later (§9.1).
func (ss *session) ring(tx *transaction.ClientTransaction, cancel *sip.Request, dst transport.Destination) {
	<-ss.leg.Done()
	ss.mu.Lock()
	final := ss.final
	ss.mu.Unlock()
	if final {
		return
	}
	ss.s.cfg.Metrics.Count("sip.invite.cancelled", 1)
	if _, err := ss.s.layer.Request(cancel, dst, func(*sip.Response, error) {}); err != nil {
		tx.Terminate()
		return
	}
	ss.s.cfg.Clock.AfterFunc(cancelWait, tx.Terminate)
}

// cancelOf is the CANCEL of rcs-as's INVITE (RFC 3261 §9.1): its
// Request-URI, Via, Route, From, To, Call-ID and CSeq number.
func cancelOf(invite *sip.Request) (*sip.Request, error) {
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	c := &sip.Request{Method: "CANCEL", URI: invite.URI}
	for _, name := range []string{"Via", "Route", "From", "To", "Call-ID"} {
		for _, v := range invite.Header.Values(name) {
			if err := c.Header.Add(name, v); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range [][2]string{{"Max-Forwards", "70"}, {"CSeq", sip.CSeq{Seq: cseq.Seq, Method: "CANCEL"}.String()}} {
		if err := c.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// inviteAnswered takes what rcs-as's INVITE got, on the goroutine that
// read it, so what may block runs on another. Each 2xx is acknowledged;
// the first sets up the session, and one from another fork is ended at
// once (RFC 3261 §13.2.2.4). Nothing reaches the engine after the first
// final answer.
func (s *Server) inviteAnswered(ss *session, req *sip.Request, res *sip.Response, err error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	switch {
	case err != nil && ss.final:
		// The transaction ended after its answer (Terminate).
	case err != nil:
		ss.final = true
		s.cfg.Metrics.Count("sip.invite.timeout", 1)
		go ss.fail(fmt.Errorf("sipas: invite: %w", messaging.ErrOffline))
	case res.StatusCode < 200:
	case res.StatusCode >= 300:
		if !ss.final {
			ss.final = true
			s.cfg.Metrics.Count(fmt.Sprintf("sip.invite.%d", res.StatusCode), 1)
			go ss.fail(pagerOutcome(res.StatusCode))
		}
	case ss.d == nil:
		ss.final = true
		d, err := dialog.UAC(req, res)
		if err != nil {
			// Without a dialog there is no ACK to send; the client's
			// UAS gives up on its 2xx and ends the session.
			s.cfg.Metrics.Count("sip.invite.no_dialog", 1)
			go ss.fail(err)
			return
		}
		ack, err := d.Request("ACK", s.ids)
		if err != nil {
			go ss.fail(err)
			return
		}
		ss.d, ss.ack = d, ack
		ss.interval = answeredInterval(res)
		go s.established(ss, res)
	case sameDialog(ss.d, res):
		ack, next := ss.ack, ss.d.NextHop()
		go s.sendACK(ack, next)
	default:
		go s.dropFork(req, res)
	}
}

// fail ends a session that did not come about, and tells the engine.
func (ss *session) fail(err error) {
	ss.s.engine.InviteFailed(ss.inv, err)
	ss.end()
}

func sameDialog(d *dialog.Dialog, res *sip.Response) bool {
	to, err := res.Header.To()
	return err == nil && to.Tag() == d.RemoteTag()
}

// established acknowledges the 2xx that set up ss and gives its SDP answer
// to the leg. An answer rcs-as cannot use ends the session: one in which
// the client is passive, which msrp-relay never dials, says it takes no
// session from the network (messaging.ErrNoSessions, ADR 0004).
func (s *Server) established(ss *session, res *sip.Response) {
	ss.mu.Lock()
	ack, next := ss.ack, ss.d.NextHop()
	ss.mu.Unlock()
	// Known before the ACK leaves, so that a BYE right behind it finds
	// the session.
	added := s.addSession(ss)
	s.sendACK(ack, next)
	if added != nil {
		// The session cannot be kept: it is ended, and the message waits
		// for the next one.
		s.engine.InviteFailed(ss.inv, fmt.Errorf("%w: %w", added, messaging.ErrOffline))
		ss.bye("")
		return
	}
	path, reason, err := answeredPath(res)
	if err == nil {
		err = ss.leg.Answer(path)
	}
	if err != nil {
		s.cfg.Metrics.Count("sip.invite.unusable_answer", 1)
		s.engine.InviteFailed(ss.inv, err)
		ss.bye(reason)
		return
	}
	ss.mu.Lock()
	ss.remotePath = joinPath(path)
	ss.mu.Unlock()
	s.cfg.Metrics.Count("sip.invite.accepted", 1)
	ss.arm()
	ss.watch(nil)
}

// dropFork acknowledges a 2xx from a fork other than the one that set up
// the session, and ends that dialog with a BYE (RFC 3261 §13.2.2.4).
func (s *Server) dropFork(req *sip.Request, res *sip.Response) {
	d, err := dialog.UAC(req, res)
	if err != nil {
		return
	}
	ack, err := d.Request("ACK", s.ids)
	if err != nil {
		return
	}
	s.sendACK(ack, d.NextHop())
	bye, err := d.Request("BYE", s.ids)
	if err != nil {
		return
	}
	s.cfg.Metrics.Count("sip.invite.fork_dropped", 1)
	s.sendInDialog(bye, d.NextHop())
}

// answeredInterval is the session timer of a 2xx, zero for none. rcs-as
// does not offer the extension, so the client refreshes (RFC 4028 §9), and
// rcs-as only ends a session left unrefreshed.
func answeredInterval(res *sip.Response) time.Duration {
	if !res.Header.Has("Session-Expires") {
		return 0
	}
	se, err := res.Header.SessionExpires()
	if err != nil || se.Delta == 0 {
		return 0
	}
	return time.Duration(se.Delta) * time.Second
}

// answeredPath is the MSRP path of a 2xx's SDP answer. The answerer must
// connect, active, since rcs-as never does; an answer without a=setup is
// passive (RFC 4145 §4), and with one, the BYE that ends the session
// carries directionRefused.
func answeredPath(res *sip.Response) (path []msrp.URI, reason string, err error) {
	answer, err := sdpBody(&res.Header, res.Body)
	if err != nil {
		return nil, "", err
	}
	_, path, setup, err := firstMSRP(answer, sdp.SetupPassive)
	switch {
	case err != nil:
		return nil, "", err
	case setup == sdp.SetupPassive:
		return nil, directionRefused, fmt.Errorf("sipas: passive answer: %w", messaging.ErrNoSessions)
	}
	return path, "", nil
}

// inviteRequest builds the INVITE of ss, as Pager builds a MESSAGE: to the
// core, terminating for the recipient, from the peer, asserted.
func (s *Server) inviteRequest(ss *session) (*sip.Request, error) {
	inv := ss.inv
	recipient, err := sip.ParseURI(inv.Recipient)
	if err != nil {
		return nil, fmt.Errorf("sipas: recipient: %w", messaging.ErrUndeliverable)
	}
	peer, err := sip.ParseURI(inv.Peer)
	if err != nil {
		return nil, fmt.Errorf("sipas: peer: %w", messaging.ErrUndeliverable)
	}
	tag, err := s.ids.Tag()
	if err != nil {
		return nil, err
	}
	callID, err := s.ids.CallID(s.cfg.Host)
	if err != nil {
		return nil, err
	}
	branch, err := s.ids.Branch()
	if err != nil {
		return nil, err
	}
	if ss.sdp, err = s.offerSDP(ss); err != nil {
		return nil, err
	}
	icsi := chatICSI
	if inv.Mode == store.Standalone {
		icsi = largeICSI
	}
	from := sip.Address{URI: peer}
	from.Params.Set("tag", tag)
	v := sip.Via{Transport: "TCP", Host: viaPlaceholderHost}
	v.Params.Set("branch", branch)
	req := &sip.Request{Method: "INVITE", URI: recipient, Body: ss.sdp}
	fields := [][2]string{
		{"Via", v.String()},
		{"Max-Forwards", "70"},
		{"Route", "<" + s.cfg.Core.String() + ">"},
		{"From", from.String()},
		{"To", "<" + inv.Recipient + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 INVITE"},
		{"Contact", sip.Address{URI: s.cfg.Contact}.String() + ";" + ss.contactTag()},
		{"P-Asserted-Identity", "<" + inv.Peer + ">"},
		{"P-Served-User", "<" + inv.Recipient + ">;sescase=term"},
		{"P-Asserted-Service", icsi},
		{"Accept-Contact", "*;" + ss.contactTag()},
		{"Allow", allowed},
	}
	for _, h := range [][2]string{{"Conversation-ID", inv.Conversation.ID}, {"Contribution-ID", inv.Conversation.Contribution},
		{"InReplyTo-Contribution-ID", inv.Conversation.InReplyTo}} {
		if h[1] != "" {
			fields = append(fields, h)
		}
	}
	fields = append(fields, [2]string{"Content-Type", sdpType})
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, fmt.Errorf("sipas: %s: %w", f[0], errors.Join(err, messaging.ErrUndeliverable))
		}
	}
	return req, nil
}

// offerSDP is rcs-as's offer for ss's leg: actpass, with the leg's path at
// this task (ADR 0004).
func (s *Server) offerSDP(ss *session) ([]byte, error) {
	local := ss.leg.Local()
	m := sdp.Media{Type: "message", Port: local.Port, Proto: sdp.ProtoMSRP, Formats: []string{"*"}}
	if err := m.SetAcceptTypes(messaging.AcceptTypes(ss.mode)); err != nil {
		return nil, err
	}
	if s.cfg.MaxMessageSize > 0 {
		if err := m.SetMaxSize(int64(s.cfg.MaxMessageSize)); err != nil {
			return nil, err
		}
	}
	if err := m.SetPath([]string{local.String()}); err != nil {
		return nil, err
	}
	if err := m.SetSetup(sdp.SetupActPass); err != nil {
		return nil, err
	}
	m.Attributes.Add("sendrecv", "")
	o := ss.origin
	offer := &sdp.Session{
		Origin: o, Name: "-", Connection: &sdp.Connection{NetType: "IN", AddrType: o.AddrType, Address: o.Address},
		Times: []sdp.Time{{}}, Media: []sdp.Media{m},
	}
	return offer.Marshal()
}
