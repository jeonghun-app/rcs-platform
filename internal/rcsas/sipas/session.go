package sipas

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// The OMA CPM ICSIs of a chat session and of a large-mode message (RCC.07
// §2.6.1): what an INVITE is for. Their feature tags go in the Contact of
// rcs-as's sessions and, for the INVITEs it sends, in Accept-Contact, so
// that scscf forks them to the contacts that take them (RFC 3841).
const (
	chatICSI  = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session"
	largeICSI = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.largemsg"
	chatTag   = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session"`
	largeTag  = `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg"`
	sdpType   = "application/sdp"
)

// directionRefused is the Reason with which pcscf ends a session whose
// client answered rcs-as's offer passive (ADR 0004), and with which rcs-as
// ends one whose answer it finds passive itself.
const directionRefused = `SIP;cause=488;text="MSRP direction not supported"`

// minSessionExpires is the shortest session interval rcs-as takes, RFC
// 4028 §4's minimum; a request for less is answered 422 with Min-SE.
const minSessionExpires = 90

// dialogTimeout bounds the lookup of a dialog's next hop.
const dialogTimeout = 5 * time.Second

// session is one SIP session rcs-as is a party to and the MSRP leg it
// anchors in it: a client's INVITE it answered, or one it sent to deliver
// (inv). The fields below mu are guarded by it.
type session struct {
	s   *Server
	leg *messaging.Leg
	// user is the client's identity in the session, which
	// Config.MaxSessionsPerUser bounds.
	user string
	mode store.Mode
	// inv is the invitation of a session rcs-as started; zero otherwise.
	inv messaging.Invitation

	mu sync.Mutex
	d  *dialog.Dialog
	// remotePath is the a=path of the other side, which a re-INVITE or
	// UPDATE must keep.
	remotePath string
	// origin and sdp are the o= line and the body of the last SDP rcs-as
	// sent in the session, from which an answer to a refresh is made
	// (RFC 3264 §8).
	origin sdp.Origin
	sdp    []byte
	// interval is the session timer, zero for none (RFC 4028).
	interval time.Duration
	timer    msrp.Timer
	// ack is the ACK of the 2xx rcs-as's INVITE got, sent again for each
	// retransmission of it (RFC 3261 §13.2.2.4).
	ack *sip.Request
	// final is set once rcs-as's INVITE has a final answer.
	final bool
	ended bool
}

// contactTag is the feature tag of the session's service.
func (ss *session) contactTag() string {
	if ss.mode == store.Standalone {
		return largeTag
	}
	return chatTag
}

// Why addSession did not add a session.
var (
	errClosing         = errors.New("sipas: closing")
	errTooManySessions = errors.New("sipas: too many sessions on this task")
	errUserSessions    = errors.New("sipas: too many sessions for the user")
)

// addSession makes ss reachable by the requests in its dialog, unless s
// is closing or a bound on sessions is reached (threat model T9).
func (s *Server) addSession(ss *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.roomFor(ss.user); err != nil {
		return err
	}
	s.sessions[ss.d.ID()] = ss
	s.perUser[ss.user]++
	return nil
}

// roomFor reports whether a session for user may be added; it needs s.mu.
func (s *Server) roomFor(user string) error {
	switch {
	case s.closed:
		return errClosing
	case len(s.sessions) >= s.cfg.MaxSessions:
		s.cfg.Metrics.Count("sip.session.task_limit", 1)
		return errTooManySessions
	case s.perUser[user] >= s.cfg.MaxSessionsPerUser:
		s.cfg.Metrics.Count("sip.session.user_limit", 1)
		return errUserSessions
	}
	return nil
}

func (s *Server) removeSession(ss *session) {
	ss.mu.Lock()
	d := ss.d
	ss.mu.Unlock()
	if d == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[d.ID()] != ss {
		return
	}
	delete(s.sessions, d.ID())
	if s.perUser[ss.user]--; s.perUser[ss.user] <= 0 {
		delete(s.perUser, ss.user)
	}
}

// sessionOf finds the session of a request the other side sent in it, by
// the dialog's identifier, rcs-as's tag being To's (dialog.Dialog.ID).
func (s *Server) sessionOf(req *sip.Request) *session {
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	if err1 != nil || err2 != nil {
		return nil
	}
	id := req.Header.Get("Call-ID") + "\x00" + strings.ToLower(to.Tag()) + "\x00" + strings.ToLower(from.Tag())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

// Close ends every session with a BYE, before the transport closes, and
// takes no new one. Each BYE is sent, not waited for.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	all := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		all = append(all, ss)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, ss := range all {
		wg.Go(func() { ss.bye("") })
	}
	wg.Wait()
}

// msrpOffer reads the SDP offer in body: its first MSRP media line, with
// its path, or the status that refuses it. No offer (a late offer, RFC
// 3261 §13.2.1), no MSRP line, or an offer of passive, which only a
// connecting answerer could take and rcs-as never connects (RFC 6135
// §4.2.2, ADR 0004), is 488.
func msrpOffer(h *sip.Header, body []byte) (*sdp.Session, int, []msrp.URI, int) {
	offer, err := sdpBody(h, body)
	if err != nil {
		return nil, 0, nil, 488
	}
	// An offer without a=setup is active (RFC 4145 §4).
	i, path, setup, err := firstMSRP(offer, sdp.SetupActive)
	if err != nil || setup == sdp.SetupPassive {
		return nil, 0, nil, 488
	}
	return offer, i, path, 0
}

func sdpBody(h *sip.Header, body []byte) (*sdp.Session, error) {
	ct, err := h.ContentType()
	if err != nil || len(body) == 0 || !strings.EqualFold(ct.Type+"/"+ct.Subtype, sdpType) {
		return nil, errors.New("sipas: no SDP")
	}
	return sdp.Parse(body)
}

// firstMSRP is the first MSRP media line of s that is not disabled, its
// path, and its role, absent when it names none.
func firstMSRP(s *sdp.Session, absent sdp.Setup) (int, []msrp.URI, sdp.Setup, error) {
	for i := range s.Media {
		m := &s.Media[i]
		if !m.IsMSRP() || m.Port == 0 {
			continue
		}
		setup, err := s.MediaSetup(i)
		switch {
		case errors.Is(err, sdp.ErrNoAttribute):
			setup = absent
		case err != nil:
			return 0, nil, "", err
		}
		values, err := m.Path()
		if err != nil {
			return 0, nil, "", err
		}
		path := make([]msrp.URI, 0, len(values))
		for _, v := range values {
			u, err := msrp.ParseURI(v)
			if err != nil {
				return 0, nil, "", err
			}
			path = append(path, u)
		}
		return i, path, setup, nil
	}
	return 0, nil, "", errors.New("sipas: no MSRP media line")
}

func joinPath(path []msrp.URI) string {
	parts := make([]string, len(path))
	for i, u := range path {
		parts[i] = u.String()
	}
	return strings.Join(parts, " ")
}

// newOrigin is the o= line of a session rcs-as describes, at host, the
// leg's instance address (ADR 0005), numbered from the clock as RFC 8866
// §5.2 suggests.
func (s *Server) newOrigin(host string) sdp.Origin {
	const ntpEpoch = 2208988800 // 1900 to 1970, in seconds
	addrType := "IP4"
	if strings.Contains(host, ":") {
		addrType = "IP6"
	}
	now := s.cfg.Clock.Now()
	return sdp.Origin{
		Username: "-", SessionID: strconv.FormatInt(now.UnixNano(), 10),
		SessionVersion: strconv.FormatInt(now.Unix()+ntpEpoch, 10),
		NetType:        "IN", AddrType: addrType, Address: host,
	}
}

// answerSDP answers line i of offer with leg's path, passive, and origin.
func (s *Server) answerSDP(offer *sdp.Session, i int, leg *messaging.Leg, mode store.Mode, origin sdp.Origin) ([]byte, error) {
	local := leg.Local()
	m, err := sdp.NegotiateMSRP(offer, i, sdp.MSRPEndpoint{
		Port: local.Port, Path: []string{local.String()}, AcceptTypes: messaging.AcceptTypes(mode),
		MaxSize: int64(s.cfg.MaxMessageSize), PreferredSetup: sdp.SetupPassive,
	})
	if err != nil {
		return nil, err
	}
	answer := sdp.NewAnswer(offer, origin, sdp.Connection{NetType: "IN", AddrType: origin.AddrType, Address: origin.Address})
	answer.Media[i] = m
	return answer.Marshal()
}

// answerRefresh answers the offer of a re-INVITE or UPDATE in ss: the same
// answer as before, with the same o= version, unless what rcs-as describes
// has changed, which takes the next version (RFC 3264 §8).
func (ss *session) answerRefresh(offer *sdp.Session, i int) ([]byte, error) {
	ss.mu.Lock()
	origin, last := ss.origin, ss.sdp
	ss.mu.Unlock()
	body, err := ss.s.answerSDP(offer, i, ss.leg, ss.mode, origin)
	if err != nil || slices.Equal(body, last) {
		return body, err
	}
	n, err := strconv.ParseUint(origin.SessionVersion, 10, 63)
	if err != nil {
		return nil, err
	}
	origin.SessionVersion = strconv.FormatUint(n+1, 10)
	if body, err = ss.s.answerSDP(offer, i, ss.leg, ss.mode, origin); err != nil {
		return nil, err
	}
	ss.mu.Lock()
	ss.origin, ss.sdp = origin, body
	ss.mu.Unlock()
	return body, nil
}

// sessionHeaders adds the header fields of a 2xx in a session: Contact with
// the service's feature tag, Allow, the SDP if any and, with a timer, the
// Session-Expires the UAC refreshes (RFC 4028 §9).
func (s *Server) sessionHeaders(res *sip.Response, tag string, body []byte, interval time.Duration) error {
	fields := [][2]string{
		{"Contact", sip.Address{URI: s.cfg.Contact}.String() + ";" + tag},
		{"Allow", allowed},
		{"Supported", "timer"},
	}
	if interval > 0 {
		fields = append(fields, [2]string{"Require", "timer"},
			[2]string{"Session-Expires", strconv.Itoa(int(interval/time.Second)) + ";refresher=uac"})
	}
	if len(body) > 0 {
		fields = append(fields, [2]string{"Content-Type", sdpType})
	}
	for _, f := range fields {
		if err := res.Header.Add(f[0], f[1]); err != nil {
			return err
		}
	}
	res.Body = body
	return nil
}

// sessionInterval is the session timer a request asks for and rcs-as
// takes, zero for none, or the status that refuses it: 422 below
// minSessionExpires. rcs-as never refreshes a session itself. A UAC that
// does not support the extension would leave that to it, and one that asks
// for refresher=uas does so explicitly (RFC 4028 §9): for either it takes
// no timer, as a UAS without the extension does, and the session ends with
// its MSRP connection or a BYE.
func sessionInterval(req *sip.Request) (time.Duration, int) {
	if !req.Header.Has("Session-Expires") {
		return 0, 0
	}
	se, err := req.Header.SessionExpires()
	if err != nil {
		return 0, 400
	}
	if se.Delta < minSessionExpires {
		return 0, 422
	}
	supported, err := req.Header.Supported()
	if err != nil {
		return 0, 400
	}
	if !containsFold(supported, "timer") || se.Refresher() == "uas" {
		return 0, 0
	}
	return time.Duration(se.Delta) * time.Second, 0
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) })
}

// watch ends the session from rcs-as's side when it must: a 2xx that got
// no ACK (RFC 3261 §13.3.1.4); a leg that ended on its own, as when
// msrp-relay dropped its connection; or a terminating large-mode leg that
// has made its delivery (messaging.Leg.Finished).
func (ss *session) watch(u *proxy.UAS) {
	if u != nil {
		if _, err := u.ACK(context.Background()); errors.Is(err, proxy.ErrNoACK) {
			ss.s.cfg.Metrics.Count("sip.session.no_ack", 1)
			ss.bye("")
			return
		}
	}
	select {
	case <-ss.leg.Done():
	case <-ss.leg.Finished():
	}
	ss.bye("")
}

// arm starts the session timer again: without a refresh before the
// interval runs out less min(32 s, interval/3), rcs-as ends the session
// (RFC 4028 §10).
func (ss *session) arm() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.timer != nil {
		ss.timer.Stop()
		ss.timer = nil
	}
	if ss.interval <= 0 || ss.ended {
		return
	}
	ss.timer = ss.s.cfg.Clock.AfterFunc(ss.interval-min(32*time.Second, ss.interval/3), func() {
		ss.s.cfg.Metrics.Count("sip.session.expired", 1)
		ss.bye("")
	})
}

// end forgets the session and closes its leg; it reports whether it was
// the call that did.
func (ss *session) end() bool {
	ss.mu.Lock()
	if ss.ended {
		ss.mu.Unlock()
		return false
	}
	ss.ended = true
	if ss.timer != nil {
		ss.timer.Stop()
	}
	ss.mu.Unlock()
	ss.s.removeSession(ss)
	_ = ss.leg.Close()
	return true
}

// bye ends the session from rcs-as's side with a BYE in its dialog,
// carrying reason if it is not empty.
func (ss *session) bye(reason string) {
	if !ss.end() {
		return
	}
	ss.mu.Lock()
	var req *sip.Request
	var next sip.URI
	err := errors.New("sipas: no dialog")
	if ss.d != nil {
		req, err = ss.d.Request("BYE", ss.s.ids)
		next = ss.d.NextHop()
	}
	ss.mu.Unlock()
	if err != nil {
		return
	}
	if reason != "" && req.Header.Add("Reason", reason) != nil {
		return
	}
	ss.s.cfg.Metrics.Count("sip.bye.sent", 1)
	ss.s.sendInDialog(req, next)
}

// sendInDialog sends rcs-as's request in a dialog to next, and does not
// wait for its answer: there is nothing left to do with it.
func (s *Server) sendInDialog(req *sip.Request, next sip.URI) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		s.cfg.Metrics.Count("sip.dialog.unresolved", 1)
		return
	}
	dst.Listener = s.cfg.Listener
	if _, err := s.layer.Request(req, dst, func(*sip.Response, error) {}); err != nil {
		s.cfg.Metrics.Count("sip.dialog.unsent", 1)
	}
}

// sendACK sends the ACK of a 2xx to next. It belongs to no transaction
// (RFC 3261 §13.2.2.4); each copy is a request of its own, since the
// transport writes its Via.
func (s *Server) sendACK(ack *sip.Request, next sip.URI) {
	ctx, cancel := context.WithTimeout(context.Background(), dialogTimeout)
	defer cancel()
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		s.cfg.Metrics.Count("sip.dialog.unresolved", 1)
		return
	}
	dst.Listener = s.cfg.Listener
	if _, err := s.sender.SendRequest(ack.Clone(), dst); err != nil {
		s.cfg.Metrics.Count("sip.dialog.unsent", 1)
	}
}

// inDialog serves a request the other side sent in a session: BYE ends
// it, a re-INVITE or UPDATE refreshes it (RFC 4028 §7), OPTIONS is
// answered, and nothing else is taken.
func (s *Server) inDialog(_ context.Context, u *proxy.UAS) {
	req := u.Request().Message
	ss := s.sessionOf(req)
	if ss == nil {
		s.respond(u, req, 481)
		return
	}
	ss.mu.Lock()
	err := ss.d.Accept(req)
	ended := ss.ended
	ss.mu.Unlock()
	switch {
	case ended || errors.Is(err, dialog.ErrNotInDialog):
		s.respond(u, req, 481)
		return
	case errors.Is(err, dialog.ErrOutOfOrder):
		s.respond(u, req, 500)
		return
	case err != nil:
		s.respond(u, req, 400)
		return
	}
	switch req.Method {
	case "BYE":
		s.cfg.Metrics.Count("sip.bye.received", 1)
		// Ended before the 200 leaves, so that what the other side does
		// next finds the session gone.
		if ss.end() && ss.inv.Recipient != "" && directionRefusedBy(req) {
			// The client answered passive and pcscf ended the session
			// (ADR 0004): it takes no session from the network.
			s.engine.InviteFailed(ss.inv, messaging.ErrNoSessions)
		}
		s.respond(u, req, 200)
	case "INVITE", "UPDATE":
		s.refresh(u, ss, req)
	case "OPTIONS":
		s.respond(u, req, 200)
	default:
		s.respond(u, req, 405)
	}
}

// directionRefusedBy reports a BYE whose Reason is SIP cause 488, with
// which pcscf ends a session whose client answered passive (ADR 0004).
func directionRefusedBy(req *sip.Request) bool {
	reasons, err := req.Header.Reason()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(reasons, func(r sip.Reason) bool {
		cause, ok := r.Cause()
		return ok && cause == 488 && strings.EqualFold(r.Protocol, "SIP")
	})
}

// refresh answers a re-INVITE or UPDATE in ss. One that keeps the MSRP
// path refreshes the session timer; one that moves it is refused (488),
// since a leg does not move. A re-INVITE without an offer would need one
// from rcs-as in the 2xx (RFC 3261 §14.2), and is refused too; an UPDATE
// without one is a plain refresh (RFC 3311 §5.2).
func (s *Server) refresh(u *proxy.UAS, ss *session, req *sip.Request) {
	if bad := unsupported(req, "timer"); len(bad) > 0 {
		s.refuseUnsupported(u, req, bad)
		return
	}
	var body []byte
	if len(req.Body) > 0 || req.Method == "INVITE" {
		offer, i, path, code := msrpOffer(&req.Header, req.Body)
		ss.mu.Lock()
		moved := code == 0 && joinPath(path) != ss.remotePath
		ss.mu.Unlock()
		if code != 0 || moved {
			s.cfg.Metrics.Count("sip.refresh.refused", 1)
			s.respond(u, req, 488)
			return
		}
		var err error
		if body, err = ss.answerRefresh(offer, i); err != nil {
			s.respond(u, req, 488)
			return
		}
	}
	interval, code := sessionInterval(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	ss.mu.Lock()
	tag := ss.d.LocalTag()
	ss.mu.Unlock()
	res, err := sip.NewResponse(req, 200, "", tag)
	if err != nil || s.sessionHeaders(res, ss.contactTag(), body, interval) != nil {
		return // the proxy answers 500
	}
	ss.mu.Lock()
	ss.interval = interval
	ss.mu.Unlock()
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		return
	}
	s.cfg.Metrics.Count("sip.refresh.answered", 1)
	ss.arm()
}
