package sipas

import (
	"context"
	"errors"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// invite answers a client's INVITE for a chat session or a large-mode
// message (RCC.07 §3.2, §3.3). msrp-relay, which pcscf put in the media
// path, offers a=setup:active with its core path (ADR 0004): rcs-as opens
// the leg there, answers passive with the leg's path, and the relay
// connects to it (messaging.Engine.Serve). Messages on the leg go through
// the engine like pager-mode ones: stored, then delivered to the peer.
func (s *Server) invite(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	if bad := unsupported(req, "timer"); len(bad) > 0 {
		s.refuseUnsupported(u, req, bad)
		return
	}
	// The service is what the client asks for: a chat session, or one for
	// a large message. A file transfer and the rest are not served here.
	var mode store.Mode
	switch {
	case names(req, "oma.cpm.largemsg"):
		mode = store.Standalone
	case names(req, "oma.cpm.session"):
		mode = store.Chat
	default:
		s.cfg.Metrics.Count("sip.invite.service_refused", 1)
		s.respond(u, req, 403)
		return
	}
	sender, identities, code := s.asserted(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	peer, ok := messaging.UserOf(req.URI.String(), s.cfg.HomeDomain)
	if !ok {
		s.respond(u, req, 404)
		return
	}
	conv, err := messaging.ParseConversationHeaders(req.Header.Get("Conversation-ID"),
		req.Header.Get("Contribution-ID"), req.Header.Get("InReplyTo-Contribution-ID"))
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	interval, code := sessionInterval(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	// A group chat's INVITE has a resource list beside its SDP, which
	// msrpOffer does not take: group sessions are not served yet.
	offer, i, path, code := msrpOffer(&req.Header, req.Body)
	if code != 0 {
		s.cfg.Metrics.Count("sip.invite.offer_refused", 1)
		s.respond(u, req, code)
		return
	}
	tag, err := s.ids.Tag()
	if err != nil {
		return // the proxy answers 500
	}
	d, err := dialog.UAS(req, tag, s.cfg.Contact)
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	leg, err := s.engine.OpenLeg(messaging.LegParams{
		Remote: path, User: sender, Identities: identities, Peer: peer, Conversation: conv,
		Mode: mode, Direction: messaging.Originating,
	})
	if err != nil {
		s.respond(u, req, 500)
		return
	}
	ss := &session{s: s, leg: leg, user: sender, mode: mode, d: d, remotePath: joinPath(path), interval: interval}
	ss.origin = s.newOrigin(leg.Local().Host)
	if ss.sdp, err = s.answerSDP(offer, i, leg, mode, ss.origin); err != nil {
		_ = leg.Close()
		s.respond(u, req, 488)
		return
	}
	res, err := sip.NewResponse(req, 200, "", tag)
	if err == nil {
		err = s.sessionHeaders(res, ss.contactTag(), ss.sdp, interval)
	}
	// A CANCEL that came meanwhile has the proxy answer 487 (proxy.Router).
	if err != nil || ctx.Err() != nil {
		_ = leg.Close()
		return
	}
	// Known before the 2xx leaves, so that a BYE right behind its ACK
	// finds the session.
	if err := s.addSession(ss); err != nil {
		_ = leg.Close()
		if errors.Is(err, errUserSessions) {
			s.respond(u, req, 403)
			return
		}
		// The client may try again in a moment, and another task may
		// take it. A 500, not a 503, which scscf would turn into a 500
		// of its own without Retry-After (RFC 3261 §16.7 step 6).
		s.respondRetry(u, req, 500)
		return
	}
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		ss.end()
		return
	}
	s.cfg.Metrics.Count("sip.invite.answered", 1)
	ss.arm()
	go ss.watch(u)
}

// names reports whether req asks for the service whose ICSI ends in icsi:
// in a feature tag of Accept-Contact or in a service header. Contact is
// not read: it lists what the client takes, which may be more.
func names(req *sip.Request, icsi string) bool {
	for _, h := range []string{"Accept-Contact", "P-Asserted-Service", "P-Preferred-Service"} {
		for _, v := range req.Header.Values(h) {
			if strings.Contains(v, icsi) {
				return true
			}
		}
	}
	return false
}
