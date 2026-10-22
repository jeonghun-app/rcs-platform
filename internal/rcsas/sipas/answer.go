package sipas

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/content"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// dialogResponse is a 2xx that sets up a dialog with req's sender: req's
// Record-Route copied in order (RFC 3261 §12.1.1, RFC 6665 §4.1.2.1). It
// is the client's route set, without which pcscf refuses every request the
// client sends in the dialog, its BYE among them (#541).
func dialogResponse(req *sip.Request, code int, tag string) (*sip.Response, error) {
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		return nil, err
	}
	for _, rr := range req.Header.Values("Record-Route") {
		if err := res.Header.Add("Record-Route", rr); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// invite answers a client's INVITE for a chat session or a large-mode
// message (RCC.07 §3.2, §3.3). msrp-relay, which pcscf put in the media
// path, offers a=setup:active with its core path (ADR 0004): rcs-as opens
// the leg there, answers passive with the leg's path, and the relay
// connects to it (messaging.Engine.Serve). Messages on the leg go through
// the engine like pager-mode ones: stored, then delivered to the peer.
func (s *Server) invite(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	if s.refuseUnsupported(u, req, "timer") {
		return
	}
	// The service is what the client asks for: a chat session, or one for
	// a large message. A file transfer and the rest are not served here.
	var mode store.Mode
	switch {
	case names(req, "oma.cpm.largemsg"):
		mode = store.Standalone
	case names(req, "oma.cpm.session"), names(req, omaIMTag):
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
	conv, ok := sessionConversation(req)
	if !ok {
		s.respond(u, req, 400)
		return
	}
	interval, code := sessionInterval(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	// A chat INVITE may carry the chat's first message beside its SDP;
	// large mode carries its message in the session only.
	offer, i, path, first, code := inviteOffer(&req.Header, req.Body, mode)
	if code != 0 {
		s.cfg.Metrics.Count("sip.invite.offer_refused", 1)
		s.respond(u, req, code)
		return
	}
	if offer.Media[i].Attributes.Has("file-selector") {
		// A file transfer (RFC 5547 §6), which rcsjta asks for with the
		// same +g.oma.sip-im tag as a chat: not served here.
		s.cfg.Metrics.Count("sip.invite.service_refused", 1)
		s.respond(u, req, 403)
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
		// No type in common, for one.
		_ = leg.Close()
		s.cfg.Metrics.Count("sip.invite.offer_refused", 1)
		s.respond(u, req, 488)
		return
	}
	res, err := dialogResponse(req, 200, tag)
	if err == nil {
		err = s.sessionHeaders(res, ss.contact(), ss.sdp, interval)
	}
	// A CANCEL that came meanwhile has the proxy answer 487 (proxy.Router).
	if err != nil || ctx.Err() != nil {
		_ = leg.Close()
		return
	}
	// Known before the 2xx leaves, so that a BYE right behind its ACK
	// finds the session; and before a first message is stored, so that an
	// INVITE past a bound stores nothing its client would send again.
	answered, err := s.addSession(ss)
	if err != nil {
		_ = leg.Close()
		if errors.Is(err, errUserSessions) {
			// The user's own sessions are what is busy (RFC 3261
			// §21.4.24); the lead's decision on #252.
			s.respond(u, req, 486)
			return
		}
		// The client may try again in a moment, and another task may
		// take it. A 500, not a 503, which scscf would turn into a 500
		// of its own without Retry-After (RFC 3261 §16.7 step 6).
		s.respondRetry(u, req, 500)
		return
	}
	defer answered()
	if first != nil {
		// The first message goes in as the session's would, stored
		// before the 2xx; one the engine refuses fails the INVITE with
		// the status a pager MESSAGE would get, and gives the session's
		// place back.
		code, busy := s.submit(ctx, messaging.Origin{
			Sender: sender, Identities: identities, Recipient: peer, Conversation: conv,
			Mode: store.Chat, CPIM: content.BodyOf(first),
		})
		s.cfg.Metrics.Count(fmt.Sprintf("sip.invite.first_message.%d", code), 1)
		if code != 202 {
			ss.end()
			if busy {
				s.respondRetry(u, req, code)
			} else {
				s.respond(u, req, code)
			}
			return
		}
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

// inviteOffer reads a client's INVITE body (inviteBody): the MSRP offer as
// msrpOffer does, and a first message, which only a chat INVITE carries;
// or 488.
func inviteOffer(h *sip.Header, body []byte, mode store.Mode) (*sdp.Session, int, []msrp.URI, []byte, int) {
	desc, first, err := inviteBody(h, body)
	if err != nil || first != nil && mode != store.Chat {
		return nil, 0, nil, nil, 488
	}
	offer, err := sdp.Parse(desc)
	if err != nil {
		return nil, 0, nil, nil, 488
	}
	offer, i, path, code := msrpOfferIn(offer)
	return offer, i, path, first, code
}

// omaIMTag is the OMA SIMPLE IM feature tag, with which rcsjta, the
// reference client, asks for a 1-to-1 chat (ChatUtils) instead of the CPM
// chat ICSI.
const omaIMTag = "+g.oma.sip-im"

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
