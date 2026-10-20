package sipas

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// Groups is what Server needs from the group chat focus, which
// *group.Service is (docs/rcs-as.md, "How the SIP layer drives it").
type Groups interface {
	Create(ctx context.Context, r group.CreateRequest) (groupstore.Group, error)
	Join(ctx context.Context, uri, who, displayName string) (groupstore.Group, error)
	Leave(ctx context.Context, uri, who string) error
	Add(ctx context.Context, uri, by string, who []group.Invitee) error
	Remove(ctx context.Context, uri, by, who string) error
	Roster(ctx context.Context, uri, who string) ([]byte, uint32, error)
	Get(ctx context.Context, uri string) (groupstore.Group, error)
}

// groupAllowed are the methods of a group chat's requests (RFC 3261
// §20.5): INVITE and SUBSCRIBE outside a dialog, the others in one.
const groupAllowed = "INVITE, ACK, CANCEL, BYE, UPDATE, SUBSCRIBE, REFER"

// groupTimeout bounds a group operation the SIP layer makes outside the
// request it serves: the Join of a 2xx to the focus's INVITE, the Leave of
// a 603.
const groupTimeout = 5 * time.Second

// isFactory reports whether u is the conference factory URI: the same
// user, which SIP compares exactly, at the same host, compared without
// case (RFC 3261 §19.1.4).
func (s *Server) isFactory(u sip.URI) bool {
	f := s.cfg.ConferenceFactory
	return u.IsSIP() && u.User == f.User && strings.EqualFold(u.Host, f.Host)
}

// atConference reports whether u is at the conference host, where every
// group's conference URI is.
func (s *Server) atConference(u sip.URI) bool {
	return u.IsSIP() && strings.EqualFold(u.Host, s.cfg.ConferenceHost)
}

// forGroup reports whether a request to u is a group chat's.
func (s *Server) forGroup(u sip.URI) bool { return s.isFactory(u) || s.atConference(u) }

// fromFocus reports a request from a conference URI: one the focus sent,
// which came back. Without the P-Served-User exclusion of the default
// profile (docs/hss.md), the core could hand the focus's INVITE to a
// participant back to rcs-as, as it could a 1-to-1 delivery (looped);
// taken for a 1-to-1 chat from the group, it would be stored and sent
// again without end. A focus's requests carry no ownTagPrefix: #121 passes
// a group's requests from task to task, which must serve them. A client
// that writes a conference URI in its own From only has its request
// refused.
func (s *Server) fromFocus(req *sip.Request) bool {
	from, err := req.Header.From()
	return err == nil && s.atConference(from.URI)
}

// conferenceURI is the conference URI u names, as the group package
// writes it: sip:<user>@ConferenceHost, without parameters.
func (s *Server) conferenceURI(u sip.URI) (string, bool) {
	if u.User == "" {
		return "", false
	}
	return "sip:" + u.User + "@" + s.cfg.ConferenceHost, true
}

// routeGroup serves a group chat's request outside a dialog: an INVITE
// that creates the group or joins it, or a SUBSCRIBE to its conference
// event package. A REFER is taken in the referrer's session (refer).
func (s *Server) routeGroup(r *proxy.Request) proxy.Decision {
	switch r.Message.Method {
	case "INVITE":
		return proxy.Decision{Serve: s.groupInvite}
	case "SUBSCRIBE":
		return proxy.Decision{Serve: s.groupSubscribe}
	}
	return s.refuseMethod(r, groupAllowed)
}

// groupInvite answers a client's INVITE to a group chat (RCC.07 Group
// Chat): to the conference factory, with a resource list of the invitees,
// it creates the group (group.Service.Create) and has the focus invite
// them; to a conference URI, it joins the group (Join). Either way the
// client gets a session with the group, a leg of Mode store.Group whose
// peer is the conference URI, answered as a 1-to-1 chat is, with the
// conference URI as Contact (RFC 4579 §5.2): what rcsjta keeps to rejoin
// the group. Nothing is stored before every part of the request has been
// read.
func (s *Server) groupInvite(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	if s.groups == nil {
		s.respond(u, req, 404)
		return
	}
	factory := s.isFactory(req.URI)
	// A client creating a group requires the recipient list extension
	// (RFC 5366 §4; rcsjta does).
	supported := []string{"timer"}
	if factory {
		supported = append(supported, "recipient-list-invite")
	}
	if s.refuseUnsupported(u, req, supported...) {
		return
	}
	if !names(req, "oma.cpm.session") && !names(req, omaIMTag) {
		s.cfg.Metrics.Count("sip.group.service_refused", 1)
		s.respond(u, req, 403)
		return
	}
	sender, identities, code := s.asserted(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	from, err := req.Header.From()
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	uri := ""
	if !factory {
		var ok bool
		if uri, ok = s.conferenceURI(req.URI); !ok {
			s.respond(u, req, 404)
			return
		}
	}
	conv, err := messaging.ParseConversationHeaders(req.Header.Get("Conversation-ID"),
		req.Header.Get("Contribution-ID"), req.Header.Get("InReplyTo-Contribution-ID"))
	if err != nil || conv.Contribution == "" {
		// The Contribution-ID names the group chat to its clients
		// (rcsjta's chat ID): every session with the group carries it.
		s.respond(u, req, 400)
		return
	}
	interval, code := sessionInterval(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	desc, list, err := groupBody(&req.Header, req.Body, factory)
	if err != nil {
		s.cfg.Metrics.Count("sip.group.offer_refused", 1)
		s.respond(u, req, 488)
		return
	}
	offer, err := sdp.Parse(desc)
	if err != nil {
		s.respond(u, req, 488)
		return
	}
	offer, i, path, code := msrpOfferIn(offer)
	if code != 0 {
		s.cfg.Metrics.Count("sip.group.offer_refused", 1)
		s.respond(u, req, code)
		return
	}
	if offer.Media[i].Attributes.Has("file-selector") {
		s.cfg.Metrics.Count("sip.group.service_refused", 1)
		s.respond(u, req, 403)
		return
	}
	if !s.answerable(offer, i) {
		s.cfg.Metrics.Count("sip.group.offer_refused", 1)
		s.respond(u, req, 488)
		return
	}
	var invitees []group.Invitee
	if factory {
		// Read no further than a group holds: a longer list is refused
		// unread (docs/rcs-as.md).
		entries, err := resourcelists.Parse(list, s.cfg.MaxGroupParticipants)
		switch {
		case errors.Is(err, resourcelists.ErrTooMany):
			s.cfg.Metrics.Count("sip.group.list_too_long", 1)
			s.respond(u, req, 403)
			return
		case err != nil:
			s.cfg.Metrics.Count("sip.group.list_refused", 1)
			s.respond(u, req, 400)
			return
		}
		for _, e := range entries {
			invitees = append(invitees, group.Invitee{Identity: e.URI, DisplayName: e.DisplayName})
		}
	}
	tag, err := s.ids.Tag()
	if err != nil {
		return // the proxy answers 500
	}
	// Its Contact is the conference URI, set once the group is known.
	d, err := dialog.UAS(req, tag, s.cfg.Contact)
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	ss := &session{s: s, user: sender, mode: store.Group, d: d, remotePath: joinPath(path), interval: interval}
	// The session's place is held before the group is changed, so that a
	// bound reached refuses the request before anything is stored.
	if err := s.reserve(ss); err != nil {
		s.refuseRoom(u, req, err)
		return
	}
	defer s.release(ss)
	var g groupstore.Group
	if factory {
		g, err = s.groups.Create(ctx, group.CreateRequest{
			Creator: sender, CreatorName: from.DisplayName, Invitees: invitees,
			Subject: req.Header.Get("Subject"), Conversation: conv.ID,
		})
	} else {
		g, err = s.groups.Join(ctx, uri, sender, from.DisplayName)
	}
	if err != nil {
		s.refuseGroup(u, req, err)
		return
	}
	ss.group = g.URI
	conv.ID = g.Conversation
	ss.conversation = conv
	if d.LocalTarget, err = sip.ParseURI(g.URI); err != nil {
		s.respond(u, req, 500)
		return
	}
	if ss.leg, err = s.engine.OpenLeg(messaging.LegParams{
		Remote: path, User: sender, Identities: identities, Peer: g.URI, Conversation: conv,
		Mode: store.Group, Direction: messaging.Originating,
	}); err != nil {
		s.respond(u, req, 500)
		return
	}
	ss.origin = s.newOrigin(ss.leg.Local().Host)
	if ss.sdp, err = s.answerSDP(offer, i, ss.leg, store.Group, ss.origin); err != nil {
		_ = ss.leg.Close()
		s.cfg.Metrics.Count("sip.group.offer_refused", 1)
		s.respond(u, req, 488)
		return
	}
	res, err := sip.NewResponse(req, 200, "", tag)
	if err == nil {
		err = s.sessionHeaders(res, ss.contact(), ss.sdp, interval)
	}
	if err != nil || ctx.Err() != nil {
		_ = ss.leg.Close()
		return
	}
	if err := s.addSession(ss); err != nil {
		_ = ss.leg.Close()
		s.refuseRoom(u, req, err)
		return
	}
	if err := u.Respond(res); err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		ss.end()
		return
	}
	if factory {
		s.cfg.Metrics.Count("sip.group.created", 1)
		go s.inviteInvited(g, conv, nil)
	} else {
		s.cfg.Metrics.Count("sip.group.joined", 1)
	}
	ss.arm()
	go ss.watch(u)
}

// answerable reports whether rcs-as can answer line i of offer, as
// answerSDP will once the leg is open, with a stand-in for the leg's path:
// checked before a group is changed, so that an offer refused, one with no
// type in common say, leaves no group behind.
func (s *Server) answerable(offer *sdp.Session, i int) bool {
	standIn := msrp.URI{Host: "rcs-as.invalid", Port: 9, SessionID: "offercheck", Transport: "tcp"}
	_, err := sdp.NegotiateMSRP(offer, i, sdp.MSRPEndpoint{
		Port: standIn.Port, Path: []string{standIn.String()}, AcceptTypes: messaging.AcceptTypes(store.Group),
		MaxSize: int64(s.cfg.MaxMessageSize), PreferredSetup: sdp.SetupPassive,
	})
	return err == nil
}

// refuseRoom answers a session rcs-as has no room for: 486 when the user's
// own sessions are what is busy (RFC 3261 §21.4.24), 500 with Retry-After
// otherwise, which scscf passes on as it is (submit).
func (s *Server) refuseRoom(u *proxy.UAS, req *sip.Request, err error) {
	if errors.Is(err, errUserSessions) {
		s.respond(u, req, 486)
		return
	}
	s.respondRetry(u, req, 500)
}

// refuseGroup answers a request the group refused: 404 for a group that
// does not exist or has ended, which a client that rejoins takes as the
// end of the group (RCC.07); 403 for whoever may not, or a group too
// large; 400 for a request that makes no sense, such as a list with
// nobody else in it; 500 with Retry-After for a group that kept changing
// under the request or a store that was busy; 500 otherwise.
func (s *Server) refuseGroup(u *proxy.UAS, req *sip.Request, err error) {
	code, retry := 500, false
	switch {
	case errors.Is(err, group.ErrNoGroup):
		code = 404
	case errors.Is(err, group.ErrNotParticipant), errors.Is(err, group.ErrNotChairman),
		errors.Is(err, group.ErrTooMany), errors.Is(err, group.ErrRateLimited):
		code = 403
	case errors.Is(err, group.ErrInvalid):
		code = 400
	case errors.Is(err, group.ErrBusy), errors.Is(err, store.ErrBusy):
		retry = true
	}
	s.cfg.Metrics.Count("sip.group.refused", 1)
	if retry {
		s.respondRetry(u, req, code)
		return
	}
	s.respond(u, req, code)
}

// inviteInvited has the focus invite each participant g holds invited, of
// those in only unless it is nil: once its creator's session is set up, or
// once a REFER added them. It goes through the engine, which counts the
// invitation, so that a message queued meanwhile waits for that session
// rather than ringing the participant again.
func (s *Server) inviteInvited(g groupstore.Group, conv messaging.Conversation, only map[string]bool) {
	for _, p := range g.Participants {
		if p.State != groupstore.Invited || only != nil && !only[p.Identity] {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
		s.engine.Invite(ctx, messaging.Invitation{
			Recipient: p.Identity, Peer: g.URI, Mode: store.Group, Subject: g.Subject,
			Conversation: messaging.Conversation{ID: g.Conversation, Contribution: conv.Contribution},
		})
		cancel()
	}
}

// declined takes a 603 Decline to the focus's INVITE as the participant
// leaving the group (docs/rcs-as.md), not as a failure to try again:
// rcsjta declines the first INVITE of a group it left while offline (RCC.07
// 6.3.3.1; isGroupChatNextInviteRejected), and takes a later one as being
// added anew.
func (ss *session) declined() {
	ss.s.release(ss)
	ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
	defer cancel()
	if err := ss.s.groups.Leave(ctx, ss.group, ss.user); err != nil {
		ss.s.cfg.Metrics.Count("sip.group.leave_failed", 1)
	} else {
		ss.s.cfg.Metrics.Count("sip.group.declined", 1)
		ss.s.endSubscriptions(ss.group, ss.user, reasonRejected)
	}
	ss.end()
}

// leaves reports a BYE with which a participant leaves its group: one with
// Reason SIP cause 200, as rcsjta ends a session its user closes
// (ImsServiceSession.closeSession, "Call completed"). Any other BYE, one
// for a session idle too long say, ends the session and keeps the
// participant in the group, which it rejoins with an INVITE to the
// conference URI, or the focus invites it back for the next message
// (RCC.07 Group Chat): a participant that left could do neither.
func leaves(req *sip.Request) bool { return sipCause(req, 200) }

// left records that a participant left its group by its BYE (Leave), and
// ends its subscriptions, so that it learns no later change.
func (s *Server) left(ctx context.Context, ss *session) {
	if err := s.groups.Leave(ctx, ss.group, ss.user); err != nil {
		s.cfg.Metrics.Count("sip.group.leave_failed", 1)
		return
	}
	s.cfg.Metrics.Count("sip.group.left", 1)
	s.endSubscriptions(ss.group, ss.user, reasonRejected)
}

// joined records that the participant answered the focus's INVITE with a
// 2xx (Join), before its leg is put to work; it reports whether the group
// took it.
func (ss *session) joined() error {
	ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
	defer cancel()
	_, err := ss.s.groups.Join(ctx, ss.group, ss.user, "")
	return err
}
