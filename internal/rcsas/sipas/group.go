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
	Established(ctx context.Context, uri string) error
}

// groupAllowed are the methods a conference URI or the factory takes
// outside a session.
const groupAllowed = "INVITE, ACK, CANCEL, BYE, UPDATE"

// groupTimeout bounds a group operation the SIP layer makes outside the
// request it serves: the Join of a 2xx to the focus's INVITE, the Leave of
// a 603.
const groupTimeout = 5 * time.Second

// isFactory reports whether u is the conference factory URI: the same
// user, which SIP compares exactly, at the same host, compared without
// case (RFC 3261 §19.1.4).
func (s *Server) isFactory(u sip.URI) bool {
	f := s.cfg.ConferenceFactory
	return u.IsSIP() && u.User == f.User && sameHost(u.Host, f.Host)
}

// atConference reports whether u is at the conference host, where every
// group's conference URI is.
func (s *Server) atConference(u sip.URI) bool {
	return u.IsSIP() && sameHost(u.Host, s.cfg.ConferenceHost)
}

// sameHost compares two host names as DNS does: without case, and with or
// without the trailing dot of a fully qualified name (RFC 3261 §25.1), so
// that conf.<domain>. is the conference host too and cannot take a group's
// request onto the 1-to-1 path (QA on #279).
func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
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
// writes it: sip:chat-<32 lower-case hex digits>@ConferenceHost, without
// parameters. Any other user part names no group, and is refused before
// the store is read: it could be too long for a DynamoDB key, and costs a
// read either way (security review on #279).
func (s *Server) conferenceURI(u sip.URI) (string, bool) {
	id, ok := strings.CutPrefix(u.User, "chat-")
	if !ok || len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return "", false
	}
	return "sip:" + u.User + "@" + s.cfg.ConferenceHost, true
}

// groupConversation reads the conversation headers of a group chat's
// request, as sessionConversation does. Its Contribution-ID, which names
// the chat to its clients (rcsjta's chat ID) and which every session with
// the group carries, is required; without a Conversation-ID the group
// makes one (group.CreateRequest.Conversation).
func groupConversation(req *sip.Request) (messaging.Conversation, bool) {
	c, ok := sessionConversation(req)
	return c, ok && c.Contribution != ""
}

// sessionConversation reads the conversation headers of a session's
// INVITE: each a token as in a pager MESSAGE (messaging.ValidID), but the
// Conversation-ID optional, as rcsjta sends only a Contribution-ID with an
// INVITE (code review on #279). One that names a Conversation-ID or a
// reply without a Contribution-ID is refused, as by
// messaging.ParseConversationHeaders; one without any is a session outside
// a conversation, as before.
func sessionConversation(req *sip.Request) (messaging.Conversation, bool) {
	trim := func(name string) string { return strings.Trim(req.Header.Get(name), " \t") }
	c := messaging.Conversation{
		ID: trim(messaging.HeaderConversationID), Contribution: trim(messaging.HeaderContributionID),
		InReplyTo: trim(messaging.HeaderInReplyTo),
	}
	valid := func(v string) bool { return v == "" || messaging.ValidID(v) }
	ok := valid(c.ID) && valid(c.Contribution) && valid(c.InReplyTo) &&
		(c.Contribution != "" || c.ID == "" && c.InReplyTo == "")
	return c, ok
}

// invitees are the entries of a resource list as the group's invitees,
// leaving out the conference factory and any URI at the conference host:
// the focus's INVITE to one would come back to rcs-as and be refused as a
// loop, again at every retry of a message for it (security review on
// #279).
func (s *Server) invitees(entries []resourcelists.Entry) []group.Invitee {
	var out []group.Invitee
	for _, e := range entries {
		if u, err := sip.ParseURI(e.URI); err == nil && s.forGroup(u) {
			s.cfg.Metrics.Count("sip.group.invitee_skipped", 1)
			continue
		}
		out = append(out, group.Invitee{Identity: e.URI, DisplayName: e.DisplayName})
	}
	return out
}

// routeGroup serves a group chat's request outside a session: an INVITE
// that creates the group or joins it. The conference event package and
// REFER come in a later part of #137.
func (s *Server) routeGroup(r *proxy.Request) proxy.Decision {
	if r.Message.Method == "INVITE" {
		return proxy.Decision{Serve: s.groupInvite}
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
	conv, ok := groupConversation(req)
	if !ok {
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
		invitees = s.invitees(entries)
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
			Subject: req.Header.Get("Subject"), Conversation: conv.ID, Contribution: conv.Contribution,
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
		go s.establish(g, conv)
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
		errors.Is(err, group.ErrTooMany), errors.Is(err, group.ErrRateLimited), errors.Is(err, group.ErrTaken):
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

// establish makes a new group last once its creator has its session
// (group.Service.Established): until then a CANCEL, or a failure after
// the group was stored, leaves a group that ends on its own, and that the
// creator's next INVITE under the same Contribution-ID takes up again.
// Then the focus invites the invitees.
func (s *Server) establish(g groupstore.Group, conv messaging.Conversation) {
	ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
	err := s.groups.Established(ctx, g.URI)
	cancel()
	if err != nil {
		s.cfg.Metrics.Count("sip.group.establish_failed", 1)
	}
	s.inviteAll(g, conv)
}

// inviteAll has the focus invite each participant g holds invited, once
// its creator's session is set up: through the engine, which counts the
// invitation, so that a message queued meanwhile waits for that session
// rather than ringing the participant again.
func (s *Server) inviteAll(g groupstore.Group, conv messaging.Conversation) {
	for _, p := range g.Participants {
		if p.State != groupstore.Invited {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
		s.engine.Invite(ctx, messaging.Invitation{
			Recipient: p.Identity, Peer: g.URI, Mode: store.Group, Subject: g.Subject, Referrer: g.Creator,
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

// left records that a participant left its group by its BYE (Leave).
func (s *Server) left(ctx context.Context, ss *session) {
	if err := s.groups.Leave(ctx, ss.group, ss.user); err != nil {
		s.cfg.Metrics.Count("sip.group.leave_failed", 1)
		return
	}
	s.cfg.Metrics.Count("sip.group.left", 1)
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

// RosterChanged implements group.Notifier. Subscriptions to the conference
// event package (RFC 4575) come in a later part of #137; until then a
// roster change is sent to no one.
func (s *Server) RosterChanged(context.Context, group.RosterUpdate) {}
