package sipas

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// refer serves a participant's REFER in its session with a group (RFC 4579
// §5.5, §5.11), as rcsjta sends it (GroupChatSession.inviteParticipants):
//
//   - Refer-To naming someone adds them (group.Service.Add), and the focus
//     invites them.
//   - Refer-To a cid: URI, with Require: multiple-refer and a resource list
//     as the body, adds everyone in it (RFC 5368), the list read no
//     further than a group holds besides its referrer.
//   - Refer-To naming a participant with method=BYE removes them (Remove),
//     which only the chairman may: their sessions with the group get a BYE
//     and their subscriptions end, so that they learn no later change.
//
// It is answered 202. With Refer-Sub: false (RFC 4488), which rcsjta
// sends, there is no implicit subscription; without it, the subscription
// ends at once with one NOTIFY: rcs-as does not report each invitation's
// outcome.
func (s *Server) refer(ctx context.Context, u *proxy.UAS, ss *session, req *sip.Request) {
	if s.refuseUnsupported(u, req, "multiple-refer", "norefersub") {
		return
	}
	targets := req.Header.Values("Refer-To")
	if len(targets) != 1 {
		s.respond(u, req, 400)
		return
	}
	target, err := sip.ParseAddress(targets[0])
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	var who []group.Invitee
	remove := false
	switch {
	case target.URI.Scheme == "cid":
		ct, err := req.Header.ContentType()
		if err != nil || !strings.EqualFold(ct.Type+"/"+ct.Subtype, resourcelists.ContentType) {
			s.respondWith(u, req, 415, [2]string{"Accept", resourcelists.ContentType})
			return
		}
		entries, skipped, err := resourcelists.Parse(req.Body, s.cfg.MaxGroupParticipants-1)
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
		// A bad entry is left out, as in a new group's list.
		s.cfg.Metrics.Count("sip.group.invitee_skipped.malformed", int64(skipped))
		who = s.invitees(entries)
	default:
		method, _ := target.URI.Param("method")
		remove = strings.EqualFold(method, "BYE")
		// The URI names the participant; its header components are no
		// part of who they are, and the group leaves out its parameters.
		id := target.URI
		id.Headers = nil
		who = []group.Invitee{{Identity: id.String(), DisplayName: target.DisplayName}}
		if !remove {
			// Nobody at the factory or the conference host is added
			// (invitees); a list with none left is refused by Add.
			who = s.invitees([]resourcelists.Entry{{URI: who[0].Identity, DisplayName: who[0].DisplayName}})
		}
	}
	if remove {
		err = s.groups.Remove(ctx, ss.group, ss.user, who[0].Identity)
	} else {
		err = s.groups.Add(ctx, ss.group, ss.user, who)
	}
	if err != nil {
		s.refuseGroup(u, req, err)
		return
	}
	s.respondReferred(u, req, ss)
	if remove {
		s.cfg.Metrics.Count("sip.group.removed", 1)
		if removed, ok := messaging.UserOf(who[0].Identity, s.cfg.HomeDomain); ok {
			s.removed(ss.group, removed)
		}
		return
	}
	s.cfg.Metrics.Count("sip.group.added", 1)
	go s.inviteAdded(ss.group, who, ss.conversation, ss.user)
}

// respondReferred answers a REFER 202 and, unless it asked for no implicit
// subscription (RFC 4488 §4), ends that subscription at once with a NOTIFY
// (RFC 3515 §2.4.4): rcs-as does not follow each invitation for the
// referrer, who learns of it from the roster.
func (s *Server) respondReferred(u *proxy.UAS, req *sip.Request, ss *session) {
	noSub := strings.EqualFold(strings.TrimSpace(req.Header.Get("Refer-Sub")), "false")
	ss.mu.Lock()
	tag := ss.d.LocalTag()
	ss.mu.Unlock()
	res, err := sip.NewResponse(req, 202, "", tag)
	if err == nil && noSub {
		err = res.Header.Add("Refer-Sub", "false")
	}
	if err == nil {
		err = u.Respond(res)
	}
	if err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		return
	}
	if noSub {
		return
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return
	}
	event := sip.Event{Type: "refer"}
	event.Params.Set("id", strconv.FormatUint(uint64(cseq.Seq), 10))
	ss.mu.Lock()
	notify, err := ss.d.Notify(event, terminated("noresource"), "message/sipfrag", []byte("SIP/2.0 200 OK\r\n"), s.ids)
	next := ss.d.NextHop()
	ss.mu.Unlock()
	if err == nil {
		s.sendInDialog(notify, next)
	}
}

// removed ends what the participant user removed from the group uri still
// has with it: its sessions, with a BYE, and its subscriptions.
func (s *Server) removed(uri, user string) {
	s.endSubscriptions(uri, user, reasonRejected)
	s.mu.Lock()
	var ended []*session
	for _, ss := range s.sessions {
		if ss.group == uri && ss.user == user {
			ended = append(ended, ss)
		}
	}
	s.mu.Unlock()
	for _, ss := range ended {
		ss.bye("")
	}
}

// inviteAdded has the focus invite those of who that the group now holds
// invited, as inviteAll does for a new group: someone already joined is
// left alone.
func (s *Server) inviteAdded(uri string, who []group.Invitee, conv messaging.Conversation, referrer string) {
	ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
	g, err := s.groups.Get(ctx, uri)
	cancel()
	if err != nil {
		s.cfg.Metrics.Count("sip.group.invite_failed", 1)
		return
	}
	invited := map[string]bool{}
	for _, in := range who {
		if id, ok := messaging.UserOf(in.Identity, s.cfg.HomeDomain); ok {
			invited[id] = true
		}
	}
	s.inviteInvited(g, conv, invited, referrer)
}
