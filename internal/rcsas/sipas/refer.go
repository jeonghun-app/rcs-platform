package sipas

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/resourcelists"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
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
	w := s.respondReferred(u, req, ss)
	if remove {
		s.cfg.Metrics.Count("sip.group.removed", 1)
		if removed, ok := messaging.UserOf(who[0].Identity, s.cfg.HomeDomain); ok {
			s.removed(ss.group, removed)
		}
		w.finish(true)
		return
	}
	s.cfg.Metrics.Count("sip.group.added", 1)
	go s.inviteAdded(ss.group, who, ss.conversation, ss.user, w)
}

// respondReferred answers a REFER 202. Unless it asked for no implicit
// subscription (RFC 4488 §4), as rcsjta does, the subscription starts with
// a NOTIFY of "SIP/2.0 100 Trying" (RFC 3515 §2.4.4) and ends with the
// outcome of what the REFER asked for, which the returned referWatch
// reports; nil when there is none. The outcome is only 200 or 480, never
// the invitee's own answer, which would tell the referrer whether a number
// is a subscriber and whether it is online (security review on #340).
func (s *Server) respondReferred(u *proxy.UAS, req *sip.Request, ss *session) *referWatch {
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
		return nil
	}
	if noSub {
		return nil
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return nil
	}
	w := &referWatch{ss: ss, event: sip.Event{Type: "refer"}}
	w.event.Params.Set("id", strconv.FormatUint(uint64(cseq.Seq), 10))
	active := sip.SubscriptionState{State: "active"}
	active.Params.Set("expires", strconv.Itoa(int(referWait/time.Second)))
	// The outcome may never come, as for an invitation the engine does
	// not send; the subscription ends all the same. The bound is armed
	// before the first NOTIFY, so that it runs from the 202.
	w.mu.Lock()
	w.timer = s.cfg.Clock.AfterFunc(referWait, func() { w.finish(false) })
	w.mu.Unlock()
	w.send(active, 100)
	return w
}

// referWait bounds a REFER's implicit subscription: longer than the
// focus's INVITE may ring (RCSAS_ANSWER_TIMEOUT) and be cancelled.
const referWait = 2 * time.Minute

// referWatch is the implicit subscription of a REFER (RFC 3515): it ends
// with a NOTIFY of the outcome, for an addition of one person the
// outcome of the focus's INVITE.
type referWatch struct {
	ss    *session
	event sip.Event
	// mu guards timer, which its own callback may read before AfterFunc
	// has returned.
	mu    sync.Mutex
	timer msrp.Timer
	once  sync.Once
	// key is where watchRefer filed it, "" if nowhere; gone, that it has
	// ended and is not to be filed. Both are under the Server's mu.
	key  string
	gone bool
	// refused is set by an answer to one of its NOTIFYs that ends the
	// subscription (RFC 6665 §4.2.2), or its timeout: from then on it sends
	// none, its outcome either (#429).
	refused atomic.Bool
}

// send sends a NOTIFY of code as a sipfrag in the referrer's session,
// unless the referrer has ended the subscription by its answer to one, and
// reports whether it did.
func (w *referWatch) send(state sip.SubscriptionState, code int) bool {
	ss := w.ss
	if w.refused.Load() {
		ss.s.cfg.Metrics.Count("sip.refer.notify_after_refusal", 1)
		return false
	}
	frag := fmt.Sprintf("SIP/2.0 %d %s\r\n", code, sip.DefaultReason(code))
	ss.mu.Lock()
	if ss.ended {
		ss.mu.Unlock()
		return false
	}
	notify, err := ss.d.Notify(w.event, state, "message/sipfrag", []byte(frag), ss.s.ids)
	next := ss.d.NextHop()
	ss.mu.Unlock()
	if err != nil {
		return false
	}
	ss.s.sendInDialogThen(notify, next, func(res *sip.Response, err error) {
		if !(errors.Is(err, transaction.ErrTimeout) || err == nil && endsSubscription(res.StatusCode)) {
			return
		}
		// The watch stays filed until its outcome or its bound ends it as
		// usual (finish), which then sends nothing.
		w.refused.Store(true)
		ss.s.cfg.Metrics.Count("sip.refer.notify_failed", 1)
	})
	return true
}

// finish ends the subscription, once, with "200 OK" if what the REFER
// asked for came about and "480 Temporarily Unavailable" for any failure,
// a timeout included; nil does nothing.
func (w *referWatch) finish(ok bool) {
	if w == nil {
		return
	}
	code := 480
	if ok {
		code = 200
	}
	w.once.Do(func() {
		w.mu.Lock()
		timer := w.timer
		w.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		w.ss.s.unwatchRefer(w)
		if w.send(terminated("noresource"), code) {
			w.ss.s.cfg.Metrics.Count("sip.refer.notified", 1)
		}
	})
}

// watchRefer has w told the outcome of the focus's INVITE to who in the
// group uri (referDone).
func (s *Server) watchRefer(uri, who string, w *referWatch) {
	if w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.gone {
		return
	}
	k := uri + "\x00" + who
	w.key = k
	s.refers[k] = append(s.refers[k], w)
}

// unwatchRefer forgets w, ended by its bound or told already, so that
// REFERs whose INVITE never comes are not kept.
func (s *Server) unwatchRefer(w *referWatch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.gone = true
	if w.key == "" {
		return
	}
	ws := slices.DeleteFunc(s.refers[w.key], func(x *referWatch) bool { return x == w })
	if len(ws) == 0 {
		delete(s.refers, w.key)
	} else {
		s.refers[w.key] = ws
	}
	w.key = ""
}

// referDone tells the REFERs that asked for the focus's INVITE to who in
// the group uri whether it set up a session.
func (s *Server) referDone(uri, who string, ok bool) {
	if uri == "" {
		return // a 1-to-1 session: no REFER waits for it
	}
	s.mu.Lock()
	k := uri + "\x00" + who
	ws := s.refers[k]
	delete(s.refers, k)
	s.mu.Unlock()
	for _, w := range ws {
		w.finish(ok)
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
func (s *Server) inviteAdded(uri string, who []group.Invitee, conv messaging.Conversation, referrer string, w *referWatch) {
	ctx, cancel := context.WithTimeout(context.Background(), groupTimeout)
	g, err := s.groups.Get(ctx, uri)
	cancel()
	if err != nil {
		s.cfg.Metrics.Count("sip.group.invite_failed", 1)
		w.finish(false)
		return
	}
	invited := map[string]bool{}
	for _, in := range who {
		if id, ok := messaging.UserOf(in.Identity, s.cfg.HomeDomain); ok {
			invited[id] = true
		}
	}
	// A REFER for one person learns how the focus's INVITE ended; one for
	// a list, or for someone in the group already, learns that the
	// additions were made.
	if p, ok := oneInvited(g, invited); ok {
		s.watchRefer(uri, p, w)
	} else {
		w.finish(true)
	}
	s.inviteInvited(g, conv, invited, referrer)
}

// oneInvited is the one participant of only that g holds invited, if only
// names one.
func oneInvited(g groupstore.Group, only map[string]bool) (string, bool) {
	if len(only) != 1 {
		return "", false
	}
	for id := range only {
		if p, ok := g.Participant(id); ok && p.State == groupstore.Invited {
			return id, true
		}
	}
	return "", false
}
