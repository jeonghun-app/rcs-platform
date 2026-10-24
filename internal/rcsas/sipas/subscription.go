package sipas

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// conferenceEvent is the conference event package (RFC 4575 §3).
const conferenceEvent = "conference"

// The bounds of a subscription's duration, in seconds (RFC 6665 §4.2.1.1):
// a SUBSCRIBE without Expires gets the longest; one for less than the
// shortest is answered 423 with Min-Expires.
const (
	maxSubscriptionExpires = 3600
	minSubscriptionExpires = 60
)

// DefaultMaxSubscriptionsPerUser bounds the subscriptions one user holds
// on a task across all its groups, so that one account cannot take the
// task's whole share (Config.MaxSessions) from everyone else (security
// review on #340): a user in many groups subscribes once in each.
const DefaultMaxSubscriptionsPerUser = 32

// MaxSubscriptionsPerParticipant bounds the subscriptions one participant
// holds to one group: one per device it is signed in on, a few at most.
// The subscriptions of a task are bounded by Config.MaxSessions, apart from
// its sessions.
const MaxSubscriptionsPerParticipant = 4

// The reasons a subscription ends with (RFC 6665 §4.1.3): its subscriber
// left or was removed and may not subscribe again; the task is stopping,
// and the subscriber may subscribe again at once, to another; its time ran
// out, or the subscriber ended it.
const (
	reasonRejected    = "rejected"
	reasonDeactivated = "deactivated"
	reasonTimeout     = "timeout"
)

// subscription is a participant's subscription to its group's conference
// event package (RFC 4575), which rcs-as, the focus, notifies. Its state is
// in this task's memory only, on the task that owns the group (#121): a
// task that loses the group ends it (deactivated) for the client to
// subscribe again through the owner. The
// fields below mu are guarded by it; holding it while a NOTIFY is built and
// handed to the transaction layer keeps each subscription's NOTIFYs in the
// order of their versions.
type subscription struct {
	s *Server
	// group is the conference URI, user the subscriber, as the group
	// names it, and event the Event the SUBSCRIBE named, which every NOTIFY
	// repeats with its id.
	group, user string
	event       sip.Event

	mu sync.Mutex
	d  *dialog.Dialog
	// version is the roster version the subscriber has, from the last
	// NOTIFY: a change at or below it is in what it has already.
	version uint32
	// stale is set when a NOTIFY failed but the subscription stands: the
	// subscriber lacks a document, and the next change sends it all.
	stale   bool
	expires time.Time
	timer   msrp.Timer
	// armed counts arm's calls, so that a timer superseded by a refresh
	// that ran first knows it.
	armed uint64
	ended bool
	// refused is set by the answer to a NOTIFY that ends the subscription,
	// on the transaction's goroutine, before the subscription is removed
	// under mu: from then on no NOTIFY goes, though a change may come in
	// between (RFC 6665 §4.2.2, #423).
	refused atomic.Bool
}

func (sub *subscription) key() string { return sub.group + "\x00" + sub.user }

var errTooManySubscriptions = errors.New("sipas: too many subscriptions")

// addSubscription makes sub reachable by the requests in its dialog and by
// RosterChanged, within the bounds; it needs sub.mu, which keeps any
// NOTIFY from it until its first.
func (s *Server) addSubscription(sub *subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return errClosing
	case s.subsOf[sub.key()] >= MaxSubscriptionsPerParticipant:
		s.cfg.Metrics.Count("sip.subscription.user_limit", 1)
		return errUserSessions
	case s.subsOf[sub.user] >= s.cfg.MaxSubscriptionsPerUser:
		// Before the task's bound, so that a user who filled the task
		// hears it is its own bound (security review on #340).
		s.cfg.Metrics.Count("sip.subscription.user_limit", 1)
		return errUserSessions
	case len(s.subs) >= s.cfg.MaxSessions:
		s.cfg.Metrics.Count("sip.subscription.task_limit", 1)
		return errTooManySubscriptions
	}
	s.subs[sub.d.ID()] = sub
	s.subsOf[sub.key()]++
	s.subsOf[sub.user]++
	if s.groupSubs[sub.group] == nil {
		s.groupSubs[sub.group] = map[*subscription]bool{}
	}
	s.groupSubs[sub.group][sub] = true
	return nil
}

func (s *Server) removeSubscription(sub *subscription) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subs[sub.d.ID()] != sub {
		return
	}
	delete(s.subs, sub.d.ID())
	for _, k := range []string{sub.key(), sub.user} {
		if s.subsOf[k]--; s.subsOf[k] <= 0 {
			delete(s.subsOf, k)
		}
	}
	delete(s.groupSubs[sub.group], sub)
	if len(s.groupSubs[sub.group]) == 0 {
		delete(s.groupSubs, sub.group)
	}
}

// subscriptionsOf are the subscriptions to the group uri, of user alone
// when it is not empty.
func (s *Server) subscriptionsOf(uri, user string) []*subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*subscription
	for sub := range s.groupSubs[uri] {
		if user == "" || sub.user == user {
			out = append(out, sub)
		}
	}
	return out
}

// subscriptionOf finds the subscription of a request the subscriber sent
// in its dialog.
func (s *Server) subscriptionOf(req *sip.Request) *subscription {
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	if err1 != nil || err2 != nil {
		return nil
	}
	id := req.Header.Get("Call-ID") + "\x00" + strings.ToLower(to.Tag()) + "\x00" + strings.ToLower(from.Tag())
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subs[id]
}

// subscriptionExpires is the duration a SUBSCRIBE asks for, within the
// bounds, or the status that refuses it: 423 below the shortest (RFC 6665
// §4.2.1.1), 400 for an Expires that does not read. Zero is a fetch, or the
// end of a subscription.
func subscriptionExpires(req *sip.Request) (uint32, int) {
	if !req.Header.Has("Expires") {
		return maxSubscriptionExpires, 0
	}
	n, err := req.Header.Expires()
	switch {
	case err != nil && n == 0:
		return 0, 400
	case n == 0:
		return 0, 0
	case n < minSubscriptionExpires:
		return 0, 423
	}
	return min(n, maxSubscriptionExpires), 0
}

// groupSubscribe serves a participant's SUBSCRIBE to its group's
// conference event package (RFC 4575 §4): 200, and a first NOTIFY with the
// full roster (group.Service.Roster), then a NOTIFY with each change
// (RosterChanged). Only a current participant may subscribe: the roster
// says who talks to whom. A SUBSCRIBE with Expires 0 fetches the roster
// once.
func (s *Server) groupSubscribe(ctx context.Context, u *proxy.UAS) {
	req := u.Request().Message
	if s.groups == nil {
		s.respond(u, req, 404)
		return
	}
	if s.refuseUnsupported(u, req) {
		return
	}
	event, err := req.Header.Event()
	if err != nil || !strings.EqualFold(event.Type, conferenceEvent) {
		// 489 Bad Event names the packages served (RFC 6665 §8.3.1).
		s.cfg.Metrics.Count("sip.subscription.bad_event", 1)
		s.respondWith(u, req, 489, [2]string{"Allow-Events", conferenceEvent})
		return
	}
	if !acceptsConferenceInfo(req) {
		s.respondWith(u, req, 406, [2]string{"Accept", conference.ContentType})
		return
	}
	who, _, code := s.asserted(req)
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	uri, ok := s.conferenceURI(req.URI)
	if !ok {
		s.respond(u, req, 404)
		return
	}
	expires, code := subscriptionExpires(req)
	if code == 423 {
		s.respondWith(u, req, 423, [2]string{"Min-Expires", strconv.Itoa(minSubscriptionExpires)})
		return
	}
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	tag, err := s.ids.Tag()
	if err != nil {
		return // the proxy answers 500
	}
	// The dialog's local target, the Contact of every message in it, the
	// NOTIFYs and the refreshes' 200s too (focusContact).
	focus, err := sip.ParseURI(focusContact(uri))
	if err != nil {
		s.respond(u, req, 404)
		return
	}
	d, err := dialog.UAS(req, tag, focus)
	if err != nil {
		s.respond(u, req, 400)
		return
	}
	sub := &subscription{s: s, group: uri, user: who, event: event, d: d}
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if expires > 0 {
		// Known before the roster is read, so that a change made
		// meanwhile reaches it: after the first NOTIFY, as sub.mu holds
		// it until then, and only if the roster read did not have it.
		if err := s.addSubscription(sub); err != nil {
			s.refuseRoom(u, req, err)
			return
		}
	}
	rctx, cancel := context.WithTimeout(ctx, groupTimeout)
	doc, version, err := s.groups.Roster(rctx, uri, who)
	cancel()
	if err != nil {
		if expires > 0 {
			sub.ended = true
			s.removeSubscription(sub)
		}
		s.refuseGroup(u, req, err)
		return
	}
	res, err := dialogResponse(req, 200, tag)
	if err == nil {
		err = errors.Join(res.Header.Add("Expires", strconv.Itoa(int(expires))),
			res.Header.Add("Contact", sip.Address{URI: focus}.String()))
	}
	if err == nil {
		err = u.Respond(res)
	}
	if err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
		if expires > 0 {
			sub.ended = true
			s.removeSubscription(sub)
		}
		return
	}
	sub.version = version
	if expires == 0 {
		s.cfg.Metrics.Count("sip.subscription.fetched", 1)
		sub.ended = true
		sub.notify(terminated(reasonTimeout), doc)
		return
	}
	s.cfg.Metrics.Count("sip.subscription.started", 1)
	sub.arm(expires)
	sub.notify(sub.active(), doc)
}

// acceptsConferenceInfo reports whether req's Accept, if any, takes the
// conference-info documents of the package (RFC 4575 §4.3).
func acceptsConferenceInfo(req *sip.Request) bool {
	values := req.Header.Values("Accept")
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			mt, _, _ := strings.Cut(strings.TrimSpace(t), ";")
			if strings.EqualFold(strings.TrimSpace(mt), conference.ContentType) || strings.TrimSpace(mt) == "*/*" {
				return true
			}
		}
	}
	return false
}

// resubscribe serves a SUBSCRIBE in a subscription's dialog: a refresh,
// answered with the full roster as the first NOTIFY is, since a refresh is
// how a subscriber that saw a gap in the versions catches up (RFC 4575
// §4.6); or, with Expires 0, its end (RFC 6665 §4.1.2.3).
func (s *Server) resubscribe(ctx context.Context, u *proxy.UAS, sub *subscription, req *sip.Request) {
	expires, code := subscriptionExpires(req)
	if code == 423 {
		s.respondWith(u, req, 423, [2]string{"Min-Expires", strconv.Itoa(minSubscriptionExpires)})
		return
	}
	if code != 0 {
		s.respond(u, req, code)
		return
	}
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.ended {
		s.respond(u, req, 481)
		return
	}
	if expires == 0 {
		s.respondExpires(u, req, sub, 0)
		sub.end(reasonTimeout)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, groupTimeout)
	doc, version, err := s.groups.Roster(rctx, sub.group, sub.user)
	cancel()
	if err != nil {
		s.refuseGroup(u, req, err)
		if errors.Is(err, group.ErrNotParticipant) || errors.Is(err, group.ErrNoGroup) {
			sub.end(reasonRejected)
		}
		return
	}
	s.respondExpires(u, req, sub, expires)
	s.cfg.Metrics.Count("sip.subscription.refreshed", 1)
	// The full roster brings a stale subscription up to date too.
	sub.version, sub.stale = version, false
	sub.arm(expires)
	sub.notify(sub.active(), doc)
}

func (s *Server) respondExpires(u *proxy.UAS, req *sip.Request, sub *subscription, expires uint32) {
	res, err := sip.NewResponse(req, 200, "", sub.d.LocalTag())
	if err == nil {
		err = errors.Join(res.Header.Add("Expires", strconv.Itoa(int(expires))),
			res.Header.Add("Contact", sip.Address{URI: sub.d.LocalTarget}.String()))
	}
	if err == nil {
		err = u.Respond(res)
	}
	if err != nil {
		s.cfg.Metrics.Count("sip.respond_failed", 1)
	}
}

// RosterChanged implements group.Notifier: each subscription to the group
// gets the change in a NOTIFY, unless it has it already. One that would
// see a gap in the versions, as when two changes race to it, gets the full
// roster instead, so that no subscriber is left to find the gap itself.
//
// The subscriptions that need the full roster share one read of the group
// per change (code review on #340). A subscription whose subscriber the
// change took out of the group (RosterUpdate.Departed) ends with it, under
// the same lock, so that it gets no later change.
func (s *Server) RosterChanged(ctx context.Context, up group.RosterUpdate) {
	full := &sharedRoster{s: s, uri: up.Group}
	for _, sub := range s.subscriptionsOf(up.Group, "") {
		sub.changed(ctx, up, full)
	}
}

// sharedRoster reads a group's full roster once, for every subscription
// of one change that needs it.
type sharedRoster struct {
	s    *Server
	uri  string
	read bool
	g    groupstore.Group
	doc  []byte
	err  error
}

func (r *sharedRoster) get(ctx context.Context) (groupstore.Group, []byte, error) {
	if !r.read {
		r.read = true
		rctx, cancel := context.WithTimeout(ctx, groupTimeout)
		r.g, r.doc, r.err = r.s.groups.FullRoster(rctx, r.uri)
		cancel()
	}
	return r.g, r.doc, r.err
}

func (sub *subscription) changed(ctx context.Context, up group.RosterUpdate, full *sharedRoster) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	switch {
	case sub.ended || up.Version <= sub.version && !sub.stale:
	case !sub.stale && (up.Full || up.Version == sub.version+1):
		sub.version = up.Version
		sub.notify(sub.active(), up.Document)
	default:
		g, doc, err := full.get(ctx)
		p, member := g.Participant(sub.user)
		switch {
		case errors.Is(err, group.ErrNoGroup) || err == nil && (!member || !p.State.Active()):
			sub.end(reasonRejected)
			return
		case err != nil:
			// The next change, or the subscriber's refresh, brings it
			// up to date.
			sub.s.cfg.Metrics.Count("sip.subscription.roster_failed", 1)
			return
		case g.Version > sub.version || sub.stale:
			sub.s.cfg.Metrics.Count("sip.subscription.resynced", 1)
			sub.version, sub.stale = g.Version, false
			sub.notify(sub.active(), doc)
		}
	}
	if !sub.ended && slices.Contains(up.Departed, sub.user) {
		sub.end(reasonRejected)
	}
}

// endSubscriptions ends the subscriptions of user to the group uri with
// reason: it left or was removed (docs/rcs-as.md), so that it learns no
// later change.
func (s *Server) endSubscriptions(uri, user, reason string) {
	for _, sub := range s.subscriptionsOf(uri, user) {
		sub.mu.Lock()
		if !sub.ended {
			sub.end(reason)
		}
		sub.mu.Unlock()
	}
}

// active is the state of a subscription in force, with the seconds left
// (RFC 6665 §4.1.3); it needs sub.mu.
func (sub *subscription) active() sip.SubscriptionState {
	st := sip.SubscriptionState{State: "active"}
	left := max(int64(sub.expires.Sub(sub.s.cfg.Clock.Now())/time.Second), 0)
	st.Params.Set("expires", strconv.FormatInt(left, 10))
	return st
}

func terminated(reason string) sip.SubscriptionState {
	st := sip.SubscriptionState{State: "terminated"}
	st.Params.Set("reason", reason)
	return st
}

// arm runs the subscription for expires seconds from now; it needs sub.mu.
func (sub *subscription) arm(expires uint32) {
	if sub.timer != nil {
		sub.timer.Stop()
	}
	d := time.Duration(expires) * time.Second
	sub.expires = sub.s.cfg.Clock.Now().Add(d)
	sub.armed++
	armed := sub.armed
	sub.timer = sub.s.cfg.Clock.AfterFunc(d, func() {
		sub.mu.Lock()
		defer sub.mu.Unlock()
		// A refresh that came while this waited for the lock armed the
		// subscription again, and this timer no longer counts (code
		// review on #340).
		if !sub.ended && sub.armed == armed {
			sub.s.cfg.Metrics.Count("sip.subscription.expired", 1)
			sub.end(reasonTimeout)
		}
	})
}

// end ends the subscription with a last NOTIFY that says why, without a
// document; it needs sub.mu. What it returns is closed once that NOTIFY is
// answered, or was not sent.
func (sub *subscription) end(reason string) <-chan struct{} {
	sub.ended = true
	if sub.timer != nil {
		sub.timer.Stop()
	}
	sub.s.removeSubscription(sub)
	sub.s.cfg.Metrics.Count("sip.subscription.ended."+reason, 1)
	return sub.notify(terminated(reason), nil)
}

// notify sends a NOTIFY in the subscription's dialog with state and doc, if
// any; it needs sub.mu. A NOTIFY that times out, or that is answered with
// one of the codes RFC 6665 §4.2.2 says end the subscription, or 430
// (RFC 5626 §5.3.2, the flow is gone), ends it without another: the
// subscriber is gone, and the next one it makes starts afresh. Any other
// failure, a 503 from a proxy whose queue is full say (RFC 5057 Table 1:
// a complaint about the transaction, not the usage), keeps the
// subscription, marked stale: the subscriber missed a document, so the
// next change brings it the full roster. What it returns is closed once
// the NOTIFY is answered, or was not sent.
func (sub *subscription) notify(state sip.SubscriptionState, doc []byte) <-chan struct{} {
	if sub.refused.Load() {
		// The subscriber has said the subscription is gone.
		sub.s.cfg.Metrics.Count("sip.subscription.notify_after_refusal", 1)
		return closedChan
	}
	contentType := ""
	if len(doc) > 0 {
		contentType = conference.ContentType
	}
	req, err := sub.d.Notify(sub.event, state, contentType, doc, sub.s.ids)
	if err != nil {
		sub.s.cfg.Metrics.Count("sip.subscription.notify_unsent", 1)
		return closedChan
	}
	sub.s.cfg.Metrics.Count("sip.subscription.notified", 1)
	return sub.s.sendInDialogThen(req, sub.d.NextHop(), func(res *sip.Response, err error) {
		if err == nil && res.StatusCode < 300 {
			return
		}
		gone := errors.Is(err, transaction.ErrTimeout) || err == nil && endsSubscription(res.StatusCode)
		if gone {
			// At once, before the removal below gets mu.
			sub.refused.Store(true)
		}
		sub.s.cfg.Metrics.Count("sip.subscription.notify_failed", 1)
		go func() {
			if hold := refusalTakesLock.Load(); hold != nil {
				(*hold)()
			}
			sub.mu.Lock()
			defer sub.mu.Unlock()
			switch {
			case sub.ended:
			case gone:
				sub.ended = true
				if sub.timer != nil {
					sub.timer.Stop()
				}
				sub.s.removeSubscription(sub)
			default:
				sub.s.cfg.Metrics.Count("sip.subscription.stale", 1)
				sub.stale = true
			}
		}()
	})
}

// refusalTakesLock, empty but in tests, runs as the answer to a failed
// NOTIFY goes to take the subscription's lock to remove or mark it: a test
// holds it there to show that nothing waits on the removal (#423). It is
// atomic since such a goroutine may outlive the test that set it.
var refusalTakesLock atomic.Pointer[func()]

// endsSubscription reports a final answer to a NOTIFY that ends its
// subscription: those of RFC 6665 §4.2.2, and 430 (RFC 5626 §5.3.2).
func endsSubscription(code int) bool {
	switch code {
	case 404, 405, 410, 416, 480, 481, 482, 483, 484, 485, 489, 501, 604, 430:
		return true
	}
	return false
}
