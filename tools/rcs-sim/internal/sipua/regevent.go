package sipua

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// RegEventExpires is the expiry a UE asks for its subscription to its own
// registration state (TS 24.229 §5.1.1.3).
const RegEventExpires = 600000

// queueLength bounds the notifications a Subscription holds unread.
const queueLength = 64

// Notification is one NOTIFY of a subscription (RFC 6665 §4.1.3).
type Notification struct {
	// State is the Subscription-State: "active", "pending" or
	// "terminated", with Reason for a terminated one ("deactivated",
	// "rejected", "timeout", "noresource", ...).
	State, Reason string
	// Info is the body, read by internal/sip/reginfo; nil without one. Err
	// says why a body could not be read, for the scenario to fail on: the
	// NOTIFY is answered 200 still.
	Info *reginfo.Info
	Err  error
}

// Subscription is this UA's subscription to the reg event of its own IMPU
// (RFC 3680, TS 24.229 §5.1.1.3). Its methods are safe for concurrent use.
type Subscription struct {
	ua            *UA
	key           string
	callID, local string
	notifications chan Notification
	// Dropped counts notifications that came while the queue was full.
	Dropped atomic.Int64

	mu sync.Mutex
	// remote, remoteTarget and routes are the dialog's. The NOTIFY sets
	// it up (RFC 6665 §4.4.1, TS 24.229 §5.1.1.3): the first one's
	// Record-Route is the route set, and each one's Contact the remote
	// target, as NOTIFY refreshes it (§3.2, RFC 3261 §12.2.2). Until a
	// NOTIFY has come, they are the 2xx's, so that an Unsubscribe then
	// still has a dialog to go in. notified is set at the first NOTIFY.
	remote       string
	remoteTarget sip.URI
	routes       []string
	notified     bool
	cseq         uint32
	remoteCSeq   uint32
	// remoteTag is the notifier's tag once the 2xx or a NOTIFY has given
	// it; seenCSeq says remoteCSeq holds a NOTIFY's, which may be 0.
	remoteTag string
	seenCSeq  bool
	ended     bool
	done      chan struct{}
}

// Notifications delivers each NOTIFY, in order.
func (s *Subscription) Notifications() <-chan Notification { return s.notifications }

// Done is closed once the subscription has ended: by a terminated NOTIFY,
// or by an answer to Unsubscribe that says it no longer exists.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// SubscribeRegEvent subscribes to the reg event of the UA's own IMPU and
// returns the subscription with the SUBSCRIBE's final response. A non-2xx
// returns no subscription and a *StatusError. The first NOTIFY, with the
// full state, may come before the 2xx or after it.
func (ua *UA) SubscribeRegEvent(ctx context.Context) (*Subscription, *sip.Response, error) {
	req, err := ua.NewRequest("SUBSCRIBE", ua.cfg.IMPU)
	if err != nil {
		return nil, nil, err
	}
	contact := sip.Contact{Address: sip.Address{URI: ua.contact.URI}}
	contact.URI.Params = slices.Clone(ua.contact.URI.Params)
	contact.URI.Params.SetFlag("ob")
	add(req, &err, "Contact", contact.String())
	add(req, &err, "Event", "reg")
	add(req, &err, "Accept", "application/reginfo+xml")
	add(req, &err, "Expires", strconv.Itoa(RegEventExpires))
	if err != nil {
		return nil, nil, err
	}
	from, err := req.Header.From()
	if err != nil {
		return nil, nil, err
	}
	callID := req.Header.Get("Call-ID")
	cseq, _ := req.Header.CSeq()
	s := &Subscription{
		ua: ua, key: subscriptionKey(callID, from.Tag()), callID: callID, local: req.Header.Get("From"),
		notifications: make(chan Notification, queueLength), cseq: cseq.Seq, done: make(chan struct{}),
	}
	// Kept before the SUBSCRIBE goes, so a NOTIFY that overtakes its 2xx
	// finds it.
	ua.mu.Lock()
	ua.subs[s.key] = s
	ua.mu.Unlock()
	res, err := ua.Send(ctx, req)
	switch {
	case err != nil:
		ua.forgetSubscription(s)
		return nil, nil, err
	case res.StatusCode >= 300:
		ua.forgetSubscription(s)
		return nil, res, &StatusError{Method: "SUBSCRIBE", Code: res.StatusCode}
	}
	// The 2xx's Record-Route, reversed (§12.1.2), stands in as the route
	// set until a NOTIFY gives its own.
	var routes []string
	if rr, err := res.Header.RecordRoute(); err == nil {
		for _, a := range slices.Backward(rr) {
			routes = append(routes, a.String())
		}
	}
	s.mu.Lock()
	if !s.notified {
		s.remote, s.routes, s.remoteTarget = res.Header.Get("To"), routes, contactOr(res, ua.cfg.IMPU)
		if to, err := res.Header.To(); err == nil {
			s.remoteTag = to.Tag()
		}
	}
	s.mu.Unlock()
	return s, res, nil
}

func subscriptionKey(callID, localTag string) string { return callID + "\x00" + localTag }

// contactOr is the URI of m's Contact, or def without a usable one.
func contactOr(m sip.Message, def sip.URI) sip.URI {
	if cs, err := m.Headers().Contact(); err == nil && len(cs) > 0 && !cs[0].Star {
		return cs[0].URI
	}
	return def
}

// fromNotify takes the dialog from a NOTIFY it accepted: all of it from
// the first, the remote target from every one.
func (s *Subscription) fromNotify(req *sip.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.notified {
		s.notified = true
		s.remote, s.routes, s.remoteTag = req.Header.Get("From"), nil, fromTag(req)
		if rr, err := req.Header.RecordRoute(); err == nil {
			for _, a := range rr {
				s.routes = append(s.routes, a.String())
			}
		}
		s.remoteTarget = s.ua.cfg.IMPU
	}
	s.remoteTarget = contactOr(req, s.remoteTarget)
}

// fromTag is the tag of req's From, or "".
func fromTag(req *sip.Request) string {
	from, err := req.Header.From()
	if err != nil {
		return ""
	}
	return from.Tag()
}

// end ends the subscription once.
func (s *Subscription) end() {
	s.mu.Lock()
	if !s.ended {
		s.ended = true
		close(s.done)
	}
	s.mu.Unlock()
	s.ua.forgetSubscription(s)
}

// Unsubscribe ends the subscription with a SUBSCRIBE of Expires: 0 in its
// dialog (RFC 6665 §4.1.2.3), and returns its final response. The NOTIFY
// that follows, terminated, closes Done. A non-2xx returns a *StatusError
// with it, as SubscribeRegEvent does; one that says the subscription no
// longer exists, 481 among them (§4.1.2.2), ends it at once. Before any
// NOTIFY it goes in the dialog the 2xx described.
func (s *Subscription) Unsubscribe(ctx context.Context) (*sip.Response, error) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return nil, ErrDialogEnded
	}
	s.cseq++
	d := &Dialog{ua: s.ua, callID: s.callID, local: s.local, remote: s.remote, remoteTarget: s.remoteTarget, routes: s.routes}
	req, err := d.request("SUBSCRIBE", s.cseq)
	s.mu.Unlock()
	// A target refresh request carries a Contact (RFC 3261 §12.2.1.1).
	contact := sip.Contact{Address: sip.Address{URI: s.ua.contact.URI}}
	contact.URI.Params = slices.Clone(s.ua.contact.URI.Params)
	contact.URI.Params.SetFlag("ob")
	add(req, &err, "Contact", contact.String())
	add(req, &err, "Event", "reg")
	add(req, &err, "Expires", "0")
	if err != nil {
		return nil, err
	}
	res, err := s.ua.Send(ctx, req)
	if err != nil {
		return nil, err
	}
	if subscriptionGone(res.StatusCode) {
		s.end()
	}
	if res.StatusCode >= 300 {
		return res, &StatusError{Method: "SUBSCRIBE", Code: res.StatusCode}
	}
	return res, nil
}

// subscriptionGone reports whether code, the answer to a SUBSCRIBE in the
// subscription's dialog, means the subscription has ended (RFC 6665
// §4.1.2.2).
func subscriptionGone(code int) bool {
	switch code {
	case 404, 405, 410, 416, 480, 481, 482, 483, 484, 485, 489, 501, 604:
		return true
	}
	return false
}

// subscriptionOf returns the subscription a NOTIFY belongs to: its Call-ID
// and its To tag, which is this side's.
func (ua *UA) subscriptionOf(req *sip.Request) *Subscription {
	if req.Method != "NOTIFY" {
		return nil
	}
	to, err := req.Header.To()
	if err != nil {
		return nil
	}
	ua.mu.Lock()
	defer ua.mu.Unlock()
	return ua.subs[subscriptionKey(req.Header.Get("Call-ID"), to.Tag())]
}

func (ua *UA) forgetSubscription(s *Subscription) {
	ua.mu.Lock()
	delete(ua.subs, s.key)
	ua.mu.Unlock()
}

// receive answers a NOTIFY (RFC 6665 §4.1.3): 200, or 400 without a
// Subscription-State it can read, 489 for another event package, 481 for
// an event id the SUBSCRIBE did not have (§8.2.1) or a From tag that is
// not the dialog's, 500 for a CSeq not above the last. Each one it accepts updates the dialog (fromNotify).
func (s *Subscription) receive(tx *transaction.ServerTransaction) {
	req := tx.Request()
	code := 200
	cseq, err := req.Header.CSeq()
	ev, evErr := req.Header.Event()
	state, stateErr := req.Header.SubscriptionState()
	s.mu.Lock()
	switch {
	case err != nil || evErr != nil || stateErr != nil:
		code = 400
	case !strings.EqualFold(ev.Type, "reg"):
		code = 489
	case ev.ID() != "":
		// The SUBSCRIBE had no id, and an event is matched by id too.
		code = 481
	case s.remoteTag != "" && fromTag(req) != s.remoteTag:
		// Another dialog: reg event subscriptions do not fork (RFC 3680
		// §4.9), and a NOTIFY that matches no subscription is 481
		// (RFC 6665 §4.1.3).
		code = 481
	case s.seenCSeq && cseq.Seq <= s.remoteCSeq:
		code = 500
	default:
		s.remoteCSeq, s.seenCSeq = cseq.Seq, true
	}
	s.mu.Unlock()
	if code == 200 {
		s.fromNotify(req)
	}
	if res, err := sip.NewResponse(req, code, "", ""); err == nil {
		_ = tx.Respond(res)
	}
	if code != 200 {
		return
	}
	n := notification(req, state)
	select {
	case s.notifications <- n:
	default:
		s.Dropped.Add(1)
	}
	if n.State == "terminated" {
		s.end()
	}
}

// notification reads a NOTIFY's body, with its Subscription-State.
func notification(req *sip.Request, state sip.SubscriptionState) Notification {
	n := Notification{State: strings.ToLower(state.State), Reason: strings.ToLower(state.Reason())}
	if len(req.Body) == 0 {
		return n
	}
	if ct, err := req.Header.ContentType(); err != nil || !strings.EqualFold(ct.Type+"/"+ct.Subtype, "application/reginfo+xml") {
		n.Err = errors.New("sipua: the NOTIFY's body is not application/reginfo+xml")
		return n
	}
	n.Info, n.Err = reginfo.Parse(req.Body)
	return n
}

// ContactURI is the URI of the UA's registered contact, as reginfo lists
// it.
func (ua *UA) ContactURI() sip.URI { return ua.contact.URI }
