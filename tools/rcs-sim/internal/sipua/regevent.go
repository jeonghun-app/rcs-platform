package sipua

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// RegEventExpires is the expiry a UE asks for its subscription to its own
// registration state (TS 24.229 §5.1.1.3).
const RegEventExpires = 600000

// queueLength bounds the notifications a Subscription holds unread.
const queueLength = 64

// RegInfo is the body of a reg event NOTIFY (RFC 3680 §5.3).
type RegInfo struct {
	// Version rises by one in each NOTIFY of a subscription (§5.3.1).
	Version uint64
	// State is "full" or "partial".
	State         string
	Registrations []RegInfoRegistration
}

// RegInfoRegistration is one address-of-record's registration.
type RegInfoRegistration struct {
	AOR, ID string
	// State is "init", "active" or "terminated".
	State    string
	Contacts []RegInfoContact
}

// RegInfoContact is one contact of a registration. Event says what changed
// it: "registered", "created", "refreshed", "shortened", "expired",
// "deactivated", "probation", "unregistered" or "rejected" (§5.3.2).
type RegInfoContact struct {
	ID, URI string
	// State is "active" or "terminated".
	State, Event string
	Expires      uint64
}

// Contact returns the contact whose URI equals uri (RFC 3261 §19.1.4), if
// the registration of aor lists it: the notifier writes the URI back, in
// its own parameter order and case.
func (r *RegInfo) Contact(aor, uri string) (RegInfoContact, bool) {
	want, err := sip.ParseURI(uri)
	if err != nil {
		return RegInfoContact{}, false
	}
	for _, reg := range r.Registrations {
		if reg.AOR != aor {
			continue
		}
		for _, c := range reg.Contacts {
			if got, err := sip.ParseURI(c.URI); err == nil && got.Equal(want) {
				return c, true
			}
		}
	}
	return RegInfoContact{}, false
}

// xmlRegInfo is RegInfo as RFC 3680 §5.4 writes it.
type xmlRegInfo struct {
	XMLName       xml.Name `xml:"urn:ietf:params:xml:ns:reginfo reginfo"`
	Version       uint64   `xml:"version,attr"`
	State         string   `xml:"state,attr"`
	Registrations []struct {
		AOR      string `xml:"aor,attr"`
		ID       string `xml:"id,attr"`
		State    string `xml:"state,attr"`
		Contacts []struct {
			ID      string `xml:"id,attr"`
			State   string `xml:"state,attr"`
			Event   string `xml:"event,attr"`
			Expires uint64 `xml:"expires,attr"`
			URI     string `xml:"uri"`
		} `xml:"contact"`
	} `xml:"registration"`
}

// ParseRegInfo reads an application/reginfo+xml body.
func ParseRegInfo(body []byte) (*RegInfo, error) {
	// As the platform's parsers do (and ft's decode): no document type
	// declaration, and nothing after the root element.
	if bytes.Contains(body, []byte("<!DOCTYPE")) {
		return nil, errors.New("sipua: the reginfo body has a document type declaration")
	}
	var x xmlRegInfo
	dec := xml.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&x); err != nil {
		return nil, errors.New("sipua: the reginfo body is not RFC 3680 XML")
	}
	if !onlyMiscAfter(dec) {
		return nil, errors.New("sipua: the reginfo body goes on after its root element")
	}
	if x.State != "full" && x.State != "partial" {
		return nil, errors.New("sipua: the reginfo state is neither full nor partial")
	}
	r := &RegInfo{Version: x.Version, State: x.State}
	for _, xr := range x.Registrations {
		reg := RegInfoRegistration{AOR: xr.AOR, ID: xr.ID, State: xr.State}
		for _, xc := range xr.Contacts {
			reg.Contacts = append(reg.Contacts, RegInfoContact{
				ID: xc.ID, URI: strings.TrimSpace(xc.URI), State: xc.State, Event: xc.Event, Expires: xc.Expires,
			})
		}
		r.Registrations = append(r.Registrations, reg)
	}
	return r, nil
}

// Notification is one NOTIFY of a subscription (RFC 6665 §4.1.3).
type Notification struct {
	// State is the Subscription-State: "active", "pending" or
	// "terminated", with Reason for a terminated one ("deactivated",
	// "rejected", "timeout", "noresource", ...).
	State, Reason string
	// Info is the body; nil without one. Err says why a body could not be
	// read, for the scenario to fail on: the NOTIFY is answered 200 still.
	Info *RegInfo
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
	ended        bool
	done         chan struct{}
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
		s.remote, s.routes = req.Header.Get("From"), nil
		if rr, err := req.Header.RecordRoute(); err == nil {
			for _, a := range rr {
				s.routes = append(s.routes, a.String())
			}
		}
		s.remoteTarget = s.ua.cfg.IMPU
	}
	s.remoteTarget = contactOr(req, s.remoteTarget)
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
// that follows, terminated, closes Done. An answer that says the
// subscription no longer exists, 481 among them (§4.1.2.2), ends it at
// once. Before any NOTIFY it goes in the dialog the 2xx described.
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
	if err == nil && subscriptionGone(res.StatusCode) {
		s.end()
	}
	return res, err
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
// an event id the SUBSCRIBE did not have (§8.2.1), 500 for a CSeq lower
// than the last. Each one it accepts updates the dialog (fromNotify).
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
	case s.remoteCSeq != 0 && cseq.Seq <= s.remoteCSeq:
		code = 500
	default:
		s.remoteCSeq = cseq.Seq
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

// onlyMiscAfter reports whether what dec has left after the root element
// is only white space, comments and processing instructions, as XML's
// Misc allows.
func onlyMiscAfter(dec *xml.Decoder) bool {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.Comment, xml.ProcInst:
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return false
			}
		default:
			return false
		}
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
	n.Info, n.Err = ParseRegInfo(req.Body)
	return n
}
