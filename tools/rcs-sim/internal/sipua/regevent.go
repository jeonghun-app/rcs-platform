package sipua

import (
	"context"
	"encoding/xml"
	"errors"
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

// Contact returns the contact whose URI is uri, if the registration of aor
// lists it.
func (r *RegInfo) Contact(aor, uri string) (RegInfoContact, bool) {
	for _, reg := range r.Registrations {
		if reg.AOR != aor {
			continue
		}
		for _, c := range reg.Contacts {
			if c.URI == uri {
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
	var x xmlRegInfo
	if err := xml.Unmarshal(body, &x); err != nil {
		return nil, errors.New("sipua: the reginfo body is not RFC 3680 XML")
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
	// remote, remoteTarget and routes are the dialog's, from the 2xx or
	// the first NOTIFY, whichever comes first (RFC 6665 §4.1.2.4).
	remote       string
	remoteTarget sip.URI
	routes       []string
	cseq         uint32
	remoteCSeq   uint32
	ended        bool
	done         chan struct{}
}

// Notifications delivers each NOTIFY, in order.
func (s *Subscription) Notifications() <-chan Notification { return s.notifications }

// Done is closed once a NOTIFY has terminated the subscription.
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
	// The 2xx's Record-Route, reversed, is the route set (§12.1.2), unless
	// a NOTIFY set up the dialog first.
	var routes []string
	if rr, err := res.Header.RecordRoute(); err == nil {
		for _, a := range slices.Backward(rr) {
			routes = append(routes, a.String())
		}
	}
	s.establish(res.Header.Get("To"), res, routes)
	return s, res, nil
}

func subscriptionKey(callID, localTag string) string { return callID + "\x00" + localTag }

// establish takes the dialog's remote side from m, a 2xx or a NOTIFY, if no
// earlier message gave it.
func (s *Subscription) establish(remote string, m sip.Message, routes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.remote != "" {
		return
	}
	s.remote, s.routes = remote, routes
	s.remoteTarget = s.ua.cfg.IMPU
	if cs, err := m.Headers().Contact(); err == nil && len(cs) > 0 && !cs[0].Star {
		s.remoteTarget = cs[0].URI
	}
}

// Unsubscribe ends the subscription with a SUBSCRIBE of Expires: 0 in its
// dialog (RFC 6665 §4.1.2.3), and returns its final response. The NOTIFY
// that follows, terminated, closes Done.
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
	add(req, &err, "Event", "reg")
	add(req, &err, "Expires", "0")
	if err != nil {
		return nil, err
	}
	return s.ua.Send(ctx, req)
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

// receive answers a NOTIFY (RFC 6665 §4.1.3): 200, or 489 for another
// event package, 500 for a CSeq lower than the last. The first one sets
// up the dialog if the 2xx has not yet (§4.1.2.4), its Record-Route in
// order being the route set.
func (s *Subscription) receive(tx *transaction.ServerTransaction) {
	req := tx.Request()
	code := 200
	cseq, err := req.Header.CSeq()
	ev := strings.ToLower(strings.TrimSpace(strings.SplitN(req.Header.Get("Event"), ";", 2)[0]))
	s.mu.Lock()
	switch {
	case err != nil:
		code = 400
	case ev != "reg":
		code = 489
	case s.remoteCSeq != 0 && cseq.Seq <= s.remoteCSeq:
		code = 500
	default:
		s.remoteCSeq = cseq.Seq
	}
	s.mu.Unlock()
	if code == 200 {
		var routes []string
		if rr, err := req.Header.RecordRoute(); err == nil {
			for _, a := range rr {
				routes = append(routes, a.String())
			}
		}
		s.establish(req.Header.Get("From"), req, routes)
	}
	if res, err := sip.NewResponse(req, code, "", ""); err == nil {
		_ = tx.Respond(res)
	}
	if code != 200 {
		return
	}
	n := notification(req)
	select {
	case s.notifications <- n:
	default:
		s.Dropped.Add(1)
	}
	if n.State == "terminated" {
		s.mu.Lock()
		if !s.ended {
			s.ended = true
			close(s.done)
		}
		s.mu.Unlock()
		s.ua.forgetSubscription(s)
	}
}

// notification reads a NOTIFY's Subscription-State and body.
func notification(req *sip.Request) Notification {
	var n Notification
	parts := strings.Split(req.Header.Get("Subscription-State"), ";")
	n.State = strings.ToLower(strings.TrimSpace(parts[0]))
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "reason") {
			n.Reason = strings.ToLower(v)
		}
	}
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
