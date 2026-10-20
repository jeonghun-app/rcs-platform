package pcscf

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// pcscf subscribes to the reg event of the users it serves (TS 24.229
// §5.2.3), so that it learns when the network ends a registration (§5.2.5.2)
// and stops serving it. The #16 plan E decisions shape it:
//
//   - one subscription per default public identity registered on this task,
//     kept while any flow of the task holds a registration of that user,
//     and ended with Expires: 0 once none does (decision 3);
//   - sent along the registration's Service-Route to the user's scscf
//     (§5.2.3 1B), decision 2), for max(2 × the registration's time left,
//     minSubscriptionExpires) (decision 4);
//   - a network deregistration removes the registrations it names and
//     leaves the flow open, so the client can register again over it
//     (decision 5).
//
// Subscriptions live in task memory, as registrations do: when the task
// ends, scscf's next NOTIFY fails and scscf ends the subscription.
const (
	regEvent = "reg"
	// minSubscriptionExpires is the least Expires a SUBSCRIBE asks for.
	minSubscriptionExpires = 1200 * time.Second
	// refreshLead is how long before it expires a subscription is
	// refreshed; one granted for less than twice that is refreshed half way
	// (§5.2.3).
	refreshLead = 600 * time.Second
	// resubscribeAfter is the least time between two SUBSCRIBEs that set up
	// a subscription of one identity, so that a notifier that refuses or
	// ends them at once cannot make pcscf send them in a loop. A failed or
	// ended subscription is set up again by the sweep once it has passed.
	resubscribeAfter = sweepInterval
	// refusedResubscribeAfter replaces it after a refusal that will not
	// change soon: a 4xx, 5xx or 6xx other than 408 and 481, or a
	// subscription ended as rejected, noresource or invariant (RFC 6665
	// §4.1.3).
	refusedResubscribeAfter = time.Hour
	// maxSubscribesPerSweep bounds the subscriptions one sweep sets up, so
	// that after an outage of scscf the task does not send one SUBSCRIBE per
	// user at once.
	maxSubscribesPerSweep = 500
	// subscriptionPrefix starts the user part of a subscription's Contact.
	// A flow token is base64url, which has no dot, so the two never meet.
	subscriptionPrefix = "reg."
	// metricDeregistered counts the registrations a reg event NOTIFY ended.
	metricDeregistered = "regevent.deregistered"
)

// subscription is pcscf's subscription to the reg event of one user.
type subscription struct {
	// key is the default public identity as aorKey writes it, and impu the
	// identity.
	key  string
	impu sip.URI
	// id is the user part of the subscription's Contact, which the NOTIFYs
	// carry in their Request-URI.
	id string
	// subscribe is the SUBSCRIBE that set it up, and dialog the dialog its
	// first NOTIFY set up (RFC 6665 §4.4.1), nil until then.
	subscribe *sip.Request
	dialog    *dialog.Dialog
	// expires is when the subscription ends unless refreshed, and length
	// how long it was last granted for; zero until a 2xx or a NOTIFY says.
	expires time.Time
	length  time.Duration
	// version is the version of the last registration information
	// document, or -1 before the first (RFC 3680 §5.2).
	version int64
	// busy says a SUBSCRIBE of it is under way.
	busy bool
}

// subscriptions are this task's reg event subscriptions. Its methods are
// safe for concurrent use.
type subscriptions struct {
	mu    sync.Mutex
	byKey map[string]*subscription
	byID  map[string]*subscription
	// notBefore is when an identity may next get a new subscription.
	notBefore map[string]time.Time
	// ctx ends, and wg waits for, the SUBSCRIBEs being sent; once closed
	// no other is.
	ctx    context.Context
	wg     sync.WaitGroup
	closed bool
}

func newSubscriptions(ctx context.Context) *subscriptions {
	return &subscriptions{ctx: ctx, byKey: map[string]*subscription{}, byID: map[string]*subscription{}, notBefore: map[string]time.Time{}}
}

// goSend runs f, which sends a SUBSCRIBE, off the caller's goroutine: the
// caller is a REGISTER's response or the sweep, which must not wait for a
// lookup or a connection to scscf.
func (s *subscriptions) goSend(f func(ctx context.Context)) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		f(s.ctx)
	}()
}

// wait waits for the SUBSCRIBEs being sent. close stops any other: the
// sweep may still be running when the service stops.
func (s *subscriptions) wait() { s.wg.Wait() }

func (s *subscriptions) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
}

// dropLocked forgets sub, and keeps a new subscription of its identity
// back until after. mu must be held.
func (s *subscriptions) dropLocked(sub *subscription, after time.Time) {
	if s.byKey[sub.key] == sub {
		delete(s.byKey, sub.key)
	}
	delete(s.byID, sub.id)
	if after.After(s.notBefore[sub.key]) {
		s.notBefore[sub.key] = after
	}
}

func (s *subscriptions) drop(sub *subscription, after time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(sub, after)
}

// defaultIdentity is the default public identity of reg (RFC 7315 §4.1):
// the first P-Associated-URI, or the registered identity without one.
func defaultIdentity(reg *registration) sip.URI {
	if len(reg.associated) > 0 {
		return reg.associated[0].URI
	}
	return reg.uri
}

// defaultKey is defaultIdentity as aorKey writes it.
func defaultKey(reg *registration) string { return aorKey(defaultIdentity(reg)) }

// subscribeFor sets up the subscription of reg's user unless this task has
// one, or set one up too recently. It reports whether it started one.
func (p *pcscf) subscribeFor(reg *registration) bool {
	if p.subs == nil || p.send == nil || len(reg.serviceRoute) == 0 {
		return false
	}
	key := defaultKey(reg)
	now := p.now()
	p.subs.mu.Lock()
	if p.subs.byKey[key] != nil || now.Before(p.subs.notBefore[key]) {
		p.subs.mu.Unlock()
		return false
	}
	id, err := p.icid()
	if err != nil {
		p.subs.mu.Unlock()
		return false
	}
	sub := &subscription{key: key, impu: bare(defaultIdentity(reg)), id: subscriptionPrefix + id, version: -1, busy: true}
	p.subs.byKey[key], p.subs.byID[sub.id] = sub, sub
	p.subs.notBefore[key] = now.Add(resubscribeAfter)
	p.subs.mu.Unlock()
	p.subs.goSend(func(ctx context.Context) { p.startSubscription(ctx, sub, reg) })
	return true
}

// subscriptionExpires is how long a SUBSCRIBE for reg's user asks for.
func (p *pcscf) subscriptionExpires(reg *registration) time.Duration {
	return max(2*reg.expires.Sub(p.now()), minSubscriptionExpires).Truncate(time.Second)
}

// startSubscription sends the SUBSCRIBE that sets up sub (§5.2.3 1)):
// Request-URI and To the user's default public identity, From this pcscf,
// along the Service-Route of reg, with this task's Path URI for that
// registration as P-Asserted-Identity, which scscf checks against the Path
// it keeps, and a new charging identifier.
func (p *pcscf) startSubscription(ctx context.Context, sub *subscription, reg *registration) {
	contact := sip.URI{Scheme: "sip", User: sub.id, Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	contact.Params.Set("transport", "tcp")
	from := sip.Address{URI: sip.URI{Scheme: "sip", Host: p.cfg.PublicHost}}
	expires := p.subscriptionExpires(reg)
	req, err := dialog.Initial("SUBSCRIBE", sub.impu, from, sip.Address{URI: sub.impu}, reg.serviceRoute, contact, hostOf(p.cfg.CoreHost), p.ids)
	if err == nil {
		err = p.prepareSubscribe(req, reg, expires)
	}
	var dst transport.Destination
	if err == nil {
		dst, err = p.resolve.Resolve(ctx, reg.serviceRoute[0].URI)
	}
	if err != nil {
		p.subs.drop(sub, time.Time{})
		return
	}
	p.subs.mu.Lock()
	sub.subscribe = req
	p.subs.mu.Unlock()
	err = p.send(req, dst, func(res *sip.Response, err error) { p.subscribed(sub, res, err, true) })
	if err != nil {
		p.subs.drop(sub, time.Time{})
	}
}

// prepareSubscribe adds what every SUBSCRIBE of pcscf carries: the event,
// Expires, the document type it reads, the Path URI of reg as
// P-Asserted-Identity (§5.2.3 1) f)) and a P-Charging-Vector.
func (p *pcscf) prepareSubscribe(req *sip.Request, reg *registration, expires time.Duration) error {
	icid, err := p.icid()
	if err != nil {
		return err
	}
	path := p.pathURI(reg)
	for _, f := range [][2]string{
		{"Event", regEvent},
		{"Expires", strconv.Itoa(int(expires / time.Second))},
		{"Accept", reginfo.ContentType},
		{"P-Asserted-Identity", sip.Address{URI: path}.String()},
		{"P-Charging-Vector", p.chargingVector(icid)},
	} {
		if err := req.Header.Set(f[0], f[1]); err != nil {
			return err
		}
	}
	return nil
}

// subscribed takes the response to a SUBSCRIBE of sub, or its failure: a
// 2xx grants it for its Expires; a refusal or a failure ends it, unless the
// failure is of a SUBSCRIBE that set it up and a NOTIFY has set up its
// dialog already, which then stands (RFC 6665 §4.1.2.4).
func (p *pcscf) subscribed(sub *subscription, res *sip.Response, err error, initial bool) {
	if err == nil && res.StatusCode < 200 {
		return
	}
	now := p.now()
	p.subs.mu.Lock()
	defer p.subs.mu.Unlock()
	sub.busy = false
	switch {
	case err != nil:
		if !initial || sub.dialog == nil {
			p.subs.dropLocked(sub, now.Add(resubscribeAfter))
		}
	case res.StatusCode >= 300:
		// 408 is a failure, and 481 to a refresh says the notifier lost
		// the subscription, which a new one recovers (RFC 6665 §4.1.2.2).
		after := now.Add(resubscribeAfter)
		if res.StatusCode != 408 && res.StatusCode != 481 {
			after = now.Add(refusedResubscribeAfter)
		}
		p.subs.dropLocked(sub, after)
	default:
		secs, err := res.Header.Expires()
		if err != nil || secs == 0 {
			p.subs.dropLocked(sub, now.Add(resubscribeAfter))
			return
		}
		sub.length = time.Duration(secs) * time.Second
		sub.expires = now.Add(sub.length)
	}
}

// refreshDue reports whether sub is to be refreshed at now.
func refreshDue(sub *subscription, now time.Time) bool {
	return !sub.expires.IsZero() && !now.Before(sub.expires.Add(-min(refreshLead, sub.length/2)))
}

// reconcileSubscriptions brings the subscriptions in line with the
// registrations, on every sweep: it sets up the missing ones, refreshes the
// ones about to expire, and ends those of users with no registration left
// on this task, or forgets them if no NOTIFY ever set up their dialog.
func (p *pcscf) reconcileSubscriptions() {
	if p.subs == nil {
		return
	}
	live := p.registry.defaults()
	now := p.now()
	var refresh, end []*subscription
	p.subs.mu.Lock()
	for key, t := range p.subs.notBefore {
		if !now.Before(t) {
			delete(p.subs.notBefore, key)
		}
	}
	for key, sub := range p.subs.byKey {
		_, registered := live[key]
		switch {
		case sub.busy:
		case !registered:
			p.subs.dropLocked(sub, time.Time{})
			if sub.dialog != nil {
				end = append(end, sub)
			}
		case sub.dialog == nil:
			if !sub.expires.IsZero() && !now.Before(sub.expires) {
				p.subs.dropLocked(sub, time.Time{})
			}
		case refreshDue(sub, now):
			sub.busy = true
			refresh = append(refresh, sub)
		}
	}
	p.subs.mu.Unlock()
	for _, sub := range end {
		p.subs.goSend(func(ctx context.Context) { p.resubscribe(ctx, sub, nil) })
	}
	for _, sub := range refresh {
		reg := live[sub.key]
		p.subs.goSend(func(ctx context.Context) { p.resubscribe(ctx, sub, reg) })
	}
	started := 0
	for _, reg := range live {
		if started == maxSubscribesPerSweep {
			break
		}
		if p.subscribeFor(reg) {
			started++
		}
	}
}

// resubscribe sends a SUBSCRIBE in sub's dialog: a refresh for reg's user,
// or with reg nil the end of the subscription (RFC 6665 §4.1.2.2,
// §4.1.2.3), whose NOTIFY is then answered 481, since sub is forgotten.
func (p *pcscf) resubscribe(ctx context.Context, sub *subscription, reg *registration) {
	p.subs.mu.Lock()
	expires := time.Duration(0)
	var path *registration
	if reg != nil {
		expires, path = p.subscriptionExpires(reg), reg
	}
	req, err := sub.dialog.Subscribe(sip.Event{Type: regEvent}, uint32(expires/time.Second), p.ids)
	next := sub.dialog.NextHop()
	p.subs.mu.Unlock()
	if err == nil && path != nil {
		err = p.prepareSubscribe(req, path, expires)
	} else if err == nil {
		err = p.prepareEnd(req)
	}
	var dst transport.Destination
	if err == nil {
		dst, err = p.resolve.Resolve(ctx, next)
	}
	if err == nil {
		err = p.send(req, dst, func(res *sip.Response, err error) {
			if reg != nil {
				p.subscribed(sub, res, err, false)
			}
		})
	}
	if err != nil && reg != nil {
		p.subs.drop(sub, p.now().Add(resubscribeAfter))
	}
}

// prepareEnd readies the SUBSCRIBE that ends a subscription: Expires: 0
// already, and a charging vector. Its user has no registration left, so it
// asserts no Path.
func (p *pcscf) prepareEnd(req *sip.Request) error {
	icid, err := p.icid()
	if err != nil {
		return err
	}
	return req.Header.Set("P-Charging-Vector", p.chargingVector(icid))
}

// ownURI reports whether u names this task's core listener: the
// Request-URI of a request the core sends pcscf itself, a NOTIFY of its
// subscriptions.
func (p *pcscf) ownURI(u sip.URI) bool {
	return u.IsSIP() && strings.HasPrefix(u.User, subscriptionPrefix) &&
		proxy.SameHost(u.Host, hostOf(p.cfg.CoreHost)) && u.Port == p.corePort
}

// serveNotify answers a request addressed to one of pcscf's subscriptions:
// a NOTIFY of the reg event in its dialog (RFC 6665 §4.1.3). The first
// sets up the dialog (§4.4.1). The registration information acts on the
// registrations of the subscription's user (§5.2.5.2), and a terminated
// subscription is forgotten, to be set up again by the sweep if the user
// is still registered.
func (p *pcscf) serveNotify(_ context.Context, u *proxy.UAS) {
	req := u.Request().Message
	code, info := p.acceptNotify(req)
	// A NOTIFY has a To tag, its dialog's; the tag given is for one
	// without, which is answered all the same.
	res, err := sip.NewResponse(req, code, "", p.mustTag())
	if err != nil {
		return
	}
	if code == 405 {
		_ = res.Header.Set("Allow", "NOTIFY")
	}
	_ = res.Header.Set("P-Charging-Vector", p.terminatingCharging(req, ""))
	_ = u.Respond(res)
	if info != nil {
		p.deregistered(info.key, info.doc)
	}
}

// mustTag is a To tag for a response to a request without one.
func (p *pcscf) mustTag() string {
	tag, err := p.ids.Tag()
	if err != nil {
		return "pcscf"
	}
	return tag
}

// notified is a registration information document to act on, for the
// subscription of key.
type notified struct {
	key string
	doc *reginfo.Info
}

// acceptNotify checks req against the subscription it names and takes it:
// its CSeq and target into the dialog, the document's version, and the end
// of the subscription. It returns the response code and the document to
// act on, if any. Nothing changes unless the code is 200.
func (p *pcscf) acceptNotify(req *sip.Request) (int, *notified) {
	if req.Method != "NOTIFY" {
		return 405, nil
	}
	if ev, err := req.Header.Event(); err != nil || !strings.EqualFold(ev.Type, regEvent) || ev.ID() != "" {
		return 489, nil
	}
	state, err := req.Header.SubscriptionState()
	if err != nil {
		return 400, nil
	}
	var doc *reginfo.Info
	if len(req.Body) > 0 {
		ct, err := req.Header.ContentType()
		if err != nil || !strings.EqualFold(ct.Type+"/"+ct.Subtype, reginfo.ContentType) {
			return 415, nil
		}
		if doc, err = reginfo.Parse(req.Body); err != nil {
			return 400, nil
		}
	}
	now := p.now()
	p.subs.mu.Lock()
	defer p.subs.mu.Unlock()
	sub := p.subs.byID[req.URI.User]
	if sub == nil {
		return 481, nil
	}
	var d *dialog.Dialog
	if sub.dialog == nil {
		if sub.subscribe == nil || !sameSubscription(sub.subscribe, req) {
			return 481, nil
		}
		if d, err = dialog.FromNotify(sub.subscribe, req); err != nil {
			return 400, nil
		}
	} else {
		c := *sub.dialog
		switch err := c.Accept(req); {
		case errors.Is(err, dialog.ErrNotInDialog):
			return 481, nil
		case errors.Is(err, dialog.ErrOutOfOrder):
			return 500, nil
		case err != nil:
			return 400, nil
		}
		d = &c
	}
	sub.dialog = d
	if secs, ok := state.Expires(); ok && !strings.EqualFold(state.State, "terminated") {
		sub.expires = now.Add(time.Duration(secs) * time.Second)
		if sub.length == 0 {
			sub.length = time.Duration(secs) * time.Second
		}
	}
	var out *notified
	if doc != nil && int64(doc.Version) > sub.version {
		sub.version = int64(doc.Version)
		out = &notified{key: sub.key, doc: doc}
	}
	if strings.EqualFold(state.State, "terminated") {
		p.subs.dropLocked(sub, now.Add(resubscribeDelay(state)))
	}
	return 200, out
}

// sameSubscription reports whether notify is in the subscription subscribe
// asked for: the same Call-ID, compared exactly, and its To tag the
// SUBSCRIBE's From tag, compared without case (RFC 6665 §4.4.1, RFC 3261
// §8.1.1.4, §7.3.1).
func sameSubscription(subscribe, notify *sip.Request) bool {
	from, err1 := subscribe.Header.From()
	to, err2 := notify.Header.To()
	return err1 == nil && err2 == nil && notify.Header.Get("Call-ID") == subscribe.Header.Get("Call-ID") &&
		to.Tag() != "" && strings.EqualFold(to.Tag(), from.Tag())
}

// resubscribeDelay is how long after a subscription ended a new one may be
// set up (RFC 6665 §4.1.3): never before resubscribeAfter, after its
// retry-after if longer, and after refusedResubscribeAfter if the notifier
// said a new one would fare no better.
func resubscribeDelay(state sip.SubscriptionState) time.Duration {
	switch strings.ToLower(state.Reason()) {
	case "rejected", "noresource", "invariant":
		return refusedResubscribeAfter
	}
	d := resubscribeAfter
	if secs, ok := state.RetryAfter(); ok {
		d = max(d, min(time.Duration(secs)*time.Second, refusedResubscribeAfter))
	}
	return d
}

// deregistered acts on a registration information document of the
// subscription of key (§5.2.5.2): a registration of this task whose
// identity the document ends, or all of whose contacts it ends, is removed,
// and an identity it ends is no longer one the registrations of that user
// may assert. The flows stay open (#16 plan E, decision 5).
func (p *pcscf) deregistered(key string, doc *reginfo.Info) {
	for _, reg := range p.registry.ofDefault(key) {
		ended, changed := endedBy(reg, doc)
		if ended {
			p.registry.remove(reg.flow, reg.aor)
			if p.metrics != nil {
				p.metrics.Count(metricDeregistered, 1)
			}
			continue
		}
		if changed != nil {
			p.registry.replace(reg, changed)
		}
	}
}

// endedBy reports what doc ends of reg: all of it, or else, in changed, a
// copy without the contacts and associated identities it ends; changed is
// nil when doc ends nothing.
func endedBy(reg *registration, doc *reginfo.Info) (ended bool, changed *registration) {
	contacts := slices.Clone(reg.contacts)
	associated := slices.Clone(reg.associated)
	for _, el := range doc.Registrations {
		aor, err := sip.ParseURI(el.AOR)
		if err != nil {
			continue
		}
		gone := func(c sip.Contact) bool {
			found := el.ByURI(c.URI)
			return len(found) > 0 && !slices.ContainsFunc(found, func(f reginfo.Contact) bool { return f.State == reginfo.ContactActive })
		}
		if sameIdentity(reg.uri, aor) {
			if el.State == reginfo.Terminated {
				return true, nil
			}
			contacts = slices.DeleteFunc(contacts, gone)
			continue
		}
		if el.State == reginfo.Terminated || len(reg.contacts) > 0 && !slices.ContainsFunc(reg.contacts, func(c sip.Contact) bool { return !gone(c) }) {
			associated = slices.DeleteFunc(associated, func(a sip.Address) bool { return sameIdentity(a.URI, aor) })
		}
	}
	if len(contacts) == 0 {
		return true, nil
	}
	if len(contacts) == len(reg.contacts) && len(associated) == len(reg.associated) {
		return false, nil
	}
	c := *reg
	c.contacts, c.associated = contacts, associated
	return false, &c
}

// sameIdentity reports whether a and b are the same public identity: the
// same URI without its parameters, compared as URIs (RFC 3261 §19.1.4, RFC
// 3966 §4), so that user=phone or another parameter one side writes does
// not tell them apart.
func sameIdentity(a, b sip.URI) bool {
	if a.Scheme != "tel" {
		a.Params = nil
	}
	if b.Scheme != "tel" {
		b.Params = nil
	}
	a.Headers, b.Headers = nil, nil
	return a.Equal(b)
}

// sender starts a client transaction: transaction.Layer.Request, through
// the proxy's layer, so that the responses come back to it.
type sender func(req *sip.Request, dst transport.Destination, h transaction.ResponseHandler) error
