package pcscf

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
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
	// refusedResubscribeAfter replaces it, and the backoff of failures
	// stops there, after a refusal that will not change soon (refusedFor),
	// or a subscription ended as rejected, noresource or invariant (RFC
	// 6665 §4.1.3).
	refusedResubscribeAfter = time.Hour
	// timerN is how long after its SUBSCRIBE a subscription waits for the
	// NOTIFY that sets up its dialog before it has failed (RFC 6665
	// §4.1.2.4: 64*T1).
	timerN = 64 * transaction.DefaultT1
	// maxSubscribesPerSweep bounds the subscriptions one sweep sets up, and
	// maxRefreshesPerSweep the refreshes it sends, so that after an outage
	// of scscf the task does not send one SUBSCRIBE per user at once.
	maxSubscribesPerSweep = 500
	maxRefreshesPerSweep  = 500
	// subscriptionPrefix starts the user part of a subscription's Contact.
	// A flow token is base64url, which has no dot, so the two never meet.
	subscriptionPrefix = "reg."
	// metricDeregistered counts the registrations a reg event NOTIFY ended,
	// and metricSubscribeFailed the SUBSCRIBEs that failed, were refused
	// or got no NOTIFY: while they fail, the network cannot deregister
	// anyone through pcscf (security review of #239).
	metricDeregistered    = "regevent.deregistered"
	metricSubscribeFailed = "regevent.subscribe_failed"
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
	// requested is what its last SUBSCRIBE asked for.
	expires   time.Time
	length    time.Duration
	requested time.Duration
	// sent is when the SUBSCRIBE that set it up went, from which a NOTIFY
	// must come within timerN.
	sent time.Time
	// path is the Path URI its last SUBSCRIBE asserted, which the one that
	// ends it asserts again (§5.2.3).
	path sip.URI
	// refreshNow asks the next sweep to refresh it whatever its expiry: a
	// partial document skipped a version, and a refresh brings a full one
	// (RFC 3680 §5.2).
	refreshNow bool
	// retryAt holds a refresh back after one failed, by the backoff of
	// failLocked and the failure's Retry-After.
	retryAt time.Time
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
	// notBefore is when an identity may next get a new subscription, and
	// failures how many of its SUBSCRIBEs in a row failed, which sets the
	// backoff of the next.
	notBefore map[string]time.Time
	failures  map[string]int
	// seen is, by user, what the documents of the user's subscriptions
	// have shown active; it outlives a subscription, so that the first
	// full document of the next one can end what went meanwhile.
	seen map[string]*seenState
	// background sends the SUBSCRIBEs off the caller's goroutine: the
	// caller is a REGISTER's response or the sweep, which must not wait for
	// a lookup or a connection to scscf.
	background
}

func newSubscriptions(ctx context.Context) *subscriptions {
	return &subscriptions{background: background{ctx: ctx}, byKey: map[string]*subscription{}, byID: map[string]*subscription{},
		notBefore: map[string]time.Time{}, failures: map[string]int{}, seen: map[string]*seenState{}}
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

// failLocked forgets sub, which failed, and keeps a new subscription of its
// identity back by a backoff that doubles with each failure in a row from
// resubscribeAfter to refusedResubscribeAfter, or by at least wait. The
// registrations stay: a failed subscription deregisters no one. mu must be
// held.
func (p *pcscf) failLocked(sub *subscription, now time.Time, wait time.Duration) {
	p.subs.dropLocked(sub, now.Add(p.backoffLocked(sub.key, wait)))
}

// backoffLocked counts a failure of key's SUBSCRIBEs and returns how long
// the next waits: resubscribeAfter, doubling with each failure in a row up
// to refusedResubscribeAfter, or wait if longer. mu must be held.
func (p *pcscf) backoffLocked(key string, wait time.Duration) time.Duration {
	n := p.subs.failures[key]
	p.subs.failures[key] = n + 1
	backoff := refusedResubscribeAfter
	if n < 8 {
		backoff = min(resubscribeAfter<<n, refusedResubscribeAfter)
	}
	if p.metrics != nil {
		p.metrics.Count(metricSubscribeFailed, 1)
	}
	return max(backoff, min(wait, refusedResubscribeAfter))
}

// deferRefreshLocked holds sub's next refresh back after one failed that
// leaves it valid, by the same backoff, so an overloaded scscf is not
// asked again every sweep. mu must be held.
func (p *pcscf) deferRefreshLocked(sub *subscription, now time.Time, wait time.Duration) {
	sub.retryAt = now.Add(p.backoffLocked(sub.key, wait))
}

// refusedFor reports whether a SUBSCRIBE refused with code will be refused
// again soon: a 4xx or 6xx that says the request, the event or the user is
// wrong, not that the notifier is busy or lost the subscription. A 403 is
// not one: scscf answers it whenever the identity is not registered there,
// so that a subscriber cannot learn who is (#256), and so to a SUBSCRIBE
// that comes before the registration it follows is stored; it backs off
// like any failure.
func refusedFor(code int) bool {
	switch code {
	case 404, 405, 410, 416, 489, 501, 603, 604:
		return true
	}
	return false
}

// endsSubscription reports whether a refresh refused with code ends the
// subscription (RFC 6665 §4.1.2.2); any other failure leaves it valid
// until it expires, and the sweep tries again.
func endsSubscription(code int) bool {
	switch {
	case code == 404 || code == 405 || code == 410 || code == 416 || code == 489 || code == 501 || code == 604:
		return true
	case code >= 480 && code <= 485:
		return true
	}
	return false
}

// retryAfterOf is a response's Retry-After, or zero.
func retryAfterOf(res *sip.Response) time.Duration {
	v := strings.TrimSpace(strings.SplitN(res.Header.Get("Retry-After"), ";", 2)[0])
	secs, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0
	}
	return time.Duration(secs) * time.Second
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
	p.subs.goRun(func(ctx context.Context) { p.startSubscription(ctx, sub, reg) })
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
	// A panic below fails sub as an error does, so that it does not stay
	// busy and the sweep subscribes again after resubscribeAfter (#471 code
	// review). mu is held only around assignments, never across a call
	// that may panic.
	settled := false
	defer func() {
		if !settled {
			p.failSubscription(sub, p.now())
		}
	}()
	contact := sip.URI{Scheme: "sip", User: sub.id, Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	contact.Params.Set("transport", "tcp")
	from := sip.Address{URI: sip.URI{Scheme: "sip", Host: p.cfg.PublicHost}}
	expires := p.subscriptionExpires(reg)
	req, err := dialog.Initial("SUBSCRIBE", sub.impu, from, sip.Address{URI: sub.impu}, reg.serviceRoute, contact, hostOf(p.cfg.CoreHost), p.ids)
	if err == nil {
		err = p.prepareSubscribe(req, reg, sip.URI{}, expires)
	}
	var dst transport.Destination
	if err == nil {
		dst, err = p.resolve.Resolve(ctx, reg.serviceRoute[0].URI)
	}
	now := p.now()
	if err != nil {
		settled = true
		p.failSubscription(sub, now)
		return
	}
	path := p.pathURI(reg)
	p.subs.mu.Lock()
	sub.subscribe, sub.sent, sub.requested, sub.path = req, now, expires, path
	p.subs.mu.Unlock()
	// The send is synchronous; its handler takes mu, after this returns.
	err = p.send(req, dst, func(res *sip.Response, err error) { p.subscribed(sub, res, err, true) })
	settled = true
	if err != nil {
		p.failSubscription(sub, now)
	}
}

// failSubscription fails sub as failLocked does, with mu taken.
func (p *pcscf) failSubscription(sub *subscription, now time.Time) {
	p.subs.mu.Lock()
	defer p.subs.mu.Unlock()
	p.failLocked(sub, now, 0)
}

// prepareSubscribe adds what every SUBSCRIBE of pcscf carries, a refresh
// and the one that ends the subscription included: the event, Expires, the
// document type it reads, the Path URI of reg as P-Asserted-Identity
// (§5.2.3 1) f)), or path when reg is nil, and a P-Charging-Vector.
func (p *pcscf) prepareSubscribe(req *sip.Request, reg *registration, path sip.URI, expires time.Duration) error {
	icid, err := p.icid()
	if err != nil {
		return err
	}
	if reg != nil {
		path = p.pathURI(reg)
	}
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

// subscribed takes the response to a SUBSCRIBE of sub, or its failure. A
// 2xx grants it for its Expires. A SUBSCRIBE that set it up and failed, or
// was refused, ends it, unless a NOTIFY has set up its dialog already,
// which then stands (RFC 6665 §4.1.2.4): it is set up again after a
// backoff, or after an hour if refusedFor says it would be refused again.
// A refresh that failed leaves it valid until it expires, the sweep trying
// again, unless the code ends it (RFC 6665 §4.1.2.2, TS 24.229 §5.2.3).
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
		switch {
		case initial && sub.dialog == nil:
			p.failLocked(sub, now, 0)
		case !initial:
			p.deferRefreshLocked(sub, now, 0)
		case p.metrics != nil:
			p.metrics.Count(metricSubscribeFailed, 1)
		}
	case res.StatusCode >= 300:
		switch {
		case initial && refusedFor(res.StatusCode), !initial && endsSubscription(res.StatusCode) && refusedFor(res.StatusCode):
			p.failLocked(sub, now, refusedResubscribeAfter)
		case initial, endsSubscription(res.StatusCode):
			p.failLocked(sub, now, retryAfterOf(res))
		default:
			p.deferRefreshLocked(sub, now, retryAfterOf(res))
		}
	default:
		secs, err := res.Header.Expires()
		if err != nil && !initial {
			// A refresh's 2xx without Expires: what was asked for.
			secs, err = uint32(sub.requested/time.Second), nil
		}
		if err != nil || secs == 0 {
			p.failLocked(sub, now, 0)
			return
		}
		sub.length = time.Duration(secs) * time.Second
		sub.expires = now.Add(sub.length)
		if !initial {
			delete(p.subs.failures, sub.key)
			sub.retryAt = time.Time{}
		}
	}
}

// refreshDue reports whether sub is to be refreshed at now.
func refreshDue(sub *subscription, now time.Time) bool {
	if now.Before(sub.retryAt) {
		return false
	}
	return sub.refreshNow || !sub.expires.IsZero() && !now.Before(sub.expires.Add(-min(refreshLead, sub.length/2)))
}

// reconcileSubscriptions brings the subscriptions in line with the
// registrations, on every sweep: it sets up the missing ones, refreshes the
// ones about to expire, ends those of users with no registration left on
// this task, and fails those no NOTIFY set up within timerN or that lapsed.
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
	// A user with no registration left on the task needs no record, nor
	// a count of failures.
	for key := range p.subs.seen {
		if _, ok := live[key]; !ok {
			delete(p.subs.seen, key)
		}
	}
	for key := range p.subs.failures {
		if _, ok := live[key]; !ok {
			delete(p.subs.failures, key)
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
			// No NOTIFY within Timer N: the subscription failed.
			if !sub.sent.IsZero() && !now.Before(sub.sent.Add(timerN)) {
				p.failLocked(sub, now, 0)
			}
		case !sub.expires.IsZero() && !now.Before(sub.expires):
			// Its refreshes kept failing, and it has lapsed.
			p.failLocked(sub, now, 0)
		case refreshDue(sub, now) && len(refresh) < maxRefreshesPerSweep:
			sub.busy, sub.refreshNow = true, false
			refresh = append(refresh, sub)
		}
	}
	p.subs.mu.Unlock()
	for _, sub := range end {
		p.subs.goRun(func(ctx context.Context) { p.resubscribe(ctx, sub, nil) })
	}
	for _, sub := range refresh {
		reg := live[sub.key]
		p.subs.goRun(func(ctx context.Context) { p.resubscribe(ctx, sub, reg) })
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
// Both assert a Path (§5.2.3): the refresh reg's, the end the last one
// asserted. A refresh that cannot be sent leaves sub as it was, for the
// sweep to try again.
func (p *pcscf) resubscribe(ctx context.Context, sub *subscription, reg *registration) {
	// A panic below leaves sub as a refresh that cannot be sent does, for
	// the sweep to try again, with mu released (#471 code review).
	settled := false
	defer func() {
		if !settled && reg != nil {
			p.subscribed(sub, nil, errSubscribePanicked, false)
		}
	}()
	req, next, path, expires, err := p.resubscribeRequest(sub, reg)
	if err == nil {
		err = p.prepareSubscribe(req, reg, path, expires)
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
	settled = true
	if err != nil && reg != nil {
		p.subscribed(sub, nil, err, false)
	}
}

// errSubscribePanicked is a refresh whose making or sending panicked.
var errSubscribePanicked = errors.New("pcscf: a SUBSCRIBE panicked")

// resubscribeRequest builds sub's next SUBSCRIBE under mu, released
// whatever happens.
func (p *pcscf) resubscribeRequest(sub *subscription, reg *registration) (req *sip.Request, next sip.URI, path sip.URI, expires time.Duration, err error) {
	p.subs.mu.Lock()
	defer p.subs.mu.Unlock()
	if reg != nil {
		expires = p.subscriptionExpires(reg)
		sub.requested, sub.path = expires, p.pathURI(reg)
	}
	path = sub.path
	req, err = sub.dialog.Subscribe(sip.Event{Type: regEvent}, uint32(expires/time.Second), p.ids)
	if err == nil {
		next = sub.dialog.NextHop()
	}
	return req, next, path, expires, err
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
	p.answerNotify(u.Request().Message, u.Respond)
}

// answerNotify takes req, a NOTIFY, and answers it through respond.
func (p *pcscf) answerNotify(req *sip.Request, respond func(*sip.Response) error) {
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
	// The registrations go before the 200 does, so that the notifier, and
	// anything it does next, finds them gone.
	if info != nil {
		p.deregistered(info.key, info.doc, info.seen)
	}
	_ = respond(res)
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
	// seen is what earlier documents showed active.
	seen *seenState
}

// seenState is what the reg event documents of one user have shown
// active: the bindings, by bindingKey, and the identities, canonical. A
// full document ends, because it does not list it, only what this shows:
// a binding pcscf stored but the notifier has not reported yet, whose 200
// overtook the document, is ended only by a document that lists it ended,
// or by its expiry (security review of #239).
type seenState struct {
	bindings map[string]reginfo.Contact
	aors     map[string]bool
	// index is the bindings as shown looks them up, made at its first
	// call: a full document asks once for every contact of every
	// registration of the user, and the record may hold maxSeenBindings
	// (#239 review).
	index *seenIndex
}

// seenIndex is a record's bindings ready for shown: the reg-ids of those
// with a +sip.instance, by the instance in lower case, and the URIs,
// parsed once, of those with an instance and of those without.
type seenIndex struct {
	byInstance   map[string][]seenRegID
	withInstance []sip.URI
	noInstance   []sip.URI
}

func newSeenState() *seenState {
	return &seenState{bindings: map[string]reginfo.Contact{}, aors: map[string]bool{}}
}

// maxSeenBindings bounds what one user's record holds: the contacts of
// one document.
const maxSeenBindings = 256 * 64

// bindingKey names a binding of a document: its +sip.instance and
// reg-id, or its URI without an instance.
func bindingKey(c reginfo.Contact) string {
	if inst, ok := c.Param("+sip.instance"); ok {
		id, _ := c.Param("reg-id")
		return "i\x00" + strings.ToLower(inst) + "\x00" + id
	}
	return "u\x00" + c.URI
}

// aorOf is an identity as seenState keeps it.
func aorOf(s string) string {
	if c, ok := identity.CanonicalIMPU(s); ok {
		return c
	}
	return s
}

func (s *seenState) clone() *seenState {
	c := newSeenState()
	maps.Copy(c.bindings, s.bindings)
	maps.Copy(c.aors, s.aors)
	return c
}

// update takes in doc: a full document is the whole state, so the record
// becomes what it shows active; a partial one adds what it shows active
// and drops what it shows ended.
func (s *seenState) update(doc *reginfo.Info) {
	if doc.State == reginfo.Full {
		clear(s.bindings)
		clear(s.aors)
	}
	for _, el := range doc.Registrations {
		if el.State == reginfo.Active {
			s.aors[aorOf(el.AOR)] = true
		} else {
			delete(s.aors, aorOf(el.AOR))
		}
		for _, c := range el.Contacts {
			if c.Active() && el.State == reginfo.Active {
				if len(s.bindings) < maxSeenBindings {
					s.bindings[bindingKey(c)] = c
				}
			} else {
				delete(s.bindings, bindingKey(c))
			}
		}
	}
}

// shown reports whether c's binding is one s has seen active, matching as
// bindingsOf does. s must not change once asked: a record is read from a
// clone (acceptNotify).
func (s *seenState) shown(c sip.Contact) bool {
	if s == nil {
		return false
	}
	if s.index == nil {
		s.index = indexBindings(s.bindings)
	}
	x := s.index
	inst, hasInst := c.Instance()
	if hasInst {
		regID, hasRegID, err := c.RegID()
		want := strconv.FormatUint(uint64(regID), 10)
		for _, id := range x.byInstance[strings.ToLower(inst)] {
			if !id.has || !hasRegID || err != nil || id.v == want {
				return true
			}
		}
	} else if slices.ContainsFunc(x.withInstance, c.URI.Equal) {
		return true
	}
	return slices.ContainsFunc(x.noInstance, c.URI.Equal)
}

// seenRegID is a binding's reg-id, if it has one.
type seenRegID struct {
	v   string
	has bool
}

func indexBindings(bindings map[string]reginfo.Contact) *seenIndex {
	x := &seenIndex{byInstance: map[string][]seenRegID{}}
	for _, rc := range bindings {
		u, err := sip.ParseURI(rc.URI)
		inst, ok := rc.Param("+sip.instance")
		switch {
		case ok:
			id, has := rc.Param("reg-id")
			key := strings.ToLower(inst)
			x.byInstance[key] = append(x.byInstance[key], seenRegID{id, has})
			if err == nil {
				x.withInstance = append(x.withInstance, u)
			}
		case err == nil:
			x.noInstance = append(x.noInstance, u)
		}
	}
	return x
}

// shownAOR reports whether s has seen u active.
func (s *seenState) shownAOR(u sip.URI) bool {
	return s != nil && s.aors[aorOf(u.String())]
}

// acceptNotify checks req against the subscription it names and takes it:
// its CSeq and target into the dialog, the document's version, and the end
// of the subscription. It returns the response code and the document to
// act on, if any. Nothing changes unless the code is 200. The subscription
// is looked up before the body is read, so a NOTIFY for none costs no
// parse.
func (p *pcscf) acceptNotify(req *sip.Request) (int, *notified) {
	if req.Method != "NOTIFY" {
		return 405, nil
	}
	p.subs.mu.Lock()
	known := p.subs.byID[req.URI.User] != nil
	p.subs.mu.Unlock()
	if !known {
		return 481, nil
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
		if sub.subscribe == nil {
			return 481, nil
		}
		switch d, err = dialog.FromNotify(sub.subscribe, req); {
		case errors.Is(err, dialog.ErrNotInDialog):
			return 481, nil
		case err != nil:
			return 400, nil
		}
		delete(p.subs.failures, sub.key)
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
	terminated := strings.EqualFold(state.State, "terminated")
	if secs, ok := state.Expires(); ok && !terminated {
		sub.length = time.Duration(secs) * time.Second
		sub.expires = now.Add(sub.length)
	} else if !terminated && sub.expires.IsZero() {
		// An active NOTIFY must say when it ends (RFC 6665 §4.2.2); one
		// that does not gets what was granted or asked for, so that a
		// refresh is always due some time.
		sub.length = cmp.Or(sub.length, sub.requested, minSubscriptionExpires)
		sub.expires = now.Add(sub.length)
	}
	var out *notified
	if doc != nil && int64(doc.Version) > sub.version {
		if doc.State == reginfo.Partial && sub.version >= 0 && int64(doc.Version) > sub.version+1 {
			// A partial document was missed: a refresh brings a full one
			// (RFC 3680 §5.2).
			sub.refreshNow = true
		}
		sub.version = int64(doc.Version)
		seen := p.subs.seen[sub.key]
		if seen == nil {
			seen = newSeenState()
			p.subs.seen[sub.key] = seen
		}
		out = &notified{key: sub.key, doc: doc, seen: seen.clone()}
		seen.update(doc)
	}
	if terminated {
		p.subs.dropLocked(sub, now.Add(resubscribeDelay(state)))
	}
	return 200, out
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
// subscription of key (§5.2.5.2), on the registrations of that user on
// this task alone (endedBy). A registration ended is removed only if it is
// still the one read, so a REGISTER's 200 saved meanwhile stays. The flows
// stay open (#16 plan E, decision 5).
func (p *pcscf) deregistered(key string, doc *reginfo.Info, seen *seenState) {
	for _, reg := range p.registry.ofDefault(key) {
		ended, changed := endedBy(reg, doc, seen)
		if ended {
			if p.registry.removeIf(reg) && p.metrics != nil {
				p.metrics.Count(metricDeregistered, 1)
			}
			continue
		}
		if changed != nil {
			p.registry.replace(reg, changed)
			p.keepSeen(key, defaultKey(changed))
		}
	}
}

// keepSeen gives the user's record under key to newKey too, when a
// registration's default identity, which keys it, changed: the document
// ended the default identity and left another (#239 review). The sweep
// forgets the record of a key no registration has.
func (p *pcscf) keepSeen(key, newKey string) {
	if p.subs == nil || key == newKey {
		return
	}
	p.subs.mu.Lock()
	defer p.subs.mu.Unlock()
	if old := p.subs.seen[key]; old != nil && p.subs.seen[newKey] == nil {
		p.subs.seen[newKey] = old.clone()
	}
}

// endedBy reports what doc ends of reg: all of it, or else, in changed, a
// copy without the contacts and associated identities it ends; changed is
// nil when doc ends nothing. Identities are found in doc as ByAOR finds
// them, and a contact of reg is its binding in doc (bindingsOf).
//
//   - A partial document ends what it lists as ended: the registered
//     identity not active, or every binding of reg's contacts terminated;
//     a contact whose binding it terminates; an associated identity not
//     active, or none of whose bindings with reg's contacts is active.
//   - A full document is the whole state (RFC 3680 §5.2): what it lists
//     not active is ended, and what it does not list is ended too if an
//     earlier document showed it active (seen); one the notifier has not
//     reported yet is left (security review of #239).
//   - A registration with associated identities none of which is left is
//     ended as well, so its flow cannot fall back to asserting an identity
//     the network never listed (security review of #239).
func endedBy(reg *registration, doc *reginfo.Info, seen *seenState) (ended bool, changed *registration) {
	full := doc.State == reginfo.Full
	// gone reports whether doc ends the binding of c under el.
	gone := func(el reginfo.Registration, c sip.Contact) bool {
		found := bindingsOf(el, c)
		switch {
		case slices.ContainsFunc(found, reginfo.Contact.Active):
			return false
		case len(found) > 0:
			return true
		}
		return full && seen.shown(c)
	}
	contacts := slices.Clone(reg.contacts)
	switch el, ok := doc.ByAOR(reg.uri); {
	case ok && el.State != reginfo.Active, !ok && full && seen.shownAOR(reg.uri):
		return true, nil
	case !ok && full:
		// An identity no document has listed, such as a barred one a UE
		// registered with, which scscf leaves out of reginfo: its bindings
		// are judged wherever the document lists them.
		var all reginfo.Registration
		for _, r := range doc.Registrations {
			if r.State == reginfo.Active {
				all.Contacts = append(all.Contacts, r.Contacts...)
			}
		}
		contacts = slices.DeleteFunc(contacts, func(c sip.Contact) bool { return gone(all, c) })
	case ok:
		contacts = slices.DeleteFunc(contacts, func(c sip.Contact) bool { return gone(el, c) })
	}
	if len(contacts) == 0 {
		return true, nil
	}
	associated := slices.DeleteFunc(slices.Clone(reg.associated), func(a sip.Address) bool {
		if sameIdentity(a.URI, reg.uri) {
			return false // it stands or falls with the registration
		}
		el, ok := doc.ByAOR(a.URI)
		switch {
		case !ok:
			return full && seen.shownAOR(a.URI)
		case el.State != reginfo.Active:
			return true
		}
		return !slices.ContainsFunc(reg.contacts, func(c sip.Contact) bool { return !gone(el, c) })
	})
	if len(reg.associated) > 0 && len(associated) == 0 {
		return true, nil
	}
	if len(contacts) == len(reg.contacts) && len(associated) == len(reg.associated) {
		return false, nil
	}
	c := *reg
	c.contacts, c.associated = contacts, associated
	return false, &c
}

// bindingsOf is the contacts of el that are c's binding: those with c's
// +sip.instance, and its reg-id when both have one, matched with
// reginfo.Contact.Param, since one URI may be bound once per flow (RFC
// 5626 §6); or, when either has no instance, those at c's URI (RFC 3261
// §19.1.4).
func bindingsOf(el reginfo.Registration, c sip.Contact) []reginfo.Contact {
	inst, hasInst := c.Instance()
	regID, hasRegID, err := c.RegID()
	hasRegID = hasRegID && err == nil
	var out []reginfo.Contact
	for _, rc := range el.Contacts {
		if ri, ok := rc.Param("+sip.instance"); ok && hasInst {
			if !strings.EqualFold(ri, inst) {
				continue
			}
			if rr, ok := rc.Param("reg-id"); ok && hasRegID && rr != strconv.FormatUint(uint64(regID), 10) {
				continue
			}
			out = append(out, rc)
			continue
		}
		if u, err := sip.ParseURI(rc.URI); err == nil && u.Equal(c.URI) {
			out = append(out, rc)
		}
	}
	return out
}

// sameIdentity reports whether a and b are the same public identity, in
// the form the HSS keeps one in (identity.CanonicalIMPU), as reginfo's
// ByAOR compares them; without such a form, as URIs.
func sameIdentity(a, b sip.URI) bool {
	// URI headers are no part of an identity.
	a.Headers, b.Headers = nil, nil
	ca, okA := identity.CanonicalIMPU(a.String())
	cb, okB := identity.CanonicalIMPU(b.String())
	if okA && okB {
		return ca == cb
	}
	return a.Equal(b)
}

// sender starts a client transaction: transaction.Layer.Request, through
// the proxy's layer, so that the responses come back to it.
type sender func(req *sip.Request, dst transport.Destination, h transaction.ResponseHandler) error
