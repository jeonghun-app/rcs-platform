package routing

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/textproto"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Sender sends a request in a client transaction to the next hop its
// Request-URI names and returns the final response, or an error when there
// is none (a timeout, a transport failure). The request comes without a
// Via: the Sender adds the one it has (RFC 3261 §8.1.1.7), with its own
// branch and the address it sends from.
type Sender interface {
	Send(ctx context.Context, req *sip.Request) (*sip.Response, error)
}

// thirdParty is the third-party registrations under way, queued per
// application server so that one that does not answer holds up no other
// (#379 QA).
type thirdParty struct {
	wg sync.WaitGroup

	mu      sync.Mutex
	servers map[string]*serverQueue
}

// serverQueue is one application server's third-party registrations: at
// most MaxThirdParty at the server at a time, which hold a slot only while
// they are sent, and up to queuedPerServer times that many waiting or sent.
//
// They are queued per set and identity registered, as the server keeps a
// registration per To (#420): each identity's go in the order the
// registrar told of them, so that the server does not hear a registration
// after the deregistration that followed it, and one past a bound takes
// the place of the same identity's last one waiting, which it is newer
// than, so that the server hears the latest state (#379 code review). At
// most queuedPerSet of a whole set's are queued, whatever its identities,
// so that one user's refreshes do not take the queue (#379 and #446 code
// review), but for an identity with nothing queued, whose first goes past
// the set's cap so that it is not dropped while the server's queue has
// room (#446 QA): a set holds at most queuedPerSet plus its identities, at
// most state.MaxIdentities.
//
// An end with none to take the place of goes past either bound, by at most
// MaxThirdParty, as no later registration would tell the server of it
// (#420). Past that it evicts the oldest refresh waiting under another
// key, which the identity's next re-registration makes good, and only with
// none to evict is it dropped, counted apart (#446 QA, the lead's decision
// on #420). So at most (queuedPerServer+1) × MaxThirdParty are counted,
// which bounds the goroutines that wait for a server that does not answer.
// Those evicted are outside that bound: each lingers until the one before
// it of its identity is done and it gets a slot, which it gives back at
// once, sending nothing.
type serverQueue struct {
	slots  chan struct{}
	queued int
	// keys are the queues per set and identity, and sets count each set's
	// registrations queued.
	keys map[string]*keyQueue
	sets map[string]int
	// waiting are the registrations queued and not yet sent, oldest first;
	// an end may evict the refreshes among them.
	waiting []*pending
}

// keyQueue is the registrations of one identity of a set queued for one
// server: tail is closed once the last one told of is done, and last is
// that one, nil once evicted.
type keyQueue struct {
	tail   chan struct{}
	queued int
	last   *pending
}

// pending is a registration queued for a server, which a later one of the
// same identity may take the place of until it is sent, and an end of
// another evict.
type pending struct {
	r        registrar.ThirdPartyRegistration
	server   ifc.ApplicationServer
	set, key string
	sent     bool
	evicted  bool
}

// queuedPerServer bounds the registrations queued for a server, as a
// multiple of MaxThirdParty: with the ends' headroom of one MaxThirdParty
// more, it bounds the goroutines that wait for a server that does not
// answer.
const queuedPerServer = 4

// queuedPerSet bounds one set's registrations queued for a server, all its
// identities together, the ones under way included: a registration, a
// refresh and an end, with room for one more. An end goes past it as past
// the server's bound, and so does an identity's first with none of its own
// queued (serverQueue).
const queuedPerSet = 4

// Registered sends the application servers whose criteria take r's
// REGISTER a third-party REGISTER for it (TS 24.229 §5.4.1.7), off the
// caller's goroutine, to each server apart. The criteria are read now,
// from r.Profile or the store: once a set has ended its profile goes. One
// past a server's or a set's bound (serverQueue) replaces its identity's
// last one waiting; with none, a refresh is dropped and counted, and an
// end goes past the bound, or evicts a waiting refresh, or is dropped and
// counted apart. One told of after Stop is dropped and counted.
func (rt *Router) Registered(ctx context.Context, r registrar.ThirdPartyRegistration) {
	if rt.cfg.Sender == nil {
		return
	}
	services, err := rt.thirdPartyServices(ctx, r)
	if err != nil {
		rt.internalLog("reading the services of a registration", err)
		return
	}
	req := r.Request
	if req == nil {
		req = rt.registerOf(r.IMPU)
	}
	t := r.Type
	matched, err := services.Match(view{req: req}, ifc.Context{Case: ifc.Originating, RegistrationType: &t})
	if err != nil {
		rt.count("ifc.budget_exceeded")
		return
	}
	if len(matched) == 0 {
		return
	}
	r.Request, r.Response = withoutCredentials(r.Request), clonedResponse(r.Response)
	set := r.Set.IMPI + "\x00" + r.Set.IMPU
	key := set + "\x00" + r.IMPU
	ctx = context.WithoutCancel(ctx)
	rt.stop.Lock()
	defer rt.stop.Unlock()
	if rt.stopped {
		rt.count("routing.third_party.dropped")
		return
	}
	for _, fc := range matched {
		p := &pending{r: r, server: fc.ApplicationServer, set: set, key: key}
		q, prev, done, queued := rt.enqueue(fc.ApplicationServer.ServerName, p)
		if !queued {
			continue
		}
		rt.tp.wg.Add(1)
		go func() {
			defer rt.tp.wg.Done()
			defer close(done)
			if !rt.turn(prev, q.slots) {
				// Given up at the stop, unless an end evicted it first,
				// which no longer counts it (#446 code review).
				rt.tp.mu.Lock()
				evicted := p.evicted
				if !evicted {
					q.unwait(p)
					q.release(p)
				}
				rt.tp.mu.Unlock()
				if !evicted {
					rt.count("routing.third_party.dropped_at_stop")
				}
				return
			}
			defer func() { <-q.slots }()
			rt.tp.mu.Lock()
			if p.evicted {
				rt.tp.mu.Unlock()
				return
			}
			p.sent = true
			q.unwait(p)
			r, server := p.r, p.server
			rt.tp.mu.Unlock()
			rt.registerWith(ctx, r, server)
			rt.tp.mu.Lock()
			q.release(p)
			rt.tp.mu.Unlock()
		}()
	}
}

// turn waits for the registration of the same identity before this one,
// prev, to be done and takes one of the server's slots. It is false, with no slot taken,
// once StopBy has given up. The wait is short then: StopBy cuts short the
// send of whatever holds the turn.
func (rt *Router) turn(prev, slots chan struct{}) bool {
	if prev != nil {
		<-prev
	}
	slots <- struct{}{}
	if rt.halted.Err() != nil {
		<-slots
		return false
	}
	return true
}

// enqueue queues p, a registration for server, and returns its server's
// queue, the channel the one before it of the same key closes, nil if
// none, and the one it closes itself. Past either bound p takes the place
// of its key's last one waiting, or, a refresh, is dropped, either way
// counted and not queued; an end goes past the bounds, or evicts a waiting
// refresh, or is dropped and counted apart (serverQueue).
func (rt *Router) enqueue(server string, p *pending) (q *serverQueue, prev, done chan struct{}, queued bool) {
	rt.tp.mu.Lock()
	defer rt.tp.mu.Unlock()
	q = rt.tp.servers[server]
	if q == nil {
		q = &serverQueue{slots: make(chan struct{}, rt.cfg.MaxThirdParty), keys: map[string]*keyQueue{}, sets: map[string]int{}}
		rt.tp.servers[server] = q
	}
	kq := q.keys[p.key]
	bound := queuedPerServer * rt.cfg.MaxThirdParty
	end := p.r.Type == ifc.DeRegistration
	switch {
	case q.queued < bound && (q.sets[p.set] < queuedPerSet || kq == nil):
	case kq != nil && kq.last != nil && !kq.last.sent:
		kq.last.r, kq.last.server = p.r, p.server
		rt.count("routing.third_party.replaced")
		return nil, nil, nil, false
	case end && q.queued < bound+rt.cfg.MaxThirdParty:
		rt.count("routing.third_party.end_past_bound")
	case end && rt.evict(q, p.key):
	case end:
		rt.count("routing.third_party.end_dropped")
		return nil, nil, nil, false
	default:
		rt.count("routing.third_party.dropped")
		return nil, nil, nil, false
	}
	if kq == nil {
		kq = &keyQueue{}
		q.keys[p.key] = kq
	}
	prev, done = kq.tail, make(chan struct{})
	kq.tail, kq.last = done, p
	kq.queued++
	q.sets[p.set]++
	q.queued++
	// Every type: an end a re-registration then takes the place of is a
	// refresh an end may evict (#446 QA).
	q.waiting = append(q.waiting, p)
	return q, prev, done, true
}

// evict evicts the oldest re-registration waiting under another key than
// key, or with none the oldest initial registration, which then is no
// longer counted and is never sent, and reports whether there was one. A
// re-registration lost is no loss to the server, which knows the
// registration and its last Expires; an initial one lost leaves it unaware
// of the user until the next refresh, and rcs-as holds the user's stored
// messages until then (#446 code review).
func (rt *Router) evict(q *serverQueue, key string) bool {
	for _, typ := range []ifc.RegistrationType{ifc.ReRegistration, ifc.InitialRegistration} {
		if w := q.oldestWaiting(key, typ); w != nil {
			rt.evictOne(q, w)
			return true
		}
	}
	return false
}

// oldestWaiting is the oldest registration of typ waiting under another key
// than key, nil if none. The type is the one it carries now, after any
// replacement.
func (q *serverQueue) oldestWaiting(key string, typ ifc.RegistrationType) *pending {
	for _, w := range q.waiting {
		if w.key != key && !w.sent && !w.evicted && w.r.Type == typ {
			return w
		}
	}
	return nil
}

// evictOne evicts w: it is no longer counted, and never sent.
func (rt *Router) evictOne(q *serverQueue, w *pending) {
	w.evicted = true
	q.unwait(w)
	if kq := q.keys[w.key]; kq != nil && kq.last == w {
		kq.last = nil
	}
	q.release(w)
	rt.count("routing.third_party.evicted")
}

// unwait takes p off the registrations waiting.
func (q *serverQueue) unwait(p *pending) {
	if i := slices.Index(q.waiting, p); i >= 0 {
		q.waiting = slices.Delete(q.waiting, i, i+1)
	}
}

// release no longer counts p, sent or evicted.
func (q *serverQueue) release(p *pending) {
	q.queued--
	if q.sets[p.set]--; q.sets[p.set] <= 0 {
		delete(q.sets, p.set)
	}
	if kq := q.keys[p.key]; kq != nil {
		if kq.queued--; kq.queued == 0 {
			delete(q.keys, p.key)
		}
	}
}

// thirdPartyServices are the criteria of r's identity.
func (rt *Router) thirdPartyServices(ctx context.Context, r registrar.ThirdPartyRegistration) (*ifc.Set, error) {
	if r.Profile != nil {
		return rt.servicesIn(r.Profile, r.IMPU)
	}
	return rt.servicesOf(ctx, r.Set, r.IMPU)
}

// registerOf is the REGISTER the criteria see for an end the network made,
// which no UE's REGISTER comes with: one for impu, to the home domain.
func (rt *Router) registerOf(impu string) *sip.Request {
	req := &sip.Request{Method: "REGISTER", URI: sip.URI{Scheme: "sip", Host: rt.cfg.HomeDomain}}
	for _, f := range [][2]string{{"From", "<" + impu + ">"}, {"To", "<" + impu + ">"}} {
		_ = req.Header.Add(f[0], f[1])
	}
	return req
}

// registerWith sends server the third-party REGISTER for r and counts what
// came of it. A server that does not answer, or answers 408 or 5xx, has
// its default handling apply (§5.4.1.7): SESSION_CONTINUED goes on, and
// SESSION_TERMINATED, which would deregister the user, is only counted and
// logged for now (#14, issuecomment-6312969529).
func (rt *Router) registerWith(ctx context.Context, r registrar.ThirdPartyRegistration, server ifc.ApplicationServer) {
	as, err := sip.ParseURI(server.ServerName)
	if err != nil || !as.IsSIP() || as.Host == "" {
		rt.count("routing.third_party.bad_server")
		return
	}
	req, err := rt.thirdPartyRequest(r, as, server)
	if err != nil {
		rt.internalLog("building a third-party REGISTER", err)
		return
	}
	ctx, cancel := rt.bounded(ctx, rt.cfg.ThirdPartyTimeout)
	defer cancel()
	res, err := rt.cfg.Sender.Send(ctx, req)
	if err != nil && rt.halted.Err() != nil {
		// Cut short by the stop, not unanswered: no default handling.
		rt.count("routing.third_party.dropped_at_stop")
		return
	}
	switch {
	case err == nil && res.StatusCode < 300:
		rt.count("routing.third_party.registered")
		return
	case err == nil && res.StatusCode != 408 && (res.StatusCode < 500 || res.StatusCode >= 600):
		// A 6xx is the server's answer too, not its silence.
		rt.count("routing.third_party.refused")
		return
	}
	rt.count("routing.third_party.unanswered")
	if server.DefaultHandling == ifc.SessionTerminated {
		rt.count("routing.third_party.terminated_unanswered")
		rt.log.Warn("routing: a third-party REGISTER whose default handling ends the session had no answer; the user stays registered")
	}
}

// thirdPartyRequest is the third-party REGISTER to as for r (§5.4.1.7): from
// the S-CSCF, for the user in To, with the set's Expires, and, as the
// criterion asks, the UE's REGISTER and the 200 for it in a message/sip
// body each, both in a multipart/mixed one.
func (rt *Router) thirdPartyRequest(r registrar.ThirdPartyRegistration, as sip.URI, server ifc.ApplicationServer) (*sip.Request, error) {
	tag, err := rt.ids.Tag()
	if err != nil {
		return nil, err
	}
	callID, err := rt.ids.CallID(rt.cfg.RecordRoute.URI.Host)
	if err != nil {
		return nil, err
	}
	self := sip.URI{Scheme: rt.cfg.RecordRoute.URI.Scheme, Host: rt.cfg.RecordRoute.URI.Host, Port: rt.cfg.RecordRoute.URI.Port}
	self.Params.Set("transport", "tcp")
	from := sip.Address{URI: self}
	from.Params.Set("tag", tag)
	req := &sip.Request{Method: "REGISTER", URI: as}
	fields := [][2]string{
		{"Max-Forwards", "70"},
		{"From", from.String()},
		{"To", "<" + r.IMPU + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 REGISTER"},
		{"Contact", sip.Address{URI: self}.String()},
		// Whole seconds, rounded up, so that a set with a live binding is
		// never said to have none.
		{"Expires", strconv.FormatInt(int64((r.Expires+time.Second-1)/time.Second), 10)},
	}
	var parts [][]byte
	if server.IncludeRegisterRequest && r.Request != nil {
		b, err := r.Request.Bytes()
		if err != nil {
			return nil, err
		}
		parts = append(parts, b)
	}
	if server.IncludeRegisterResponse && r.Response != nil {
		b, err := r.Response.Bytes()
		if err != nil {
			return nil, err
		}
		parts = append(parts, b)
	}
	switch len(parts) {
	case 1:
		fields = append(fields, [2]string{"Content-Type", "message/sip"})
		req.Body = parts[0]
	case 2:
		boundary, err := rt.ids.Tag()
		if err != nil {
			return nil, err
		}
		fields = append(fields, [2]string{"Content-Type", "multipart/mixed;boundary=" + boundary})
		if req.Body, err = multipartBody(boundary, parts); err != nil {
			return nil, err
		}
	}
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// multipartBody writes parts, each message/sip, as a multipart/mixed body
// with boundary (RFC 2046 §5.1.1).
func multipartBody(boundary string, parts [][]byte) ([]byte, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, err
	}
	for _, p := range parts {
		pw, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"message/sip"}})
		if err != nil {
			return nil, err
		}
		if _, err := pw.Write(p); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// withoutCredentials is a copy of the UE's REGISTER for a server's body,
// without its Authorization and Proxy-Authorization: the Digest response
// and nonces would let a server guess a password offline, and no server
// needs them (#379, lead's decision).
func withoutCredentials(r *sip.Request) *sip.Request {
	if r == nil {
		return nil
	}
	c := r.Clone()
	c.Header.Del("Authorization")
	c.Header.Del("Proxy-Authorization")
	return c
}

func clonedResponse(r *sip.Response) *sip.Response {
	if r == nil {
		return nil
	}
	return r.Clone()
}
