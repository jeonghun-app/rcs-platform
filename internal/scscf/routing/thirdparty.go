package routing

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/textproto"
	"strconv"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Sender sends a request in a client transaction to the next hop its
// Request-URI names and returns the final response, or an error when there
// is none (a timeout, a transport failure).
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
// they are sent, and up to queuedPerServer of them waiting or sent. Each
// set's go in the order the registrar told of them, so that the server
// does not hear a registration after the deregistration that followed it,
// and at most queuedPerSet of a set's are queued, so that one set's
// refreshes do not take the queue (#379 code review). One past either
// bound takes the place of its set's last one waiting, which it is newer
// than, so that the server hears the set's latest state, its end above
// all (#379 code review); it is dropped only when its set has none
// waiting.
type serverQueue struct {
	slots  chan struct{}
	queued int
	sets   map[string]*setQueue
}

// setQueue is a set's registrations queued for one server: tail is closed
// once the last one told of is done, and last is that one.
type setQueue struct {
	tail   chan struct{}
	queued int
	last   *pending
}

// pending is a registration queued for a server, which a later one of its
// set may take the place of until it is sent.
type pending struct {
	r      registrar.ThirdPartyRegistration
	server ifc.ApplicationServer
	sent   bool
}

// queuedPerServer bounds the registrations queued for a server, as a
// multiple of MaxThirdParty, which bounds the goroutines that wait for a
// server that does not answer.
const queuedPerServer = 4

// queuedPerSet bounds one set's registrations queued for a server, the one
// under way included: a registration, a refresh and an end, with room for
// one more.
const queuedPerSet = 4

// Registered sends the application servers whose criteria take r's
// REGISTER a third-party REGISTER for it (TS 24.229 §5.4.1.7), off the
// caller's goroutine, to each server apart. The criteria are read now,
// from r.Profile or the store: once a set has ended its profile goes. One
// past a server's or a set's queue (serverQueue) replaces its set's last
// one waiting, or, with none, is dropped and counted, as is one told of
// after Stop.
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
	key := r.Set.IMPI + "\x00" + r.Set.IMPU
	ctx = context.WithoutCancel(ctx)
	rt.stop.Lock()
	defer rt.stop.Unlock()
	if rt.stopped {
		rt.count("routing.third_party.dropped")
		return
	}
	for _, fc := range matched {
		p := &pending{r: r, server: fc.ApplicationServer}
		q, sq, prev, done, queued := rt.enqueue(fc.ApplicationServer.ServerName, key, p)
		if !queued {
			continue
		}
		rt.tp.wg.Add(1)
		go func() {
			defer rt.tp.wg.Done()
			if rt.turn(prev, q.slots) {
				rt.tp.mu.Lock()
				p.sent = true
				r, server := p.r, p.server
				rt.tp.mu.Unlock()
				rt.registerWith(ctx, r, server)
				<-q.slots
			} else {
				rt.count("routing.third_party.dropped_at_stop")
			}
			rt.tp.mu.Lock()
			q.queued--
			if sq.queued--; sq.queued == 0 {
				delete(q.sets, key)
			}
			rt.tp.mu.Unlock()
			close(done)
		}()
	}
}

// turn waits for the set's registration before this one, prev, to be done
// and takes one of the server's slots. It is false, with no slot taken,
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

// enqueue queues p, a registration of the set key for server, and returns
// its queues, the channel the one before it of the set's closes, nil if
// none, and the one it closes itself. Past either bound p takes the place
// of the set's last one waiting, or is dropped; either way, counted, and
// not queued.
func (rt *Router) enqueue(server, key string, p *pending) (q *serverQueue, sq *setQueue, prev, done chan struct{}, queued bool) {
	rt.tp.mu.Lock()
	defer rt.tp.mu.Unlock()
	q = rt.tp.servers[server]
	if q == nil {
		q = &serverQueue{slots: make(chan struct{}, rt.cfg.MaxThirdParty), sets: map[string]*setQueue{}}
		rt.tp.servers[server] = q
	}
	sq = q.sets[key]
	switch {
	case q.queued < queuedPerServer*rt.cfg.MaxThirdParty && (sq == nil || sq.queued < queuedPerSet):
	case sq != nil && sq.last != nil && !sq.last.sent:
		sq.last.r, sq.last.server = p.r, p.server
		rt.count("routing.third_party.replaced")
		return nil, nil, nil, nil, false
	default:
		rt.count("routing.third_party.dropped")
		return nil, nil, nil, nil, false
	}
	if sq == nil {
		sq = &setQueue{}
		q.sets[key] = sq
	}
	prev, done = sq.tail, make(chan struct{})
	sq.tail, sq.last = done, p
	sq.queued++
	q.queued++
	return q, sq, prev, done, true
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
	branch, err := rt.ids.Branch()
	if err != nil {
		return nil, err
	}
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
		{"Via", "SIP/2.0/TCP invalid;branch=" + branch},
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
