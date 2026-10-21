package routing

import (
	"context"
	"strconv"
	"strings"
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

// thirdParty is the third-party registrations under way: at most
// MaxThirdParty at a time, each set's in the order the registrar told of
// them, so that a server does not hear a registration after the
// deregistration that followed it.
type thirdParty struct {
	slots chan struct{}
	wg    sync.WaitGroup

	mu sync.Mutex
	// tails are the last registration of each set under way, closed once
	// it is done.
	tails map[string]chan struct{}
}

// Registered sends the application servers whose criteria take r's
// REGISTER a third-party REGISTER for it (TS 24.229 §5.4.1.7), off the
// caller's goroutine. The criteria are read now, from r.Profile or the
// store: once a set has ended its profile goes. Past MaxThirdParty
// registrations under way, it is dropped and counted.
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
	select {
	case rt.tp.slots <- struct{}{}:
	default:
		rt.count("routing.third_party.dropped")
		return
	}
	r.Request, r.Response = clonedRequest(r.Request), clonedResponse(r.Response)
	key := r.Set.IMPI + "\x00" + r.Set.IMPU
	done := make(chan struct{})
	rt.tp.mu.Lock()
	prev := rt.tp.tails[key]
	rt.tp.tails[key] = done
	rt.tp.mu.Unlock()
	rt.tp.wg.Add(1)
	ctx = context.WithoutCancel(ctx)
	go func() {
		defer func() {
			rt.tp.mu.Lock()
			if rt.tp.tails[key] == done {
				delete(rt.tp.tails, key)
			}
			rt.tp.mu.Unlock()
			close(done)
			<-rt.tp.slots
			rt.tp.wg.Done()
		}()
		if prev != nil {
			<-prev
		}
		for _, fc := range matched {
			rt.registerWith(ctx, r, fc.ApplicationServer)
		}
	}()
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
	ctx, cancel := context.WithTimeout(ctx, rt.cfg.ThirdPartyTimeout)
	defer cancel()
	res, err := rt.cfg.Sender.Send(ctx, req)
	switch {
	case err == nil && res.StatusCode < 300:
		rt.count("routing.third_party.registered")
		return
	case err == nil && res.StatusCode != 408 && res.StatusCode < 500:
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
		req.Body = multipart(boundary, parts)
	}
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// multipart writes parts, each message/sip, as a multipart/mixed body with
// boundary (RFC 2046 §5.1.1).
func multipart(boundary string, parts [][]byte) []byte {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\nContent-Type: message/sip\r\n\r\n")
		b.Write(p)
		b.WriteString("\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func clonedRequest(r *sip.Request) *sip.Request {
	if r == nil {
		return nil
	}
	return r.Clone()
}

func clonedResponse(r *sip.Response) *sip.Response {
	if r == nil {
		return nil
	}
	return r.Clone()
}
