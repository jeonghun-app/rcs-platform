package routing

import (
	"context"
	"errors"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// origParam marks the Service-Route the registrar gives a user's P-CSCF,
// which the user's requests come along: they are originating (TS 24.229
// §5.4.3.2).
const origParam = "orig"

// Initial routes a request outside a dialog, other than those the
// registrar and the reg event notifier answer: one back from an
// application server goes on along its served user's iFC chain from where
// it left (odi), one along a Service-Route is originating, and any other is
// terminating, for the user its Request-URI names, as a request from the
// I-CSCF or one an application server sends for its user (#137) is.
func (rt *Router) Initial(ctx context.Context, r *proxy.Request) proxy.Decision {
	if v, ok := routedODI(r.Routed); ok {
		return rt.decide(rt.resume(ctx, r, v), false)
	}
	if alongServiceRoute(r.Routed) {
		return rt.Originating(ctx, r)
	}
	return rt.Terminating(ctx, r)
}

// alongServiceRoute reports whether a consumed Route carries orig.
func alongServiceRoute(routed []sip.Address) bool {
	for _, a := range routed {
		if _, ok := a.URI.Param(origParam); ok {
			return true
		}
	}
	return false
}

// Originating routes a request of the registered user its P-Asserted-
// Identity names, which the P-CSCF asserted (TS 24.229 §5.4.3.2): along the
// user's originating iFC chain, then toward the user it is for, through the
// I-CSCF (toTerminatingSide), the S-CSCF recording the route. It is 403 for
// a request asserting no public identity, or one of a user that is not
// registered or is barred, and 500 with Retry-After for a store that
// cannot be read.
func (rt *Router) Originating(ctx context.Context, r *proxy.Request) proxy.Decision {
	return rt.decide(rt.originating(ctx, r), true)
}

func (rt *Router) originating(ctx context.Context, r *proxy.Request) step {
	impu, ok := assertedUser(r.Message)
	if !ok {
		rt.count("routing.originating.no_identity")
		return answer(403, "Forbidden")
	}
	now := rt.cfg.Now()
	set, err := rt.lookup(ctx, impu, now)
	switch {
	case errors.Is(err, errBarred):
		rt.count("routing.originating.barred")
		return answer(403, "Forbidden")
	case errors.Is(err, errEnding) || err == nil && (set == nil || len(live(set, now)) == 0):
		rt.count("routing.originating.not_registered")
		return answer(403, "Forbidden")
	case err != nil:
		rt.internalLog("looking up the served user", err)
		return rt.unavailable(r.Message)
	}
	rt.count("routing.originating")
	pos := position{served: impu, scase: ifc.Originating, registered: true, priority: -1}
	return rt.next(ctx, r.Message, pos, set, rt.toTerminatingSide(r.Message))
}

// assertedUser is the first P-Asserted-Identity of req that is a public
// identity, canonical.
func assertedUser(req *sip.Request) (string, bool) {
	ids, err := req.Header.PAssertedIdentity()
	if err != nil {
		return "", false
	}
	for _, a := range ids {
		if impu, ok := identity.CanonicalIMPU(a.URI.String()); ok {
			return impu, true
		}
	}
	return "", false
}

// resume goes on with a request an application server sent back, along
// the iFC chain of the position v holds: 403 for one the S-CSCF did not
// sign for the request, or that has expired (ADR 0005).
func (rt *Router) resume(ctx context.Context, r *proxy.Request, v string) step {
	now := rt.cfg.Now()
	pos, err := rt.openODI(v, r.Message.Header.Get("Call-ID"), now)
	if err != nil {
		rt.count("routing.odi.refused")
		return answer(403, "Forbidden")
	}
	rt.count("routing.odi.resumed")
	set, err := rt.lookup(ctx, pos.served, now)
	switch {
	case errors.Is(err, errBarred):
		rt.count("routing.odi.barred")
		if pos.scase == ifc.Originating {
			return answer(403, "Forbidden")
		}
		return answer(404, "Not Found")
	case errors.Is(err, errEnding):
		// The user deregistered meanwhile, and set is nil: the chain ends
		// as it would without services.
	case err != nil:
		rt.internalLog("looking up the served user", err)
		return rt.unavailable(r.Message)
	}
	if pos.scase == ifc.Originating {
		return rt.next(ctx, r.Message, pos, set, rt.toTerminatingSide(r.Message))
	}
	if set == nil {
		rt.count("routing.terminating.not_registered")
		return answer(480, "Temporarily Unavailable")
	}
	if !namesServedUser(r.Message.URI, set) {
		// The server sent the request on to someone else (TS 24.229
		// §5.4.3.3): the served user's other services and contacts are no
		// longer the request's, the new user's S-CSCF is.
		rt.count("routing.terminating.retargeted")
		return rt.toTerminatingSide(r.Message)(ctx)
	}
	return rt.next(ctx, r.Message, pos, set, rt.toContacts(r.Message, set))
}

// namesServedUser reports whether u is one of set's identities, the served
// user's or another of its implicit set, as a tel URI the server put for
// the SIP one is.
func namesServedUser(u sip.URI, set *state.Registration) bool {
	impu, ok := identity.CanonicalIMPU(u.String())
	if !ok {
		return false
	}
	_, ok = inSet(set, impu)
	return ok
}

// toTerminatingSide is the end of an originating request's iFC chain: the
// I-CSCF of the home network, which finds the S-CSCF of the user the
// request is for (TS 24.229 §5.4.3.2). A tel URI with a global number is
// sent as the SIP URI of the number in the home domain, as no ENUM is
// asked; a request for another domain, or for a local number, is 404, for
// the platform has no way to other networks.
func (rt *Router) toTerminatingSide(req *sip.Request) func(context.Context) step {
	return func(context.Context) step {
		u, ok := rt.inHomeDomain(req.URI)
		if !ok {
			rt.count("routing.originating.no_route")
			return answer(404, "Not Found")
		}
		rt.count("routing.originating.to_icscf")
		t := proxy.Target{URI: u, Routes: []sip.Address{{URI: rt.cfg.ICSCF}}}
		return step{hops: []hop{{target: t, prepare: dropServedUser}}}
	}
}

// inHomeDomain is u as a SIP URI of the home domain: a SIP URI of it as it
// is, or a tel URI of a global number as sip:<number>@<home>;user=phone
// (RFC 3261 §19.1.6).
func (rt *Router) inHomeDomain(u sip.URI) (sip.URI, bool) {
	switch {
	case u.Scheme == "tel":
		n, ok := u.E164()
		if !ok {
			return sip.URI{}, false
		}
		return sip.URI{Scheme: "sip", User: n, Host: rt.cfg.HomeDomain, Params: sip.Params{{Name: "user", Value: "phone"}}}, true
	case u.IsSIP() && proxy.SameHost(u.Host, rt.cfg.HomeDomain):
		return u, true
	}
	return sip.URI{}, false
}

// dropServedUser removes the P-Served-User the S-CSCF put in toward an
// application server, which comes back with the request: on the
// terminating side it would read as a request an application server sent
// for its user, which rcs-as's triggers let pass (docs/hss.md).
func dropServedUser(_ context.Context, req *sip.Request) error {
	req.Header.Del("P-Served-User")
	return nil
}

// fromEdgeProxy reports whether src is a P-CSCF task's core listener.
func (rt *Router) fromEdgeProxy(src transport.Source) bool {
	return src.Addr.IsValid() && rt.edgeProxy(src.Addr.Addr().String())
}
