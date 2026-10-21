package routing

import (
	"context"
	"errors"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// step is where a request goes next: an answer, or hops.
type step struct {
	status   int
	reason   string
	response *sip.Response
	hops     []hop
}

func answer(status int, reason string) step { return step{status: status, reason: reason} }

// hop is one target with what its branch needs: prepare changes the
// branch's copy before it is sent, and failed, when the branch ends without
// a 2xx, says where the request goes instead, or how it is answered
// (plan.final).
type hop struct {
	target  proxy.Target
	prepare func(ctx context.Context, req *sip.Request) error
	// failed is nil for a hop whose failure ends the request.
	failed func(ctx context.Context, f proxy.BranchFailure) step
}

// plan holds the hops of one request by target, for the Decision's hooks,
// which the proxy calls for every branch, and the answer of a chain that
// ended after its last hop failed.
type plan struct {
	mu     sync.Mutex
	hops   map[string]hop
	status int
	reason string
}

// decide is the Decision for s: its answer, or its hops, with the S-CSCF's
// Record-Route if recordRoute.
func (rt *Router) decide(s step, recordRoute bool) proxy.Decision {
	switch {
	case s.response != nil:
		return proxy.Decision{Response: s.response}
	case s.status != 0:
		return proxy.Decision{Status: s.status, Reason: s.reason}
	}
	p := &plan{hops: map[string]hop{}}
	d := proxy.Decision{Targets: p.add(s.hops), Prepare: p.prepare, OnBranchFailure: p.failed, OnFinal: p.final}
	if recordRoute {
		d.RecordRoute = []sip.Address{rt.cfg.RecordRoute}
	}
	return d
}

func (p *plan) add(hops []hop) []proxy.Target {
	if len(hops) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]proxy.Target, 0, len(hops))
	for _, h := range hops {
		p.hops[keyOf(h.target)] = h
		out = append(out, h.target)
	}
	return out
}

func (p *plan) hop(t proxy.Target) (hop, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h, ok := p.hops[keyOf(t)]
	return h, ok
}

// errNoHop is a branch to a target the plan does not hold, which the proxy
// only sends to those the plan gave it.
var errNoHop = errors.New("routing: a branch to a target not planned")

func (p *plan) prepare(ctx context.Context, t proxy.Target, req *sip.Request) error {
	h, ok := p.hop(t)
	if !ok {
		return errNoHop
	}
	return h.prepare(ctx, req)
}

// failed is the step after a failed branch: its hops are tried, and an
// answer replaces the final response the proxy chose, as the chain's own
// (final), unless a later branch succeeds.
func (p *plan) failed(ctx context.Context, f proxy.BranchFailure) []proxy.Target {
	h, ok := p.hop(f.Target)
	if !ok || h.failed == nil {
		return nil
	}
	s := h.failed(ctx, f)
	status, reason := s.status, s.reason
	if s.response != nil {
		status, reason = s.response.StatusCode, s.response.Reason
	}
	if status != 0 {
		p.mu.Lock()
		p.status, p.reason = status, reason
		p.mu.Unlock()
	}
	return p.add(s.hops)
}

// final gives the final response the chain's answer if it has one, and
// otherwise turns a 430 into 480, as the proxy does without OnFinal: 430 is
// between an edge proxy and the S-CSCF (RFC 5626 §11.5).
func (p *plan) final(_ context.Context, res *sip.Response) {
	if res.StatusCode < 300 {
		return
	}
	p.mu.Lock()
	status, reason := p.status, p.reason
	p.mu.Unlock()
	switch {
	case status != 0:
		res.StatusCode, res.Reason = status, reason
	case res.StatusCode == 430:
		res.StatusCode, res.Reason = 480, sip.DefaultReason(480)
	}
}

// next is the request's next step in its served user's iFC chain after
// pos (TS 24.229 §5.4.3.2, §5.4.3.3): the application server of the next
// criterion of set's profile that applies, or, once none does, end.
//
// A request is evaluated without a P-Served-User unless it came with one
// of its own (position.kept): the one the S-CSCF inserts toward an
// application server comes back with the request, and a criterion that
// excludes requests an application server sends for its users, as rcs-as's
// do (docs/hss.md), would otherwise miss every request that passed another
// server first (#14). A request too large to evaluate is refused with 500
// (ifc.LimitError, #14): a condition left unexamined could let it pass a
// server it must not.
func (rt *Router) next(ctx context.Context, req *sip.Request, pos position, set *state.Registration, end func(context.Context) step) step {
	if set == nil {
		return end(ctx)
	}
	services, err := rt.servicesOf(ctx, set.Key, pos.served)
	switch {
	case errors.Is(err, errBadProfile):
		rt.internalLog("reading the served user's services", err)
		return answer(500, "Server Internal Error")
	case err != nil:
		rt.internalLog("reading the served user's profile", err)
		return rt.unavailable(req)
	}
	v := view{req: req}
	if !pos.kept {
		v.hide = "P-Served-User"
	}
	fc, ok, err := services.Next(v, ifc.Context{Case: pos.scase, Unregistered: !pos.registered}, pos.priority)
	switch {
	case err != nil:
		// Next fails only with a *ifc.LimitError.
		rt.count("ifc.budget_exceeded")
		return answer(500, "Server Internal Error")
	case !ok:
		return end(ctx)
	}
	after := pos
	after.priority = fc.Priority
	as, err := sip.ParseURI(fc.ApplicationServer.ServerName)
	if err != nil || !as.IsSIP() || as.Host == "" {
		// It names no server the S-CSCF can send to, and is passed over
		// as a server that cannot be reached would be, its session
		// continued: refusing every request of the user would be worse.
		rt.count("routing.ifc.bad_server")
		return rt.next(ctx, req, after, set, end)
	}
	rt.count("routing.ifc.application_server")
	return rt.toAS(req, after, set, as, fc.ApplicationServer.DefaultHandling, end)
}

// toAS is the hop to an application server: the request's Request-URI
// unchanged, along the server and then back to the S-CSCF, whose Route
// carries pos signed (odi), with P-Served-User naming the served user and
// the session case (RFC 5502). Without an answer from the server, the
// criterion's default handling applies: SESSION_CONTINUED goes on with the
// chain as if the server had not matched, SESSION_TERMINATED ends the
// request with the proxy's answer (TS 24.229 §5.4.3.2). An answer the
// server sends is passed on as it is, a 500 with Retry-After included.
func (rt *Router) toAS(req *sip.Request, pos position, set *state.Registration, as sip.URI, handling ifc.DefaultHandling, end func(context.Context) step) step {
	server := as
	server.Params = append(sip.Params(nil), as.Params...)
	server.Params.SetFlag("lr")
	back := rt.cfg.RecordRoute.URI
	back.Params = append(sip.Params(nil), back.Params...)
	back.Params.Set(odiParam, rt.signODI(pos, req.Header.Get("Call-ID"), rt.cfg.Now().Add(rt.cfg.ODILifetime)))
	t := proxy.Target{URI: req.URI, Routes: []sip.Address{{URI: server}, {URI: back}}}
	if req.Method != "INVITE" {
		// An INVITE's branch may ring for long, and Timeout would cancel
		// it: the server's silence is Timer B's to find (RFC 3261 §17.1.1).
		t.Timeout = rt.cfg.ASTimeout
	}
	return step{hops: []hop{{
		target: t,
		prepare: func(_ context.Context, b *sip.Request) error {
			return b.Header.Set("P-Served-User", servedUser(pos))
		},
		failed: func(ctx context.Context, f proxy.BranchFailure) step {
			if handling != ifc.SessionContinued || !unanswered(f) {
				return step{}
			}
			rt.count("routing.ifc.default_handling_continued")
			return rt.next(ctx, req, pos, set, end)
		},
	}}}
}

// unanswered reports whether a branch ended without an answer from its
// target: a failure the proxy made up (a timeout, the transport), or a 408.
func unanswered(f proxy.BranchFailure) bool {
	return f.Err != nil || f.Response != nil && f.Response.StatusCode == 408
}

// servedUser is the P-Served-User toward an application server: the served
// user, a canonical public identity that needs no escaping, with its
// session case and registration state (RFC 5502).
func servedUser(pos position) string {
	scase, reg := "term", "unreg"
	if pos.scase == ifc.Originating {
		scase = "orig"
	}
	if pos.registered {
		reg = "reg"
	}
	return "<" + pos.served + ">;sescase=" + scase + ";regstate=" + reg
}

// unavailable answers req 500 with Retry-After: the store or the HSS
// failed, and the caller may try again soon (RFC 3261 §21.5.1).
func (rt *Router) unavailable(req *sip.Request) step {
	tag, err := rt.ids.Tag()
	if err != nil {
		return answer(500, "Server Internal Error")
	}
	res, err := sip.NewResponse(req, 500, "Server Internal Error", tag)
	if err != nil {
		return answer(500, "Server Internal Error")
	}
	_ = res.Header.Set("Retry-After", storeRetryAfter)
	return step{response: res}
}
