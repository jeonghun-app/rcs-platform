package pcscf

import (
	"context"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// terminate routes a request from the core to a client (TS 24.229 §5.2.6.4,
// #16 plan D), keeping no dialog state: the flow it goes over is the token
// in a consumed Route naming this task's core listener, the Path of the
// client's registration for a request outside a dialog, or the core-facing
// Record-Route value pcscf wrote for one inside. It is sent over that flow
// and nowhere else, so no Route or Request-URI the request carries can send
// it on. A request naming no flow, or one that is not a client flow of this
// task (closed, from an earlier start, or a core connection), is answered
// 430 Flow Failed, which scscf takes as a sign to try the client's other
// flows (RFC 5626 §5.3), and so is one whose flow fails while it is sent.
//
// A request outside a dialog gets pcscf's two Record-Route values, the
// client-facing one on top, so that the dialog's requests come back through
// this task on both sides; the core-facing one keeps the Path's ob and the
// request's icid (§5.2.6.4.4 3)). P-Asserted-Identity is removed when the
// request asks for privacy of the identity (RFC 3323 §4.2, RFC 3325 §9.3).
// The request reaches the client without the network's charging data. The
// client's responses carry the request's charging identifiers and this
// network as the type 1 term-ioi; a 1xx or 2xx to a request outside a
// dialog asserts the identity the request was for (§5.2.6.4.4 1), 6)).
func (p *pcscf) terminate(_ context.Context, r *proxy.Request) proxy.Decision {
	var entry *sip.URI
	for i, a := range r.Routed {
		if a.URI.User != "" && proxy.SameHost(a.URI.Host, hostOf(p.cfg.CoreHost)) && a.URI.Port == p.corePort {
			entry = &r.Routed[i].URI
			break
		}
	}
	if entry == nil || p.clientFlow == nil || !p.clientFlow(transport.FlowID(entry.User)) {
		return proxy.Decision{Status: statusFlowFailed, Reason: "Flow Failed"}
	}
	flow := transport.FlowID(entry.User)
	initial := r.Initial()
	charging := p.terminatingCharging(r.Message)
	asserted := p.calledIdentity(flow, r.Message)
	private := privacyID(r.Message)
	d := proxy.Decision{
		Targets: []proxy.Target{{URI: r.Message.URI, Destination: &transport.Destination{Flow: flow}}},
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			if private {
				req.Header.Del("P-Asserted-Identity")
			}
			stripCharging(&req.Header)
			return nil
		},
		OnResponse: func(_ context.Context, res *sip.Response) {
			if res.StatusCode == 100 {
				return
			}
			_ = res.Header.Set("P-Charging-Vector", charging)
			if initial && res.StatusCode < 300 {
				res.Header.Del("P-Preferred-Identity")
				if asserted != nil {
					_ = res.Header.Set("P-Asserted-Identity", asserted.String())
				}
			}
		},
		// scscf, the authoritative proxy, needs the 430 (RFC 5626 §11.5).
		OnFinal: func(context.Context, *sip.Response) {},
	}
	if initial {
		rr := p.recordRoute(flow, entry.Params.Has("ob"), icidOfVector(charging))
		d.RecordRoute = []sip.Address{rr[1], rr[0]}
	}
	return d
}

// terminatingCharging is the P-Charging-Vector of the client's responses to
// req: its icid-value, a new one if it has none, its orig-ioi if any, and
// this network as the type 1 term-ioi (§5.2.6.4.4 6)).
func (p *pcscf) terminatingCharging(req *sip.Request) string {
	var cv sip.ChargingVector
	if got, err := req.Header.PChargingVector(); err == nil && got.ICID() != "" {
		cv.Params.Set("icid-value", got.ICID())
		if v, ok := got.Params.Get("orig-ioi"); ok {
			cv.Params.Set("orig-ioi", v)
		}
	} else if icid, err := p.icid(); err == nil {
		cv.Params.Set("icid-value", icid)
	}
	cv.Params.Set("term-ioi", p.cfg.HomeDomain)
	return cv.String()
}

// icidOfVector is the icid-value of a P-Charging-Vector pcscf wrote.
func icidOfVector(cv string) string {
	v, _, _ := strings.Cut(strings.TrimPrefix(cv, "icid-value="), ";")
	return v
}

// calledIdentity is the identity a client's response to req asserts: the
// P-Called-Party-ID the core wrote (§5.2.6.4.4 1)); without one, the
// Request-URI if it is an identity the flow registered, or else the
// default public identity of the flow's first registration; nil if there
// is none.
func (p *pcscf) calledIdentity(flow transport.FlowID, req *sip.Request) *sip.Address {
	if called, err := req.Header.PCalledPartyID(); err == nil {
		return &sip.Address{URI: bare(called.URI)}
	}
	regs := p.registry.flowRegistrations(flow)
	key := identityKey(req.URI)
	for _, reg := range regs {
		if i := slices.IndexFunc(reg.associated, func(a sip.Address) bool { return identityKey(a.URI) == key }); i >= 0 {
			return &sip.Address{URI: bare(reg.associated[i].URI)}
		}
	}
	if len(regs) == 0 || len(regs[0].associated) == 0 {
		return nil
	}
	return &sip.Address{URI: bare(regs[0].associated[0].URI)}
}

// privacyID reports whether req asks for privacy of the identity: Privacy
// has id (RFC 3323 §4.2, RFC 3325 §9.3).
func privacyID(req *sip.Request) bool {
	for _, v := range req.Header.Values("Privacy") {
		if slices.ContainsFunc(strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }), func(s string) bool {
			return strings.EqualFold(strings.TrimSpace(s), "id")
		}) {
			return true
		}
	}
	return false
}
