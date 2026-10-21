package pcscf

import (
	"context"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// metricPAIOmitted counts the requests from the core outside a dialog whose
// responses assert no identity, since the request named none, and
// metricRecordRouteMalformed those whose Record-Route did not parse, so
// that their answers' Record-Route goes upstream as the client wrote it.
const (
	metricPAIOmitted           = "terminating.pai_omitted"
	metricRecordRouteMalformed = "terminating.record_route_malformed"
)

// toClientOnly are the network's headers a request from the core loses
// before it reaches a client, beside the charging data (TS 24.229 §5.2.1):
// whom the core served and the profile it chose say nothing to the client.
var toClientOnly = []string{"P-Served-User", "P-Profile-Key"}

// terminate routes a request from the core to a client (TS 24.229 §5.2.6.4,
// #16 plan D), keeping no dialog state: the flow it goes over is the token
// in a consumed Route naming this task's core listener, the Path of the
// client's registration for a request outside a dialog, or the core-facing
// Record-Route value pcscf wrote for one inside. It is sent over that flow
// and nowhere else, so no Route or Request-URI the request carries can send
// it on. A request naming no flow, or one that is not a live client flow
// of this task (closed, from an earlier start, or a core connection), is
// answered 430 Flow Failed, which scscf takes as a sign to try the client's
// other flows (RFC 5626 §5.3). So does a flow already gone before the send,
// and one that closes while the request is under way, before its final
// response: the transport tells the proxy (OnFlowClosed, Proxy.FlowClosed),
// which ends the branch at once instead of at Timer B or F (#234).
//
// A request outside a dialog that sets up one gets pcscf's two Record-Route
// values, the client-facing one on top, so that the dialog's requests come
// back through this task on both sides; a standalone one, such as MESSAGE,
// gets none. The core-facing one keeps the Path's ob and the request's icid
// (§5.2.6.4.4 3)), and binds the flow to the dialog's Call-ID. A request
// inside a dialog must name its live flow by the value written for its
// Call-ID, or it is 403. P-Asserted-Identity is removed when the request
// asks for privacy of the identity (RFC 3323 §4.2, RFC 3325 §9.3), and the
// request reaches the client without the network's charging data and the
// other headers in toClientOnly.
//
// The client's responses carry the request's charging identifiers, or the
// dialog's when a request inside it has none, and this network as the type
// 1 term-ioi. A 1xx or 2xx to a request that sets up a dialog, and any
// response to a standalone one, asserts the identity the request was for,
// its P-Called-Party-ID (§5.2.6.4.4 1), §5.2.6.4.8 2)). A 1xx or 2xx that
// does not return pcscf's Record-Route values and the core's as they were
// has them put back (§5.2.6.4.4 3) b)), so a client cannot change the
// route the core keeps.
func (p *pcscf) terminate(_ context.Context, r *proxy.Request) proxy.Decision {
	var entry *sip.URI
	for i, a := range r.Routed {
		if a.URI.User != "" && proxy.SameHost(a.URI.Host, hostOf(p.cfg.CoreHost)) && a.URI.Port == p.corePort {
			entry = &r.Routed[i].URI
			break
		}
	}
	if entry == nil || p.clientFlow == nil || !p.clientFlow(transport.FlowID(entry.User)) {
		p.count(metricTerminatingFlow, 1)
		return proxy.Decision{Status: statusFlowFailed, Reason: "Flow Failed"}
	}
	flow := transport.FlowID(entry.User)
	initial := r.Initial()
	callID := r.Message.Header.Get("Call-ID")
	// Inside a dialog only the Record-Route value pcscf wrote for it, not
	// the Path or another dialog's, names the flow.
	if !initial && !p.inDialogWith(*entry, callID) {
		p.count(metricTerminatingRoute, 1)
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	fallback := ""
	if !initial {
		fallback, _ = routeICID(*entry)
	}
	charging := p.terminatingCharging(r.Message, fallback)
	forming := initial && dialogForming(r.Message.Method)
	var asserted *sip.Address
	if initial {
		if called, err := r.Message.Header.PCalledPartyID(); err == nil {
			asserted = &sip.Address{URI: bare(called.URI)}
		} else if p.metrics != nil {
			p.metrics.Count(metricPAIOmitted, 1)
		}
	}
	private := privacyID(&r.Message.Header)
	d := proxy.Decision{
		Targets: []proxy.Target{{URI: r.Message.URI, Destination: &transport.Destination{Flow: flow}}},
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			if private {
				req.Header.Del("P-Asserted-Identity")
			}
			stripCharging(&req.Header)
			for _, name := range toClientOnly {
				req.Header.Del(name)
			}
			return nil
		},
		// scscf, the authoritative proxy, needs the 430 (RFC 5626 §11.5).
		// A flow that failed as the request went is 430 too, which the
		// proxy makes; it is counted with the ones refused above. A 430
		// the client sent over its flow, still live, is passed on but not
		// counted, as no flow failed (#345 QA).
		OnFinal: func(_ context.Context, res *sip.Response) {
			if res.StatusCode == statusFlowFailed && !p.clientFlow(flow) {
				p.count(metricTerminatingFlow, 1)
			}
		},
	}
	// routes is the Record-Route a 1xx or 2xx must return, nil when it
	// cannot be known: the core's did not parse, so a rewrite would lose it.
	var routes []sip.Address
	if forming {
		rr := p.recordRoute(flow, entry.Params.Has("ob"), icidOfVector(charging), callID)
		d.RecordRoute = []sip.Address{rr[1], rr[0]}
		if received, err := r.Message.Header.RecordRoute(); err == nil {
			routes = append(slices.Clone(d.RecordRoute), received...)
		} else if p.metrics != nil {
			p.metrics.Count(metricRecordRouteMalformed, 1)
		}
	}
	d.OnResponse = func(_ context.Context, res *sip.Response) {
		if res.StatusCode == 100 {
			return
		}
		_ = res.Header.Set("P-Charging-Vector", charging)
		// The client's preference is for its own requests (RFC 3325
		// §9.2); the network never sees it in a response.
		res.Header.Del("P-Preferred-Identity")
		if routes != nil && res.StatusCode < 300 {
			keepRecordRoute(&res.Header, routes)
		}
		if initial && (!forming || res.StatusCode < 300) {
			res.Header.Del("P-Asserted-Identity")
			if asserted != nil {
				_ = res.Header.Set("P-Asserted-Identity", asserted.String())
			}
		}
	}
	// MSRP sessions rcs-as sets up, and the requests inside them, are
	// anchored through msrp-relay (ADR 0004).
	if initial {
		return p.anchorInitial(r, d, coreSide, flow)
	}
	return p.anchorInDialog(r, d, coreSide, flow)
}

// keepRecordRoute puts routes back as the Record-Route of a response that
// does not carry them as they were sent.
func keepRecordRoute(h *sip.Header, routes []sip.Address) {
	got, err := h.RecordRoute()
	if err == nil && slices.EqualFunc(got, routes, func(a, b sip.Address) bool { return a.String() == b.String() }) {
		return
	}
	h.Del("Record-Route")
	for _, a := range routes {
		_ = h.Add("Record-Route", a.String())
	}
}

// terminatingCharging is the P-Charging-Vector of the client's responses to
// req: its icid-value, or else fallback, the dialog's, or else a new one,
// an icid-value a route could not carry (validICID) counting as none, so
// that the dialog's route and its answers carry the same one;
// its orig-ioi if any; and this network as the type 1 term-ioi (§5.2.6.4.4
// 6)). Values keep the quoting they came with.
func (p *pcscf) terminatingCharging(req *sip.Request, fallback string) string {
	var cv sip.ChargingVector
	got, err := req.Header.PChargingVector()
	param := func(name string) (sip.Param, bool) {
		if err != nil {
			return sip.Param{}, false
		}
		i := slices.IndexFunc(got.Params, func(p sip.Param) bool { return strings.EqualFold(p.Name, name) })
		if i < 0 {
			return sip.Param{}, false
		}
		return got.Params[i], true
	}
	if v, ok := param("icid-value"); ok && validICID(got.ICID()) {
		cv.Params = append(cv.Params, v)
	} else if fallback != "" {
		cv.Params.Set("icid-value", fallback)
	} else if icid, err := p.icid(); err == nil {
		cv.Params.Set("icid-value", icid)
	}
	if v, ok := param("orig-ioi"); ok {
		cv.Params = append(cv.Params, v)
	}
	cv.Params.Set("term-ioi", p.cfg.HomeDomain)
	return cv.String()
}

// icidOfVector is the icid-value of a P-Charging-Vector pcscf wrote.
func icidOfVector(cv string) string {
	var h sip.Header
	if h.Set("P-Charging-Vector", cv) != nil {
		return ""
	}
	got, err := h.PChargingVector()
	if err != nil {
		return ""
	}
	return got.ICID()
}

// privacyID reports whether a message asks for privacy of the identity:
// Privacy has id (RFC 3323 §4.2, RFC 3325 §9.3).
func privacyID(h *sip.Header) bool {
	for _, v := range h.Values("Privacy") {
		if slices.ContainsFunc(strings.FieldsFunc(v, func(r rune) bool { return r == ';' || r == ',' }), func(s string) bool {
			return strings.EqualFold(strings.TrimSpace(s), "id")
		}) {
			return true
		}
	}
	return false
}
