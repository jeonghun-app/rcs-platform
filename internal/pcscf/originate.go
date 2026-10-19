package pcscf

import (
	"context"
	"net/netip"
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// originate routes a client's request outside a dialog (TS 24.229
// §5.2.6.3.3). It must come over a registered flow. pcscf asserts an
// identity the registration allows, sends it along the Service-Route the
// registration received in place of whatever Route the client wrote, and
// records two Record-Route values, so that the dialog's requests come back
// through it on either side (RFC 5658).
func (p *pcscf) originate(_ context.Context, r *proxy.Request) proxy.Decision {
	src := r.Source
	if !p.initials.allow(clientKey(src.Addr)) {
		return p.refuse(r, 503, "Too Many Requests")
	}
	regs := p.registry.flowRegistrations(src.Flow)
	if len(regs) == 0 {
		return proxy.Decision{Status: 403, Reason: "Not Registered"}
	}
	reg, ids := assertedIdentity(regs, r.Message)
	if len(reg.serviceRoute) == 0 {
		// Without it the next hop would be the Request-URI, a core
		// address the client chose, past scscf.
		return proxy.Decision{Status: 500, Reason: "No Service-Route"}
	}
	icid, err := p.icid()
	if err != nil {
		return proxy.Decision{Status: 500}
	}
	routes := slices.Clone(reg.serviceRoute)
	return proxy.Decision{
		Targets:     []proxy.Target{{URI: r.Message.URI}},
		RecordRoute: p.recordRoute(src.Flow, contactHasOb(r.Message)),
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			// The Service-Route replaces the Route (§5.2.6.3.3): what the
			// client wrote below pcscf's own entry is not where it
			// registered.
			req.Header.Del("Route")
			for _, a := range routes {
				if err := req.Header.Add("Route", a.String()); err != nil {
					return err
				}
			}
			req.Header.Del("P-Preferred-Identity")
			for _, id := range ids {
				if err := req.Header.Add("P-Asserted-Identity", id.String()); err != nil {
					return err
				}
			}
			return req.Header.Set("P-Charging-Vector", p.chargingVector(icid))
		},
	}
}

// assertedIdentity chooses the registration a request is sent under and the
// identities pcscf asserts for it (TS 24.229 §5.2.6.3.3, #16 question 5):
// the P-Preferred-Identity the client named if a registration over its flow
// allows it, or else the default public identity of the first registration,
// the first of its P-Associated-URI. A SIP identity is joined by the
// registration's first tel URI, as RFC 3325 §9.1 allows one of each. The
// P-Associated-URI lists no barred identity (TS 24.229 §5.4.1.2.2), so none
// is asserted.
func assertedIdentity(regs []*registration, req *sip.Request) (*registration, []sip.Address) {
	var reg *registration
	var id sip.URI
	if preferred, err := req.Header.PPreferredIdentity(); err == nil {
		for _, want := range preferred {
			for _, r := range regs {
				if i := slices.IndexFunc(r.associated, func(a sip.Address) bool { return aorKey(a.URI) == aorKey(want.URI) }); i >= 0 {
					reg, id = r, r.associated[i].URI
					break
				}
			}
			if reg != nil {
				break
			}
		}
	}
	if reg == nil {
		reg = regs[0]
		if len(reg.associated) > 0 {
			id = reg.associated[0].URI
		} else {
			id = reg.uri
		}
	}
	ids := []sip.Address{{URI: bare(id)}}
	if id.IsSIP() {
		if i := slices.IndexFunc(reg.associated, func(a sip.Address) bool { return a.URI.Scheme == "tel" }); i >= 0 {
			ids = append(ids, sip.Address{URI: bare(reg.associated[i].URI)})
		}
	}
	return reg, ids
}

// bare is u without the parameters and headers a P-Associated-URI may
// carry, which say nothing about the identity.
func bare(u sip.URI) sip.URI {
	u.Headers = nil
	u.Password = ""
	if u.Scheme == "tel" {
		return u
	}
	if v, ok := u.Params.Get("user"); ok {
		u.Params = sip.Params{{Name: "user", Value: v}}
	} else {
		u.Params = nil
	}
	return u
}

// recordRoute is pcscf's two Record-Route values, topmost first (RFC 5658
// §5): the one the core sees, which names this task's core listener and the
// flow, so that the dialog's requests from the core reach this flow (ADR
// 0005), with ob when the client's Contact has it (TS 24.229 §5.2.6.3.3
// 5), RFC 5626 §5.1), and the one the client sees, the public name it
// dials.
func (p *pcscf) recordRoute(flow transport.FlowID, ob bool) []sip.Address {
	core := sip.URI{Scheme: "sip", User: string(flow), Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	core.Params.Set("transport", "tcp")
	core.Params.SetFlag("lr")
	if ob {
		core.Params.SetFlag("ob")
	}
	client := sip.URI{Scheme: "sip", Host: p.cfg.PublicHost, Port: p.cfg.PublicPort}
	if p.cfg.ClientTransport == ClientTCP {
		client.Params.Set("transport", "tcp")
	} else {
		client.Params.Set("transport", "tls")
	}
	client.Params.SetFlag("lr")
	return []sip.Address{{URI: core}, {URI: client}}
}

// contactHasOb reports whether the request's Contact has the ob parameter:
// the client uses outbound for this dialog (RFC 5626 §4.3).
func contactHasOb(req *sip.Request) bool {
	contacts, err := req.Header.Contact()
	return err == nil && len(contacts) == 1 && !contacts[0].Star && contacts[0].URI.Params.Has("ob")
}

// inDialog forwards a client's request inside a dialog (#16 question 6), as
// its Route says, but only along a route set this pcscf is in for this
// flow: both of its Record-Route values were consumed, the core-facing one
// names the flow the request came on, and the next hop is a private
// address. Anything else is 403, so a client cannot aim a request at a core
// address of its choosing past the services that should see it. It keeps
// no dialog state: the flow token ties the route to the flow.
func (p *pcscf) inDialog(ctx context.Context, r *proxy.Request) proxy.Decision {
	var core, client bool
	for _, a := range r.Routed {
		switch {
		case a.URI.User == string(r.Source.Flow) && a.URI.Host == hostOf(p.cfg.CoreHost) && a.URI.Port == p.corePort:
			core = true
		case a.URI.User == "" && p.publicHost(a.URI.Host):
			client = true
		}
	}
	if !core || !client {
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	next := r.Message.URI
	if routes, err := r.Message.Header.Route(); err == nil && len(routes) > 0 {
		next = routes[0].URI
	}
	if _, err := p.resolve.Resolve(ctx, next); err != nil {
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	return proxy.Forward(r)
}

// publicHost reports whether host is a name the client-facing Record-Route
// may carry: the public name, or one of the NLB's addresses.
func (p *pcscf) publicHost(host string) bool {
	if host == p.cfg.PublicHost {
		return true
	}
	return slices.ContainsFunc(p.cfg.PublicAddrs, func(a netip.Addr) bool { return hostOf(a) == host })
}
