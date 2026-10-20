package routing

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// InDialog routes a request inside a dialog the S-CSCF recorded the route
// of: as its Route says (RFC 3261 §16.12), if the next hop is one the
// platform runs past the S-CSCF, an application server or a P-CSCF's core
// listener naming a flow, and with 403 otherwise. The S-CSCF's own entries
// are gone from the Route by now; the rest are as the client wrote them,
// so this is what keeps a client from reaching through the S-CSCF any
// address it reaches (#208, docs/threat-model.md T2).
func (rt *Router) InDialog(_ context.Context, r *proxy.Request) proxy.Decision {
	next := r.Message.URI
	routes, err := r.Message.Header.Route()
	if err != nil {
		return proxy.Decision{Status: 400, Reason: "Bad Route"}
	}
	if len(routes) > 0 {
		next = routes[0].URI
	}
	if !rt.nextHopAllowed(next) {
		rt.count("routing.in_dialog.refused")
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	rt.count("routing.in_dialog")
	return proxy.Forward(r)
}

// nextHopAllowed reports whether u is a next hop a request inside a dialog
// may go to: never the S-CSCF itself, which would send it round again; an
// application server; or a P-CSCF's core listener, with a well-formed flow
// token as its user, as pcscf writes its Path and Record-Route values.
func (rt *Router) nextHopAllowed(u sip.URI) bool {
	if !u.IsSIP() {
		return false
	}
	for _, s := range rt.cfg.Self {
		if proxy.SameHost(s.Host, u.Host) {
			return false
		}
	}
	if slices.ContainsFunc(rt.cfg.ApplicationServers, func(h string) bool { return proxy.SameHost(h, u.Host) }) {
		return true
	}
	return rt.edgeProxy(u.Host) && transport.FlowID(u.User).WellFormed()
}

// edgeProxy reports whether host names a P-CSCF task's core listener.
func (rt *Router) edgeProxy(host string) bool {
	if slices.ContainsFunc(rt.cfg.EdgeProxyHosts, func(h string) bool { return proxy.SameHost(h, host) }) {
		return true
	}
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if err != nil {
		return false
	}
	a = a.Unmap().WithZone("")
	return slices.ContainsFunc(rt.cfg.EdgeProxyNets, func(p netip.Prefix) bool { return p.Contains(a) })
}
