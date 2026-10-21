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
// address it reaches (#208, docs/threat-model.md T2). A next hop that is
// the P-CSCF's public address (Config.EdgeProxyPublicHosts) ends the route
// set, as rcsjta writes one there.
func (rt *Router) InDialog(_ context.Context, r *proxy.Request) proxy.Decision {
	next := r.Message.URI
	routes, err := r.Message.Header.Route()
	if err != nil {
		return proxy.Decision{Status: 400, Reason: "Bad Route"}
	}
	ended := len(routes) > 0 && rt.edgeProxyPublic(routes[0].URI.Host)
	if len(routes) > 0 && !ended {
		next = routes[0].URI
	}
	if !rt.nextHopAllowed(next) {
		rt.count("routing.in_dialog.refused")
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	rt.count("routing.in_dialog")
	d := proxy.Forward(r)
	if ended {
		// rcsjta's session refresh: the P-CSCF's public address it put
		// after the route set is where the client sent the dialog's first
		// INVITE, not a hop of the dialog; the route set ends before it,
		// and the request goes by its Request-URI.
		rt.count("routing.in_dialog.trailing_route")
		d.Prepare = func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			req.Header.Del("Route")
			return nil
		}
	}
	return d
}

// edgeProxyPublic reports whether host is one clients reach the P-CSCF at.
func (rt *Router) edgeProxyPublic(host string) bool {
	return slices.ContainsFunc(rt.cfg.EdgeProxyPublicHosts, func(h string) bool { return proxy.SameHost(h, host) })
}

// nextHopAllowed reports whether u is a next hop a request inside a dialog
// may go to: never the S-CSCF itself, which would send it round again; an
// application server; or a P-CSCF's core listener, with a well-formed flow
// token as its user, as pcscf writes its Path and Record-Route values.
func (rt *Router) nextHopAllowed(u sip.URI) bool {
	// A URI without a host, such as a tel URI, names no hop below.
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
