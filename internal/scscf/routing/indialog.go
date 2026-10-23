package routing

import (
	"context"
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// InDialog routes a request inside a dialog the S-CSCF recorded the route
// of: as its Route says (RFC 3261 §16.12), if the next hop is one of the two
// the S-CSCF's Record-Route value signed for the dialog when it was set up
// (recorder), and with 403 otherwise. The S-CSCF's own entries are gone
// from the Route by now; the rest are as the client wrote them, and every
// task of the core shares one network, so this is what keeps a client from
// reaching through the S-CSCF any address it reaches (#208, #322,
// docs/threat-model.md T2). The next hop must also be a listener of a
// P-CSCF's core side or of an application server, by port and transport,
// and never the S-CSCF itself. A next hop that is the P-CSCF's public
// address (Config.EdgeProxyPublicHosts) ends the route set, as rcsjta
// writes one there. A NOTIFY gets the S-CSCF's Record-Route value, signed
// as for a request that sets up a dialog.
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
	if !rt.signedFor(r, next) {
		rt.count("routing.in_dialog.refused")
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	if !rt.nextHopAllowed(next) {
		rt.count("routing.in_dialog.refused_port")
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
	}
	var rec *recorder
	if r.Message.Method == "NOTIFY" {
		// A subscriber takes its route set from the NOTIFY that creates
		// its dialog, not from the 2xx to its SUBSCRIBE (RFC 6665 §4.3,
		// §4.4.1), so the NOTIFY gets the S-CSCF's value, signed for the
		// hop toward the notifier, where the subscriber's refresh and
		// unsubscribe go next (#550). The recorder's rule holds as for a
		// request that sets up a dialog: a client's NOTIFY carries
		// pcscf's core-facing value on top (pcscf records it), so only
		// rcs-as's, which records none, is signed for its Contact.
		rec = rt.recorder(r.Message)
		d.RecordRoute = []sip.Address{rt.cfg.RecordRoute}
	}
	if ended || rec != nil {
		d.Prepare = func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			if ended {
				req.Header.Del("Route")
			}
			if rec != nil {
				return rec.prepare(req)
			}
			return nil
		}
	}
	return d
}

// signedFor reports whether next is a hop the S-CSCF signed for r's dialog:
// in the last of its own Route entries r consumed, the one next to the hop,
// as two entries of it are next to each other when a request passed it
// twice.
func (rt *Router) signedFor(r *proxy.Request, next sip.URI) bool {
	v := ""
	for _, a := range r.Routed {
		if p, ok := a.URI.Param(dlgParam); ok {
			v = p
		}
	}
	return v != "" && rt.signedHop(v, r.Message.Header.Get("Call-ID"), hopKey(next))
}

// nextHopAllowed reports whether u is a next hop a request inside a dialog
// may go to: never the S-CSCF itself, which would send it round again; a
// P-CSCF's core listener, over TCP at EdgeProxyPort; or an application
// server's listener, by its port and transport.
func (rt *Router) nextHopAllowed(u sip.URI) bool {
	for _, s := range rt.cfg.Self {
		if proxy.SameHost(s.Host, u.Host) {
			return false
		}
	}
	e := endpointOf(u)
	if e.transport == "tcp" && e.port == rt.cfg.EdgeProxyPort {
		return true
	}
	return slices.ContainsFunc(rt.cfg.ApplicationServers, func(as sip.URI) bool {
		a := endpointOf(as)
		return a.port == e.port && a.transport == e.transport
	})
}

// edgeProxyPublic reports whether host is one clients reach the P-CSCF at.
func (rt *Router) edgeProxyPublic(host string) bool {
	return slices.ContainsFunc(rt.cfg.EdgeProxyPublicHosts, func(h string) bool { return proxy.SameHost(h, host) })
}
