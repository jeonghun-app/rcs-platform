package pcscf

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// metricUnregistered counts the requests discarded because their flow has no
// registration.
const metricUnregistered = "requests.unregistered_discarded"

// originate routes a client's request outside a dialog (TS 24.229
// §5.2.6.3.3). It must come over a registered flow: one that is not is
// discarded without a response, so that a client pcscf has lost the
// registration of times out and registers again (§5.2.6.3.2A). pcscf asserts
// an identity the registration allows, sends the request along the
// Service-Route the registration received in place of whatever Route the
// client wrote, and records two Record-Route values, so that the dialog's
// requests come back through it on either side (RFC 5658).
func (p *pcscf) originate(_ context.Context, r *proxy.Request) proxy.Decision {
	src := r.Source
	if !p.initials.allow(clientKey(src.Addr)) {
		return p.refuse(r, 503, "Too Many Requests")
	}
	regs := p.registry.flowRegistrations(src.Flow)
	if len(regs) == 0 {
		if p.metrics != nil {
			p.metrics.Count(metricUnregistered, 1)
		}
		return proxy.Decision{Discard: true}
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
		RecordRoute: p.recordRoute(src.Flow, contactHasOb(r.Message), icid),
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
// identities pcscf asserts for it (TS 24.229 §5.2.6.3.1, §5.2.6.3.3 6), #16
// question 5). The identity is the first P-Preferred-Identity value a
// registration over the flow lists in its P-Associated-URI, and the request
// goes under that registration; a second such value is the alternative
// identity. A SIP URI with user=phone and a number is matched as the tel URI
// of that number too. With no match the identity is the default public
// identity, the first P-Associated-URI of the first registration.
//
// Without an alternative identity, an identity that is a user=phone SIP URI
// is joined by the registration's tel URI of the same number, if it has one;
// no other number is asserted beside it. RFC 3325 §9.1 allows one SIP or
// SIPS and one tel URI, so an alternative of the identity's own kind is not
// used. The values asserted are the registration's, without parameters
// other than user; the P-Associated-URI lists no barred identity (TS 24.229
// §5.4.1.2.2), so none is asserted.
func assertedIdentity(regs []*registration, req *sip.Request) (*registration, []sip.Address) {
	var reg *registration
	var ids []sip.URI
	if preferred, err := req.Header.PPreferredIdentity(); err == nil {
		for _, want := range preferred {
			keys := matchKeys(want.URI)
			for _, r := range regs {
				i := slices.IndexFunc(r.associated, func(a sip.Address) bool { return slices.Contains(keys, identityKey(a.URI)) })
				if i < 0 {
					continue
				}
				id := r.associated[i].URI
				switch {
				case reg == nil:
					reg, ids = r, []sip.URI{id}
				case id.IsSIP() != ids[0].IsSIP():
					ids = append(ids, id)
				}
				break
			}
			if len(ids) == 2 {
				break
			}
		}
	}
	if reg == nil {
		reg = regs[0]
		id := reg.uri
		if len(reg.associated) > 0 {
			id = reg.associated[0].URI
		}
		ids = []sip.URI{id}
	}
	if number, ok := phoneNumber(ids[0]); ok && len(ids) == 1 {
		tel := identityKey(sip.URI{Scheme: "tel", User: number})
		if i := slices.IndexFunc(reg.associated, func(a sip.Address) bool { return identityKey(a.URI) == tel }); i >= 0 {
			ids = append(ids, reg.associated[i].URI)
		}
	}
	out := make([]sip.Address, len(ids))
	for i, id := range ids {
		out[i] = sip.Address{URI: bare(id)}
	}
	return reg, out
}

// matchKeys are the identityKeys a P-Preferred-Identity value matches a
// registered identity by: its own, and for a user=phone SIP URI with a
// number that of the tel URI of the number (TS 24.229 §5.2.6.3.1).
func matchKeys(u sip.URI) []string {
	keys := []string{identityKey(u)}
	if number, ok := phoneNumber(u); ok {
		keys = append(keys, identityKey(sip.URI{Scheme: "tel", User: number}))
	}
	return keys
}

// identityKey writes an identity for matching: aorKey of it with the user
// part unescaped (RFC 3261 §19.1.4) and, for a tel URI, the number without
// visual separators (RFC 3966 §3), so that spellings of one identity match.
func identityKey(u sip.URI) string {
	user := unescape(u.User)
	if u.Scheme == "tel" {
		user = withoutSeparators(user)
	}
	return aorKey(sip.URI{Scheme: u.Scheme, User: user, Host: u.Host})
}

// phoneNumber is the global number of a SIP URI with user=phone whose user
// part starts with "+", unescaped and without user parameters or visual
// separators.
func phoneNumber(u sip.URI) (string, bool) {
	if !u.IsSIP() {
		return "", false
	}
	if v, ok := u.Params.Get("user"); !ok || !strings.EqualFold(v, "phone") {
		return "", false
	}
	number, _, _ := strings.Cut(unescape(u.User), ";")
	if !strings.HasPrefix(number, "+") {
		return "", false
	}
	return withoutSeparators(number), true
}

// unescape decodes the %HH escapes of a user part, or leaves it as it is if
// one is malformed.
func unescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

// withoutSeparators drops the visual separators of a telephone number (RFC
// 3966 §3: "-", ".", "(" and ")").
func withoutSeparators(n string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("-.()", r) {
			return -1
		}
		return r
	}, n)
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
// dials. The core-facing value also carries the dialog's icid, which the
// dialog's later requests from the client bring back for their charging
// vector (§5.2.6.3.5 7), §5.2.6.3.9 3)) since pcscf keeps no dialog state.
func (p *pcscf) recordRoute(flow transport.FlowID, ob bool, icid string) []sip.Address {
	core := sip.URI{Scheme: "sip", User: string(flow), Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	core.Params.Set("transport", "tcp")
	core.Params.SetFlag("lr")
	if ob {
		core.Params.SetFlag("ob")
	}
	core.Params.Set(icidParam, icid)
	client := sip.URI{Scheme: "sip", Host: p.cfg.PublicHost, Port: p.cfg.PublicPort}
	if p.cfg.ClientTransport == ClientTCP {
		client.Params.Set("transport", "tcp")
	} else {
		client.Params.Set("transport", "tls")
	}
	client.Params.SetFlag("lr")
	return []sip.Address{{URI: core}, {URI: client}}
}

// icidParam is the URI parameter of the core-facing Record-Route value that
// carries the dialog's icid.
const icidParam = "icid"

// contactHasOb reports whether the request's Contact has the ob parameter:
// the client uses outbound for this dialog (RFC 5626 §4.3).
func contactHasOb(req *sip.Request) bool {
	contacts, err := req.Header.Contact()
	return err == nil && len(contacts) == 1 && !contacts[0].Star && contacts[0].URI.Params.Has("ob")
}

// inDialog forwards a client's request inside a dialog (#16 question 6, as
// narrowed in the review of #208), keeping no dialog state. It is forwarded
// as its Route says only along a route set this pcscf recorded for this
// flow, and only to scscf:
//   - both of pcscf's Record-Route values were consumed, and the core-facing
//     one names the flow the request came on;
//   - the next hop is scscf's service name (PCSCF_SCSCF_HOST) on its port
//     over TCP, as scscf records itself in every dialog pcscf is in (ADR
//     0005), and resolves to a private address other than this task's.
//
// Anything else is 403, so a client cannot aim a request at a core address
// of its choosing, past the services that should see it; a failed lookup of
// scscf is 503. The requests count against the client's initial-request
// bucket, so a To tag does not lift its rate, except an ACK for a 2xx, which
// cannot be answered. The forwarded request carries the dialog's icid,
// from the core-facing value, in a P-Charging-Vector of its own.
func (p *pcscf) inDialog(ctx context.Context, r *proxy.Request) proxy.Decision {
	if r.Message.Method != "ACK" && !p.initials.allow(clientKey(r.Source.Addr)) {
		return p.refuse(r, 503, "Too Many Requests")
	}
	var core *sip.URI
	client := false
	for i, a := range r.Routed {
		switch {
		case a.URI.User == string(r.Source.Flow) && proxy.SameHost(a.URI.Host, hostOf(p.cfg.CoreHost)) && a.URI.Port == p.corePort:
			core = &r.Routed[i].URI
		case a.URI.User == "" && p.publicHost(a.URI.Host):
			client = true
		}
	}
	if core == nil || !client {
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	next := r.Message.URI
	if routes, err := r.Message.Header.Route(); err == nil && len(routes) > 0 {
		next = routes[0].URI
	}
	if !p.scscfHop(next) {
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	if _, err := p.resolve.Resolve(ctx, next); err != nil {
		if errors.As(err, new(*net.DNSError)) {
			return p.refuse(r, 503, "Service Unavailable")
		}
		return proxy.Decision{Status: 403, Reason: "Not On This Route"}
	}
	icid, _ := core.Param(icidParam)
	if !validICID(icid) {
		// The client's copy of the route lost or changed it.
		var err error
		if icid, err = p.icid(); err != nil {
			return proxy.Decision{Status: 500}
		}
	}
	d := proxy.Forward(r)
	d.Prepare = func(_ context.Context, _ proxy.Target, req *sip.Request) error {
		return req.Header.Set("P-Charging-Vector", p.chargingVector(icid))
	}
	return d
}

// scscfHop reports whether u names scscf as the next hop of a request inside
// a dialog: a sip URI of its service name, on its port, over TCP. An address
// is never scscf's name, nor is pcscf's own (Configure checks).
func (p *pcscf) scscfHop(u sip.URI) bool {
	if u.Scheme != "sip" || proxy.HostKey(u.Host) != p.cfg.SCSCFHost {
		return false
	}
	port := u.Port
	if port == 0 {
		port = transport.TCP.DefaultPort()
	}
	network, _ := u.Param("transport")
	return port == p.cfg.SCSCFPort && strings.EqualFold(network, "tcp")
}

// validICID reports whether v is an icid pcscf writes: 32 lower-case hex
// digits.
func validICID(v string) bool {
	if len(v) != 32 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// publicHost reports whether host is a name the client-facing Record-Route
// may carry: the public name, or one of the NLB's addresses.
func (p *pcscf) publicHost(host string) bool {
	if proxy.SameHost(host, p.cfg.PublicHost) {
		return true
	}
	return slices.ContainsFunc(p.cfg.PublicAddrs, func(a netip.Addr) bool { return proxy.SameHost(hostOf(a), host) })
}
