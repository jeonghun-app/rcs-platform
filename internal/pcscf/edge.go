package pcscf

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Listener names, which Source.Listener carries and which tell a client's
// request from the core's.
const (
	clientListener    = "client"
	clientUDPListener = "client-udp"
	coreListener      = "core"
)

// fromClient reports whether a message came in on a client listener. One on
// the core listener, or on a connection pcscf opened, came from the core.
func fromClient(src transport.Source) bool {
	return src.Listener == clientListener || src.Listener == clientUDPListener
}

// networkOnlyHeaders are the header fields only the network may set (TS
// 24.229 §5.2, RFC 3325, ADR 0007 §7). pcscf removes them from every
// request a client sends, so a client cannot assert an identity, a served
// user, a service or charging data, or claim a visited network; the core
// trusts them because only pcscf admits clients.
var networkOnlyHeaders = []string{
	"P-Asserted-Identity",
	"P-Served-User",
	"P-Asserted-Service",
	"P-Charging-Vector",
	"P-Charging-Function-Addresses",
	"P-Visited-Network-ID",
	"P-Associated-URI",
	"P-Called-Party-ID",
}

// stripNetworkHeaders removes networkOnlyHeaders from h.
func stripNetworkHeaders(h *sip.Header) {
	for _, name := range networkOnlyHeaders {
		h.Del(name)
	}
}

// selfURIs are the URIs that name this pcscf in Route (proxy.Config.Self).
// Clients put the public name they dial in their first Route (TS 24.229
// §5.1.2A.1.1 NOTE 15), or this task's address, with the public port, or
// with none, which means 5060 for sip and 5061 for sips or transport=tls
// (RFC 3261 §19.1.2): the NLB listens on both, so each of those ports names
// pcscf. The core listener's port at this task's address is what Path and
// the core-facing Record-Route name.
func selfURIs(cfg Config, corePort int) []sip.URI {
	ports := []int{cfg.PublicPort}
	for _, p := range []int{5060, 5061} {
		if p != cfg.PublicPort {
			ports = append(ports, p)
		}
	}
	var out []sip.URI
	add := func(host string, port int) {
		out = append(out, sip.URI{Scheme: "sip", Host: host, Port: port})
	}
	for _, port := range ports {
		add(cfg.PublicHost, port)
	}
	if cfg.CoreHost.IsValid() {
		host := hostOf(cfg.CoreHost)
		for _, port := range ports {
			add(host, port)
		}
		add(host, corePort)
	}
	return out
}

// hostOf writes an address as the host of a SIP URI.
func hostOf(a netip.Addr) string {
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

// pcscf is the location service of the proxy (proxy.Router) and the state
// behind it.
type pcscf struct {
	cfg      Config
	corePort int
	registry *registry
	// registers limits the REGISTERs of one client address.
	registers *limiter
	// flows sets a flow's idle timeout; nil in tests that need none.
	flows flowSetter
	ids   sip.IDGenerator
	now   func() time.Time
	log   *slog.Logger
}

// Route implements proxy.Router. A client's REGISTER goes to icscf. Until
// originating and terminating routing land (#16), any other request from a
// client is refused with 403, and one from the core with 430, since no flow
// it could name is served yet (RFC 5626 §5.3).
func (p *pcscf) Route(ctx context.Context, r *proxy.Request) proxy.Decision {
	if !fromClient(r.Source) {
		return proxy.Decision{Status: statusFlowFailed, Reason: "Flow Failed"}
	}
	if r.Message.Method == "REGISTER" {
		return p.register(ctx, r)
	}
	return proxy.Decision{Status: 403, Reason: "Not Registered"}
}

// statusFlowFailed is 430 Flow Failed (RFC 5626 §11.5).
const statusFlowFailed = 430
