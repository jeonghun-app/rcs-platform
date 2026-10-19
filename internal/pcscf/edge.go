package pcscf

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
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
// 24.229 §5.2.1, §5.2.6.3.3, RFC 3325, ADR 0007 §7). pcscf removes them from
// every request and response a client sends, so a client cannot assert an
// identity, a served user, a service, charging or media authorisation data,
// network feature capabilities, a private network or a profile key, claim
// a visited network, or write the Path a registrar keeps (RFC 3327 §5.1:
// proxies insert it); the core trusts them because only pcscf admits
// clients.
var networkOnlyHeaders = []string{
	"P-Asserted-Identity",
	"P-Served-User",
	"P-Asserted-Service",
	"P-Charging-Vector",
	"P-Charging-Function-Addresses",
	"P-Visited-Network-ID",
	"P-Associated-URI",
	"P-Called-Party-ID",
	"P-Media-Authorization",
	"Feature-Caps",
	"P-Private-Network-Indication",
	"P-Profile-Key",
	"Path",
}

// stripNetworkHeaders removes networkOnlyHeaders from h, and every
// P-Access-Network-Info value with the network-provided parameter: a client
// may say how it is attached, but only the network may vouch for it (TS
// 24.229 §5.2.1).
func stripNetworkHeaders(h *sip.Header) {
	for _, name := range networkOnlyHeaders {
		h.Del(name)
	}
	if !h.Has("P-Access-Network-Info") {
		return
	}
	els, err := h.Elements("P-Access-Network-Info")
	h.Del("P-Access-Network-Info")
	if err != nil {
		return // unreadable, so it cannot be told apart from a network one
	}
	for _, el := range els {
		if !networkProvided(el) {
			_ = h.Add("P-Access-Network-Info", el)
		}
	}
}

// networkProvided reports whether a P-Access-Network-Info value has the
// network-provided parameter, outside its quoted strings.
func networkProvided(v string) bool {
	quoted := false
	start := -1
	check := func(end int) bool {
		if start < 0 {
			return false
		}
		param := strings.TrimSpace(v[start:end])
		if i := strings.IndexByte(param, '='); i >= 0 {
			param = strings.TrimSpace(param[:i])
		}
		return strings.EqualFold(param, "network-provided")
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\' && quoted:
			i++
		case c == '"':
			quoted = !quoted
		case c == ';' && !quoted:
			if check(i) {
				return true
			}
			start = i + 1
		}
	}
	return check(len(v))
}

// fromClientMessage readies a message from a client before the proxy sees
// it: one place every request and response passes, so no route can forward
// a header only the network may set (review of #188).
func fromClientMessage(in transport.Inbound) {
	if fromClient(in.Source) {
		stripNetworkHeaders(in.Message.Headers())
	}
}

// selfURIs are the URIs that name this pcscf in Route (proxy.Config.Self).
// A client puts the P-CSCF's address from discovery in its first Route (TS
// 24.229 §5.1.2A.1.1 a): an IP address, the NLB's public one, since NOTE 15
// has a name resolved at discovery (rcsjta writes
// <sip:<address>:<port>;transport=...;lr>). Others write the public name.
// Each of those names pcscf on the public port, or with none, which means
// 5060 for sip and 5061 for sips or transport=tls (RFC 3261 §19.1.2): the
// NLB listens on both. So does this task's address, which a client on a
// stack without an NLB dials. The core listener's port at the task's
// address is what Path and the core-facing Record-Route name.
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
	hosts := []string{cfg.PublicHost}
	for _, a := range cfg.PublicAddrs {
		hosts = append(hosts, hostOf(a))
	}
	if cfg.CoreHost.IsValid() {
		hosts = append(hosts, hostOf(cfg.CoreHost))
	}
	for _, host := range hosts {
		for _, port := range ports {
			add(host, port)
		}
	}
	if cfg.CoreHost.IsValid() {
		add(hostOf(cfg.CoreHost), corePort)
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
	// icscfs finds icscf's addresses, every one so that a REGISTER can try
	// the next.
	icscfs allResolver
	// rand draws charging identifiers.
	rand io.Reader
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
