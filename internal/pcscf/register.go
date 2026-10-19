package pcscf

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Keep-alive (ADR 0003, #16): a client that keeps its flow alive, with RFC
// 5626 outbound or the Via keep parameter (RFC 6223), is asked to ping every
// keepAliveInterval and cut after twice that much silence on TLS, or just
// under the NLB TCP listener's 1800 s on TCP. One that does not is cut after
// 340 s, just under the NLB TLS listener's 350 s, and registers for at most
// maxExpiresWithoutKeepAlive, so a closed flow strands it for about 260 s at
// most.
const (
	keepAliveInterval          = 120
	keepAliveIdleTLS           = 180 * time.Second
	keepAliveIdleTCP           = 1740 * time.Second
	maxExpiresWithoutKeepAlive = 600
	// defaultExpires is a registrar's default when a REGISTER names none
	// (RFC 3261 §10.2.1.1).
	defaultExpires = 3600
	// retryAfter is the Retry-After of a refused REGISTER, in seconds.
	retryAfter = "1"
)

// register routes a REGISTER from a client to icscf (TS 24.229 §5.2.2.1):
// Path names this task's core listener and the flow (RFC 3327, RFC 5626
// §5.2), and the 200 is remembered, with the keep-alive the client gets.
func (p *pcscf) register(_ context.Context, r *proxy.Request) proxy.Decision {
	src := r.Source
	if !p.registers.allow(clientKey(src.Addr)) {
		return p.refuse(r, 503, "Too Many Registrations")
	}
	to, err := r.Message.Header.To()
	if err != nil {
		return proxy.Decision{Status: 400, Reason: "Bad To"}
	}
	contacts, err := r.Message.Header.Contact()
	if err != nil {
		return proxy.Decision{Status: 400, Reason: "Bad Contact"}
	}
	aor := aorKey(to.URI)
	if !p.registry.room(src.Flow, aor) {
		return p.refuse(r, 503, "Registry Full")
	}
	reg := &registration{flow: src.Flow, aor: aor, outbound: usesOutbound(r.Message, contacts)}
	reg.keepAlive = reg.outbound || viaKeep(r.Message)
	return proxy.Decision{
		Targets: []proxy.Target{{URI: r.Message.URI, Routes: []sip.Address{{URI: p.cfg.ICSCF}}}},
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			return p.prepareRegister(req, reg)
		},
		OnResponse: func(_ context.Context, res *sip.Response) {
			p.registered(res, reg, contacts)
		},
	}
}

// refuse answers a request with code and Retry-After, telling the client to
// back off.
func (p *pcscf) refuse(r *proxy.Request, code int, reason string) proxy.Decision {
	tag, err := p.ids.Tag()
	if err != nil {
		return proxy.Decision{Status: code, Reason: reason}
	}
	res, err := sip.NewResponse(r.Message, code, reason, tag)
	if err != nil {
		return proxy.Decision{Status: code, Reason: reason}
	}
	_ = res.Header.Set("Retry-After", retryAfter)
	return proxy.Decision{Response: res}
}

// usesOutbound reports whether a REGISTER uses RFC 5626 outbound: it
// supports outbound, and every contact has an instance ID and a reg-id
// (§4.2.1).
func usesOutbound(req *sip.Request, contacts sip.Contacts) bool {
	if !hasOption(req.Header.Supported, "outbound") && !hasOption(req.Header.Require, "outbound") {
		return false
	}
	if len(contacts) == 0 {
		return false
	}
	for _, c := range contacts {
		if c.Star {
			return false
		}
		_, inst := c.Instance()
		_, id, err := c.RegID()
		if !inst || !id || err != nil {
			return false
		}
	}
	return true
}

func hasOption(list func() ([]string, error), tag string) bool {
	tags, err := list()
	return err == nil && slices.ContainsFunc(tags, func(t string) bool { return strings.EqualFold(t, tag) })
}

// viaKeep reports whether the client asked for keep-alive with the Via keep
// parameter (RFC 6223 §4.4).
func viaKeep(req *sip.Request) bool {
	vias, err := req.Header.Via()
	return err == nil && len(vias) > 0 && vias[0].Params.Has("keep")
}

// prepareRegister readies the branch's REGISTER: Path naming this task's
// core listener and the flow, with ob when the client uses outbound (RFC
// 5626 §5.1), Supported: path, and, for a client that does not keep its
// flow alive, expiries of at most maxExpiresWithoutKeepAlive. The headers
// only the network may set are gone already, removed on arrival.
func (p *pcscf) prepareRegister(req *sip.Request, reg *registration) error {
	path := sip.URI{Scheme: "sip", User: string(reg.flow), Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	path.Params.Set("transport", "tcp")
	path.Params.SetFlag("lr")
	if reg.outbound {
		path.Params.SetFlag("ob")
	}
	if err := req.Header.Prepend("Path", sip.Address{URI: path}.String()); err != nil {
		return err
	}
	if !hasOption(req.Header.Supported, "path") {
		if err := req.Header.Add("Supported", "path"); err != nil {
			return err
		}
	}
	if !reg.keepAlive {
		return capExpires(&req.Header, maxExpiresWithoutKeepAlive)
	}
	return nil
}

// capExpires lowers the Expires field and each contact's expires to at most
// limit seconds, writing it where the registrar would otherwise use a
// longer default. A removal (0) and a wildcard stay as they are.
func capExpires(h *sip.Header, limit uint32) error {
	header := uint32(defaultExpires)
	if h.Has("Expires") {
		v, err := h.Expires()
		if err != nil {
			return err
		}
		header = v
		if v > limit {
			if err := h.Set("Expires", strconv.FormatUint(uint64(limit), 10)); err != nil {
				return err
			}
		}
	}
	contacts, err := h.Contact()
	if err != nil || len(contacts) == 0 || contacts[0].Star {
		return err
	}
	vals := make([]string, len(contacts))
	for i, c := range contacts {
		v, present, err := c.Expires()
		if err != nil {
			return err
		}
		if !present {
			v = header
		}
		if v > limit {
			c.Params.Set("expires", strconv.FormatUint(uint64(limit), 10))
		}
		vals[i] = c.String()
	}
	return h.Set("Contact", strings.Join(vals, ", "))
}

// registered records the outcome of a REGISTER from its final 2xx: the
// client's contacts the 200 lists, with Service-Route and P-Associated-URI,
// or that it has none left. It also tells the client how to keep its flow
// alive (RFC 5626 §4.4, RFC 6223 §5), caps a client without keep-alive to
// maxExpiresWithoutKeepAlive, and sets the flow's idle timeout to match.
func (p *pcscf) registered(res *sip.Response, reg *registration, sent sip.Contacts) {
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return
	}
	if !reg.keepAlive {
		if err := capExpires(&res.Header, maxExpiresWithoutKeepAlive); err != nil {
			p.log.Warn("REGISTER 200 has malformed expiries", slog.String("error", err.Error()))
		}
	}
	listed, err := res.Header.Contact()
	if err != nil {
		p.log.Warn("REGISTER 200 has a malformed Contact", slog.String("error", err.Error()))
		return
	}
	header := uint32(defaultExpires)
	if res.Header.Has("Expires") {
		if v, err := res.Header.Expires(); err == nil {
			header = v
		}
	}
	var mine []sip.Contact
	least := uint32(0)
	for _, c := range listed {
		if c.Star || !slices.ContainsFunc(sent, func(s sip.Contact) bool { return !s.Star && s.URI.Equal(c.URI) }) {
			continue
		}
		v, present, err := c.Expires()
		if err != nil {
			continue
		}
		if !present {
			v = header
		}
		if v == 0 {
			continue
		}
		mine = append(mine, c)
		if least == 0 || v < least {
			least = v
		}
	}
	if len(mine) == 0 {
		p.registry.remove(reg.flow, reg.aor)
		return
	}
	saved := *reg
	saved.contacts = mine
	saved.expires = p.now().Add(time.Duration(least) * time.Second)
	saved.serviceRoute, _ = res.Header.ServiceRoute()
	saved.associated, _ = res.Header.PAssociatedURI()
	if err := p.registry.save(&saved); err != nil {
		p.log.Warn("registration not kept", slog.String("error", err.Error()))
	}

	if reg.outbound {
		_ = res.Header.Set("Flow-Timer", strconv.Itoa(keepAliveInterval))
		if !hasOption(res.Header.Require, "outbound") {
			_ = res.Header.Add("Require", "outbound")
		}
	}
	if viaKeepFlag(res) {
		setViaKeep(res)
	}
	idle := p.cfg.ClientIdleTimeout
	if reg.keepAlive {
		idle = keepAliveIdleTLS
		if p.cfg.ClientTransport == ClientTCP {
			idle = keepAliveIdleTCP
		}
	}
	if p.flows != nil {
		p.flows.SetFlowIdleTimeout(reg.flow, idle)
	}
}

// viaKeepFlag reports whether the client's Via, the top one of a response
// going to it, asks for keep-alive.
func viaKeepFlag(res *sip.Response) bool {
	vias, err := res.Header.Via()
	return err == nil && len(vias) > 0 && vias[0].Params.Has("keep")
}

// setViaKeep gives the client's Via keep=keepAliveInterval (RFC 6223 §5).
func setViaKeep(res *sip.Response) {
	vias, err := res.Header.Via()
	if err != nil || len(vias) == 0 {
		return
	}
	v := vias[0]
	v.Params.Set("keep", strconv.Itoa(keepAliveInterval))
	_ = res.Header.ReplaceFirstElement("Via", v.String())
}

// flowSetter is the part of the transport registration uses.
type flowSetter interface {
	SetFlowIdleTimeout(id transport.FlowID, d time.Duration) bool
}
