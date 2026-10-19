package pcscf

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// maxICSCFAttempts bounds the icscf addresses a REGISTER tries. The
	// first may take icscfFirstTimeout, longer than the core's own retry of
	// an HSS (cxclient: two attempts of 5 s), so that a slow but healthy core
	// is not taken for a dead one; the others share what is left of
	// icscfTotalTimeout, so that a 504 after the last still reaches the
	// client before its own Timer F, 32 s (RFC 3261 §17.1.2.2). That is
	// usually two attempts. A 200 that arrives after its attempt was cut
	// short is dropped, and the client's next REGISTER recovers.
	maxICSCFAttempts  = 3
	icscfFirstTimeout = 12 * time.Second
	icscfTotalTimeout = 30 * time.Second
	// minICSCFAttempt is the least time worth giving another attempt.
	minICSCFAttempt = time.Second
	// reservationHold is how long a REGISTER holds its registry slot if its
	// final response never comes through OnResponse: the attempts' time and
	// a margin.
	reservationHold = icscfTotalTimeout + 30*time.Second
)

// metricRegisterTaskLimit counts the REGISTERs refused by the task-wide
// rate.
const metricRegisterTaskLimit = "register.refused_task_rate"

// register routes a REGISTER from a client to icscf (TS 24.229 §5.2.2.1):
// Path names this task's core listener and the flow (RFC 3327, RFC 5626
// §5.2), and the 200 is remembered, with the keep-alive the client gets. An
// icscf address that does not answer, fails or answers 3xx, 480 or 503 is
// replaced by the next, and the client gets 504 once none is left (§5.2.2.1
// 7)).
func (p *pcscf) register(ctx context.Context, r *proxy.Request) proxy.Decision {
	src := r.Source
	if !p.registers.allow(clientKey(src.Addr)) {
		return p.refuse(r, 503, "Too Many Registrations")
	}
	// Every REGISTER, authenticated or not, costs the core a UAR and an
	// authentication vector, so the task as a whole is bounded as well.
	if !p.allRegisters.allow(netip.Addr{}) {
		if p.metrics != nil {
			p.metrics.Count(metricRegisterTaskLimit, 1)
		}
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
	creds, err := r.Message.Header.Authorization()
	if err != nil {
		return proxy.Decision{Status: 400, Reason: "Bad Authorization"}
	}
	aor := aorKey(to.URI)
	switch err := p.registry.reserve(src.Flow, aor, p.now().Add(reservationHold)); {
	case errors.Is(err, errTooManyPending):
		return p.refuse(r, 503, "Too Many Registrations")
	case err != nil:
		return p.refuse(r, 503, "Registry Full")
	}
	var once sync.Once
	release := func() { once.Do(func() { p.registry.release(src.Flow, aor) }) }
	icid, err := p.icid()
	if err != nil {
		release()
		return proxy.Decision{Status: 500}
	}
	dsts, err := p.icscfs.ResolveAll(ctx, p.cfg.ICSCF)
	if err != nil {
		release()
		return proxy.Decision{Status: 504, Reason: "No I-CSCF"}
	}
	tries := &icscfTries{left: dsts[1:min(len(dsts), maxICSCFAttempts)], deadline: p.now().Add(p.icscfTotal)}
	reg := &registration{flow: src.Flow, uri: to.URI, aor: aor, outbound: usesOutbound(r.Message, contacts), viaKeep: viaKeep(r.Message)}
	return proxy.Decision{
		Targets: []proxy.Target{icscfTarget(r.Message.URI, dsts[0], p.icscfFirst)},
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			return p.prepareRegister(req, reg, icid, creds)
		},
		OnBranchFailure: func(_ context.Context, f proxy.BranchFailure) []proxy.Target {
			if !retryICSCF(f.Response.StatusCode) {
				return nil
			}
			next, left, ok := tries.next(p.now())
			if !ok {
				return nil
			}
			return []proxy.Target{icscfTarget(r.Message.URI, next, left)}
		},
		OnFinal: func(_ context.Context, res *sip.Response) {
			switch {
			case tries.exhausted.Load():
				res.StatusCode, res.Reason = 504, sip.DefaultReason(504)
			case res.StatusCode == statusFlowFailed:
				// What the proxy does without OnFinal: a client must not
				// see 430 (RFC 5626 §11.5).
				res.StatusCode, res.Reason = 480, sip.DefaultReason(480)
			}
		},
		OnResponse: func(_ context.Context, res *sip.Response) {
			if res.StatusCode < 200 {
				return
			}
			defer release()
			p.registered(res, reg, contacts)
		},
	}
}

// icscfTarget sends a REGISTER to icscf at dst, cut short after timeout so
// that another address can be tried in time.
func icscfTarget(uri sip.URI, dst transport.Destination, timeout time.Duration) proxy.Target {
	return proxy.Target{URI: uri, Destination: &dst, Timeout: timeout}
}

// retryICSCF reports whether a REGISTER that icscf answered with code, or
// that failed as code, goes to another icscf (TS 24.229 §5.2.2.1 7)): no
// answer (408), a transport failure or overload (503), a redirection or
// 480.
func retryICSCF(code int) bool {
	return code == 408 || code == 503 || code == 480 || code >= 300 && code < 400
}

// icscfTries are the icscf addresses a REGISTER has left to try, and when
// its attempts must end.
type icscfTries struct {
	mu       sync.Mutex
	left     []transport.Destination
	deadline time.Time
	// exhausted is set when a retryable failure found no address, or no
	// time, left.
	exhausted atomic.Bool
}

// next is the address to try at now and how long it may take.
func (t *icscfTries) next(now time.Time) (transport.Destination, time.Duration, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	left := t.deadline.Sub(now)
	if len(t.left) == 0 || left < minICSCFAttempt {
		t.exhausted.Store(true)
		return transport.Destination{}, 0, false
	}
	d := t.left[0]
	t.left = t.left[1:]
	return d, left, true
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

// prepareRegister readies the branch's REGISTER (TS 24.229 §5.2.2.1): icscf
// as its only Route, since pcscf chooses the I-CSCF and a Route the client
// wrote below pcscf's own must not steer it; Path naming this task's core
// listener and the flow, with ob when the client uses outbound (RFC 5626
// §5.1), and Require: path; the visited network and a new charging
// identifier; the client's credentials without integrity-protected; and,
// for a client that does not keep its flow alive, expiries of at most
// maxExpiresWithoutKeepAlive. The headers only the network may set, a
// client's Path among them, are gone already, removed on arrival.
func (p *pcscf) prepareRegister(req *sip.Request, reg *registration, icid string, creds sip.CredentialsList) error {
	req.Header.Del("Route")
	if err := req.Header.Add("Route", sip.Address{URI: p.cfg.ICSCF}.String()); err != nil {
		return err
	}
	path := sip.URI{Scheme: "sip", User: string(reg.flow), Host: hostOf(p.cfg.CoreHost), Port: p.corePort}
	path.Params.Set("transport", "tcp")
	path.Params.SetFlag("lr")
	if reg.outbound {
		path.Params.SetFlag("ob")
	}
	if err := req.Header.Prepend("Path", sip.Address{URI: path}.String()); err != nil {
		return err
	}
	if !hasOption(req.Header.Require, "path") {
		if err := req.Header.Add("Require", "path"); err != nil {
			return err
		}
	}
	if err := req.Header.Set("P-Visited-Network-ID", p.cfg.VisitedNetworkID); err != nil {
		return err
	}
	if err := req.Header.Set("P-Charging-Vector", p.chargingVector(icid)); err != nil {
		return err
	}
	// pcscf owns integrity-protected (TS 24.229 §5.2.2.1): it sets none, so
	// scscf always challenges.
	if len(creds) > 0 {
		req.Header.Del("Authorization")
		for _, c := range creds {
			c.Params = slices.Clone(c.Params)
			c.Params.Del("integrity-protected")
			if err := req.Header.Add("Authorization", c.String()); err != nil {
				return err
			}
		}
	}
	if !reg.outbound && !reg.viaKeep {
		return capExpires(&req.Header, maxExpiresWithoutKeepAlive)
	}
	return nil
}

// chargingVector is the P-Charging-Vector of a request pcscf sends for a
// client: the request's charging identifier, and this network as the type 1
// orig-ioi (TS 24.229 §5.2.2.1 3), §5.2.6.3.3 7); no term-ioi).
func (p *pcscf) chargingVector(icid string) string {
	return "icid-value=" + icid + ";orig-ioi=" + p.cfg.HomeDomain
}

// icid is a new IMS charging identifier (RFC 7315 §4.6): 128 random bits.
func (p *pcscf) icid() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(p.rand, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
// or that it has none left. A REGISTER without Contact only fetches the
// bindings (RFC 3261 §10.2.3) and changes nothing. It also tells the client
// how to keep its flow alive (RFC 5626 §4.4, RFC 6223 §5): Flow-Timer only
// when the registrar's Require: outbound says outbound applies (§5.4); it
// caps a client without keep-alive to maxExpiresWithoutKeepAlive, and sets
// the flow's idle timeout to match.
func (p *pcscf) registered(res *sip.Response, reg *registration, sent sip.Contacts) {
	if res.StatusCode < 200 || res.StatusCode >= 300 || len(sent) == 0 {
		return
	}
	outbound := reg.outbound && hasOption(res.Header.Require, "outbound")
	keepAlive := outbound || reg.viaKeep
	if !keepAlive {
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
	saved.outbound, saved.keepAlive = outbound, keepAlive
	saved.expires = p.now().Add(time.Duration(least) * time.Second)
	saved.serviceRoute, _ = res.Header.ServiceRoute()
	saved.associated, _ = res.Header.PAssociatedURI()
	if err := p.registry.save(&saved); err != nil {
		p.log.Warn("registration not kept", slog.String("error", err.Error()))
	}

	if outbound {
		_ = res.Header.Set("Flow-Timer", strconv.Itoa(keepAliveInterval))
	}
	if viaKeepFlag(res) {
		setViaKeep(res)
	}
	idle := p.cfg.ClientIdleTimeout
	if keepAlive {
		idle = keepAliveIdleTLS
		if p.cfg.ClientTransport == ClientTCP {
			idle = keepAliveIdleTCP
		}
	}
	if p.flows != nil && !p.flows.SetFlowIdleTimeout(reg.flow, idle) {
		// The flow closed before its 200, and OnFlowClosed found nothing
		// to remove. Saving before this check means that whichever runs
		// second, this or OnFlowClosed, removes the registration (QA of
		// #198).
		p.registry.remove(reg.flow, reg.aor)
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
