package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// viaPlaceholderHost is the sent-by of the Via the proxy adds. The transport
// replaces it with the sent-by of the listener the request leaves through (RFC
// 3261 §18.1.1), which only it knows; "invalid" is a name that can never
// resolve (RFC 6761 §6.4), so a sender that failed to replace it would be
// noticed rather than misroute responses.
const viaPlaceholderHost = "invalid"

// isSelf reports whether u names this proxy (Config.Self): the same host,
// however it is written (SameHost), and the same port once defaults are
// applied. A form of its own address it failed to recognise would make the
// proxy forward a request to itself.
func (p *Proxy) isSelf(u sip.URI) bool { return IsSelf(p.self, u) }

// IsSelf reports whether u names one of self as the proxy recognises its own
// Route entries: a SIP or SIPS URI with the same host, compared as SameHost
// does, and the same port, defaults applied. A Router that looks for its
// service further down a Route uses it so that both checks agree on what is
// this service.
func IsSelf(self []sip.URI, u sip.URI) bool {
	if !u.IsSIP() {
		return false
	}
	port := portOf(u)
	for _, s := range self {
		if SameHost(s.Host, u.Host) && portOf(s) == port {
			return true
		}
	}
	return false
}

// SameHost reports whether two URI hosts name the same host: names compared
// without case or a trailing dot, addresses as addresses, so that an
// IPv4-mapped IPv6 address, a bracketed IPv6 address or a different
// spelling of an IPv6 address matches the plain form.
func SameHost(a, b string) bool {
	return HostKey(a) == HostKey(b)
}

// HostKey writes a URI host in the form SameHost compares: an address in
// its canonical text without brackets, zone or IPv4 mapping, a name in
// lower case without a trailing dot.
func HostKey(host string) string {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// portOf is the port a SIP or SIPS URI names, explicitly or by default (RFC
// 3261 §19.1.2).
func portOf(u sip.URI) int {
	if u.Port != 0 {
		return u.Port
	}
	if t, _ := u.Param("transport"); u.Scheme == "sips" || strings.EqualFold(t, "tls") {
		return transport.TLS.DefaultPort()
	}
	return transport.UDP.DefaultPort()
}

func hasLR(u sip.URI) bool {
	_, ok := u.Param("lr")
	return ok
}

// rejection is the answer to a request the proxy refuses before routing it.
type rejection struct {
	code   int
	fields [][2]string
}

// validate applies the checks of RFC 3261 §16.3 a proxy can make: the scheme of
// the Request-URI (step 2), Max-Forwards (step 3), loops (step 4) and
// Proxy-Require (step 5). Syntax (step 1) was checked by the transport. loop is
// the request's loop-detection hash. A nil result means the request may be
// forwarded.
//
// A request with Max-Forwards 0 is refused whatever its method. Step 3 lets a
// proxy answer such an OPTIONS itself instead, which none of the services
// needs.
func (p *Proxy) validate(req *sip.Request, loop string) *rejection {
	switch req.URI.Scheme {
	case "sip", "sips", "tel":
	default:
		return &rejection{code: 416}
	}
	if req.Header.Has("Max-Forwards") {
		n, err := req.Header.MaxForwards()
		if err != nil {
			return &rejection{code: 400}
		}
		if n == 0 {
			return &rejection{code: 483}
		}
	}
	if loop != "" && p.looped(req, loop) {
		p.stats.loops.Add(1)
		return &rejection{code: 482}
	}
	tags, err := req.Header.Elements("Proxy-Require")
	if err != nil {
		return &rejection{code: 400}
	}
	var unsupported []string
	for _, t := range tags {
		if !p.supported[strings.ToLower(t)] {
			unsupported = append(unsupported, t)
		}
	}
	if len(unsupported) > 0 {
		return &rejection{code: 420, fields: [][2]string{{"Unsupported", strings.Join(unsupported, ", ")}}}
	}
	if _, err := req.Header.Route(); err != nil {
		return &rejection{code: 400}
	}
	return nil
}

// looped reports whether a Via of req carries a branch this proxy built for a
// request with the same loop hash: the request has come back unchanged in
// everything that decides where it goes, which is a loop, while a request that
// comes back changed is a spiral (RFC 5393 §4.2.2, replacing RFC 3261 §16.3
// step 4). The hash is keyed, so a branch ending in it can only be this proxy's,
// and every Via is inspected without matching its sent-by.
func (p *Proxy) looped(req *sip.Request, loop string) bool {
	vias, err := req.Header.Via()
	if err != nil {
		return false
	}
	for _, v := range vias {
		if strings.HasSuffix(v.Branch(), "."+loop) {
			return true
		}
	}
	return false
}

// loopHash is the second part of the branch IDs of a request's branches (RFC
// 5393 §4.2.1): it covers the Request-URI and Route as received, which decide
// where the request goes, and the fields that identify the request, but not the
// method, so a CANCEL and the ACK for a non-2xx response share the INVITE's
// branch ID. A Router that routes on other header fields sees a request that
// comes back with only those changed refused as a loop.
func (p *Proxy) loopHash(req *sip.Request) string {
	h := p.newHash("loop")
	write(h, req.URI.String())
	routes, _ := req.Header.Elements("Route")
	for _, r := range routes {
		write(h, r)
	}
	writeIdentity(h, req)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// statelessBranch is the branch ID of an ACK forwarded statelessly. RFC 3261
// §16.11 has it computed from what a retransmission does not change: the
// received branch when it is an RFC 3261 one, and otherwise the top Via, the
// tags, Call-ID, CSeq number and Request-URI.
func (p *Proxy) statelessBranch(req *sip.Request) string {
	h := p.newHash("stateless")
	vias, err := req.Header.Via()
	if err == nil && len(vias) > 0 && vias[0].HasMagicCookie() {
		write(h, vias[0].Branch())
	} else {
		write(h, req.Header.Get("Via"))
		write(h, req.URI.String())
		writeIdentity(h, req)
	}
	return sip.MagicCookie + hex.EncodeToString(h.Sum(nil)[:16])
}

// toTag is the To tag of the responses the proxy makes up for req. It is a keyed
// hash of the request's transaction identity, so every response to one request
// carries the same tag, as RFC 3261 §8.2.6.2 asks, without the proxy keeping it,
// and it is as unpredictable as the random tag of §19.3.
func (p *Proxy) toTag(req *sip.Request) string {
	h := p.newHash("tag")
	write(h, req.Header.Get("Via"))
	writeIdentity(h, req)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func (p *Proxy) newHash(purpose string) hash.Hash {
	h := hmac.New(sha256.New, p.key)
	write(h, purpose)
	return h
}

// write adds s to h with a terminator, so no two sequences of fields hash alike.
func write(h hash.Hash, s string) {
	h.Write([]byte(s))
	h.Write([]byte{0})
}

func writeIdentity(h hash.Hash, req *sip.Request) {
	from, _ := req.Header.From()
	to, _ := req.Header.To()
	cseq, _ := req.Header.CSeq()
	callID, _ := req.Header.CallID()
	write(h, from.Tag())
	write(h, to.Tag())
	write(h, callID)
	write(h, strconv.FormatUint(uint64(cseq.Seq), 10))
}

// preprocess applies RFC 3261 §16.4 to a copy of req and returns it as the
// Router sees it.
//
// A Request-URI that names this proxy and carries lr is a Record-Route value of
// ours that a strict router upstream moved there; it is replaced by the last
// Route, which that router appended for the purpose. Then the topmost Route is
// removed while it names this proxy: §16.4 removes one, and RFC 5658 §5 lets a
// proxy that recorded two routes remove both. maddr in the Request-URI is not
// interpreted: IMS does not use it, and the transport does not honour it in a
// Via either.
func (p *Proxy) preprocess(req *sip.Request, src transport.Source) (*Request, error) {
	in := copyRequest(req)
	r := &Request{Message: in, Source: src}
	routes, err := in.Header.Route()
	if err != nil {
		return nil, err
	}
	if len(routes) > 0 && p.isSelf(in.URI) && hasLR(in.URI) {
		r.Routed = append(r.Routed, sip.Address{URI: in.URI})
		in.URI = routes[len(routes)-1].URI
		if err := removeLastRoute(&in.Header); err != nil {
			return nil, err
		}
		routes = routes[:len(routes)-1]
	}
	for len(routes) > 0 && p.isSelf(routes[0].URI) {
		r.Routed = append(r.Routed, routes[0])
		if err := in.Header.RemoveFirstElement("Route"); err != nil {
			return nil, err
		}
		routes = routes[1:]
	}
	return r, nil
}

// copyRequest copies req except for its body, which the copy shares: no copy
// modifies a body in place (Prepare and OnResponse may only replace one), so a
// context holds one body however many branches it forwards.
func copyRequest(req *sip.Request) *sip.Request {
	c := &sip.Request{Method: req.Method, URI: cloneURI(req.URI), Header: req.Header.Clone(), Body: req.Body}
	return c
}

// cloneURI copies u, parameters included, so that a change to the copy's
// parameters cannot reach u.
func cloneURI(u sip.URI) sip.URI { return (&sip.Request{URI: u}).Clone().URI }

// removeLastRoute removes the last Route element. Only the Route fields are
// rewritten, one element per line with each element's text kept.
func removeLastRoute(h *sip.Header) error {
	els, err := h.Elements("Route")
	if err != nil || len(els) == 0 {
		return err
	}
	h.Del("Route")
	for _, e := range els[:len(els)-1] {
		if err := h.Add("Route", e); err != nil {
			return err
		}
	}
	return nil
}

// errPrepare marks a failure of Decision.Prepare, which fails the branch with
// 500 rather than as a transport error.
var errPrepare = errors.New("proxy: preparing the request failed")

// buildBranch makes the copy of r forwarded to t (RFC 3261 §16.6 steps 1 to 7)
// and finds its next hop; the caller adds the Via (step 8). recordRoute is false
// for an ACK, which cannot change a dialog's route set.
func (p *Proxy) buildBranch(ctx context.Context, r *Request, d *Decision, t Target, recordRoute bool) (*sip.Request, transport.Destination, error) {
	fwd := copyRequest(r.Message)
	fwd.URI = cloneURI(t.URI)
	mf := "70"
	if fwd.Header.Has("Max-Forwards") {
		n, err := fwd.Header.MaxForwards()
		if err != nil {
			return nil, transport.Destination{}, err
		}
		mf = strconv.Itoa(n - 1)
	}
	if err := fwd.Header.Set("Max-Forwards", mf); err != nil {
		return nil, transport.Destination{}, err
	}
	if recordRoute {
		if err := prependAll(&fwd.Header, "Record-Route", d.RecordRoute); err != nil {
			return nil, transport.Destination{}, err
		}
	}
	if err := prependAll(&fwd.Header, "Route", t.Routes); err != nil {
		return nil, transport.Destination{}, err
	}
	if d.Prepare != nil {
		if err := d.Prepare(ctx, t, fwd); err != nil {
			return nil, transport.Destination{}, fmt.Errorf("%w: %w", errPrepare, err)
		}
	}
	strict, err := fixStrictNextHop(fwd)
	if err != nil {
		return nil, transport.Destination{}, err
	}
	if t.Destination != nil {
		return fwd, *t.Destination, nil
	}
	// §16.6 step 7: the next hop is the topmost Route, or the Request-URI when
	// there is none or when it now names a strict router.
	next := fwd.URI
	routes, err := fwd.Header.Route()
	if err != nil {
		return nil, transport.Destination{}, err
	}
	if len(routes) > 0 && !strict {
		next = routes[0].URI
	}
	dst, err := p.resolver.Resolve(ctx, next)
	if err != nil {
		return nil, transport.Destination{}, err
	}
	return fwd, dst, nil
}

// prependAll puts values on top of the field name, the first topmost.
func prependAll(h *sip.Header, name string, values []sip.Address) error {
	for i := len(values) - 1; i >= 0; i-- {
		if err := h.Prepend(name, values[i].String()); err != nil {
			return err
		}
	}
	return nil
}

// fixStrictNextHop applies RFC 3261 §16.6 step 6: when the next hop, the
// topmost Route, lacks lr it is a strict router, which expects to find itself in
// the Request-URI, so the Request-URI moves to the end of the Route and the
// topmost Route takes its place. It reports whether it did so.
func fixStrictNextHop(req *sip.Request) (bool, error) {
	routes, err := req.Header.Route()
	if err != nil || len(routes) == 0 || hasLR(routes[0].URI) {
		return false, err
	}
	if err := req.Header.Add("Route", sip.Address{URI: req.URI}.String()); err != nil {
		return false, err
	}
	req.URI = routes[0].URI
	return true, req.Header.RemoveFirstElement("Route")
}

// addVia puts the proxy's Via on top (§16.6 step 8). The transport rewrites the
// transport and sent-by for the way the request actually leaves.
func addVia(req *sip.Request, dst transport.Destination, branch string) error {
	network := dst.Network
	if network == "" {
		network = transport.UDP
	}
	v := sip.Via{Transport: string(network), Host: viaPlaceholderHost}
	v.Params.Set("branch", branch)
	return req.Header.Prepend("Via", v.String())
}

// checkRecordRoute applies the constraint of §16.6 step 4 to a Router's
// Record-Route values: each must be a SIP or SIPS URI with lr, since an element
// that found no lr would treat the proxy as a strict router.
func checkRecordRoute(values []sip.Address) error {
	for _, a := range values {
		if !a.URI.IsSIP() || !hasLR(a.URI) {
			return errors.New("proxy: a Record-Route value must be a SIP or SIPS URI with lr")
		}
	}
	return nil
}
