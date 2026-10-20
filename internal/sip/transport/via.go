package transport

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// stampReceived adds the received and rport parameters a server puts in the top
// Via of a request (RFC 3261 §18.2.1, RFC 3581 §4), so the response can find its
// way back to src whatever the client wrote as its sent-by.
//
// received is added when the sent-by host is not src's address, as §18.2.1 says,
// and also whenever the request asks for rport (RFC 3581 §4) or already carries a
// received parameter. Overwriting one the client wrote matters: responses go to
// received, so leaving a forged one would let a client aim responses at someone
// else.
func stampReceived(req *sip.Request, src netip.AddrPort) error {
	vias, err := req.Header.Via()
	if err != nil {
		return err
	}
	top := vias[0]
	changed := false
	_, rport := top.RPort()
	if rport || top.Received() != "" || !hostIsAddr(top.Host, src.Addr()) {
		if ip := src.Addr().String(); top.Received() != ip {
			top.Params.Set("received", ip)
			changed = true
		}
	}
	if rport {
		if p := strconv.Itoa(int(src.Port())); paramValue(top.Params, "rport") != p {
			top.Params.Set("rport", p)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return replaceTopVia(&req.Header, top)
}

func paramValue(ps sip.Params, name string) string {
	v, _ := ps.Get(name)
	return v
}

// hostIsAddr reports whether a sent-by host is the IP address a.
func hostIsAddr(host string, a netip.Addr) bool {
	h, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return err == nil && h.Unmap() == a.Unmap()
}

// setSentBy makes the top Via of an outgoing request name the transport and the
// sent-by it is leaving through (RFC 3261 §18.1.1). The Via is rewritten only when
// it differs, so a request the core built right, and every retransmission, goes
// out unchanged.
func setSentBy(req *sip.Request, network Network, host string, port int) error {
	vias, err := req.Header.Via()
	if err != nil {
		return err
	}
	if len(vias) == 0 {
		return errors.New("transport: request has no Via")
	}
	top := vias[0]
	if strings.EqualFold(top.Transport, string(network)) && strings.EqualFold(top.Host, host) && top.Port == port {
		return nil
	}
	top.Transport, top.Host, top.Port = string(network), host, port
	return replaceTopVia(&req.Header, top)
}

// replaceTopVia writes v as the first Via element. Every other Via, and every
// other field, keeps its original bytes, so a forwarded message differs from the
// received one only in the element this transport changed.
func replaceTopVia(h *sip.Header, v sip.Via) error {
	return h.ReplaceFirstElement("Via", v.String())
}

// ownsTopVia applies RFC 3261 §18.1.2: a response whose top Via sent-by is not one
// this transport writes was misrouted and is discarded.
func (t *Transport) ownsTopVia(res *sip.Response, f *flow) bool {
	vias, err := res.Header.Via()
	if err != nil || len(vias) == 0 {
		return false
	}
	top := vias[0]
	n, ok := parseNetwork(top.Transport)
	if !ok {
		return false
	}
	port := top.Port
	if port == 0 {
		port = n.DefaultPort()
	}
	matches := func(host string, p int) bool {
		return p == port && strings.EqualFold(host, top.Host)
	}
	t.mu.Lock()
	for _, l := range t.listeners {
		if matches(l.sentBy()) {
			t.mu.Unlock()
			return true
		}
	}
	t.mu.Unlock()
	if f != nil && f.conn != nil && f.lis == nil {
		host, p, err := t.sentByOf(f)
		return err == nil && matches(host, p)
	}
	return false
}

// responseTarget is where RFC 3261 §18.2.2 sends a response when it cannot, or
// must not, use the connection the request came on: the received address, or the
// sent-by host when it is an address, at the rport port when the request asked
// for one (RFC 3581 §4) and the sent-by port otherwise.
//
// maddr is ignored. Sending to a multicast or arbitrary address named by the
// request would make this server a reflector for any client, and IMS does not use
// multicast.
func responseTarget(top sip.Via, useRPort bool) (Network, netip.AddrPort, error) {
	n, ok := parseNetwork(top.Transport)
	if !ok {
		return "", netip.AddrPort{}, fmt.Errorf("%w: unsupported transport in Via", ErrUnroutable)
	}
	host := top.Received()
	if host == "" {
		host = top.Host
	}
	a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	if err != nil {
		return "", netip.AddrPort{}, fmt.Errorf("%w: sent-by is a host name and received is absent", ErrUnroutable)
	}
	port := top.Port
	if rp, present := top.RPort(); useRPort && present && rp != 0 {
		port = rp
	}
	if port == 0 {
		port = n.DefaultPort()
	}
	return n, netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}
