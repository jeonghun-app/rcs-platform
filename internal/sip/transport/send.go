package transport

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// udpMTULimit is the size above which a request meant for UDP goes over TCP
// instead, when the path MTU is unknown (RFC 3261 §18.1.1).
const udpMTULimit = 1300

// Destination says where to send a request: over a flow, or to an address.
type Destination struct {
	// Flow, when set, sends over that flow and nowhere else; the send fails with
	// ErrNoFlow if the flow is gone. Network and Addr are then ignored.
	Flow FlowID
	// Network and Addr name the peer otherwise. An open TCP connection to Addr is
	// reused; TCP and TLS dial one if there is none.
	Network Network
	Addr    netip.AddrPort
	// ServerName is the name an outbound TLS connection verifies. A connection
	// is only reused for the name it was verified for.
	ServerName string
	// Listener names the listener whose advertised sent-by the request carries.
	// Empty takes the first listener of the network. A flow always uses its own
	// listener.
	Listener string
}

// SendRequest sends a request and reports the transport it actually used.
//
// The top Via is made to name that transport and this transport's sent-by (RFC
// 3261 §18.1.1); the core supplies the Via with its branch. A request for UDP that
// is larger than 1300 bytes is sent over TCP instead (§18.1.1), and over UDP after
// all if the TCP connection cannot be opened. The transaction layer uses the
// returned Network to decide whether to retransmit.
//
// SendRequest never writes on the caller's goroutine: a stream message is queued
// for the connection's writer. It can still block, for up to DialTimeout while a
// connection is opened and for up to WriteTimeout while the queue is full, unless
// opts include NoWait, which the goroutine reading a connection uses. A handler
// that forwards from one flow to another should therefore send off the reading
// goroutine. The caller must not use req concurrently, since the Via may be
// rewritten.
func (t *Transport) SendRequest(req *sip.Request, dst Destination, opts ...SendOption) (Network, error) {
	wait := !noWait(opts)
	if t.isClosed() {
		return "", ErrClosed
	}
	if dst.Flow != "" {
		f := t.flows.lookup(dst.Flow)
		if f == nil {
			return "", ErrNoFlow
		}
		return f.network, t.sendOn(f, req, wait)
	}
	switch dst.Network {
	case UDP:
		l := t.udpListenerFor(dst.Listener, dst.Addr)
		if l == nil {
			return "", ErrNoListener
		}
		if err := setSentBy(req, UDP, l.sentByHost, l.sentByPort); err != nil {
			return "", err
		}
		b, err := req.Bytes()
		if err != nil {
			return "", err
		}
		if len(b) <= udpMTULimit {
			return UDP, t.sendDatagram(l, dst.Addr, b)
		}
		f, err := t.streamTo(TCP, dst.Addr, "")
		if err != nil {
			// §18.1.1: fall back to UDP when the TCP attempt is refused.
			return UDP, t.sendDatagram(l, dst.Addr, b)
		}
		return TCP, t.sendStream(f, req, dst.Listener, wait)
	case TCP, TLS:
		f, err := t.streamTo(dst.Network, dst.Addr, dst.ServerName)
		if err != nil {
			return "", err
		}
		return dst.Network, t.sendStream(f, req, dst.Listener, wait)
	}
	return "", fmt.Errorf("transport: unsupported network %q", dst.Network)
}

// sendOn sends a request over a flow it arrived on or this transport opened.
func (t *Transport) sendOn(f *flow, req *sip.Request, wait bool) error {
	if f.conn == nil {
		if err := setSentBy(req, UDP, f.lis.sentByHost, f.lis.sentByPort); err != nil {
			return err
		}
		return t.writeMessage(f, req, wait)
	}
	return t.sendStream(f, req, "", wait)
}

func (t *Transport) sendStream(f *flow, req *sip.Request, listener string, wait bool) error {
	host, port, err := t.sentByOf(f)
	if err != nil {
		return err
	}
	if f.lis == nil && listener != "" {
		if l := t.listenerNamed(listener); l != nil && l.network == f.network {
			host, port = l.sentBy()
		}
	}
	if err := setSentBy(req, f.network, host, port); err != nil {
		return err
	}
	return t.writeMessage(f, req, wait)
}

func (t *Transport) listenerNamed(name string) *listener {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.listeners {
		if l.name == name {
			return l
		}
	}
	return nil
}

func (t *Transport) writeMessage(f *flow, m sip.Message, wait bool) error {
	b, err := m.Bytes()
	if err != nil {
		return err
	}
	return t.write(f, b, wait)
}

func (t *Transport) sendDatagram(l *listener, to netip.AddrPort, b []byte) error {
	if len(b) > maxDatagram {
		return errors.New("transport: message too large for a datagram")
	}
	if _, err := l.pc.WriteToUDPAddrPort(b, to); err != nil {
		t.stats.writeErrors.Add(1)
		return fmt.Errorf("transport: sending datagram: %w", err)
	}
	return nil
}

// SendResponse sends a response to the request that came from src, routed as RFC
// 3261 §18.2.2 says.
//
// Over TCP or TLS the response goes back on the request's connection. If that has
// closed, a new connection is opened to the received address (or the sent-by
// address) and the sent-by port, except for a request from a client-facing
// listener, which fails with ErrNoFlow (see ListenerConfig.ClientFacing). Over UDP
// it goes to the received address and the rport port, or the sent-by port, from
// the socket the request arrived on, which is what a client behind a NAT expects
// (RFC 3581 §4).
//
// Over a live connection SendResponse waits for at most WriteTimeout for room in
// the send queue, and not at all with NoWait; opening a new connection adds up to
// DialTimeout. A UDP send does not block.
func (t *Transport) SendResponse(res *sip.Response, src Source, opts ...SendOption) error {
	wait := !noWait(opts)
	if t.isClosed() {
		return ErrClosed
	}
	vias, err := res.Header.Via()
	if err != nil {
		return err
	}
	if len(vias) == 0 {
		return fmt.Errorf("%w: response has no Via", ErrUnroutable)
	}
	if src.Network.Reliable() {
		if f := t.flows.lookup(src.Flow); f != nil {
			return t.writeMessage(f, res, wait)
		}
		if l := t.listenerNamed(src.Listener); l != nil && l.clientFacing {
			return ErrNoFlow
		}
		n, addr, err := responseTarget(vias[0], false)
		if err != nil {
			return err
		}
		if !n.Reliable() {
			return fmt.Errorf("%w: connection closed and the Via names %s", ErrUnroutable, n)
		}
		f, err := t.streamTo(n, addr, "")
		if err != nil {
			return err
		}
		return t.writeMessage(f, res, wait)
	}
	_, addr, err := responseTarget(vias[0], true)
	if err != nil {
		return err
	}
	l := t.udpListenerFor(src.Listener, addr)
	if l == nil {
		return ErrNoListener
	}
	b, err := res.Bytes()
	if err != nil {
		return err
	}
	return t.sendDatagram(l, addr, b)
}
