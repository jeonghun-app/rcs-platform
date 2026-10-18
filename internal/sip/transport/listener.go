package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// maxDatagram is the largest UDP payload over IPv4 or IPv6 without jumbograms.
const maxDatagram = 65535

type listener struct {
	t       *Transport
	name    string
	network Network
	proxy   bool
	local   netip.AddrPort
	// sentByHost and sentByPort are what this listener writes into, and accepts
	// in, the sent-by of a Via.
	sentByHost string
	sentByPort int

	ln net.Listener // TCP and TLS
	pc *net.UDPConn // UDP
}

func (l *listener) close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return l.pc.Close()
}

// Listen opens a listening socket and starts serving it. It returns the bound
// address, which is useful when cfg.Addr has port 0.
func (t *Transport) Listen(cfg ListenerConfig) (netip.AddrPort, error) {
	switch cfg.Network {
	case UDP, TCP:
	case TLS:
		if t.cfg.TLS == nil {
			return netip.AddrPort{}, fmt.Errorf("%w: TLS listener without a TLS configuration", ErrNoListener)
		}
	default:
		return netip.AddrPort{}, fmt.Errorf("transport: unsupported network %q", cfg.Network)
	}
	if cfg.ProxyProtocol && cfg.Network == UDP {
		return netip.AddrPort{}, errors.New("transport: the PROXY protocol is only supported on TCP and TLS")
	}
	if cfg.AdvertisedPort < 0 || cfg.AdvertisedPort > 65535 {
		return netip.AddrPort{}, errors.New("transport: advertised port out of range")
	}

	l := &listener{t: t, network: cfg.Network, proxy: cfg.ProxyProtocol}
	var lc net.ListenConfig
	if cfg.Network == UDP {
		pc, err := lc.ListenPacket(context.Background(), "udp", cfg.Addr)
		if err != nil {
			return netip.AddrPort{}, err
		}
		l.pc = pc.(*net.UDPConn)
		l.local = l.pc.LocalAddr().(*net.UDPAddr).AddrPort()
	} else {
		ln, err := lc.Listen(context.Background(), "tcp", cfg.Addr)
		if err != nil {
			return netip.AddrPort{}, err
		}
		l.ln = ln
		l.local = ln.Addr().(*net.TCPAddr).AddrPort()
	}
	l.local = netip.AddrPortFrom(l.local.Addr().Unmap(), l.local.Port())
	if cfg.AdvertisedHost == "" && l.local.Addr().IsUnspecified() {
		// 0.0.0.0 or :: in a Via would send every response nowhere.
		l.close()
		return netip.AddrPort{}, errors.New("transport: a listener on an unspecified address needs AdvertisedHost")
	}
	l.name = cfg.Name
	if l.name == "" {
		l.name = string(cfg.Network) + " " + l.local.String()
	}
	l.sentByHost, l.sentByPort = cfg.AdvertisedHost, cfg.AdvertisedPort
	if l.sentByHost == "" {
		l.sentByHost = hostString(l.local.Addr())
	}
	if l.sentByPort == 0 {
		l.sentByPort = int(l.local.Port())
	}

	t.mu.Lock()
	err := func() error {
		if t.closed {
			return ErrClosed
		}
		for _, o := range t.listeners {
			if o.name == l.name {
				return fmt.Errorf("transport: duplicate listener name %q", l.name)
			}
		}
		return nil
	}()
	if err != nil {
		t.mu.Unlock()
		l.close()
		return netip.AddrPort{}, err
	}
	t.listeners = append(t.listeners, l)
	t.wg.Add(1)
	t.mu.Unlock()

	if l.pc != nil {
		go l.serveUDP()
	} else {
		go l.acceptLoop()
	}
	return l.local, nil
}

// hostString writes an address as a Via sent-by host: IPv6 in brackets (RFC 3261
// §25.1 IPv6reference).
func hostString(a netip.Addr) string {
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

func (l *listener) serveUDP() {
	t := l.t
	defer t.wg.Done()
	buf := make([]byte, maxDatagram)
	var backoff time.Duration
	for {
		n, from, err := l.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A read error on a UDP socket is usually about one datagram and the
			// socket is still good, but backing off keeps a persistent one from
			// spinning.
			backoff = nextBackoff(backoff)
			t.cfg.Logger.Warn("sip transport: UDP read failed", "listener", l.name, "err", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		msg, err := sip.ParseDatagram(buf[:n], t.cfg.Limits)
		if errors.Is(err, sip.ErrKeepAlive) {
			continue
		}
		if err != nil {
			t.stats.malformedDatagrams.Add(1)
			continue
		}
		f, _ := t.flows.udp(l, from)
		if f == nil {
			t.stats.udpFlowsRejected.Add(1)
			continue
		}
		t.deliver(f, msg)
	}
}

func (l *listener) acceptLoop() {
	t := l.t
	defer t.wg.Done()
	var backoff time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Running out of file descriptors is the usual cause; spinning on it
			// would only make it worse. net/http backs off the same way.
			backoff = nextBackoff(backoff)
			t.cfg.Logger.Warn("sip transport: accept failed", "listener", l.name, "err", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if !t.reserveAccepted() {
			t.stats.rejected.Add(1)
			c.Close()
			continue
		}
		t.stats.accepted.Add(1)
		t.wg.Add(1)
		go l.serveAccepted(c)
	}
}

func nextBackoff(d time.Duration) time.Duration {
	return min(max(2*d, 5*time.Millisecond), time.Second)
}

func (t *Transport) reserveAccepted() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.accepted >= t.cfg.MaxConnections {
		return false
	}
	t.accepted++
	return true
}

func (t *Transport) releaseAccepted() {
	t.mu.Lock()
	t.accepted--
	t.mu.Unlock()
}

// serveAccepted reads the PROXY header and runs the TLS handshake if the listener
// needs them, then serves the connection as a flow.
func (l *listener) serveAccepted(c net.Conn) {
	t := l.t
	defer t.wg.Done()
	defer t.releaseAccepted()

	remote := addrPortOf(c.RemoteAddr())
	if l.proxy {
		c.SetReadDeadline(time.Now().Add(t.cfg.ReadTimeout))
		h, err := ReadProxyHeader(c)
		if err != nil {
			t.stats.proxyHeaderErrors.Add(1)
			c.Close()
			return
		}
		if h.Command == ProxyLocal {
			// An NLB health check: the connection is good, but there is no client
			// to make a flow for (ADR 0003).
			t.stats.healthChecks.Add(1)
			c.Close()
			return
		}
		remote = h.Source
	}
	if l.network == TLS {
		tc := tls.Server(c, t.cfg.TLS)
		ctx, cancel := context.WithTimeout(context.Background(), t.cfg.ReadTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			t.stats.tlsHandshakeErrors.Add(1)
			c.Close()
			return
		}
		c = tc
	}
	c.SetReadDeadline(time.Time{})

	f := t.flows.newFlow(l.network, l, remote)
	f.conn = c
	if !t.flows.addStream(f) {
		c.Close()
		return
	}
	t.serveStream(f)
}

func addrPortOf(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := a.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	default:
		ap, _ = netip.ParseAddrPort(a.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// sentBy is the sent-by host and port of a listener, as written in a Via.
func (l *listener) sentBy() (string, int) { return l.sentByHost, l.sentByPort }

// listenerFor returns the first listener of a network, whose sent-by a request
// leaving on a connection this transport opened carries.
func (t *Transport) listenerFor(network Network) *listener {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.listeners {
		if l.network == network {
			return l
		}
	}
	return nil
}

// udpListenerFor returns the UDP socket to send to dst from: the named listener
// if it exists, otherwise the first UDP listener whose address family can reach
// dst.
func (t *Transport) udpListenerFor(name string, dst netip.AddrPort) *listener {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, l := range t.listeners {
		if l.network == UDP && name != "" && l.name == name {
			return l
		}
	}
	for _, l := range t.listeners {
		if l.network != UDP {
			continue
		}
		a := l.local.Addr()
		if a.Is4() == dst.Addr().Is4() || (a.Is6() && a.IsUnspecified()) {
			return l
		}
	}
	return nil
}

// sentByOf returns the sent-by this transport writes for a message leaving on f.
func (t *Transport) sentByOf(f *flow) (string, int) {
	if f.lis != nil {
		return f.lis.sentBy()
	}
	if l := t.listenerFor(f.network); l != nil {
		return l.sentBy()
	}
	// No listener for this transport: responses can only come back on the
	// connection, so its local address is as good a sent-by as any.
	local := addrPortOf(f.conn.LocalAddr())
	return hostString(local.Addr()), int(local.Port())
}
