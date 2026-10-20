package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// maxDatagram is the largest UDP payload over IPv4 or IPv6 without jumbograms.
const maxDatagram = 65535

type listener struct {
	t            *Transport
	name         string
	network      Network
	proxy        bool
	clientFacing bool
	idle         time.Duration
	sendQueue    int
	local        netip.AddrPort
	// sentByHost and sentByPort are what this listener writes into, and accepts
	// in, the sent-by of a Via.
	sentByHost string
	sentByPort int

	ln net.Listener // TCP and TLS
	pc *net.UDPConn // UDP

	stopOnce sync.Once
	stopErr  error

	// maxConns is ListenerConfig.MaxConnections, 0 for no limit of its own;
	// accepted counts this listener's connections against it, under t.mu.
	maxConns    int
	accepted    int
	proxyHeader time.Duration
}

// stop closes the socket; later calls do nothing.
func (l *listener) stop() error {
	l.stopOnce.Do(func() {
		if l.ln != nil {
			l.stopErr = l.ln.Close()
		} else {
			l.stopErr = l.pc.Close()
		}
	})
	return l.stopErr
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
	if cfg.MaxConnections < 0 || cfg.MaxConnections > 0 && cfg.Network == UDP {
		return netip.AddrPort{}, errors.New("transport: listener MaxConnections must be positive and is for TCP and TLS")
	}
	if cfg.ProxyHeaderTimeout < 0 || cfg.ProxyHeaderTimeout > 0 && !cfg.ProxyProtocol {
		return netip.AddrPort{}, errors.New("transport: ProxyHeaderTimeout must be positive and needs ProxyProtocol")
	}

	l := &listener{
		t:            t,
		network:      cfg.Network,
		proxy:        cfg.ProxyProtocol,
		clientFacing: cfg.ClientFacing || cfg.ProxyProtocol,
		idle:         cfg.IdleTimeout,
		maxConns:     cfg.MaxConnections,
		proxyHeader:  cfg.ProxyHeaderTimeout,
	}
	if l.proxyHeader == 0 {
		l.proxyHeader = DefaultProxyHeaderTimeout
	}
	if l.idle <= 0 {
		l.idle = t.cfg.IdleTimeout
	}
	switch l.sendQueue = cfg.SendQueueBytes; {
	case l.sendQueue > 0:
	case l.clientFacing:
		l.sendQueue = DefaultClientSendQueueBytes
	default:
		l.sendQueue = t.cfg.SendQueueBytes
	}
	lc := net.ListenConfig{KeepAliveConfig: coreKeepAlive}
	switch {
	case cfg.KeepAlive != nil:
		lc.KeepAliveConfig = *cfg.KeepAlive
	case l.clientFacing:
		lc.KeepAliveConfig = net.KeepAliveConfig{}
	}
	if !lc.KeepAliveConfig.Enable {
		// Without this Go turns keep-alive on with its defaults.
		lc.KeepAlive = -1
	}
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
		l.stop()
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
		l.stop()
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
		// Only a message that will be delivered may create a flow, so junk from
		// many source ports cannot fill the table.
		if !t.accept(msg, from, nil) {
			continue
		}
		f := t.flows.udpFlow(l, from)
		if f == nil {
			nf := t.flows.newFlow(UDP, l, from)
			if !t.admit(nf) {
				continue
			}
			var ok bool
			if f, ok = t.flows.addUDP(nf); !ok || f != nf {
				// Admitted but never entered: report it so the count Admit keeps
				// stays balanced.
				t.flowClosed(nf)
			}
			if !ok {
				continue
			}
		}
		t.handler(Inbound{Message: msg, Source: f.source()})
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
		if refused := t.reserveAccepted(l, c); refused != nil {
			refused.Add(1)
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

// reserveAccepted takes a slot for a connection accepted on l, or returns
// the counter of the refusal: the listener's own limit, checked first since
// it is what a client flood reaches, or the transport's.
func (t *Transport) reserveAccepted(l *listener, c net.Conn) *atomic.Uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.closed:
		return &t.stats.rejected
	case l.maxConns > 0 && l.accepted >= l.maxConns && l.clientFacing:
		return &t.stats.clientListenerRejected
	case l.maxConns > 0 && l.accepted >= l.maxConns:
		return &t.stats.coreListenerRejected
	case t.accepted >= t.cfg.MaxConnections:
		return &t.stats.rejected
	}
	t.accepted++
	l.accepted++
	t.pending[c] = struct{}{}
	return nil
}

func (t *Transport) releaseAccepted(l *listener, c net.Conn) {
	t.mu.Lock()
	t.accepted--
	l.accepted--
	delete(t.pending, c)
	t.mu.Unlock()
}

// unpend moves an accepted connection out of the pending set once it is a flow,
// which Close reaches through the flow table. It reports false if Close has
// already run, in which case the connection has been closed.
func (t *Transport) unpend(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.pending, c)
	return !t.closed
}

// serveAccepted reads the PROXY header and runs the TLS handshake if the listener
// needs them, then serves the connection as a flow.
func (l *listener) serveAccepted(raw net.Conn) {
	t := l.t
	defer t.wg.Done()
	defer t.releaseAccepted(l, raw)
	capSendBuffer(raw)

	remote := addrPortOf(raw.RemoteAddr())
	if l.proxy {
		raw.SetReadDeadline(time.Now().Add(l.proxyHeader))
		h, err := ReadProxyHeader(raw)
		if err != nil {
			// A connection closed before its first byte is a TCP health
			// check or a scan, a timeout a slow or silent client, and only
			// a malformed header a peer that is not the NLB, which the NLB
			// being misconfigured shows as.
			switch ne := net.Error(nil); {
			case errors.Is(err, io.EOF):
				t.stats.proxyHeaderEmpty.Add(1)
			case errors.As(err, &ne) && ne.Timeout():
				t.stats.proxyHeaderTimeouts.Add(1)
			default:
				t.stats.proxyHeaderErrors.Add(1)
			}
			raw.Close()
			return
		}
		if h.Command == ProxyLocal {
			// An NLB health check: the connection is good, but there is no client
			// to make a flow for (ADR 0003).
			t.stats.healthChecks.Add(1)
			raw.Close()
			return
		}
		remote = h.Source
		// The TLS handshake and the first message have bounds of their own.
		raw.SetReadDeadline(time.Time{})
	}
	f := t.flows.newFlow(l.network, l, remote)
	if !t.admit(f) {
		raw.Close()
		return
	}
	// From here on the flow is admitted, so it is reported closed exactly once:
	// by the table if it gets there, here otherwise.
	c := raw
	if l.network == TLS {
		tc := tls.Server(raw, t.cfg.TLS)
		ctx, cancel := context.WithTimeout(context.Background(), t.cfg.ReadTimeout)
		err := tc.HandshakeContext(ctx)
		cancel()
		if err != nil {
			t.stats.tlsHandshakeErrors.Add(1)
			raw.Close()
			t.flowClosed(f)
			return
		}
		c = tc
	}
	c.SetReadDeadline(time.Time{})
	f.conn = c
	f.idle.Store(int64(l.idle))
	t.startWriter(f)
	if !t.unpend(raw) || !t.flows.addStream(f) {
		f.q.close()
		c.Close()
		t.flowClosed(f)
		return
	}
	t.serveStream(f, true)
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
func (t *Transport) sentByOf(f *flow) (string, int, error) {
	if f.lis != nil {
		h, p := f.lis.sentBy()
		return h, p, nil
	}
	if l := t.listenerFor(f.network); l != nil {
		h, p := l.sentBy()
		return h, p, nil
	}
	// No listener for this transport: responses can only come back on the
	// connection, so its local address is as good a sent-by as any. A Dialer
	// that returns something other than a TCP connection may have no address,
	// and a Via without one is useless.
	local := addrPortOf(f.conn.LocalAddr())
	if !local.IsValid() || local.Port() == 0 {
		return "", 0, fmt.Errorf("%w: no %s listener and no local address for the Via", ErrNoListener, f.network)
	}
	return hostString(local.Addr()), int(local.Port()), nil
}
