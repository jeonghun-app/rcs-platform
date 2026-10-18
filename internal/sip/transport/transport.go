package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Defaults for the zero fields of Config.
const (
	DefaultMaxConnections       = 10000
	DefaultMaxDialedConnections = 1024
	DefaultMaxUDPFlows          = 65536
	// DefaultMaxUDPFlowsPerIP keeps one host with many source ports from
	// displacing everyone else's UDP flows. Clients behind a carrier-grade NAT
	// share an address, so an operator whose clients use UDP through one raises
	// it.
	DefaultMaxUDPFlowsPerIP = 256
	// DefaultIdleTimeout is just below the 1800 s idle timeout of the NLB's TCP
	// listeners (ADR 0003). Cutting a silent flow here first sends the client a
	// FIN, so it reconnects, and a terminating request finds no flow and gets
	// 430 at once; cutting it after the NLB has silently dropped the connection
	// would let that request be written into a dead connection and time out. The
	// NLB's TLS listeners have a fixed 350 s idle timeout, so the listener behind
	// one sets ListenerConfig.IdleTimeout below that and the P-CSCF asks clients
	// for keep-alives more often with Flow-Timer (RFC 5626 §4.4.1).
	DefaultIdleTimeout = 1740 * time.Second
	// DefaultUDPFlowTimeout is the shortest UDP mapping lifetime a NAT may use
	// (RFC 4787 §4.3 REQ-5). Mobile NATs often keep mappings no longer, and
	// reporting a flow alive past its mapping would send terminating requests
	// into nothing until Timer F instead of answering 430.
	DefaultUDPFlowTimeout = 120 * time.Second
	// DefaultReadTimeout is 64*T1 with the default T1: a request that takes
	// longer than that to arrive belongs to a transaction its sender has already
	// given up on (RFC 3261 §17.1.1.2, §17.1.2.2).
	DefaultReadTimeout  = 32 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultDialTimeout  = 5 * time.Second
	// DefaultSendQueueBytes lets a core connection absorb a burst of a
	// thousand typical requests while its peer catches up. A peer that never
	// reads costs at most twice this before its connection is closed.
	DefaultSendQueueBytes = 4 << 20
)

// Errors returned by the send methods. Errors from the network are returned
// wrapped, so callers test these with errors.Is.
var (
	// ErrNoFlow means the FlowID names no live flow: it is unknown, forged,
	// from an earlier process, or its connection has closed. A proxy answers
	// a request it cannot forward for this reason with 430 Flow Failed (RFC 5626
	// §5.3.1). A response to a request from a client-facing listener whose
	// connection has closed also fails with it.
	ErrNoFlow = errors.New("transport: no such flow")
	// ErrClosed means the transport has been closed.
	ErrClosed = errors.New("transport: closed")
	// ErrNoListener means a UDP message has no socket to leave from, or a TLS
	// listener has no certificate configured.
	ErrNoListener = errors.New("transport: no suitable listener")
	// ErrUnroutable means the transport cannot tell where, or how safely, to
	// send: an unsupported transport or a sent-by host name without received in
	// a response's top Via (RFC 3263 resolution is not done here), or a TLS
	// connection with no server name to verify.
	ErrUnroutable = errors.New("transport: cannot route the message")
	// ErrTooManyConnections means MaxDialedConnections outbound connections
	// are open or being opened.
	ErrTooManyConnections = errors.New("transport: too many outbound connections")
	// ErrQueueFull means a stream connection's send queue was full, so its peer
	// was not reading; the connection has been closed.
	ErrQueueFull = errors.New("transport: send queue full; connection closed")
)

// Handler receives every message the transport accepts. It runs on the goroutine
// that read the message, one call at a time per connection and per UDP socket, so
// messages from one flow arrive in order. It must hand off anything slow: while it
// runs, nothing else is read from that connection, or from that UDP socket, which
// every UDP client shares.
type Handler func(Inbound)

// Inbound is a message received from the network.
type Inbound struct {
	// Message has passed sip.Message.Validate. A request's top Via carries the
	// received and rport parameters this transport added (RFC 3261 §18.2.1,
	// RFC 3581 §4).
	Message sip.Message
	Source  Source
}

// Source says where a message came from, and is where a response to a request
// is routed (RFC 3261 §18.2.2).
type Source struct {
	Flow    FlowID
	Network Network
	// Addr is the client address: from the PROXY header when the listener
	// requires one, otherwise the socket peer.
	Addr netip.AddrPort
	// Listener is the name of the listener the message arrived on, empty when
	// it arrived on a connection this transport opened.
	Listener string
}

// Dialer opens outbound connections; *net.Dialer implements it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Config configures a Transport. Zero durations and limits take the defaults
// above.
type Config struct {
	// TLS is the server configuration of TLS listeners. A TLS listener cannot be
	// opened without it.
	TLS *tls.Config
	// TLSClient is the configuration of outbound TLS connections. Its
	// ServerName is replaced by Destination.ServerName when that is set. Nil
	// means the system roots and no client certificate.
	TLSClient *tls.Config

	// MaxConnections bounds the TCP and TLS connections accepted from peers,
	// counted from accept, so it also bounds handshakes in progress.
	MaxConnections int
	// MaxDialedConnections bounds the connections this transport opens,
	// separately, so a flood of clients cannot stop a proxy from reaching the
	// core and nothing a client writes can make it open connections without
	// limit.
	MaxDialedConnections int
	// MaxUDPFlows bounds the UDP sources tracked as flows, and MaxUDPFlowsPerIP
	// those of one source address. At either limit the least recently seen flow
	// in its scope makes room for the new one.
	MaxUDPFlows      int
	MaxUDPFlowsPerIP int
	// IdleTimeout is how long a stream connection may go without receiving a
	// byte between messages; keep-alives count. ListenerConfig.IdleTimeout
	// overrides it for one listener.
	IdleTimeout time.Duration
	// UDPFlowTimeout is how long a UDP flow lives without a datagram.
	UDPFlowTimeout time.Duration
	// ReadTimeout bounds receiving one message from its first byte, the PROXY
	// header and the TLS handshake, and, on an accepted connection, everything
	// until the first message is complete, so a connection that never sends a
	// message frees its MaxConnections slot quickly.
	ReadTimeout time.Duration
	// WriteTimeout bounds writing one message. A stream connection whose write
	// fails or times out is closed, since part of a message may have been sent.
	WriteTimeout time.Duration
	// SendQueueBytes bounds what may wait to be written to one stream
	// connection: a send waits for room, for at most WriteTimeout, while it is
	// exceeded, and a NoWait send may use as much again. A connection whose
	// queue stays full is closed.
	SendQueueBytes int
	// DialTimeout bounds opening an outbound connection, TLS handshake
	// included.
	DialTimeout time.Duration

	// Limits bound every message read, on every transport.
	Limits sip.Limits

	// Admit, if set, is asked about every new inbound flow once its client
	// address is known: after the PROXY header and before the TLS handshake of
	// a stream connection, or on the first datagram from a UDP source. Returning
	// false refuses the flow (the connection is closed, the datagram dropped)
	// and counts it. A service enforces per-client limits with it. It runs on
	// the accepting or reading goroutine and must not block.
	Admit func(id FlowID, info FlowInfo) bool
	// OnFlowClosed, if set, is told once about every flow that ends: each
	// admitted inbound flow (even if its TLS handshake then fails) and each
	// outbound connection. UDP flows end when they expire, which is noticed on
	// the next lookup or datagram, when they are displaced, or on Close. It must
	// not block, and must not call back into the transport synchronously.
	OnFlowClosed func(id FlowID, info FlowInfo)

	// Dialer opens outbound connections; nil uses a net.Dialer with the core
	// keep-alive described at ListenerConfig.KeepAlive.
	Dialer Dialer
	// Rand is the source of the flow key; nil uses crypto/rand.
	Rand io.Reader
	// Now is the clock for UDP flow expiry; nil uses time.Now. Socket deadlines
	// always use the real clock, which the network does.
	Now func() time.Time
	// Logger receives operational events, never message content, addresses or
	// flow IDs. Nil discards them.
	Logger *slog.Logger
}

func (c Config) withDefaults() Config {
	setDefault(&c.MaxConnections, DefaultMaxConnections)
	setDefault(&c.MaxDialedConnections, DefaultMaxDialedConnections)
	setDefault(&c.MaxUDPFlows, DefaultMaxUDPFlows)
	setDefault(&c.MaxUDPFlowsPerIP, DefaultMaxUDPFlowsPerIP)
	setDefault(&c.IdleTimeout, DefaultIdleTimeout)
	setDefault(&c.UDPFlowTimeout, DefaultUDPFlowTimeout)
	setDefault(&c.ReadTimeout, DefaultReadTimeout)
	setDefault(&c.WriteTimeout, DefaultWriteTimeout)
	setDefault(&c.DialTimeout, DefaultDialTimeout)
	setDefault(&c.SendQueueBytes, DefaultSendQueueBytes)
	if c.Dialer == nil {
		c.Dialer = &net.Dialer{KeepAliveConfig: coreKeepAlive}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}

func setDefault[T int | time.Duration](v *T, d T) {
	if *v <= 0 {
		*v = d
	}
}

// coreKeepAlive is the TCP keep-alive of core-facing connections: probes after
// 15 s of silence, every 15 s, nine times, which are Go's defaults. A core peer
// whose task has gone away is noticed within about three minutes, and the probes
// keep the VPC's connection tracking warm on quiet core links.
var coreKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 15 * time.Second, Count: 9}

// ListenerConfig describes one listening socket.
type ListenerConfig struct {
	// Name identifies the listener in Source and is part of the flow identity.
	// Names must be unique; empty takes "<network> <bound address>".
	Name    string
	Network Network
	// Addr is the local address to bind, such as "0.0.0.0:5060" or
	// "127.0.0.1:0".
	Addr string
	// AdvertisedHost and AdvertisedPort are the sent-by this transport writes
	// in the Via of requests it sends through this listener's transport (RFC
	// 3261 §18.1.1) and accepts in responses (§18.1.2), such as the task address
	// behind a load balancer. Empty and zero take the bound address and port; a
	// listener bound to an unspecified address needs AdvertisedHost.
	AdvertisedHost string
	AdvertisedPort int
	// ProxyProtocol requires a PROXY protocol v2 header at the start of every
	// connection (TCP and TLS only), for listeners behind the NLB (ADR 0003,
	// RCS_PROXY_PROTOCOL). It implies ClientFacing.
	ProxyProtocol bool
	// ClientFacing marks a listener clients connect to, directly or through the
	// load balancer, as opposed to one other core nodes use. On such a
	// listener:
	//   - a response whose connection has closed fails with ErrNoFlow instead of
	//     opening a new connection to the address in its Via (RFC 3261
	//     §18.2.2). A client behind a NAT cannot be reached that way, and the
	//     address is the client's to choose, so dialing it would let any client
	//     make this server open connections wherever it likes. A client using
	//     RFC 5626 outbound treats the lost flow as a failure anyway.
	//   - TCP keep-alive probes are off by default (see KeepAlive).
	ClientFacing bool
	// KeepAlive sets the TCP keep-alive of accepted connections; nil takes the
	// default. A client-facing listener sends no probes: the client chooses its
	// own keep-alive interval (RFC 5626 §4.4), and a probe from the server would
	// wake the radio of every idle phone. Other listeners use the core
	// keep-alive, 15 s probes, as dialed connections do.
	KeepAlive *net.KeepAliveConfig
	// IdleTimeout overrides Config.IdleTimeout for connections accepted on
	// this listener, such as one behind the NLB's TLS listener (350 s).
	IdleTimeout time.Duration
}

// Transport sends and receives SIP messages and owns the flow table. Its methods
// are safe for concurrent use.
type Transport struct {
	cfg     Config
	handler Handler
	flows   *flowTable
	stats   counters

	mu        sync.Mutex
	listeners []*listener
	dialing   map[reuseKey]*dialCall
	closed    bool
	// accepted counts accepted connections, from accept to close, against
	// MaxConnections.
	accepted int
	// pending holds accepted connections that are not flows yet (PROXY header
	// or TLS handshake in progress), so Close can close them at once.
	pending map[net.Conn]struct{}

	wg sync.WaitGroup
}

type dialCall struct {
	done chan struct{}
	f    *flow
	err  error
}

// New returns a Transport that passes every message it accepts to h. It draws a
// fresh flow key from cfg.Rand, so FlowIDs of any earlier Transport are unknown
// to it.
func New(cfg Config, h Handler) (*Transport, error) {
	if h == nil {
		return nil, errors.New("transport: nil handler")
	}
	cfg = cfg.withDefaults()
	var key [sha256.Size]byte
	if _, err := io.ReadFull(cfg.Rand, key[:]); err != nil {
		return nil, fmt.Errorf("transport: drawing the flow key: %w", err)
	}
	t := &Transport{
		cfg:     cfg,
		handler: h,
		dialing: make(map[reuseKey]*dialCall),
		pending: make(map[net.Conn]struct{}),
	}
	t.flows = newFlowTable(key, cfg.Now, tableConfig{
		udpTimeout:  cfg.UDPFlowTimeout,
		maxUDP:      cfg.MaxUDPFlows,
		maxUDPPerIP: cfg.MaxUDPFlowsPerIP,
		onClosed:    t.flowClosed,
	})
	return t, nil
}

func (t *Transport) flowClosed(f *flow) {
	if t.cfg.OnFlowClosed != nil {
		t.cfg.OnFlowClosed(f.id, f.info())
	}
}

// admit asks Config.Admit about a new inbound flow.
func (t *Transport) admit(f *flow) bool {
	if t.cfg.Admit == nil || t.cfg.Admit(f.id, f.info()) {
		return true
	}
	t.stats.refused.Add(1)
	return false
}

// Flow resolves a FlowID. It reports false for every ID that does not name a live
// flow of this Transport.
func (t *Transport) Flow(id FlowID) (FlowInfo, bool) {
	f := t.flows.lookup(id)
	if f == nil {
		return FlowInfo{}, false
	}
	return f.info(), true
}

// CloseFlow closes one flow: its connection, or for UDP its table entry. It
// reports whether the flow was live. A stopping P-CSCF uses it to close its
// flows gradually rather than all at once (ADR 0003).
func (t *Transport) CloseFlow(id FlowID) bool {
	f := t.flows.lookup(id)
	if f == nil {
		return false
	}
	t.closeFlow(f)
	return true
}

// StopListening closes the TCP and TLS listeners, so no new connection is
// accepted, and leaves every flow open. UDP sockets stay open, since UDP flows
// and every UDP send use them. It is the first step of a gradual shutdown.
func (t *Transport) StopListening() {
	t.mu.Lock()
	lis := t.listeners
	t.mu.Unlock()
	for _, l := range lis {
		if l.ln != nil {
			l.stop()
		}
	}
}

// Close stops every listener and closes every connection, including those still
// in their PROXY header or TLS handshake, then waits for the goroutines of the
// transport to finish. Messages being delivered to the handler complete first.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	lis := t.listeners
	for c := range t.pending {
		c.Close()
	}
	t.mu.Unlock()

	var errs []error
	for _, l := range lis {
		errs = append(errs, l.stop())
	}
	for _, f := range t.flows.close() {
		t.closeFlow(f)
	}
	t.wg.Wait()
	return errors.Join(errs...)
}

func (t *Transport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// closeFlow closes a flow's connection, if it has one, and forgets the flow.
func (t *Transport) closeFlow(f *flow) {
	if f.closed.CompareAndSwap(false, true) && f.conn != nil {
		f.conn.Close()
		f.q.close()
	}
	t.flows.remove(f)
}

// Stats is a snapshot of the transport's gauges and counters, for metrics.
type Stats struct {
	// Gauges.
	OpenInbound     int // accepted TCP and TLS flows
	OpenOutbound    int // connections this transport opened
	OpenUDPFlows    int
	PendingAccepted int // accepted, PROXY header or TLS handshake in progress

	// Counters since New.
	Accepted           uint64 // TCP and TLS connections accepted
	Rejected           uint64 // connections refused at MaxConnections
	Refused            uint64 // flows Config.Admit refused
	Dialed             uint64 // outbound connections opened
	DialErrors         uint64
	DialLimited        uint64 // dials refused at MaxDialedConnections
	ProxyHeaderErrors  uint64 // connections closed for a missing or invalid PROXY header
	HealthChecks       uint64 // PROXY LOCAL connections, closed without a flow
	TLSHandshakeErrors uint64
	FramingErrors      uint64 // stream connections closed because a message did not parse
	TruncatedMessages  uint64 // stream connections the peer closed in the middle of a message
	IdleTimeouts       uint64
	ReadTimeouts       uint64 // stream connections closed mid-message or before their first message
	WriteErrors        uint64
	QueueOverflows     uint64 // stream connections closed because their send queue was full
	KeepAlives         uint64 // CRLF pings answered
	MalformedDatagrams uint64
	InvalidMessages    uint64 // framed but refused by Validate; dropped
	StrayResponses     uint64 // responses whose top Via is not ours (RFC 3261 §18.1.2); dropped
	UDPFlowsEvicted    uint64 // UDP flows displaced at MaxUDPFlows or MaxUDPFlowsPerIP
}

type counters struct {
	accepted, rejected, refused, dialed, dialErrors, dialLimited,
	proxyHeaderErrors, healthChecks, tlsHandshakeErrors, framingErrors,
	truncatedMessages, idleTimeouts, readTimeouts, writeErrors, queueOverflows, keepAlives,
	malformedDatagrams, invalidMessages, strayResponses atomic.Uint64
}

// Stats returns the current gauges and counters.
func (t *Transport) Stats() Stats {
	c := &t.stats
	ts := t.flows.stats()
	t.mu.Lock()
	pending := len(t.pending)
	t.mu.Unlock()
	return Stats{
		OpenInbound:        ts.inbound,
		OpenOutbound:       ts.outbound,
		OpenUDPFlows:       ts.udp,
		PendingAccepted:    pending,
		Accepted:           c.accepted.Load(),
		Rejected:           c.rejected.Load(),
		Refused:            c.refused.Load(),
		Dialed:             c.dialed.Load(),
		DialErrors:         c.dialErrors.Load(),
		DialLimited:        c.dialLimited.Load(),
		ProxyHeaderErrors:  c.proxyHeaderErrors.Load(),
		HealthChecks:       c.healthChecks.Load(),
		TLSHandshakeErrors: c.tlsHandshakeErrors.Load(),
		FramingErrors:      c.framingErrors.Load(),
		TruncatedMessages:  c.truncatedMessages.Load(),
		IdleTimeouts:       c.idleTimeouts.Load(),
		ReadTimeouts:       c.readTimeouts.Load(),
		WriteErrors:        c.writeErrors.Load(),
		QueueOverflows:     c.queueOverflows.Load(),
		KeepAlives:         c.keepAlives.Load(),
		MalformedDatagrams: c.malformedDatagrams.Load(),
		InvalidMessages:    c.invalidMessages.Load(),
		StrayResponses:     c.strayResponses.Load(),
		UDPFlowsEvicted:    ts.evicted,
	}
}

// deliver checks a framed stream message and hands it to the handler.
func (t *Transport) deliver(f *flow, msg sip.Message) {
	if t.accept(msg, f.remote, f) {
		t.handler(Inbound{Message: msg, Source: f.source()})
	}
}

// accept checks a framed message from remote: it must validate, a request gets
// received and rport, and a response must carry our sent-by (RFC 3261 §18.1.2).
// f is the stream flow it arrived on, nil for UDP. Refusals are counted.
func (t *Transport) accept(msg sip.Message, remote netip.AddrPort, f *flow) bool {
	if err := msg.Validate(); err != nil {
		t.stats.invalidMessages.Add(1)
		return false
	}
	switch m := msg.(type) {
	case *sip.Request:
		if err := stampReceived(m, remote); err != nil {
			t.stats.invalidMessages.Add(1)
			return false
		}
	case *sip.Response:
		if !t.ownsTopVia(m, f) {
			t.stats.strayResponses.Add(1)
			return false
		}
	}
	return true
}
