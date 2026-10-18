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
	DefaultMaxConnections = 10000
	DefaultMaxUDPFlows    = 65536
	// DefaultIdleTimeout matches the NLB idle timeout of the SIP listeners (ADR
	// 0003), so a quiet flow the load balancer keeps is not cut here first.
	DefaultIdleTimeout = 1800 * time.Second
	// DefaultReadTimeout is 64*T1 with the default T1: a request that takes
	// longer than that to arrive belongs to a transaction its sender has already
	// given up on (RFC 3261 §17.1.1.2, §17.1.2.2).
	DefaultReadTimeout  = 32 * time.Second
	DefaultWriteTimeout = 10 * time.Second
	DefaultDialTimeout  = 5 * time.Second
)

// Errors returned by the send methods. Errors from the network are returned
// wrapped, so callers test these with errors.Is.
var (
	// ErrNoFlow means the FlowID names no live flow: it is unknown, forged,
	// from an earlier process, or its connection has closed. A proxy answers
	// a request it cannot forward for this reason with 430 Flow Failed (RFC 5626
	// §5.3.1).
	ErrNoFlow = errors.New("transport: no such flow")
	// ErrClosed means the transport has been closed.
	ErrClosed = errors.New("transport: closed")
	// ErrNoListener means a UDP message has no socket to leave from, or a TLS
	// listener has no certificate configured.
	ErrNoListener = errors.New("transport: no suitable listener")
	// ErrUnroutable means a response's top Via does not say where to send it:
	// an unsupported transport, or a sent-by host name with no received
	// parameter, which would need RFC 3263 resolution this package does not do.
	ErrUnroutable = errors.New("transport: cannot route the message")
)

// Handler receives every message the transport accepts. It runs on the goroutine
// that read the message, one call at a time per connection and per UDP socket, so
// messages from one flow arrive in order; it must hand off anything slow.
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
	// counted from accept, so it also bounds handshakes in progress. Outbound
	// connections are not counted: a flood of clients must not stop a proxy from
	// reaching the core.
	MaxConnections int
	// MaxUDPFlows bounds the UDP sources tracked as flows. A datagram from a new
	// source when the table is full is dropped and counted.
	MaxUDPFlows int
	// IdleTimeout is how long a stream connection may go without receiving a
	// byte between messages (keep-alives count), and how long a UDP flow lives
	// without a datagram.
	IdleTimeout time.Duration
	// ReadTimeout bounds receiving one message from its first byte, the PROXY
	// header and the TLS handshake.
	ReadTimeout time.Duration
	// WriteTimeout bounds writing one message. A stream connection whose write
	// fails or times out is closed, since part of a message may have been sent.
	WriteTimeout time.Duration
	// DialTimeout bounds opening an outbound connection, TLS handshake
	// included.
	DialTimeout time.Duration

	// Limits bound every message read, on every transport.
	Limits sip.Limits

	// Dialer opens outbound connections; nil uses a net.Dialer.
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
	if c.MaxConnections <= 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.MaxUDPFlows <= 0 {
		c.MaxUDPFlows = DefaultMaxUDPFlows
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = DefaultReadTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.Dialer == nil {
		c.Dialer = &net.Dialer{}
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
	// behind a load balancer. Empty and zero take the bound address and port.
	AdvertisedHost string
	AdvertisedPort int
	// ProxyProtocol requires a PROXY protocol v2 header at the start of every
	// connection (TCP and TLS only), for listeners behind the NLB (ADR 0003,
	// RCS_PROXY_PROTOCOL). Core-facing listeners leave it off.
	ProxyProtocol bool
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
	return &Transport{
		cfg:     cfg,
		handler: h,
		flows:   newFlowTable(key, cfg.Now, cfg.IdleTimeout, cfg.MaxUDPFlows),
		dialing: make(map[reuseKey]*dialCall),
	}, nil
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

// Close stops every listener and closes every connection, then waits for the
// goroutines of the transport to finish. Messages being delivered to the handler
// complete first.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	lis := t.listeners
	t.mu.Unlock()

	var errs []error
	for _, l := range lis {
		errs = append(errs, l.close())
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

// closeFlow closes a stream flow's connection and forgets the flow.
func (t *Transport) closeFlow(f *flow) {
	if f.closed.CompareAndSwap(false, true) && f.conn != nil {
		f.conn.Close()
	}
	t.flows.remove(f)
}

// Stats is a snapshot of the transport's counters, for metrics. Every field
// except OpenConnections counts events since New.
type Stats struct {
	OpenConnections int // TCP and TLS, inbound and outbound

	Accepted           uint64 // TCP and TLS connections accepted
	Rejected           uint64 // connections refused at MaxConnections
	Dialed             uint64 // outbound connections opened
	DialErrors         uint64
	ProxyHeaderErrors  uint64 // connections closed for a missing or invalid PROXY header
	HealthChecks       uint64 // PROXY LOCAL connections, closed without a flow
	TLSHandshakeErrors uint64
	FramingErrors      uint64 // stream connections closed because a message could not be framed
	IdleTimeouts       uint64
	ReadTimeouts       uint64 // stream connections closed mid-message
	WriteErrors        uint64
	KeepAlives         uint64 // CRLF pings answered
	MalformedDatagrams uint64
	InvalidMessages    uint64 // framed but refused by Validate; dropped
	StrayResponses     uint64 // responses whose top Via is not ours (RFC 3261 §18.1.2); dropped
	UDPFlowsRejected   uint64 // datagrams dropped at MaxUDPFlows
}

type counters struct {
	accepted, rejected, dialed, dialErrors, proxyHeaderErrors, healthChecks,
	tlsHandshakeErrors, framingErrors, idleTimeouts, readTimeouts, writeErrors,
	keepAlives, malformedDatagrams, invalidMessages, strayResponses,
	udpFlowsRejected atomic.Uint64
}

// Stats returns the current counters.
func (t *Transport) Stats() Stats {
	c := &t.stats
	return Stats{
		OpenConnections:    t.flows.openStreams(),
		Accepted:           c.accepted.Load(),
		Rejected:           c.rejected.Load(),
		Dialed:             c.dialed.Load(),
		DialErrors:         c.dialErrors.Load(),
		ProxyHeaderErrors:  c.proxyHeaderErrors.Load(),
		HealthChecks:       c.healthChecks.Load(),
		TLSHandshakeErrors: c.tlsHandshakeErrors.Load(),
		FramingErrors:      c.framingErrors.Load(),
		IdleTimeouts:       c.idleTimeouts.Load(),
		ReadTimeouts:       c.readTimeouts.Load(),
		WriteErrors:        c.writeErrors.Load(),
		KeepAlives:         c.keepAlives.Load(),
		MalformedDatagrams: c.malformedDatagrams.Load(),
		InvalidMessages:    c.invalidMessages.Load(),
		StrayResponses:     c.strayResponses.Load(),
		UDPFlowsRejected:   c.udpFlowsRejected.Load(),
	}
}

// deliver checks a framed message and hands it to the handler.
func (t *Transport) deliver(f *flow, msg sip.Message) {
	if err := msg.Validate(); err != nil {
		t.stats.invalidMessages.Add(1)
		return
	}
	switch m := msg.(type) {
	case *sip.Request:
		if err := stampReceived(m, f.remote); err != nil {
			t.stats.invalidMessages.Add(1)
			return
		}
	case *sip.Response:
		if !t.ownsTopVia(m, f) {
			t.stats.strayResponses.Add(1)
			return
		}
	}
	t.handler(Inbound{Message: msg, Source: f.source()})
}
