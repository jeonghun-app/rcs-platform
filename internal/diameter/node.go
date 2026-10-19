package diameter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for the Config fields left zero.
const (
	// DefaultWatchdogInterval is Twinit, RFC 3539 §3.4.1.
	DefaultWatchdogInterval = 30 * time.Second
	// MinWatchdogInterval is the smallest Twinit RFC 3539 §3.4.1 allows.
	MinWatchdogInterval = 6 * time.Second
	// DefaultReconnectMax is Tc, the RFC 6733 §12 reconnect interval.
	DefaultReconnectMax        = 30 * time.Second
	DefaultReconnectMin        = 1 * time.Second
	DefaultRequestTimeout      = 10 * time.Second
	DefaultCapabilitiesTimeout = 10 * time.Second
	DefaultMaxInFlight         = 256
	// DefaultMaxPendingConnections bounds inbound connections that have not
	// completed CER/CEA. Legitimate peers finish within milliseconds, so the
	// limit only bites when something is opening connections and sending
	// nothing.
	DefaultMaxPendingConnections = 64
)

const (
	defaultProductName = "rcs-platform"
	// watchdogJitterMilliseconds is the ±2 s RFC 3539 §3.4.1 adds to Tw.
	watchdogJitterMilliseconds = 2000
	// reopenWatchdogsBeforeOpen is how many DWAs a reconnected peer must
	// answer in REOPEN before it carries traffic (RFC 3539 §3.4.1).
	reopenWatchdogsBeforeOpen = 3
	// disconnectWaitForPeerToDrop bounds how long a node that answered a
	// DPR waits for the sender to close the connection (RFC 6733 §5.4).
	disconnectWaitForPeerToDrop = 5 * time.Second
)

// Config describes the local node.
type Config struct {
	// OriginHost and OriginRealm are this node's Diameter identity. Each
	// service instance has its own OriginHost (ADR 0005).
	OriginHost  string
	OriginRealm string
	// HostIPAddresses are advertised in CER and CEA. When empty, the local
	// address of each connection is advertised, which is the task address
	// on Fargate.
	HostIPAddresses []netip.Addr
	// VendorID is this implementation's vendor (0 is acceptable).
	VendorID         uint32
	ProductName      string // defaults to "rcs-platform"
	FirmwareRevision uint32 // omitted when zero
	// OriginStateID changes every time the node restarts and loses state
	// (RFC 6733 §8.16). It defaults to the start-up time in seconds.
	OriginStateID uint32
	// Applications are advertised in CER and CEA; at least one is needed.
	Applications       []Application
	SupportedVendorIDs []uint32

	// Dictionary validates received messages. It defaults to the base AVPs
	// only.
	Dictionary *Dictionary
	Limits     Limits

	// Accept lists the peers [Node.Serve] accepts. With no rules, every
	// inbound peer is answered with DIAMETER_UNKNOWN_PEER.
	Accept []PeerRule
	// MaxPendingConnections bounds inbound connections that have not yet
	// completed the capabilities exchange; further ones are closed as soon
	// as they are accepted. Each such connection is also closed after
	// CapabilitiesTimeout. Together they cap what unauthenticated clients
	// can hold: this many goroutines and read buffers of at most
	// MaxMessageSize.
	MaxPendingConnections int

	// WatchdogInterval is Twinit; each wait is jittered by up to ±2 s as
	// RFC 3539 §3.4.1 requires.
	WatchdogInterval    time.Duration
	RequestTimeout      time.Duration // answer wait when the context has no earlier deadline
	CapabilitiesTimeout time.Duration // dial plus CER/CEA exchange
	ReconnectMin        time.Duration // first reconnect delay of an initiated peer
	ReconnectMax        time.Duration // ceiling of the exponential backoff
	// WriteTimeout bounds one socket write; a peer that takes nothing for
	// that long is treated as failed. It defaults to WatchdogInterval.
	WriteTimeout time.Duration
	// MaxInFlight bounds concurrent inbound requests per connection (more
	// are answered with DIAMETER_TOO_BUSY), the length of the queue of
	// their answers, which handlers wait on, and the length of the queue of
	// requests that Send waits on. Answers are written first.
	MaxInFlight int

	// Clock, Random and Dial are injected for tests. Random must be safe for
	// concurrent use; it seeds identifiers and jitter, none of which is a
	// secret.
	Clock  Clock
	Random func() uint64
	Dial   func(ctx context.Context, network, address string) (net.Conn, error)
	// Logger receives connection events. Diameter identities and addresses
	// of nodes are logged; message contents and Session-Ids never are.
	Logger *slog.Logger
}

func (c *Config) setDefaults() error {
	if c.OriginHost == "" || !validIdentity([]byte(c.OriginHost)) {
		return fmt.Errorf("diameter: OriginHost %q is not a valid DiameterIdentity", c.OriginHost)
	}
	if c.OriginRealm == "" || !validIdentity([]byte(c.OriginRealm)) {
		return fmt.Errorf("diameter: OriginRealm %q is not a valid DiameterIdentity", c.OriginRealm)
	}
	if len(c.Applications) == 0 {
		return errors.New("diameter: at least one application is required")
	}
	for _, a := range c.HostIPAddresses {
		if !a.IsValid() {
			return errors.New("diameter: invalid HostIPAddress")
		}
	}
	for _, r := range c.Accept {
		if err := r.validate(); err != nil {
			return err
		}
	}
	if c.ProductName == "" {
		c.ProductName = defaultProductName
	}
	if c.Dictionary == nil {
		d, err := NewDictionary()
		if err != nil {
			return err
		}
		c.Dictionary = d
	}
	c.Limits = c.Limits.withDefaults()
	if c.WatchdogInterval == 0 {
		c.WatchdogInterval = DefaultWatchdogInterval
	}
	if c.WatchdogInterval < MinWatchdogInterval {
		return fmt.Errorf("diameter: WatchdogInterval below the RFC 3539 minimum of %s", MinWatchdogInterval)
	}
	setDuration(&c.WriteTimeout, c.WatchdogInterval)
	setDuration(&c.RequestTimeout, DefaultRequestTimeout)
	setDuration(&c.CapabilitiesTimeout, DefaultCapabilitiesTimeout)
	setDuration(&c.ReconnectMin, DefaultReconnectMin)
	setDuration(&c.ReconnectMax, DefaultReconnectMax)
	if c.ReconnectMax < c.ReconnectMin {
		c.ReconnectMax = c.ReconnectMin
	}
	if c.MaxInFlight <= 0 {
		c.MaxInFlight = DefaultMaxInFlight
	}
	if c.MaxPendingConnections <= 0 {
		c.MaxPendingConnections = DefaultMaxPendingConnections
	}
	if c.Clock == nil {
		c.Clock = systemClock{}
	}
	if c.Random == nil {
		c.Random = rand.Uint64
	}
	if c.Dial == nil {
		var d net.Dialer
		c.Dial = d.DialContext
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.OriginStateID == 0 {
		c.OriginStateID = uint32(c.Clock.Now().Unix())
	}
	return nil
}

func setDuration(d *time.Duration, def time.Duration) {
	if *d <= 0 {
		*d = def
	}
}

// Handler answers requests of one application command.
//
// It returns the answer, normally built with [Node.NewAnswer]. Returning an
// [*Error] instead makes the node answer with that result code and Failed-AVP;
// any other error is answered with DIAMETER_UNABLE_TO_COMPLY and logged
// without the message. The node fixes the answer's header (command code,
// application, identifiers) to match the request. ctx ends when the
// connection closes.
type Handler interface {
	ServeDiameter(ctx context.Context, peer *Peer, req *Message) (*Message, error)
}

// HandlerFunc adapts a function to [Handler].
type HandlerFunc func(ctx context.Context, peer *Peer, req *Message) (*Message, error)

// ServeDiameter calls f.
func (f HandlerFunc) ServeDiameter(ctx context.Context, peer *Peer, req *Message) (*Message, error) {
	return f(ctx, peer, req)
}

type handlerKey struct{ app, code uint32 }

// Node is a Diameter node: it accepts and initiates peer connections and
// routes requests to handlers. All methods are safe for concurrent use.
type Node struct {
	cfg      Config
	log      *slog.Logger
	sessions *SessionIDGenerator
	e2e      atomic.Uint32

	ctx    context.Context // ends at Shutdown; stops reconnect loops
	cancel context.CancelFunc
	wg     sync.WaitGroup

	hmu       sync.RWMutex
	handlers  map[handlerKey]Handler
	errorAVPs map[uint32]func(req *Message) []*AVP

	mu        sync.Mutex
	closed    bool
	listeners map[net.Listener]struct{}
	conns     map[*conn]struct{} // every connection, including those still exchanging capabilities
	peers     map[string]*Peer   // open peers by lower-case Origin-Host
	// exchanging counts accepted connections still in the capabilities
	// exchange; limitLogged keeps a flood from logging every refusal.
	exchanging  int
	limitLogged bool
}

// NewNode validates cfg and returns a node. It does nothing on the network
// until [Node.Serve] or [Node.Connect] is called.
func NewNode(cfg Config) (*Node, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	n := &Node{
		cfg:       cfg,
		log:       cfg.Logger.With("diameter_origin_host", cfg.OriginHost),
		sessions:  NewSessionIDGenerator(cfg.OriginHost, cfg.Clock.Now()),
		handlers:  make(map[handlerKey]Handler),
		errorAVPs: make(map[uint32]func(req *Message) []*AVP),
		listeners: make(map[net.Listener]struct{}),
		conns:     make(map[*conn]struct{}),
		peers:     make(map[string]*Peer),
	}
	n.e2e.Store(uint32(cfg.Random()))
	n.ctx, n.cancel = context.WithCancel(context.Background())
	return n, nil
}

// Handle registers h for requests with the application id and command code.
// It panics on a duplicate registration or on a base protocol command, which
// the node answers itself; both are programming errors found at start-up.
func (n *Node) Handle(appID, code uint32, h Handler) {
	if h == nil {
		panic("diameter: nil handler")
	}
	if appID == AppCommon {
		panic("diameter: base protocol commands are handled by the node")
	}
	n.hmu.Lock()
	defer n.hmu.Unlock()
	key := handlerKey{appID, code}
	if _, ok := n.handlers[key]; ok {
		panic(fmt.Sprintf("diameter: duplicate handler for application %d command %d", appID, code))
	}
	n.handlers[key] = h
}

// HandleFunc registers f as with [Node.Handle].
func (n *Node) HandleFunc(appID, code uint32, f func(ctx context.Context, peer *Peer, req *Message) (*Message, error)) {
	n.Handle(appID, code, HandlerFunc(f))
}

// SetErrorAVPs registers f to supply the AVPs an application's answers must
// carry, for the failure answers the node builds itself: decode faults,
// [*Error] values and other errors returned by handlers, and handler panics.
// Cx, for example, requires Vendor-Specific-Application-Id and
// Auth-Session-State in every answer (TS 29.229 §6.1).
//
// f is not used for protocol errors (3xxx): those use the generic
// answer-message format of RFC 6733 §7.2, while 4xxx and 5xxx answers use the
// command's own format (§7.1.4, §7.1.5). f gets the request as far as it was
// decoded and must not panic or block; it runs on the connection's read loop
// for decode faults. Like [Node.Handle], it panics for the base protocol.
func (n *Node) SetErrorAVPs(appID uint32, f func(req *Message) []*AVP) {
	if appID == AppCommon {
		panic("diameter: base protocol answers are built by the node")
	}
	n.hmu.Lock()
	defer n.hmu.Unlock()
	n.errorAVPs[appID] = f
}

func (n *Node) applicationErrorAVPs(req *Message) []*AVP {
	n.hmu.RLock()
	f := n.errorAVPs[req.ApplicationID]
	n.hmu.RUnlock()
	if f == nil {
		return nil
	}
	return f(req)
}

// handler returns the handler for a request and the result code to answer
// with when there is none.
func (n *Node) handler(appID, code uint32) (Handler, uint32) {
	n.hmu.RLock()
	defer n.hmu.RUnlock()
	if h, ok := n.handlers[handlerKey{appID, code}]; ok {
		return h, 0
	}
	for k := range n.handlers {
		if k.app == appID {
			return nil, ResultCommandUnsupported
		}
	}
	return nil, ResultApplicationUnsupported
}

// NewSessionID returns a new Session-Id for this node (RFC 6733 §8.8).
func (n *Node) NewSessionID(optional string) string { return n.sessions.Next(optional) }

// NewRequest builds a request carrying Session-Id (when sessionID is not
// empty), Origin-Host and Origin-Realm, followed by avps. Session-Id comes
// first because the command ABNF fixes its position (RFC 6733 §8.8). The
// identifiers are assigned by [Peer.Send].
func (n *Node) NewRequest(code, appID uint32, sessionID string, avps ...*AVP) *Message {
	m := &Message{Flags: FlagRequest, Code: code, ApplicationID: appID}
	if sessionID != "" {
		m.Add(NewAVP(AVPSessionID, FlagMandatory, 0, []byte(sessionID)))
	}
	m.Add(n.originAVPs()...)
	m.Add(avps...)
	return m
}

func (n *Node) originAVPs() []*AVP {
	return []*AVP{
		NewAVP(AVPOriginHost, FlagMandatory, 0, []byte(n.cfg.OriginHost)),
		NewAVP(AVPOriginRealm, FlagMandatory, 0, []byte(n.cfg.OriginRealm)),
	}
}

// NewAnswer builds the answer to req with a Result-Code. It copies Session-Id
// and the P bit, sets Origin-Host and Origin-Realm, sets the E bit for a
// protocol error result (RFC 6733 §7.2), and copies Proxy-Info AVPs in order
// at the end (§6.2).
func (n *Node) NewAnswer(req *Message, resultCode uint32, avps ...*AVP) *Message {
	a := n.answerHeader(req)
	if IsProtocolError(resultCode) {
		a.Flags |= FlagError
	}
	a.Add(NewAVP(AVPResultCode, FlagMandatory, 0, Unsigned32(resultCode)))
	a.Add(n.originAVPs()...)
	a.Add(avps...)
	a.Add(req.FindAll(AVPProxyInfo, 0)...)
	return a
}

// NewExperimentalAnswer builds the answer to req with an Experimental-Result
// instead of a Result-Code, as vendor applications such as Cx do for their own
// result codes (RFC 6733 §7.6, TS 29.229 §6.2). It is otherwise like
// [Node.NewAnswer]; an experimental result is never a protocol error.
func (n *Node) NewExperimentalAnswer(req *Message, vendorID, code uint32, avps ...*AVP) *Message {
	a := n.answerHeader(req)
	a.Add(NewGrouped(AVPExperimentalResult, FlagMandatory, 0,
		NewAVP(AVPVendorID, FlagMandatory, 0, Unsigned32(vendorID)),
		NewAVP(AVPExperimentalResultCode, FlagMandatory, 0, Unsigned32(code)),
	))
	a.Add(n.originAVPs()...)
	a.Add(avps...)
	a.Add(req.FindAll(AVPProxyInfo, 0)...)
	return a
}

func (n *Node) answerHeader(req *Message) *Message {
	a := &Message{
		Flags:         req.Flags & FlagProxiable,
		Code:          req.Code,
		ApplicationID: req.ApplicationID,
		HopByHop:      req.HopByHop,
		EndToEnd:      req.EndToEnd,
	}
	if sid := req.Find(AVPSessionID, 0); sid != nil {
		a.Add(sid)
	}
	return a
}

// errorAnswer answers req with e (RFC 6733 §7.2): the application's required
// AVPs (see [Node.SetErrorAVPs]), Error-Message and Failed-AVP follow the
// result.
func (n *Node) errorAnswer(req *Message, e *Error) *Message {
	var extra []*AVP
	if req.ApplicationID != AppCommon && !IsProtocolError(e.ResultCode) {
		extra = append(extra, n.applicationErrorAVPs(req)...)
	}
	if e.Message != "" {
		extra = append(extra, NewAVP(AVPErrorMessage, 0, 0, []byte(e.Message)))
	}
	if e.FailedAVP != nil {
		extra = append(extra, NewGrouped(AVPFailedAVP, FlagMandatory, 0, e.FailedAVP))
	}
	return n.NewAnswer(req, e.ResultCode, extra...)
}

// nextEndToEnd returns an End-to-End Identifier: the low 12 bits of the
// current time in the high bits and a counter from a random start in the
// rest, so identifiers stay unique across a restart (RFC 6733 §3).
func (n *Node) nextEndToEnd() uint32 {
	low := n.e2e.Add(1) & 0xfffff
	return uint32(n.cfg.Clock.Now().Unix()&0xfff)<<20 | low
}

// Peer returns the open peer with the Origin-Host, or nil.
func (n *Node) Peer(host string) *Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.peers[strings.ToLower(host)]
}

// Peers returns every peer with an open connection, for example to pick one
// by realm (ADR 0005: HSS-initiated requests go to any connected `scscf`).
func (n *Node) Peers() []*Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		out = append(out, p)
	}
	return out
}

// Serve accepts connections on l and runs the responder side of the
// capabilities exchange for each. It returns [ErrNodeClosed] after
// [Node.Shutdown], or the first Accept error.
func (n *Node) Serve(l net.Listener) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrNodeClosed
	}
	n.listeners[l] = struct{}{}
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.listeners, l)
		n.mu.Unlock()
	}()
	for {
		nc, err := l.Accept()
		if err != nil {
			if n.isClosed() {
				return ErrNodeClosed
			}
			return err
		}
		// Adding to the wait group under the lock that Shutdown takes before
		// waiting guarantees the Add happens before the Wait.
		n.mu.Lock()
		if n.closed {
			n.mu.Unlock()
			_ = nc.Close()
			return ErrNodeClosed
		}
		if n.exchanging >= n.cfg.MaxPendingConnections {
			first := !n.limitLogged
			n.limitLogged = true
			n.mu.Unlock()
			_ = nc.Close()
			if first {
				n.log.Warn("diameter connections refused: too many have not completed CER",
					"limit", n.cfg.MaxPendingConnections, "remote", nc.RemoteAddr().String())
			}
			continue
		}
		n.exchanging++
		n.wg.Add(1)
		n.mu.Unlock()
		go func() {
			defer n.wg.Done()
			n.accept(nc)
		}()
	}
}

// exchangeDone releases a connection's place among those still exchanging
// capabilities.
func (n *Node) exchangeDone() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.exchanging--
	if n.exchanging < n.cfg.MaxPendingConnections {
		n.limitLogged = false
	}
}

func (n *Node) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

// PeerConfig describes a peer this node connects to.
type PeerConfig struct {
	// Address is the TCP address to dial, e.g. "hss.rcs.local:3868".
	Address string
	// Host and Realm, when set, must match the Origin-Host and Origin-Realm
	// in the peer's CEA.
	Host  string
	Realm string
}

// Connect starts maintaining a connection to the peer: dial, capabilities
// exchange, and reconnection with exponential backoff whenever the
// connection fails. The returned peer is unavailable until the first
// exchange succeeds. After a connection fails (watchdog expiry or transport
// error, not a DPR), a reconnection to the same Origin-Host is unavailable
// until the RFC 3539 §3.4.1 REOPEN state has seen three watchdog answers.
func (n *Node) Connect(pc PeerConfig) (*Peer, error) {
	if pc.Address == "" {
		return nil, errors.New("diameter: peer address is required")
	}
	p := &Peer{cfg: &pc, host: pc.Host, realm: pc.Realm}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrNodeClosed
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.maintain(p)
	}()
	return p, nil
}

// maintain is the initiator loop of one peer.
//
// failedHost is the Origin-Host of the last connection if it ended in a
// failure (watchdog expiry or a transport error) rather than a DPR exchange.
// Only a reconnection to that same node starts in REOPEN: RFC 3539 §3.4.1
// uses REOPEN to stop traffic flapping back to a node that has just failed.
// A node that left cleanly (an hss task replaced in a rolling update, ADR
// 0003) or a different node behind the same address has not failed, and
// with a single connection per peer there is no alternate to carry the
// traffic meanwhile, so those reconnections are usable at once.
func (n *Node) maintain(p *Peer) {
	attempt := 0
	failedHost := ""
	for {
		c, err := n.initiate(p, failedHost)
		var delay time.Duration
		if err != nil {
			n.log.Warn("diameter peer connection failed", "address", p.cfg.Address, "error", err)
			delay = n.backoff(attempt)
			attempt++
		} else {
			attempt = 0
			select {
			case <-c.done:
			case <-n.ctx.Done():
				return
			}
			delay = n.backoff(0)
			cause, clean := c.remoteDisconnectCause()
			failedHost = c.caps.host
			if clean {
				failedHost = ""
				if cause != DisconnectRebooting {
					// A peer that is busy or does not want this connection
					// is left alone for the longest interval before the
					// next try (RFC 6733 §5.4.3).
					delay = n.cfg.ReconnectMax
				}
			}
		}
		if !n.sleep(delay) {
			return
		}
	}
}

// backoff is the delay before reconnection attempt number attempt:
// exponential from ReconnectMin to ReconnectMax, then randomised into its
// upper half so that many instances restarted together do not reconnect in
// lockstep.
func (n *Node) backoff(attempt int) time.Duration {
	d := n.cfg.ReconnectMin
	for i := 0; i < attempt && d < n.cfg.ReconnectMax; i++ {
		d *= 2
	}
	d = min(d, n.cfg.ReconnectMax)
	half := d / 2
	return half + time.Duration(n.cfg.Random()%uint64(half+1))
}

// sleep waits on the node clock and reports false if the node shut down.
func (n *Node) sleep(d time.Duration) bool {
	wake := make(chan struct{})
	t := n.cfg.Clock.AfterFunc(d, func() { close(wake) })
	defer t.Stop()
	select {
	case <-wake:
		return true
	case <-n.ctx.Done():
		return false
	}
}

// watchdogInterval is Tw: Twinit jittered by up to ±2 s (RFC 3539 §3.4.1).
func (n *Node) watchdogInterval() time.Duration {
	jitter := int64(n.cfg.Random()%(2*watchdogJitterMilliseconds+1)) - watchdogJitterMilliseconds
	return n.cfg.WatchdogInterval + time.Duration(jitter)*time.Millisecond
}

// register records a connection that may need closing at shutdown.
func (n *Node) register(c *conn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.conns[c] = struct{}{}
	return true
}

// open makes c the connection of peer p, unless another open connection
// already serves the same Origin-Host: RFC 6733 §5.6.4 allows one connection
// per peer identity.
func (n *Node) open(c *conn, p *Peer) bool {
	key := strings.ToLower(c.caps.host)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	if _, dup := n.peers[key]; dup {
		return false
	}
	n.peers[key] = p
	p.attach(c)
	return true
}

// forget removes a closed connection from the node's tables.
func (n *Node) forget(c *conn, p *Peer, host string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.conns, c)
	if p != nil {
		key := strings.ToLower(host)
		if n.peers[key] == p && p.current() == c {
			delete(n.peers, key)
		}
		p.detach(c)
	}
}

// Shutdown stops accepting and reconnecting, and on every open connection
// refuses new requests (DIAMETER_UNABLE_TO_DELIVER), lets running handlers
// send their answers, sends DPR (REBOOTING) and waits for the DPA (at most
// RequestTimeout) before closing. When ctx ends first, every connection
// is closed at once and Shutdown returns ctx's error without waiting for
// handlers that ignore their context.
func (n *Node) Shutdown(ctx context.Context) error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrNodeClosed
	}
	n.closed = true
	for l := range n.listeners {
		_ = l.Close()
	}
	conns := make([]*conn, 0, len(n.conns))
	for c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	n.cancel()

	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.disconnect(ctx, DisconnectRebooting)
		}()
	}
	wg.Wait()

	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, c := range conns {
			c.close(ErrNodeClosed)
		}
		return ctx.Err()
	}
}
