package cxclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
)

// Defaults for the zero fields of Config.
const (
	DefaultPort = 3868
	// DefaultResolveInterval is how often the HSS name is resolved again. A
	// task that starts is reached within it; one that stops is already
	// unavailable through its watchdog, so this bounds only how long a
	// connection to a vanished address is retried.
	DefaultResolveInterval = 15 * time.Second
	// DefaultRequestTimeout bounds one attempt. Two attempts fit well inside
	// the 32 s a SIP transaction waits (Timer B and F), and the HSS bounds its
	// own work per request at 3 s.
	DefaultRequestTimeout = 5 * time.Second
	// DefaultMaxPeers bounds the HSS tasks connected at once, so a DNS
	// answer, however large, cannot make the client open connections without
	// limit.
	DefaultMaxPeers = 32
)

// Resolver resolves the HSS service name; *net.Resolver has it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Metrics is what the client records; *runtime.Metrics has it. No name carries
// an identity.
//
//	cxclient.peers                 available HSS peers, sampled at every resolve
//	                               (a gauge: read Average or Minimum, not Sum)
//	cxclient.peer.added, .removed  HSS tasks that appeared in or left DNS
//	cxclient.resolve.error         failed resolutions; the peers are kept
//	cxclient.<CMD>.<result>        answers by command and result code, or
//	                               error.<kind> when there was none
//	cxclient.<CMD>.latency         time from the first attempt to the outcome
//	cxclient.<CMD>.retry           second attempts on another peer
//	cxclient.RTR.<result>, cxclient.PPR.<result>  answers sent to the HSS
type Metrics interface {
	Count(name string, n int64)
	Timing(name string, d time.Duration)
}

// Config configures a Client.
type Config struct {
	// OriginHost is this instance's own Diameter identity (ADR 0005), from
	// OriginHostFor; OriginRealm is the realm of the IMS core.
	OriginHost  string
	OriginRealm string
	// DestinationRealm is the HSS's realm: every request is routed by it (TS
	// 29.229 §5.5), and a connection to a node of another realm is refused.
	DestinationRealm string
	// ServerName is the S-CSCF name, shared by every scscf instance (ADR
	// 0005), sent in MAR and SAR unless the request names one. Empty for
	// icscf.
	ServerName string

	// HSS is the name every HSS task is registered under in Cloud Map,
	// hss.<namespace>, and Port the Diameter port of the tasks.
	HSS  string
	Port int
	// Resolver resolves HSS; nil is net.DefaultResolver.
	Resolver        Resolver
	ResolveInterval time.Duration
	// MaxPeers bounds the HSS tasks connected at once.
	MaxPeers int
	// RequestTimeout bounds each attempt of a request.
	RequestTimeout time.Duration

	// Node configures the Diameter node of each connection: watchdog,
	// timeouts, HostIPAddresses, and the Clock, Random and Dial that tests
	// inject. Identity, applications, dictionary and the accept rules are the
	// client's own; the client never accepts connections.
	Node diameter.Config

	// OnRTR and OnPPR handle the requests the HSS sends (TS 29.228 §6.1.3
	// deregistration, §6.2.2 profile push): the result they return is the
	// answer's. Nil answers DIAMETER_UNABLE_TO_COMPLY, which an icscf, which
	// never serves a user, should do. They run on a goroutine per request and
	// may block until ctx ends.
	OnRTR func(ctx context.Context, r *cx.RTR) cx.Result
	OnPPR func(ctx context.Context, r *cx.PPR) cx.Result

	Metrics Metrics
	// Logger receives peer events: addresses and Diameter identities of HSS
	// tasks, never a request's content or Session-Id. Nil discards them.
	Logger *slog.Logger
}

// OriginHostFor is the Diameter identity of one instance of a service under
// ADR 0005: <service>-<task id>.<namespace>, such as scscf-1a2b3c.rcs.local.
func OriginHostFor(service, taskID, namespace string) (string, error) {
	host := service + "-" + taskID + "." + namespace
	if service == "" || taskID == "" || !identity.IsDomainName(host) {
		return "", fmt.Errorf("cxclient: %q is not a valid Origin-Host", host)
	}
	return host, nil
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("cxclient: closed")

// Client keeps a Cx connection to every HSS task and sends requests over
// them. Its methods are safe for concurrent use.
type Client struct {
	cfg      Config
	sessions *diameter.SessionIDGenerator
	dict     *diameter.Dictionary
	log      *slog.Logger
	metrics  Metrics
	clock    diameter.Clock

	mu     sync.Mutex
	peers  map[netip.Addr]*hssPeer
	closed bool

	next     atomic.Uint64
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// hssPeer is one HSS task. Each has a node of its own because a node keeps
// reconnecting to every peer it was given and has no way to drop one: a task
// that left DNS is dropped by shutting its node down. All nodes share the
// instance's Origin-Host and the client's Session-Id generator.
type hssPeer struct {
	addr netip.Addr
	node *diameter.Node
	peer *diameter.Peer
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) diameter.Timer { return time.AfterFunc(d, f) }

type discardMetrics struct{}

func (discardMetrics) Count(string, int64)          {}
func (discardMetrics) Timing(string, time.Duration) {}

// New returns a client and starts resolving the HSS name, at once and then
// every ResolveInterval; requests fail with ErrNoPeer until a task is
// connected.
func New(cfg Config) (*Client, error) {
	if cfg.HSS == "" || !identity.IsDomainName(cfg.HSS) {
		return nil, errors.New("cxclient: HSS must be a domain name")
	}
	if cfg.DestinationRealm == "" {
		return nil, errors.New("cxclient: DestinationRealm is required")
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.ResolveInterval <= 0 {
		cfg.ResolveInterval = DefaultResolveInterval
	}
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = DefaultMaxPeers
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = discardMetrics{}
	}
	clock := cfg.Node.Clock
	if clock == nil {
		clock = systemClock{}
	}
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		return nil, err
	}
	n := cfg.Node
	n.OriginHost, n.OriginRealm = cfg.OriginHost, cfg.OriginRealm
	n.Applications = []diameter.Application{cx.Application}
	n.SupportedVendorIDs = []uint32{cx.Vendor3GPP, cx.VendorETSI}
	n.Dictionary = dict
	n.Accept = nil
	if n.RequestTimeout == 0 {
		n.RequestTimeout = cfg.RequestTimeout
	}
	if n.OriginStateID == 0 {
		// One value for every node: it says when this instance started (RFC
		// 6733 §8.16), not when a connection did.
		n.OriginStateID = uint32(clock.Now().Unix())
	}
	if n.Logger == nil {
		n.Logger = cfg.Logger
	}
	// Validate the identity once, here, rather than at the first DNS answer.
	probe, err := diameter.NewNode(n)
	if err != nil {
		return nil, err
	}
	_ = probe.Shutdown(context.Background())
	cfg.Node = n
	c := &Client{
		cfg:      cfg,
		sessions: diameter.NewSessionIDGenerator(cfg.OriginHost, clock.Now()),
		dict:     dict,
		log:      cfg.Logger,
		metrics:  cfg.Metrics,
		clock:    clock,
		peers:    map[netip.Addr]*hssPeer{},
		stop:     make(chan struct{}),
	}
	c.wg.Add(1)
	go c.resolveLoop()
	return c, nil
}

func (c *Client) resolveLoop() {
	defer c.wg.Done()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.ResolveInterval)
		// A failure is logged and counted by Refresh; the peers stay.
		_ = c.Refresh(ctx)
		cancel()
		wake := make(chan struct{})
		t := c.clock.AfterFunc(c.cfg.ResolveInterval, func() { close(wake) })
		select {
		case <-wake:
		case <-c.stop:
			t.Stop()
			return
		}
	}
}

// Refresh resolves the HSS name now and makes the peers follow the answer:
// a connection to every new address, and none to an address that has gone.
// A failed resolution leaves the peers as they are, since an HSS task does not
// stop because DNS does, and so does an empty answer.
func (c *Client) Refresh(ctx context.Context) error {
	addrs, err := c.cfg.Resolver.LookupNetIP(ctx, "ip", c.cfg.HSS)
	if err != nil {
		c.metrics.Count("cxclient.resolve.error", 1)
		c.log.Warn("cxclient: resolving the HSS failed; keeping the peers", slog.String("name", c.cfg.HSS))
		return fmt.Errorf("cxclient: resolving %s: %w", c.cfg.HSS, err)
	}
	want := map[netip.Addr]bool{}
	for _, a := range addrs {
		want[a.Unmap()] = true
	}
	if len(want) == 0 {
		c.metrics.Count("cxclient.resolve.error", 1)
		return fmt.Errorf("cxclient: %s has no address", c.cfg.HSS)
	}
	sorted := slices.SortedFunc(func(yield func(netip.Addr) bool) {
		for a := range want {
			if !yield(a) {
				return
			}
		}
	}, func(a, b netip.Addr) int { return a.Compare(b) })
	if len(sorted) > c.cfg.MaxPeers {
		c.log.Warn("cxclient: more HSS addresses than MaxPeers; ignoring the rest", slog.Int("addresses", len(sorted)))
		sorted = sorted[:c.cfg.MaxPeers]
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	var gone []*hssPeer
	keep := map[netip.Addr]bool{}
	for _, a := range sorted {
		keep[a] = true
	}
	for a, p := range c.peers {
		if !keep[a] {
			gone = append(gone, p)
			delete(c.peers, a)
		}
	}
	var errs error
	for _, a := range sorted {
		if _, ok := c.peers[a]; ok {
			continue
		}
		p, err := c.connect(a)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		c.peers[a] = p
		c.metrics.Count("cxclient.peer.added", 1)
		c.log.Info("cxclient: HSS task added", slog.String("address", a.String()))
	}
	c.mu.Unlock()

	for _, p := range gone {
		c.metrics.Count("cxclient.peer.removed", 1)
		c.log.Info("cxclient: HSS task removed", slog.String("address", p.addr.String()))
		c.shutdown(p)
	}
	c.metrics.Count("cxclient.peers", int64(len(c.available())))
	return errs
}

// connect starts a node for one HSS task. c.mu must be held.
func (c *Client) connect(a netip.Addr) (*hssPeer, error) {
	n, err := diameter.NewNode(c.cfg.Node)
	if err != nil {
		return nil, err
	}
	n.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	n.HandleFunc(cx.ApplicationID, cx.CodeRegistrationTermination, func(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		return c.serveRTR(ctx, n, req)
	})
	n.HandleFunc(cx.ApplicationID, cx.CodePushProfile, func(ctx context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		return c.servePPR(ctx, n, req)
	})
	peer, err := n.Connect(diameter.PeerConfig{
		Address: netip.AddrPortFrom(a, uint16(c.cfg.Port)).String(),
		Realm:   c.cfg.DestinationRealm,
	})
	if err != nil {
		return nil, err
	}
	return &hssPeer{addr: a, node: n, peer: peer}, nil
}

// shutdown stops a node in the background: its DPR exchange waits for the
// requests in flight, which must not hold up Refresh.
func (c *Client) shutdown(p *hssPeer) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		defer cancel()
		_ = p.node.Shutdown(ctx)
	}()
}

// available returns the peers that can take a request, in address order.
func (c *Client) available() []*hssPeer {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*hssPeer
	for _, p := range c.peers {
		if p.peer.Available() {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *hssPeer) int { return a.addr.Compare(b.addr) })
	return out
}

// pick chooses the next available peer other than not, in turn, so the load
// spreads over the tasks.
func (c *Client) pick(not *hssPeer) *hssPeer {
	ps := slices.DeleteFunc(c.available(), func(p *hssPeer) bool { return p == not })
	if len(ps) == 0 {
		return nil
	}
	return ps[c.next.Add(1)%uint64(len(ps))]
}

// PeerStatus describes one HSS task.
type PeerStatus struct {
	Address   netip.Addr
	Host      string // its Origin-Host once connected
	Available bool
}

// Peers lists the HSS tasks the client keeps a connection to.
func (c *Client) Peers() []PeerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []PeerStatus
	for a, p := range c.peers {
		out = append(out, PeerStatus{Address: a, Host: p.peer.Host(), Available: p.peer.Available()})
	}
	slices.SortFunc(out, func(a, b PeerStatus) int { return a.Address.Compare(b.Address) })
	return out
}

// Close stops resolving and disconnects from every HSS task (DPR), waiting at
// most until ctx ends.
func (c *Client) Close(ctx context.Context) error {
	c.stopOnce.Do(func() { close(c.stop) })
	c.mu.Lock()
	c.closed = true
	peers := c.peers
	c.peers = map[netip.Addr]*hssPeer{}
	c.mu.Unlock()
	var errs error
	for _, p := range peers {
		if err := p.node.Shutdown(ctx); err != nil && !errors.Is(err, diameter.ErrNodeClosed) {
			errs = errors.Join(errs, err)
		}
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		errs = errors.Join(errs, ctx.Err())
	}
	return errs
}

// serveRTR answers a Registration-Termination-Request (TS 29.228 §6.1.3) with
// the result of OnRTR.
func (c *Client) serveRTR(ctx context.Context, n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	r, err := cx.ParseRTR(req)
	if err != nil {
		return nil, err
	}
	res := cx.ResultCode(diameter.ResultUnableToComply)
	if c.cfg.OnRTR != nil {
		res = c.cfg.OnRTR(ctx, r)
	}
	c.metrics.Count("cxclient.RTR."+resultName(res), 1)
	return (&cx.RTA{Answer: cx.Answer{Result: res}}).Message(n, req)
}

// servePPR answers a Push-Profile-Request (TS 29.228 §6.2.2) with the result
// of OnPPR.
func (c *Client) servePPR(ctx context.Context, n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	r, err := cx.ParsePPR(req)
	if err != nil {
		return nil, err
	}
	res := cx.ResultCode(diameter.ResultUnableToComply)
	if c.cfg.OnPPR != nil {
		res = c.cfg.OnPPR(ctx, r)
	}
	c.metrics.Count("cxclient.PPR."+resultName(res), 1)
	return (&cx.PPA{Answer: cx.Answer{Result: res}}).Message(n, req)
}

// resultName is how a result appears in a metric name: the code, prefixed
// with exp. for a 3GPP experimental one.
func resultName(r cx.Result) string {
	s := strconv.FormatUint(uint64(r.Code), 10)
	if r.Vendor != 0 {
		return "exp." + s
	}
	return s
}
