package cxclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
	// DefaultMaxPeers bounds the HSS tasks connected at once, so a discovery
	// answer, however large, cannot make the client open connections without
	// limit.
	DefaultMaxPeers = 32
	// DefaultTimeoutExclusion is how long a task whose attempt timed out gets
	// no first attempts. A task that stops answering without closing its
	// connection stays OKAY for up to two watchdog intervals (RFC 3539
	// §3.4.1), a minute by default; without this, every request it got first
	// in that time would wait out RequestTimeout before its retry.
	DefaultTimeoutExclusion = 30 * time.Second
	// absencesBeforeRemoval is how many discovery answers in a row must leave
	// a task out, its connection down as well, before the client drops it. A
	// DNS answer names only some of the tasks when there are many (see
	// DNSDiscovery), and a task that answers is never dropped.
	absencesBeforeRemoval = 3
)

// Metrics is what the client records; *runtime.Metrics has it. No name carries
// an identity.
//
//	cxclient.peers                 gauge: available HSS peers, at every
//	                               discovery
//	cxclient.peers.known           gauge: HSS tasks the client keeps a
//	                               connection to; below the HSS task count
//	                               means RTR and PPR can be lost
//	cxclient.peer.added, .removed  HSS tasks connected and dropped
//	cxclient.resolve.error         failed discoveries; the peers are kept
//	cxclient.peer.excluded         tasks excluded after an attempt timed out
//	cxclient.RTR.refused, .PPR.refused  requests from a peer whose Origin-Host
//	                               does not match HSSHostPattern
//	cxclient.<CMD>.<result>        answers by command and result code, or
//	                               error.<kind> when there was none
//	cxclient.<CMD>.latency         time from the first attempt to the outcome
//	cxclient.<CMD>.retry           second attempts on another peer
//	cxclient.RTR.<result>, cxclient.PPR.<result>  answers sent to the HSS
type Metrics interface {
	Count(name string, n int64)
	Gauge(name string, v int64)
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

	// Discovery finds the HSS tasks: CloudMapDiscovery on AWS, which lists
	// every task. Nil resolves HSS, the name the tasks are registered under,
	// hss.<namespace>, with Resolver (net.DefaultResolver when nil), which
	// suits the compose stack. Port is the Diameter port of the tasks.
	Discovery Discovery
	HSS       string
	Resolver  Resolver
	Port      int
	// ResolveInterval is how often the tasks are discovered again.
	ResolveInterval time.Duration
	// MaxPeers bounds the HSS tasks connected at once.
	MaxPeers int
	// HSSHostPattern, if set, is the Origin-Host every HSS task must have,
	// such as hss-*.rcs.local ('*' matches within one label). A peer that
	// claims another gets no requests, and its RTR and PPR are refused: the
	// HSS can deregister any user and change any profile, so the connection
	// that carries them should be to an HSS (threat model T1).
	HSSHostPattern string
	// RequestTimeout bounds each attempt of a request, and TimeoutExclusion
	// how long a task whose attempt timed out gets no first attempts.
	RequestTimeout   time.Duration
	TimeoutExclusion time.Duration

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

	discovery Discovery

	mu     sync.Mutex
	peers  map[netip.Addr]*hssPeer
	closed bool

	next atomic.Uint64
	// ctx ends with Close, and with it a discovery in progress.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// shuttingDown counts node shutdowns in progress, for tests.
	shuttingDown atomic.Int32
}

// hssPeer is one HSS task. Each has a node of its own because a node keeps
// reconnecting to every peer it was given and has no way to drop one: a task
// that left DNS is dropped by shutting its node down. All nodes share the
// instance's Origin-Host and the client's Session-Id generator.
type hssPeer struct {
	addr netip.Addr
	node *diameter.Node
	peer *diameter.Peer

	// Guarded by Client.mu.
	absences      int
	excludedUntil time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) diameter.Timer { return time.AfterFunc(d, f) }

type discardMetrics struct{}

func (discardMetrics) Count(string, int64)          {}
func (discardMetrics) Gauge(string, int64)          {}
func (discardMetrics) Timing(string, time.Duration) {}

// New returns a client and starts resolving the HSS name, at once and then
// every ResolveInterval; requests fail with ErrNoPeer until a task is
// connected.
func New(cfg Config) (*Client, error) {
	if cfg.Discovery == nil {
		if cfg.HSS == "" || !identity.IsDomainName(cfg.HSS) {
			return nil, errors.New("cxclient: HSS must be a domain name")
		}
		cfg.Discovery = DNSDiscovery{Resolver: cfg.Resolver, Name: cfg.HSS}
	}
	if cfg.HSSHostPattern != "" && !identity.IsDomainName(strings.ReplaceAll(cfg.HSSHostPattern, "*", "x")) {
		return nil, errors.New("cxclient: HSSHostPattern must be a domain name with '*' in its labels")
	}
	if cfg.DestinationRealm == "" {
		return nil, errors.New("cxclient: DestinationRealm is required")
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
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
	if cfg.TimeoutExclusion <= 0 {
		cfg.TimeoutExclusion = DefaultTimeoutExclusion
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
		cfg:       cfg,
		sessions:  diameter.NewSessionIDGenerator(cfg.OriginHost, clock.Now()),
		dict:      dict,
		log:       cfg.Logger,
		metrics:   cfg.Metrics,
		clock:     clock,
		discovery: cfg.Discovery,
		peers:     map[netip.Addr]*hssPeer{},
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.wg.Add(1)
	go c.resolveLoop()
	return c, nil
}

func (c *Client) resolveLoop() {
	defer c.wg.Done()
	for {
		ctx, cancel := context.WithTimeout(c.ctx, c.cfg.ResolveInterval)
		// A failure is logged and counted by Refresh; the peers stay.
		_ = c.Refresh(ctx)
		cancel()
		wake := make(chan struct{})
		t := c.clock.AfterFunc(c.cfg.ResolveInterval, func() { close(wake) })
		select {
		case <-wake:
		case <-c.ctx.Done():
			t.Stop()
			return
		}
	}
}

// Refresh discovers the HSS tasks now and makes the peers follow: a
// connection to every new address, up to MaxPeers. A task stays as long as its
// connection does; one left out of absencesBeforeRemoval answers in a row
// whose connection is down too is dropped. A failed or empty answer leaves the
// peers as they are, since an HSS task does not stop because discovery does.
func (c *Client) Refresh(ctx context.Context) error {
	addrs, err := c.discovery.HSSAddresses(ctx)
	if err != nil {
		c.metrics.Count("cxclient.resolve.error", 1)
		c.log.Warn("cxclient: discovering the HSS failed; keeping the peers")
		return fmt.Errorf("cxclient: discovering the HSS: %w", err)
	}
	want := map[netip.Addr]bool{}
	for _, a := range addrs {
		want[a.Unmap()] = true
	}
	if len(want) == 0 {
		c.metrics.Count("cxclient.resolve.error", 1)
		return errors.New("cxclient: discovery found no HSS address")
	}
	sorted := slices.SortedFunc(maps.Keys(want), func(a, b netip.Addr) int { return a.Compare(b) })

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClosed
	}
	var gone []*hssPeer
	for a, p := range c.peers {
		if want[a] {
			p.absences = 0
			continue
		}
		p.absences++
		if p.absences >= absencesBeforeRemoval && !p.peer.Available() {
			gone = append(gone, p)
			delete(c.peers, a)
		}
	}
	var errs error
	ignored := 0
	for _, a := range sorted {
		if _, ok := c.peers[a]; ok {
			continue
		}
		if len(c.peers) >= c.cfg.MaxPeers {
			ignored++
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
	known := len(c.peers)
	// Counted while closed is false under mu, so Close waits for them.
	c.wg.Add(len(gone))
	c.mu.Unlock()

	if ignored > 0 {
		c.log.Warn("cxclient: more HSS tasks than MaxPeers; ignoring the rest", slog.Int("ignored", ignored))
	}
	for _, p := range gone {
		c.metrics.Count("cxclient.peer.removed", 1)
		c.log.Info("cxclient: HSS task removed", slog.String("address", p.addr.String()))
		c.shutdown(p)
	}
	c.metrics.Gauge("cxclient.peers", int64(len(c.usable(nil))))
	c.metrics.Gauge("cxclient.peers.known", int64(known))
	return errs
}

// connect starts a node for one HSS task. c.mu must be held.
func (c *Client) connect(a netip.Addr) (*hssPeer, error) {
	n, err := diameter.NewNode(c.cfg.Node)
	if err != nil {
		return nil, err
	}
	n.SetErrorAVPs(cx.ApplicationID, cx.ErrorAVPs)
	n.HandleFunc(cx.ApplicationID, cx.CodeRegistrationTermination, func(ctx context.Context, from *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		return c.serveRTR(ctx, n, from, req)
	})
	n.HandleFunc(cx.ApplicationID, cx.CodePushProfile, func(ctx context.Context, from *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		return c.servePPR(ctx, n, from, req)
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
// requests in flight, which must not hold up Refresh. The caller has counted
// it in c.wg.
func (c *Client) shutdown(p *hssPeer) {
	c.shuttingDown.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.shuttingDown.Add(-1)
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.RequestTimeout)
		defer cancel()
		_ = p.node.Shutdown(ctx)
	}()
}

// usable returns the peers that can take a first attempt now, in address
// order: available (RFC 3539 OKAY), with the expected Origin-Host, and not
// excluded after a timeout. With every available peer excluded, they are
// usable all the same: a slow answer beats none.
func (c *Client) usable(not *hssPeer) []*hssPeer {
	now := c.clock.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var ok, excluded []*hssPeer
	for _, p := range c.peers {
		if p == not || !p.peer.Available() || !c.hostOK(p.peer.Host()) {
			continue
		}
		if now.Before(p.excludedUntil) {
			excluded = append(excluded, p)
			continue
		}
		ok = append(ok, p)
	}
	if len(ok) == 0 {
		ok = excluded
	}
	slices.SortFunc(ok, func(a, b *hssPeer) int { return a.addr.Compare(b.addr) })
	return ok
}

// pick chooses the peer for a first attempt, the next in turn so the load
// spreads over the tasks.
func (c *Client) pick() *hssPeer {
	ps := c.usable(nil)
	if len(ps) == 0 {
		return nil
	}
	return ps[c.next.Add(1)%uint64(len(ps))]
}

// pickAfter chooses the peer for the retry of an attempt on failed: the next
// in address order after it. It leaves the turn alone, so a task that fails
// does not also shift the next first attempt back to itself.
func (c *Client) pickAfter(failed *hssPeer) *hssPeer {
	ps := c.usable(failed)
	if len(ps) == 0 {
		return nil
	}
	for _, p := range ps {
		if p.addr.Compare(failed.addr) > 0 {
			return p
		}
	}
	return ps[0]
}

// exclude keeps p from first attempts for TimeoutExclusion.
func (c *Client) exclude(p *hssPeer) {
	c.mu.Lock()
	p.excludedUntil = c.clock.Now().Add(c.cfg.TimeoutExclusion)
	c.mu.Unlock()
	c.metrics.Count("cxclient.peer.excluded", 1)
}

// hostOK reports whether host matches HSSHostPattern, if one is set.
func (c *Client) hostOK(host string) bool {
	return c.cfg.HSSHostPattern == "" || matchHost(c.cfg.HSSHostPattern, host)
}

// matchHost matches a host against a pattern label by label, without regard
// to case; '*' in a label matches any run of characters within that label.
func matchHost(pattern, host string) bool {
	pl, hl := strings.Split(strings.ToLower(pattern), "."), strings.Split(strings.ToLower(host), ".")
	if len(pl) != len(hl) {
		return false
	}
	for i, p := range pl {
		prefix, suffix, wild := strings.Cut(p, "*")
		if !wild {
			if p != hl[i] {
				return false
			}
			continue
		}
		if strings.Contains(suffix, "*") || len(hl[i]) < len(prefix)+len(suffix) ||
			!strings.HasPrefix(hl[i], prefix) || !strings.HasSuffix(hl[i], suffix) {
			return false
		}
	}
	return true
}

// Ready reports whether a request can be sent now: some HSS task is connected
// and available. It is the client's part of /readyz, and only of readiness:
// never wire it into /healthz, whose failure restarts the task, since an HSS
// that is down or restarting would then take every CSCF task down with it.
func (c *Client) Ready() error {
	if len(c.usable(nil)) == 0 {
		return ErrNoPeer
	}
	return nil
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

// Close stops discovering, ending a discovery in progress, and disconnects
// from every HSS task (DPR) at once, waiting at most until ctx ends.
func (c *Client) Close(ctx context.Context) error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	peers := c.peers
	c.peers = map[netip.Addr]*hssPeer{}
	c.mu.Unlock()
	var mu sync.Mutex
	var errs error
	var all sync.WaitGroup
	for _, p := range peers {
		all.Add(1)
		go func() {
			defer all.Done()
			if err := p.node.Shutdown(ctx); err != nil && !errors.Is(err, diameter.ErrNodeClosed) {
				mu.Lock()
				errs = errors.Join(errs, err)
				mu.Unlock()
			}
		}()
	}
	all.Wait()
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
func (c *Client) serveRTR(ctx context.Context, n *diameter.Node, from *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	r, err := cx.ParseRTR(req)
	if err != nil {
		return nil, err
	}
	res := cx.ResultCode(diameter.ResultUnableToComply)
	switch {
	case !c.hostOK(from.Host()):
		c.metrics.Count("cxclient.RTR.refused", 1)
		c.log.Warn("cxclient: RTR from a peer that is not an HSS", slog.String("peer", from.Host()))
	case c.cfg.OnRTR != nil:
		res = c.cfg.OnRTR(ctx, r)
	}
	c.metrics.Count("cxclient.RTR."+resultName(res), 1)
	return (&cx.RTA{Answer: cx.Answer{Result: res}}).Message(n, req)
}

// servePPR answers a Push-Profile-Request (TS 29.228 §6.2.2) with the result
// of OnPPR.
func (c *Client) servePPR(ctx context.Context, n *diameter.Node, from *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
	r, err := cx.ParsePPR(req)
	if err != nil {
		return nil, err
	}
	res := cx.ResultCode(diameter.ResultUnableToComply)
	switch {
	case !c.hostOK(from.Host()):
		c.metrics.Count("cxclient.PPR.refused", 1)
		c.log.Warn("cxclient: PPR from a peer that is not an HSS", slog.String("peer", from.Host()))
	case c.cfg.OnPPR != nil:
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
