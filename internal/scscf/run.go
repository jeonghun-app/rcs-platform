package scscf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/dynamostore"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// coreListener names the one SIP listener.
const coreListener = "core"

// Service is scscf for runtime.Main.
func Service() runtime.Service[ServiceConfig] {
	return runtime.Service[ServiceConfig]{Name: "scscf", EnvPrefix: "SCSCF_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world; tests replace them.
type deps struct {
	// rand draws the Origin-Host label and the IDs; crypto/rand when nil.
	rand io.Reader
	// store, if set, is the shared state instead of cfg.Store's.
	store state.Store
	// discovery, if set, finds the HSS tasks instead of cfg.HSSDiscovery.
	discovery cxclient.Discovery
	// dial, if set, opens the Diameter connections to the HSS tasks.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// hssResolver, if set, resolves hss.<namespace> for DNS discovery.
	hssResolver cxclient.Resolver
	// lookup and allow are the SIP resolver's (proxy.DNSResolver).
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
	allow  func(netip.Addr) bool
	// sipDialer, if set, opens the transport's connections.
	sipDialer transport.Dialer
	// writeTimeout replaces the transport's WriteTimeout when set, and
	// sendQueueBytes its SendQueueBytes.
	writeTimeout   time.Duration
	sendQueueBytes int
	// dialTimeout replaces coreDialTimeout when set; it must stay below
	// closeMargin.
	dialTimeout time.Duration
	// router, if set, routes in place of the dispatcher.
	router proxy.Router
	// transportMade, if set, hears of the transport once it is made.
	transportMade func(*transport.Transport)
	// now is the clock of the registrar, the notifier and the router.
	now func() time.Time
	// listening, if set, hears the core listener's bound address.
	listening func(netip.AddrPort)
}

// Run serves cfg until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig, d deps) error {
	if d.rand == nil {
		d.rand = rand.Reader
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.dialTimeout == 0 {
		d.dialTimeout = coreDialTimeout
	}
	store, err := openStore(ctx, cfg, d)
	if err != nil {
		return err
	}
	// The registrar answers the HSS's RTR and PPR; it is made once the Cx
	// client it needs is, so the client's handlers reach it through reg.
	var reg atomic.Pointer[registrar.Registrar]
	hss, host, err := newCxClient(ctx, rt, cfg, d, &reg)
	if err != nil {
		return err
	}
	// The stop closes the Cx client by its deadline; a return before the
	// stop closes it here. Only the first Close counts: a second would wait
	// again, with no deadline, for what the first gave up on.
	var cxClosed sync.Once
	closeCx := func(ctx context.Context) { cxClosed.Do(func() { _ = hss.Close(ctx) }) }
	defer closeCx(context.Background())
	rt.Admin.AddReadinessCheck("hss", func(context.Context) error { return hss.Ready() })

	resolver := &proxy.DNSResolver{Lookup: d.lookup, Namespace: cfg.Namespace, Allow: d.allow, Logger: rt.Logger}
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{
		DialTimeout: d.dialTimeout, WriteTimeout: d.writeTimeout, SendQueueBytes: d.sendQueueBytes, Dialer: d.sipDialer, Logger: rt.Logger,
	}, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			px.Receive(in)
		}
	})
	if err != nil {
		return err
	}
	defer func() { _ = tr.Close() }()
	if d.transportMade != nil {
		d.transportMade(tr)
	}
	coreAddr, err := tr.Listen(transport.ListenerConfig{
		Name: coreListener, Network: transport.TCP, Addr: cfg.CoreAddr, AdvertisedHost: hostOf(cfg.CoreHost),
	})
	if err != nil {
		return fmt.Errorf("scscf: core listener: %w", err)
	}
	port := int(coreAddr.Port())
	service := sip.URI{Scheme: "sip", Host: "scscf." + cfg.Namespace, Port: port}
	service.Params.Set("transport", "tcp")
	ids := sip.IDGenerator{Rand: d.rand}
	send := &sender{
		layer: func() *transaction.Layer {
			if px := p.Load(); px != nil {
				return px.Layer()
			}
			return nil
		},
		resolver: resolver, listener: coreListener, branch: ids.Branch,
	}

	notifier, err := regevent.New(regevent.Config{
		Store: store, Sender: send, Contact: service, NotifyTimeout: cfg.NotifyTimeout,
		Now: d.now, Rand: d.rand, Logger: rt.Logger, Metrics: rt.Metrics,
	})
	if err != nil {
		return err
	}
	// The registrar tells the router of every registration, and the router
	// needs the registrar for unregistered users: the router is set in
	// thirdParty once it is made, before anything is served.
	third := &lateThirdParty{}
	serviceRoute := sip.URI{Scheme: "sip", Host: "scscf." + cfg.Namespace, Port: port}
	g, err := registrar.New(registrar.Config{
		Store: store, HSS: hss, Realm: cfg.HomeDomain, ServiceRoute: serviceRoute, NonceKey: cfg.NonceKey,
		Now: d.now, Rand: d.rand, Metrics: rt.Metrics, Events: notifier, ThirdParty: third, Logger: rt.Logger,
	})
	if err != nil {
		return err
	}
	reg.Store(g)
	rr := service
	rr.Params.SetFlag("lr")
	self := selfURIs(cfg, port)
	router, err := routing.New(routing.Config{
		Store: store, Registrar: g, ICSCF: cfg.ICSCF, HomeDomain: cfg.HomeDomain,
		RecordRoute: sip.Address{URI: rr}, Self: self, DialogKeys: cfg.DialogKeys,
		EdgeProxyPort: cfg.PCSCFCorePort, ApplicationServers: cfg.ApplicationServers,
		EdgeProxyPublicHosts: cfg.EdgeProxyPublicHosts, Sender: send,
		ASTimeout: cfg.ASTimeout, ThirdPartyTimeout: cfg.ThirdPartyTimeout, MaxThirdParty: cfg.MaxThirdParty,
		Now: d.now, Rand: d.rand, Logger: rt.Logger, Metrics: rt.Metrics,
	})
	if err != nil {
		return err
	}
	third.router.Store(router)

	disp := &dispatcher{registrar: g, notifier: notifier, router: router, log: rt.Logger}
	var pr proxy.Router = disp
	if d.router != nil {
		pr = d.router
	}
	tcfg, maxContexts, maxContextBytes := proxyLimits(cfg)
	px, err := proxy.New(tr, proxy.Config{
		Self:            self,
		Router:          pr,
		Resolver:        resolver,
		Supported:       []string{"path"},
		Logger:          rt.Logger,
		Transaction:     tcfg,
		MaxContexts:     maxContexts,
		MaxContextBytes: maxContextBytes,
		// The panics recovered from the hooks, as the other services count
		// them (#428).
		Metrics: rt.Metrics,
	})
	if err != nil {
		return err
	}
	defer px.Close()
	p.Store(px)

	sweepCtx, stopSweeps := context.WithCancel(context.WithoutCancel(ctx))
	var sweeps sync.WaitGroup
	sweeps.Go(func() { g.RunSweeps(sweepCtx, cfg.SweepInterval, cfg.SweepLimit) })
	sweeps.Go(func() { runSubscriptionSweeps(sweepCtx, notifier, cfg.SweepInterval, cfg.SweepLimit, rt.Logger) })

	rt.Logger.Info("serving SIP", slog.String("core_addr", coreAddr.String()), slog.String("origin_host", host))
	rt.Ready()
	if d.listening != nil {
		d.listening(coreAddr)
	}
	<-ctx.Done()

	// The listener stays open while the drain runs, as Cloud Map's answers
	// name this task for their TTL after it is deregistered.
	stopBy := time.Now().Add(cfg.DrainTimeout + stopMargin - returnMargin)
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	defer cancelDrain()
	if n := px.Drain(drainCtx); n > 0 {
		rt.Logger.Info("answered requests left at the stop", slog.Int("requests", n))
	}
	// Nothing tells the router or the notifier of a change after this: the
	// requests are answered, and the sweeps stop.
	stopSweeps()
	sweeps.Wait()
	// The router, the first NOTIFYs and the notifier's queue share what is
	// left of the budget but closeMargin: an application server or a P-CSCF
	// that does not answer holds none of them past it (#439 QA and code
	// review). Each is waited for, the last ones even once the deadline has
	// passed, which they then report at once.
	waitCtx, cancelWait := context.WithDeadline(context.Background(), stopBy.Add(-closeMargin))
	defer cancelWait()
	routed := router.StopBy(waitCtx)
	firsts := disp.firsts.wait(waitCtx)
	queued := notifier.WaitFor(waitCtx)
	if !routed {
		rt.Logger.Info("gave up on third-party REGISTERs at the stop")
	}
	if !firsts || !queued {
		rt.Logger.Info("left NOTIFYs to the sweeps of the other tasks")
	}
	// The transport closes before the proxy does (the deferred Close), as
	// pcscf's (#366): a peer that stopped reading leaves senders waiting for
	// room in its connection's queue, and the proxy's Close waits for them,
	// for up to WriteTimeout, past the budget; closing the connections
	// releases them at once; a second Close does nothing. The sends the
	// router gave up on are released with them, but for one still opening
	// its connection, which ends within closeMargin. Then the Cx client
	// says goodbye to the HSS tasks (DPR) by the deadline.
	_ = tr.Close()
	closeCtx, cancelClose := context.WithDeadline(context.Background(), stopBy)
	defer cancelClose()
	if !routed && !router.WaitFor(closeCtx) {
		rt.Logger.Warn("third-party REGISTERs still under way at the end of the stop")
	}
	closeCx(closeCtx)
	return nil
}

// proxyLimits are the bounds of scscf's proxy, as icscf's (#311 code
// review, option A): its layer's server transaction caps, and as many
// contexts and bytes for the proxy's own bounds, so that a burst meets the
// configured count first. Both refusals are counted, the layer's and the
// proxy's.
func proxyLimits(cfg ServiceConfig) (tcfg transaction.Config, maxContexts int, maxContextBytes int64) {
	tcfg = transaction.Config{MaxServerTransactions: cfg.MaxServerTransactions, MaxServerTransactionBytes: cfg.MaxServerTransactionBytes}
	return tcfg, cfg.MaxServerTransactions, cfg.MaxServerTransactionBytes
}

// runSubscriptionSweeps runs the notifier's sweep every interval until ctx
// ends, as the registrar's RunSweeps does.
func runSubscriptionSweeps(ctx context.Context, n *regevent.Notifier, interval time.Duration, limit int, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for {
			k, err := n.Sweep(ctx, limit)
			if err != nil {
				log.Warn("scscf: subscription sweep", slog.Int("handled", k), slog.String("error", err.Error()))
			}
			if k < limit || ctx.Err() != nil {
				break
			}
		}
	}
}

// lateThirdParty is the registrar's ThirdParty until the router it needs
// is made: the router, once stored.
type lateThirdParty struct {
	router atomic.Pointer[routing.Router]
}

func (l *lateThirdParty) Registered(ctx context.Context, r registrar.ThirdPartyRegistration) {
	if rt := l.router.Load(); rt != nil {
		rt.Registered(ctx, r)
	}
}

// openStore is the shared state cfg names.
func openStore(ctx context.Context, cfg ServiceConfig, d deps) (state.Store, error) {
	if d.store != nil {
		return d.store, nil
	}
	if cfg.Store == StoreMemory {
		return state.NewMemory(), nil
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
	if err != nil {
		return nil, fmt.Errorf("scscf: loading the AWS configuration: %w", err)
	}
	ddb := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.DynamoDBEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.DynamoDBEndpoint)
		}
	})
	return dynamostore.New(ddb, dynamostore.Config{
		RegistrationsTable: cfg.RegistrationsTable, ChallengesTable: cfg.ChallengesTable, SubscriptionsTable: cfg.SubscriptionsTable,
		ChallengeKeys: cfg.ChallengeKeys, SealKeyID: cfg.SealKeyID, Rand: d.rand,
	})
}

// newCxClient is the Cx client toward the HSS tasks: it names this S-CSCF
// by its service name (ADR 0005), never a task's, and hands the HSS's RTR
// and PPR to the registrar once reg holds it.
func newCxClient(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig, d deps, reg *atomic.Pointer[registrar.Registrar]) (*cxclient.Client, string, error) {
	host := cfg.OriginHost
	if host == "" {
		label := make([]byte, 6)
		if _, err := io.ReadFull(d.rand, label); err != nil {
			return nil, "", err
		}
		var err error
		if host, err = cxclient.OriginHostFor("scscf", hex.EncodeToString(label), cfg.Namespace); err != nil {
			return nil, "", err
		}
	}
	disc := d.discovery
	if disc == nil && cfg.HSSDiscovery == DiscoveryCloudMap {
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
		if err != nil {
			return nil, "", fmt.Errorf("scscf: loading the AWS configuration: %w", err)
		}
		disc = cxclient.CloudMapDiscovery{API: servicediscovery.NewFromConfig(awsCfg), Namespace: cfg.Namespace, Service: "hss"}
	}
	c, err := cxclient.New(cxclient.Config{
		OriginHost: host, OriginRealm: cfg.OriginRealm, DestinationRealm: cfg.HSSRealm,
		ServerName: serverName(cfg),
		Discovery:  disc, HSS: "hss." + cfg.Namespace, Resolver: d.hssResolver, HSSHostPattern: cfg.HSSHostPattern,
		RequestTimeout: cfg.CxTimeout, Node: diameter.Config{Dial: d.dial},
		OnRTR: func(ctx context.Context, r *cx.RTR) cx.Result {
			if g := reg.Load(); g != nil {
				return g.HandleRTR(ctx, r)
			}
			// Not serving yet: the HSS tries another peer.
			return cx.ResultCode(diameter.ResultTooBusy)
		},
		OnPPR: func(ctx context.Context, r *cx.PPR) cx.Result {
			if g := reg.Load(); g != nil {
				return g.HandlePPR(ctx, r)
			}
			return cx.ResultCode(diameter.ResultTooBusy)
		},
		Metrics: rt.Metrics, Logger: rt.Logger,
	})
	if err != nil {
		return nil, "", err
	}
	return c, host, nil
}

// serverName is the name this S-CSCF gives the HSS, which the HSS stores
// and hands the I-CSCF (TS 29.228 §6.1.2): its service name, the same on
// every task, as icscf's S-CSCF list names it (#274 review).
func serverName(cfg ServiceConfig) string { return "sip:scscf." + cfg.Namespace }

// selfURIs are the URIs a Route naming this scscf carries: its task's
// address, and its service name.
func selfURIs(cfg ServiceConfig, port int) []sip.URI {
	var out []sip.URI
	for _, h := range []string{hostOf(cfg.CoreHost), "scscf." + cfg.Namespace} {
		if h == "" {
			continue
		}
		if u, err := sip.ParseURI("sip:" + h + ":" + strconv.Itoa(port) + ";lr"); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// hostOf writes an address as a SIP host, empty for the zero Addr.
func hostOf(a netip.Addr) string {
	switch {
	case !a.IsValid():
		return ""
	case a.Is6():
		return "[" + a.String() + "]"
	}
	return a.String()
}

// sdkLogger sends the AWS SDK's warnings to the service's JSON log and
// drops its debug lines.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}
