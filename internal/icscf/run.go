package icscf

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
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// coreListener names the one SIP listener.
const coreListener = "core"

// Service is icscf for runtime.Main.
func Service() runtime.Service[ServiceConfig] {
	return runtime.Service[ServiceConfig]{Name: "icscf", EnvPrefix: "ICSCF_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world; tests replace them.
type deps struct {
	// rand draws the Origin-Host label; crypto/rand when nil.
	rand io.Reader
	// discovery, if set, finds the HSS tasks instead of cfg.HSSDiscovery.
	discovery cxclient.Discovery
	// dial, if set, opens the Diameter connections to the HSS tasks.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
	// lookup and allow are the S-CSCF resolver's (proxy.DNSResolver):
	// net.DefaultResolver and private addresses when nil; tests resolve
	// their names to loopback.
	lookup  func(ctx context.Context, network, host string) ([]netip.Addr, error)
	allow   func(netip.Addr) bool
	shuffle func(n int, swap func(i, j int))
	// sipDialer, if set, opens the transport's connections to S-CSCFs.
	sipDialer transport.Dialer
	// hssResolver, if set, resolves hss.<namespace> for DNS discovery.
	hssResolver cxclient.Resolver
	// listening, if set, hears the core listener's bound address.
	listening func(netip.AddrPort)
	// transport, if set, gets the SIP transport once it is made.
	transport func(*transport.Transport)
	// writeTimeout replaces the transport's WriteTimeout when set.
	writeTimeout time.Duration
}

// Run serves cfg until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig, d deps) error {
	if d.rand == nil {
		d.rand = rand.Reader
	}
	hss, host, err := newCxClient(ctx, rt, cfg, d)
	if err != nil {
		return err
	}
	defer func() { _ = hss.Close(context.Background()) }()
	rt.Admin.AddReadinessCheck("hss", func(context.Context) error { return hss.Ready() })

	// The S-CSCFs are found by their Cloud Map names, every address of one
	// (#198), so a request can go to the next when a task is gone.
	dns := &proxy.DNSResolver{Lookup: d.lookup, Namespace: cfg.Namespace, Allow: d.allow, Shuffle: d.shuffle, Logger: rt.Logger}
	// The proxy is made once the core listener's port is known, which its
	// Self needs; a request that arrives before is dropped, and its sender
	// retransmits or tries another task.
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{DialTimeout: coreDialTimeout, Dialer: d.sipDialer, WriteTimeout: d.writeTimeout, Logger: rt.Logger, Metrics: rt.Metrics}, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			px.Receive(in)
		}
	})
	if err != nil {
		return err
	}
	defer func() { _ = tr.Close() }()
	if d.transport != nil {
		d.transport(tr)
	}
	coreAddr, err := tr.Listen(transport.ListenerConfig{
		Name: coreListener, Network: transport.TCP, Addr: cfg.CoreAddr,
		AdvertisedHost: hostOf(cfg.CoreHost),
	})
	if err != nil {
		return fmt.Errorf("icscf: core listener: %w", err)
	}
	self := selfURIs(cfg, int(coreAddr.Port()))
	router, err := New(Config{
		HSS: hss, SCSCFs: cfg.SCSCFs, HomeDomain: cfg.HomeDomain, Resolver: dns,
		RetryAfter: cfg.RetryAfter, RegisterTimeout: cfg.RegisterTimeout,
		IDs: sip.IDGenerator{Rand: d.rand}, Metrics: rt.Metrics, Logger: rt.Logger,
		Self: self,
	})
	if err != nil {
		return err
	}
	tcfg, maxContexts, maxContextBytes := proxyLimits(cfg)
	px, err := proxy.New(tr, proxy.Config{
		Self:            self,
		Router:          router,
		Resolver:        dns,
		Logger:          rt.Logger,
		Metrics:         rt.Metrics,
		Transaction:     tcfg,
		MaxContexts:     maxContexts,
		MaxContextBytes: maxContextBytes,
		// A REGISTER left at the stop gets 503, which pcscf retries on
		// another icscf at once (decided on #310).
		DrainAnswer: drainAnswer,
	})
	if err != nil {
		return err
	}
	defer px.Close()
	p.Store(px)
	rt.Logger.Info("serving SIP", slog.String("core_addr", coreAddr.String()),
		slog.String("origin_host", host), slog.Int("scscfs", len(cfg.SCSCFs)))
	rt.Ready()
	// After Ready, so a test that reads /readyz once told sees the HSS's
	// state rather than "starting" (QA of #276).
	if d.listening != nil {
		d.listening(coreAddr)
	}
	<-ctx.Done()
	// The listener stays open meanwhile, since Cloud Map's DNS answers name
	// this task for their TTL after it is deregistered (review of #276).
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	defer cancel()
	if n := px.Drain(drainCtx); n > 0 {
		rt.Logger.Info("answered requests left at the stop", slog.Int("requests", n))
	}
	// The transport closes before the proxy does (the deferred Close), once
	// Drain has written its answers, as in pcscf (#323). A core peer that
	// stopped reading leaves senders waiting for room in its connection's
	// queue, and the proxy's Close waits for them, for up to WriteTimeout,
	// past the stop margin (#338); closing the connections releases them at
	// once. A second Close does nothing.
	_ = tr.Close()
	return nil
}

// drainAnswer is what icscf answers a request left in progress at the end
// of its drain (proxy.Config.DrainAnswer). A REGISTER gets 503 with
// Retry-After, which pcscf retries on another icscf at once; it never
// passed through scscf, so the rule that a proxy turns a 503 into a 500
// (#281) does not apply to it. Everything else gets the proxy's 500 with
// Retry-After (decided on #310).
func drainAnswer(req *sip.Request) (int, time.Duration) {
	if req.Method == "REGISTER" {
		return 503, transaction.DefaultRetryAfter
	}
	return 500, transaction.DefaultRetryAfter
}

// proxyLimits are the bounds of icscf's proxy: its layer's server
// transaction caps (#37); as many contexts as server transactions, so the
// layer's count, not the proxy's, is the one a burst meets; and the same
// bytes for the proxy's own memory bound, which the proxy charges
// differently (a request's body, two copies of its header, and two per
// branch), so either may refuse a request first. Both refusals are counted:
// the layer's ServerTransactionsRejected and the proxy's Overloaded (code
// review of #311, option A).
func proxyLimits(cfg ServiceConfig) (tcfg transaction.Config, maxContexts int, maxContextBytes int64) {
	tcfg = transaction.Config{
		MaxServerTransactions:     cfg.MaxServerTransactions,
		MaxServerTransactionBytes: cfg.MaxServerTransactionBytes,
	}
	return tcfg, cfg.MaxServerTransactions, cfg.MaxServerTransactionBytes
}

// newCxClient is the Cx client to the HSS tasks, with this task's own
// Origin-Host (ADR 0005).
func newCxClient(ctx context.Context, rt *runtime.Runtime, cfg ServiceConfig, d deps) (*cxclient.Client, string, error) {
	host := cfg.OriginHost
	if host == "" {
		// A fresh identity at every start, as hss draws its own: an HSS
		// task never meets an Origin-Host whose previous connection failed,
		// which would hold the new one in the watchdog's REOPEN state.
		label := make([]byte, 6)
		if _, err := io.ReadFull(d.rand, label); err != nil {
			return nil, "", err
		}
		var err error
		if host, err = cxclient.OriginHostFor("icscf", hex.EncodeToString(label), cfg.Namespace); err != nil {
			return nil, "", err
		}
	}
	disc := d.discovery
	if disc == nil && cfg.HSSDiscovery == DiscoveryCloudMap {
		awsCfg, err := config.LoadDefaultConfig(ctx, config.WithLogger(sdkLogger{}))
		if err != nil {
			return nil, "", fmt.Errorf("icscf: loading the AWS configuration: %w", err)
		}
		disc = cxclient.CloudMapDiscovery{API: servicediscovery.NewFromConfig(awsCfg), Namespace: cfg.Namespace, Service: "hss"}
	}
	c, err := cxclient.New(cxclient.Config{
		OriginHost: host, OriginRealm: cfg.OriginRealm, DestinationRealm: cfg.HSSRealm,
		Discovery: disc, HSS: "hss." + cfg.Namespace, Resolver: d.hssResolver, HSSHostPattern: cfg.HSSHostPattern,
		RequestTimeout: cfg.CxTimeout, Node: diameter.Config{Dial: d.dial},
		Metrics: rt.Metrics, Logger: rt.Logger,
	})
	if err != nil {
		return nil, "", err
	}
	return c, host, nil
}

// selfURIs are the URIs a Route naming this icscf carries: its own address,
// and the service name pcscf and scscf may put in a Route.
func selfURIs(cfg ServiceConfig, port int) []sip.URI {
	var out []sip.URI
	for _, h := range []string{hostOf(cfg.CoreHost), "icscf." + cfg.Namespace} {
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

// sdkLogger sends the AWS SDK's warnings to the service's JSON log and drops
// its debug lines.
type sdkLogger struct{}

func (sdkLogger) Logf(c logging.Classification, format string, v ...any) {
	if c == logging.Warn {
		slog.Warn("aws sdk warning", slog.String("message", pii.Redact(fmt.Sprintf(format, v...))))
	}
}
