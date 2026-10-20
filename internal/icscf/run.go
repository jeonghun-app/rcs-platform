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

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/servicediscovery"
	"github.com/aws/smithy-go/logging"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
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
	// resolver finds the next hop of a forwarded request; the proxy's
	// NumericResolver when nil.
	resolver proxy.Resolver
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
	hss, host, err := newCxClient(ctx, rt, cfg, d)
	if err != nil {
		return err
	}
	defer func() { _ = hss.Close(context.Background()) }()
	rt.Admin.AddReadinessCheck("hss", func(context.Context) error { return hss.Ready() })

	router, err := New(Config{
		HSS: hss, SCSCFs: cfg.SCSCFs, HomeDomain: cfg.HomeDomain,
		RetryAfter: cfg.RetryAfter, RegisterTimeout: cfg.RegisterTimeout,
		IDs: sip.IDGenerator{Rand: d.rand}, Metrics: rt.Metrics, Logger: rt.Logger,
	})
	if err != nil {
		return err
	}

	// The proxy is made once the core listener's port is known, which its
	// Self needs; a request that arrives before is dropped, and its sender
	// retransmits or tries another task.
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{Logger: rt.Logger}, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			px.Receive(in)
		}
	})
	if err != nil {
		return err
	}
	defer func() { _ = tr.Close() }()
	coreAddr, err := tr.Listen(transport.ListenerConfig{
		Name: coreListener, Network: transport.TCP, Addr: cfg.CoreAddr,
		AdvertisedHost: hostOf(cfg.CoreHost),
	})
	if err != nil {
		return fmt.Errorf("icscf: core listener: %w", err)
	}
	px, err := proxy.New(tr, proxy.Config{
		Self:     selfURIs(cfg, int(coreAddr.Port())),
		Router:   router,
		Resolver: d.resolver,
		Logger:   rt.Logger,
	})
	if err != nil {
		return err
	}
	defer px.Close()
	p.Store(px)
	if d.listening != nil {
		d.listening(coreAddr)
	}
	rt.Logger.Info("serving SIP", slog.String("core_addr", coreAddr.String()),
		slog.String("origin_host", host), slog.Int("scscfs", len(cfg.SCSCFs)))
	rt.Ready()
	<-ctx.Done()
	return nil
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
		Discovery: disc, HSS: "hss." + cfg.Namespace, HSSHostPattern: cfg.HSSHostPattern,
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
