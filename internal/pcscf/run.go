package pcscf

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Service is pcscf for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "pcscf", EnvPrefix: "PCSCF_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world; tests replace them.
type deps struct {
	// sleep waits between the flows closed on a drain.
	sleep func(ctx context.Context, d time.Duration) error
	// listening, if set, hears the bound addresses once every listener is
	// open.
	listening func(bound)
	// router, if set, replaces pcscf's.
	router proxy.Router
	// now is the clock of registrations and limits; nil is time.Now.
	now func() time.Time
	// started, if set, gets the service's state once it runs.
	started func(*pcscf)
	// lookup resolves core host names; nil is the system resolver.
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// bound are the addresses the listeners bound; udp is zero without one.
type bound struct{ client, udp, core netip.AddrPort }

// Run serves cfg until ctx ends, then stops accepting connections and closes
// the client flows gradually over DrainTimeout (ADR 0003).
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	if d.sleep == nil {
		d.sleep = sleepCtx
	}
	if d.now == nil {
		d.now = time.Now
	}
	var tlsCfg *tls.Config
	if cfg.ClientTransport == ClientTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("pcscf: client certificate: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	fl := newFlows(cfg.MaxFlowsPerIP)
	// The proxy is made once the core listener's port is known, which its
	// Self needs; until then nothing can arrive but on the core listener,
	// and what does is dropped and retransmitted by its sender.
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{
		TLS:          tlsCfg,
		Admit:        fl.admit,
		OnFlowClosed: fl.closed,
		Logger:       rt.Logger,
	}, func(in transport.Inbound) {
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
		return fmt.Errorf("pcscf: core listener: %w", err)
	}
	pc := &pcscf{
		cfg: cfg, corePort: int(coreAddr.Port()),
		registry:  newRegistry(cfg.MaxRegistrations, d.now),
		registers: newLimiter(cfg.RegisterRate, cfg.RegisterBurst, d.now),
		flows:     tr, now: d.now, log: rt.Logger,
	}
	// A closed flow's registrations are gone (RFC 5626 §5.3).
	fl.onClosed = pc.registry.removeFlow
	router := d.router
	if router == nil {
		router = pc
	}
	px, err := proxy.New(tr, proxy.Config{
		Self:      selfURIs(cfg, int(coreAddr.Port())),
		Router:    router,
		Resolver:  coreResolver{dns: &proxy.DNSResolver{Lookup: d.lookup, Allow: allowCore(cfg)}},
		Supported: []string{"path", "outbound"},
		Logger:    rt.Logger,
	})
	if err != nil {
		return err
	}
	defer px.Close()
	p.Store(px)

	network := transport.TCP
	if cfg.ClientTransport == ClientTLS {
		network = transport.TLS
	}
	clientAddr, err := tr.Listen(transport.ListenerConfig{
		Name: clientListener, Network: network, Addr: cfg.ClientAddr,
		AdvertisedHost: cfg.PublicHost, AdvertisedPort: cfg.PublicPort,
		ProxyProtocol: cfg.ProxyProtocol, ClientFacing: true,
		IdleTimeout: cfg.ClientIdleTimeout,
	})
	if err != nil {
		return fmt.Errorf("pcscf: client listener: %w", err)
	}
	var udpAddr netip.AddrPort
	if cfg.ClientUDPAddr != "" {
		if udpAddr, err = tr.Listen(transport.ListenerConfig{
			Name: clientUDPListener, Network: transport.UDP, Addr: cfg.ClientUDPAddr,
			AdvertisedHost: cfg.PublicHost, AdvertisedPort: cfg.PublicPort, ClientFacing: true,
		}); err != nil {
			return fmt.Errorf("pcscf: client UDP listener: %w", err)
		}
	}
	if d.started != nil {
		d.started(pc)
	}
	if d.listening != nil {
		d.listening(bound{clientAddr, udpAddr, coreAddr})
	}
	rt.Logger.Info("serving SIP",
		slog.String("client_addr", clientAddr.String()),
		slog.String("client_transport", cfg.ClientTransport),
		slog.String("core_addr", coreAddr.String()),
		slog.Bool("proxy_protocol", cfg.ProxyProtocol))
	rt.Ready()
	stopSweep := every(sweepInterval, pc.registry.sweep)
	defer stopSweep()

	<-ctx.Done()
	// No new connection from here on; the existing flows are closed one by
	// one, and every client re-registers through another task.
	tr.StopListening()
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	defer cancel()
	ids := fl.ids()
	rt.Logger.Info("draining client flows", slog.Int("flows", len(ids)), slog.Duration("over", cfg.DrainTimeout))
	drain(drainCtx, ids, cfg.DrainTimeout, tr.CloseFlow, d.sleep)
	return nil
}

// sweepInterval is how often expired registrations are dropped; a lookup
// drops an expired one itself, so this only bounds memory.
const sweepInterval = 30 * time.Second

// every runs f every interval until the returned stop is called.
func every(interval time.Duration, f func()) (stop func()) {
	t := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-t.C:
				f()
			case <-done:
				return
			}
		}
	}()
	return func() { t.Stop(); close(done) }
}

// coreResolver resolves a core hop and sends it through the core listener,
// so that its Via names that listener and its responses come back there
// (proxy.Resolver).
type coreResolver struct{ dns *proxy.DNSResolver }

func (c coreResolver) Resolve(ctx context.Context, u sip.URI) (transport.Destination, error) {
	d, err := c.dns.Resolve(ctx, u)
	d.Listener = coreListener
	return d, err
}

// allowCore is the addresses a core hop may resolve to: private ones (ADR
// 0007 §5), and loopback for a stack on one host.
func allowCore(cfg Config) func(netip.Addr) bool {
	return func(a netip.Addr) bool {
		return runtime.IsPrivateAddr(a) || cfg.AllowLoopback && a.IsLoopback()
	}
}
