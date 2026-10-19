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
	// now is the clock of the drain's schedule; nil is time.Now.
	now func() time.Time
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
	if d.router == nil {
		d.router = router{}
	}
	var tlsCfg *tls.Config
	if cfg.ClientTransport == ClientTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("pcscf: client certificate: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	fl := newFlows(cfg.MaxClientFlows, cfg.MaxFlowsPerIP)
	// The proxy is made once the core listener's port is known, which its
	// Self needs. Only the core listener is open before it, scscf has no
	// reason to reach a pcscf that is not ready, and a request that does
	// arrive is dropped: its sender times out and tries another task.
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{
		TLS:            tlsCfg,
		MaxConnections: cfg.MaxConnections,
		Admit:          fl.admit,
		OnFlowClosed:   fl.closed,
		Logger:         rt.Logger,
	}, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			fromClientMessage(in)
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
	px, err := proxy.New(tr, proxy.Config{
		Self:   selfURIs(cfg, int(coreAddr.Port())),
		Router: d.router,
		Logger: rt.Logger,
	})
	if err != nil {
		return err
	}
	defer px.Close()
	p.Store(px)

	clientAddr, err := tr.Listen(clientListenerConfig(cfg))
	if err != nil {
		return fmt.Errorf("pcscf: client listener: %w", err)
	}
	var udpAddr netip.AddrPort
	if cfg.ClientUDPAddr != "" {
		if udpAddr, err = tr.Listen(udpListenerConfig(cfg)); err != nil {
			return fmt.Errorf("pcscf: client UDP listener: %w", err)
		}
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

	<-ctx.Done()
	// No new client connection from here on; the existing flows are closed
	// one by one, and every client re-registers through another task. The
	// core listener stays open, so scscf can still reach the clients not yet
	// closed (review of #188).
	tr.StopListening(clientListener)
	drainCtx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
	defer cancel()
	ids := fl.ids()
	rt.Logger.Info("draining client flows", slog.Int("flows", len(ids)), slog.Duration("over", cfg.DrainTimeout))
	drain(drainCtx, ids, cfg.DrainTimeout, tr.CloseFlow, d.sleep, d.now)
	return nil
}

// clientListenerConfig is the client stream listener: behind the NLB,
// client-facing, so no kernel keep-alive and no connection to a client's Via
// (ADR 0003), with the PROXY header required when RCS_PROXY_PROTOCOL is set.
func clientListenerConfig(cfg Config) transport.ListenerConfig {
	network := transport.TCP
	if cfg.ClientTransport == ClientTLS {
		network = transport.TLS
	}
	return transport.ListenerConfig{
		Name: clientListener, Network: network, Addr: cfg.ClientAddr,
		AdvertisedHost: cfg.PublicHost, AdvertisedPort: cfg.PublicPort,
		ProxyProtocol: cfg.ProxyProtocol, ClientFacing: true,
		IdleTimeout: cfg.ClientIdleTimeout,
	}
}

// udpListenerConfig is the dev and test UDP client listener. Its Via names
// the port it is bound to, where a UDP client sends responses (RFC 3261
// §18.2.2), not the public port of the stream listener.
func udpListenerConfig(cfg Config) transport.ListenerConfig {
	return transport.ListenerConfig{
		Name: clientUDPListener, Network: transport.UDP, Addr: cfg.ClientUDPAddr,
		AdvertisedHost: cfg.PublicHost, ClientFacing: true,
	}
}
