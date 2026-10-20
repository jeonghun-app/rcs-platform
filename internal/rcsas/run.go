package rcsas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/sipas"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// sipListener names the SIP listener, the only one: rcs-as faces the core
// alone (ADR 0007 §2).
const sipListener = "core"

// Service is rcs-as for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "rcs-as", EnvPrefix: EnvPrefix, Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world; tests replace them.
type deps struct {
	// store, if set, replaces the configured one.
	store store.Store
	// resolver, if set, replaces the namespace resolver of the core.
	resolver proxy.Resolver
	// listening, if set, hears the SIP listener's bound address.
	listening func(netip.AddrPort)
}

// Run serves cfg until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	st := d.store
	if st == nil {
		switch cfg.Store {
		case StoreMemory:
			st = store.NewMemory()
		default:
			dyn, err := awsstore.New(ctx, cfg.DynamoDB)
			if err != nil {
				return err
			}
			rt.Admin.AddReadinessCheck("dynamodb", dyn.Ready)
			st = dyn
		}
	}
	resolver := d.resolver
	if resolver == nil {
		resolver = sipas.Resolver{Namespace: cfg.Namespace}
	}
	srv, err := sipas.New(sipas.Config{
		Core: cfg.Core, Host: cfg.SIPHost.String(), HomeDomain: cfg.HomeDomain, Listener: sipListener, Resolver: resolver,
		Metrics: rt.Metrics, Logger: rt.Logger,
	})
	if err != nil {
		return err
	}
	// The proxy is made once the listener's port is known, which its Self
	// needs; a request that arrives before is dropped, and its sender
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
	addr, err := tr.Listen(transport.ListenerConfig{
		Name: sipListener, Network: transport.TCP, Addr: cfg.SIPListenAddr, AdvertisedHost: cfg.SIPHost.String(),
	})
	if err != nil {
		return fmt.Errorf("rcs-as: SIP listener: %w", err)
	}
	px, err := proxy.New(tr, proxy.Config{Self: selfURIs(cfg, addr.Port()), Router: srv, Resolver: resolver, Logger: rt.Logger})
	if err != nil {
		return err
	}
	defer px.Close()
	mc := cfg.Messaging
	mc.Logger = rt.Logger
	engine, err := messaging.New(mc, st, srv, rt.Metrics)
	if err != nil {
		return err
	}
	// Closed before the proxy and the transport, which still carry the
	// answers to the deliveries in flight that it waits for (bounded by
	// RCSAS_DELIVERY_TIMEOUT).
	defer engine.Close()
	srv.Bind(engine, px.Layer())
	p.Store(px)

	runErr := make(chan error, 1)
	go func() { runErr <- engine.Run(ctx) }()
	if d.listening != nil {
		d.listening(addr)
	}
	rt.Logger.Info("serving SIP", slog.String("sip_addr", addr.String()), slog.String("store", cfg.Store))
	rt.Ready()
	select {
	case <-ctx.Done():
		return nil
	case err := <-runErr:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

// selfURIs are the URIs by which a Route names this task: its instance
// address, and its service name in the namespace, which is the AS URI the
// default profile's iFC give scscf (hss RCS_AS_URI), on the listener's port
// and on 5060, the default a URI without a port means. The proxy compares
// them as written, never through DNS, as pcscf does.
func selfURIs(cfg Config, port uint16) []sip.URI {
	host := cfg.SIPHost.String()
	if cfg.SIPHost.Is6() {
		host = "[" + host + "]"
	}
	hosts := []string{host}
	if cfg.Namespace != "" {
		hosts = append(hosts, "rcs-as."+cfg.Namespace)
	}
	ports := []int{int(port)}
	if port != 5060 {
		ports = append(ports, 5060)
	}
	var out []sip.URI
	for _, h := range hosts {
		for _, p := range ports {
			out = append(out, sip.URI{Scheme: "sip", Host: h, Port: p})
		}
	}
	return out
}
