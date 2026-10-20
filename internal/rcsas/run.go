package rcsas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
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
		Core: cfg.Core, Host: cfg.SIPHost.String(), Listener: sipListener, Resolver: resolver,
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
	self, err := sip.ParseURI("sip:" + hostPort(cfg.SIPHost, addr.Port()) + ";transport=tcp")
	if err != nil {
		return err
	}
	px, err := proxy.New(tr, proxy.Config{Self: []sip.URI{self}, Router: srv, Resolver: resolver, Logger: rt.Logger})
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

func hostPort(a netip.Addr, port uint16) string {
	host := a.String()
	if a.Is6() {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port))
}
