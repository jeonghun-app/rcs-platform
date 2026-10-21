package rcsas

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
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
	// store and groups, if set, replace the configured ones.
	store  store.Store
	groups groupstore.Store
	// resolver, if set, replaces the namespace resolver of the core.
	resolver proxy.Resolver
	// listening, if set, hears the SIP listener's bound address.
	listening func(netip.AddrPort)
	// msrp, if set, replaces the MSRP listener.
	msrp net.Listener
}

// Run serves cfg until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	st, gst := d.store, d.groups
	switch {
	case cfg.Store == StoreMemory:
		if st == nil {
			st = store.NewMemory()
		}
		if gst == nil {
			gst = groupstore.NewMemory()
		}
	default:
		if st == nil {
			dyn, err := awsstore.New(ctx, cfg.DynamoDB)
			if err != nil {
				return err
			}
			rt.Admin.AddReadinessCheck("dynamodb", dyn.Ready)
			st = dyn
		}
		if gst == nil {
			gc := cfg.DynamoDB
			gc.Table = cfg.GroupsTable
			groups, err := awsstore.NewGroups(ctx, gc)
			if err != nil {
				return err
			}
			rt.Admin.AddReadinessCheck("dynamodb-groupchats", groups.Ready)
			gst = groups
		}
	}
	resolver := d.resolver
	if resolver == nil {
		resolver = sipas.Resolver{Namespace: cfg.Namespace}
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
	// The Contact of rcs-as's sessions is this task's address, where the
	// requests in their dialogs come back to it (ADR 0005).
	self, err := sip.ParseURI("sip:" + hostPort(cfg.SIPHost, addr.Port()) + ";transport=tcp")
	if err != nil {
		return err
	}
	srv, err := sipas.New(sipas.Config{
		Core: cfg.Core, Host: cfg.SIPHost.String(), HomeDomain: cfg.HomeDomain, Contact: self, Listener: sipListener,
		Resolver: resolver, MaxMessageSize: cfg.Messaging.MaxMessageSize, MaxSessions: cfg.MaxSessions,
		MaxOutgoingPerUser: cfg.MaxOutgoingPerUser, MaxIncomingPerUser: cfg.MaxIncomingPerUser, Metrics: rt.Metrics, Logger: rt.Logger,
		ConferenceFactory: cfg.ConferenceFactory, ConferenceHost: cfg.Group.ConferenceHost, MaxGroupParticipants: cfg.Group.MaxParticipants,
		GroupChat: cfg.GroupChat, MaxSubscriptionsPerUser: cfg.MaxSubscriptionsPerUser,
	})
	if err != nil {
		return err
	}
	px, err := proxy.New(tr, proxy.Config{Self: selfURIs(cfg, addr.Port()), Router: srv, Resolver: resolver, Logger: rt.Logger, Metrics: rt.Metrics})
	if err != nil {
		return err
	}
	defer px.Close()
	mc := cfg.Messaging
	mc.Logger, mc.HomeDomain = rt.Logger, cfg.HomeDomain
	engine, err := messaging.New(mc, st, srv, rt.Metrics)
	if err != nil {
		return err
	}
	// Closed before the proxy and the transport, which still carry the
	// answers to the deliveries in flight that it waits for (bounded by
	// RCSAS_DELIVERY_TIMEOUT).
	defer engine.Close()
	groups, err := group.New(cfg.Group, gst, engine, srv, rt.Metrics)
	if err != nil {
		return err
	}
	srv.Bind(engine, groups, px.Layer(), tr)
	// Run first of the deferred calls: the sessions end with a BYE while
	// the transport still carries it.
	defer srv.Close()
	p.Store(px)

	// msrp-relay connects here for every leg (ADR 0004).
	ml := d.msrp
	if ml == nil {
		if ml, err = net.Listen("tcp", cfg.MSRPListenAddr); err != nil {
			return fmt.Errorf("rcs-as: MSRP listener: %w", err)
		}
	}
	serveCtx, stopServing := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- engine.Serve(serveCtx, ml) }()
	defer func() { stopServing(); <-served }()

	runErr := make(chan error, 1)
	go func() { runErr <- engine.Run(ctx) }()
	if d.listening != nil {
		d.listening(addr)
	}
	rt.Logger.Info("serving SIP and MSRP", slog.String("sip_addr", addr.String()),
		slog.String("msrp_addr", ml.Addr().String()), slog.String("store", cfg.Store))
	rt.Ready()
	select {
	case <-ctx.Done():
		return nil
	case err := <-runErr:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case err := <-served:
		served <- err // for the deferred wait
		if ctx.Err() != nil {
			// The listener stopped for the shutdown, which may be seen
			// here before ctx.Done is.
			return nil
		}
		return fmt.Errorf("rcs-as: MSRP listener: %w", err)
	}
}

// selfURIs are the URIs by which a Route names this task: its instance
// address, and its service name (RCSAS_SERVICE_NAME), the host of the AS URI
// the iFC give scscf (HSS_RCS_AS_URI), on the listener's port
// and on 5060, the default a URI without a port means. The proxy compares
// them as written, never through DNS, as pcscf does.
func selfURIs(cfg Config, port uint16) []sip.URI {
	host := cfg.SIPHost.String()
	if cfg.SIPHost.Is6() {
		host = "[" + host + "]"
	}
	hosts := []string{host}
	if cfg.ServiceName != "" {
		hosts = append(hosts, cfg.ServiceName)
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

func hostPort(a netip.Addr, port uint16) string {
	host := a.String()
	if a.Is6() {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port))
}
