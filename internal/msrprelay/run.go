package msrprelay

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/dynamostore"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// controlShutdownTimeout bounds the wait for control calls in flight once
// the data path has drained; each is one store call.
const controlShutdownTimeout = 2 * time.Second

// Service is msrp-relay for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "msrp-relay", EnvPrefix: "RELAY_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world; tests replace them.
type deps struct {
	store  store.Store
	clock  msrp.Clock
	rand   io.Reader
	listen func(ctx context.Context, address string) (net.Listener, error)
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
	// listening, if set, hears the bound addresses once both listeners are
	// open.
	listening func(public, control net.Addr)
}

// Run serves cfg until ctx ends, then drains: no new client connections,
// existing bridges get RELAY_DRAIN_TIMEOUT, and the rest are closed
// (ADR 0003). The control API keeps answering while the data path drains,
// since pcscf releases and extends bindings that other tasks may hold.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	if d.clock == nil {
		d.clock = systemClock{}
	}
	if d.rand == nil {
		d.rand = rand.Reader
	}
	if d.listen == nil {
		d.listen = listenClients
	}
	if d.dial == nil {
		d.dial = coreDialer(cfg.CoreNetworks, cfg.CorePorts, cfg.CoreConnectTimeout)
	}
	st := d.store
	if st == nil {
		var err error
		if st, err = openStore(ctx, cfg); err != nil {
			return err
		}
	}
	rt.Admin.AddReadinessCheck("binding store", st.Ready)

	m := newCounters()
	tokens := make([]string, len(cfg.Tokens))
	for i, t := range cfg.Tokens {
		tokens[i] = t.v
	}
	relay, err := newRelay(relayOptions{
		Store:                   st,
		StoreTimeout:            cfg.StoreTimeout,
		Public:                  cfg.Public,
		ProxyProtocol:           cfg.ProxyProtocol,
		MaxConnections:          cfg.MaxConnections,
		MaxConnectionsPerSource: cfg.MaxConnectionsPerSource,
		MaxConcurrentBinds:      cfg.MaxConcurrentBinds,
		FailedLookupsPerSource:  cfg.FailedLookupsPerSource,
		PathWait:                cfg.PathWait,
		CoreConnectTimeout:      cfg.CoreConnectTimeout,
		IdleTimeout:             cfg.IdleTimeout,
		Edge:                    msrp.Config{KeepAliveInterval: cfg.KeepAlive, MaxFailedBinds: cfg.MaxUnknownSessions},
		Core:                    msrp.Config{KeepAliveInterval: cfg.KeepAlive},
		Dial:                    d.dial,
		Clock:                   d.clock,
		Rand:                    d.rand,
		Log:                     rt.Logger,
		Metrics:                 m,
	})
	if err != nil {
		return err
	}
	ctl := newControl(controlOptions{
		Store:        st,
		StoreTimeout: cfg.StoreTimeout,
		Public:       cfg.Public,
		CoreHost:     cfg.CoreHost,
		CoreNetworks: cfg.CoreNetworks,
		CorePorts:    cfg.CorePorts,
		Namespace:    cfg.Namespace,
		MaxExpiresIn: cfg.MaxExpiresIn,
		Tokens:       tokens,
		Clock:        d.clock,
		Rand:         d.rand,
		Log:          rt.Logger,
		Metrics:      m,
	})

	public, err := d.listen(ctx, cfg.ListenAddr)
	if err != nil {
		return err
	}
	controlLn, err := net.Listen("tcp", cfg.ControlAddr)
	if err != nil {
		_ = public.Close()
		return err
	}
	hs := &http.Server{
		Handler:           ctl,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(rt.Logger.Handler(), slog.LevelWarn),
	}
	failed := make(chan error, 2)
	go func() { failed <- relay.Serve(public) }()
	go func() { failed <- hs.Serve(controlLn) }()

	stopFlushing := every(d.clock, cfg.MetricsInterval, func() { m.flush(rt.Metrics) })
	if d.listening != nil {
		d.listening(public.Addr(), controlLn.Addr())
	}
	rt.Logger.Info("relaying MSRP",
		slog.String("public_addr", public.Addr().String()),
		slog.String("control_addr", controlLn.Addr().String()),
		slog.Bool("proxy_protocol", cfg.ProxyProtocol))
	rt.Ready()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-failed:
	}
	relay.Drain(context.Background(), cfg.DrainTimeout)
	stopCtx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(stopCtx); err != nil {
		_ = hs.Close()
	}
	// The last counts, gauges at zero, go out before the process does.
	stopFlushing()
	m.flush(rt.Metrics)
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	return runErr
}

func openStore(ctx context.Context, cfg Config) (store.Store, error) {
	if cfg.Store == StoreMemory {
		return store.NewMemory(), nil
	}
	return dynamostore.New(ctx, cfg.Table, cfg.DynamoDBEndpoint)
}

// listenClients opens the public listener with kernel TCP keep-alive off:
// it would restart the NLB's idle timer and, on TLS listeners, make the NLB
// keep both sides awake with keep-alives of its own (ADR 0003). MSRP's own
// keep-alive does the job.
func listenClients(ctx context.Context, address string) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: -1}
	return lc.Listen(ctx, "tcp", address)
}

// every runs f each interval on clock until the returned stop is called.
func every(clock msrp.Clock, interval time.Duration, f func()) (stop func()) {
	var mu sync.Mutex
	stopped := false
	var t msrp.Timer
	var tick func()
	tick = func() {
		f()
		mu.Lock()
		defer mu.Unlock()
		if !stopped {
			t = clock.AfterFunc(interval, tick)
		}
	}
	mu.Lock()
	t = clock.AfterFunc(interval, tick)
	mu.Unlock()
	return func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		t.Stop()
	}
}

// systemClock is msrp.Clock on real time.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) AfterFunc(d time.Duration, f func()) msrp.Timer { return time.AfterFunc(d, f) }
