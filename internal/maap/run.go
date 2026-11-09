package maap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Service is maap for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "maap", EnvPrefix: "MAAP_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world, replaced in tests.
type deps struct {
	listen func(network, address string) (net.Listener, error)
}

// Run serves the internal listener, apart from the runtime's admin port
// that serves health checks, until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{listen: net.Listen})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	// One decoder per task: #683's public listener shares it, so the cap
	// bounds the task's memory whichever listener the bodies come on.
	api := newInternalAPI(cfg.OperatorTokens, newDecoder(cfg.Decodes, rt.Metrics), rt)
	ln, err := d.listen("tcp", cfg.InternalAddr)
	if err != nil {
		return fmt.Errorf("maap: internal listener: %w", err)
	}
	// The write timeout stays above rcs-as's 15 s delivery calls (ADR 0009
	// §12), which #683 serves here.
	srv := &http.Server{
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          runtime.HTTPErrorLog(rt.Logger),
	}
	failed := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("maap: internal listener: %w", err)
		}
	}()
	rt.OnShutdown("internal API", srv.Shutdown)
	rt.Logger.Info("serving the internal API",
		slog.String("internal_addr", ln.Addr().String()), slog.Int("decodes", cfg.Decodes))
	rt.Ready()
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}
