package maap

import (
	"context"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Service is maap for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "maap", EnvPrefix: "MAAP_", Configure: Configure, Run: Run}
}

// Run serves maap until ctx ends. The runtime's admin port serves the
// health checks; the internal listener follows in the second part of #707.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	rt.Logger.Info("maap started", slog.String("alias_host", cfg.AliasHost), slog.Int("decodes", cfg.Decodes))
	rt.Ready()
	<-ctx.Done()
	return nil
}
