package maap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Service is maap for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "maap", EnvPrefix: "MAAP_", Configure: Configure, Run: Run}
}

// deps are what Run takes from the outside world, replaced in tests.
type deps struct {
	listen func(network, address string) (net.Listener, error)
	// registry and credentials replace maap-registry in DynamoDB; /readyz
	// checks each table whose store has a Ready method, as the DynamoDB
	// ones do.
	registry    store.Registry
	credentials store.Credentials
	// requests, counters and subscribers replace maap-requests,
	// maap-counters and maap-subscribers, with the registry only.
	requests    store.Requests
	counters    store.Counters
	subscribers store.Subscribers
}

// Run serves the internal listener, apart from the runtime's admin port
// that serves health checks, until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, deps{listen: net.Listen})
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	registry, creds, requests, counters, subs := d.registry, d.credentials, d.requests, d.counters, d.subscribers
	if registry == nil {
		ddb, err := awsstore.NewClient(ctx, cfg.DynamoDBEndpoint)
		if err != nil {
			return fmt.Errorf("maap: %w", err)
		}
		r := awsstore.NewRegistry(ddb, cfg.RegistryTable)
		registry, creds = r, r.Credentials()
		requests = awsstore.NewRequests(ddb, cfg.RequestsTable, cfg.StoreKey, cfg.StatusTTL)
		counters = awsstore.NewCounters(ddb, cfg.CountersTable, cfg.StoreKey)
		subs = awsstore.NewSubscribers(ddb, cfg.SubscribersTable)
	}
	for _, t := range []struct {
		name  string
		table any
	}{
		{"dynamodb-registry", registry}, {"dynamodb-requests", requests}, {"dynamodb-counters", counters},
		{"dynamodb-subscribers", subs},
	} {
		if r, ok := t.table.(interface{ Ready(context.Context) error }); ok {
			rt.Admin.AddReadinessCheck(t.name, r.Ready)
		}
	}
	// The internal listener's own decode pool: #683 gives the public
	// listener another, so that chatbots cannot take rcs-as's slots.
	api := newInternalAPI(cfg.OperatorTokens, newDecoder(cfg.Decodes, rt.Metrics), rt)
	api.mountChatbots(&chatbotAPI{
		decoder: api.decoder, registry: registry, domain: cfg.ChatbotDomain,
		rules: fieldRules{ports: cfg.WebhookPorts, allowHTTP: cfg.HTTPWebhooks, allowInternal: cfg.InternalWebhooks},
		// Every store of a chatbot's items is a deleter (#742 review), the
		// credentials too, though the registry's deletion takes them with
		// its partition already; the counters, a day long at most, go by
		// TTL alone (lead decision on #713).
		deleters: []store.ChatbotDeleter{creds, requests, subs},
	})
	api.mountCredentials(&credentialAPI{registry: registry, creds: creds, random: rand.Reader, now: time.Now})
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
