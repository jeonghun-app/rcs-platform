package hss

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// Service is the HSS for runtime.Main.
func Service() runtime.Service[Config] {
	// LiveAfterReady: start-up opens DynamoDB and KMS and may end at
	// HSS_START_TIMEOUT (#58); until then the container is not healthy.
	return runtime.Service[Config]{Name: "hss", EnvPrefix: "HSS_", Configure: Configure, Run: Run, LiveAfterReady: true}
}

// deps are what Run takes from the outside world, replaced in tests.
type deps struct {
	listen func(network, address string) (net.Listener, error)
	rand   io.Reader
	// aws opens the DynamoDB store and, with a KMS key, the master key.
	aws func(ctx context.Context, c awsstore.Config) (readyStore, keyring.Wrapper, error)
}

// readyStore is a store with a readiness check, as *awsstore.Dynamo is.
type readyStore interface {
	store.Store
	Ready(ctx context.Context) error
}

func defaultDeps() deps {
	return deps{listen: net.Listen, rand: rand.Reader, aws: openAWS}
}

func openAWS(ctx context.Context, c awsstore.Config) (readyStore, keyring.Wrapper, error) {
	clients, err := awsstore.NewClients(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	var w keyring.Wrapper
	if c.KMSKeyID != "" {
		w = awsstore.NewKMS(clients.KMS, c.KMSKeyID)
	}
	return awsstore.NewDynamo(clients.DynamoDB, c), w, nil
}

// Run serves Cx on the Diameter listener and the provisioning API on its own
// listener, separate from the runtime's admin port that serves health
// checks, until ctx ends.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	return run(ctx, rt, cfg, defaultDeps())
}

func run(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) error {
	st, keys, err := start(ctx, rt, cfg, d)
	if err != nil {
		return err
	}
	h, err := New(Options{
		Store: st, Keys: keys, IMSRealm: cfg.IMSRealm, FTRealm: cfg.FTRealm, ServerNames: cfg.SCSCFNames,
		MaxAuthItems: cfg.MaxAuthItems, Rand: d.rand, Logger: rt.Logger, Metrics: rt.Metrics,
	})
	if err != nil {
		return err
	}

	host := cfg.OriginHost
	if host == "" {
		// A fresh identity at every start (ADR 0005): a peer reconnecting to
		// another task, or to this one restarted, never meets an Origin-Host
		// whose previous connection failed, which would hold the new
		// connection in the watchdog's REOPEN state.
		label := make([]byte, 6)
		if _, err := io.ReadFull(d.rand, label); err != nil {
			return err
		}
		host = "hss-" + hex.EncodeToString(label) + "." + cfg.Namespace
	}
	dict, err := diameter.NewDictionary(cx.AVPs...)
	if err != nil {
		return err
	}
	node, err := diameter.NewNode(diameter.Config{
		OriginHost:         host,
		OriginRealm:        cfg.OriginRealm,
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dict,
		Accept:             []diameter.PeerRule{{Realm: cfg.PeerRealm, Networks: cfg.PeerNetworks}},
		Logger:             rt.Logger,
	})
	if err != nil {
		return err
	}
	h.ServeCx(node, cfg.CxTimeout)
	pusher := NewPusher(node, PusherOptions{
		SCSCFHostPattern: cfg.SCSCFPattern, Timeout: cfg.PushTimeout, Metrics: rt.Metrics,
		Shuffle: func(p []*diameter.Peer) { mathrand.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] }) },
	})
	api := h.NewAPI(APIOptions{
		Tokens: cfg.Tokens.t, ACSRate: float64(cfg.ACSRate), ACSBurst: cfg.ACSBurst, Notifier: pusher,
		DefaultProfile: cfg.DefaultProfile, PushTimeout: cfg.PushTimeout, StoreTimeout: cfg.APITimeout,
	})

	dl, err := d.listen("tcp", cfg.DiameterAddr)
	if err != nil {
		return err
	}
	al, err := d.listen("tcp", cfg.APIAddr)
	if err != nil {
		_ = dl.Close()
		return err
	}
	hs := &http.Server{
		Handler:           api,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          runtime.HTTPErrorLog(rt.Logger),
	}
	failed := make(chan error, 2)
	go func() {
		if err := node.Serve(dl); !errors.Is(err, diameter.ErrNodeClosed) {
			failed <- fmt.Errorf("hss: Diameter listener: %w", err)
		}
	}()
	go func() {
		if err := hs.Serve(al); !errors.Is(err, http.ErrServerClosed) {
			failed <- fmt.Errorf("hss: API listener: %w", err)
		}
	}()
	// Hooks run last registered first: the API stops taking requests, then
	// its background pushes stop, then Diameter peers are told goodbye.
	rt.OnShutdown("diameter", node.Shutdown)
	rt.OnShutdown("profile pushes", api.Close)
	rt.OnShutdown("provisioning API", hs.Shutdown)

	rt.Logger.Info("serving Cx and the provisioning API",
		slog.String("origin_host", host), slog.String("diameter_addr", dl.Addr().String()),
		slog.String("api_addr", al.Addr().String()), slog.String("key", keyDescription(cfg)))
	rt.Ready()
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}

func keyDescription(cfg Config) string {
	if cfg.KMSKeyID != "" {
		return "kms"
	}
	return "local"
}

// start opens the store and the keyring and creates the default profile,
// within HSS_START_TIMEOUT. Without the bound, a task whose route to
// DynamoDB or KMS drops packets would wait out the SDK's dial timeouts and
// retries for minutes before failing, holding a place in a rolling update;
// with it, the task exits soon and plainly, which ECS's deployment circuit
// breaker sees. /readyz answers "starting" until then.
func start(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) (store.Store, *keyring.Keyring, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.StartTimeout)
	defer cancel()
	st, keys, err := openStore(ctx, rt, cfg, d)
	if err != nil {
		return nil, nil, fmt.Errorf("hss: start-up: %w", err)
	}
	if cfg.CreateDefaultProfile {
		if err := ensureProfile(ctx, st, DefaultRCSProfile(cfg.DefaultProfile, cfg.RCSASURI)); err != nil {
			return nil, nil, fmt.Errorf("hss: creating the default service profile: %w", err)
		}
	}
	return st, keys, nil
}

// openStore opens the store and the keyring the configuration names.
func openStore(ctx context.Context, rt *runtime.Runtime, cfg Config, d deps) (store.Store, *keyring.Keyring, error) {
	localKey := func() ([]byte, error) {
		if cfg.DataKey.v != "" {
			return base64.StdEncoding.DecodeString(cfg.DataKey.v)
		}
		// Memory store only (Configure requires the key otherwise): secrets
		// live as long as the process, and so may the key.
		rt.Logger.Warn("HSS_DATA_KEY is unset: using a random data key for this process")
		k := make([]byte, keyring.DataKeySize)
		_, err := io.ReadFull(d.rand, k)
		return k, err
	}
	if cfg.Store == StoreMemory {
		k, err := localKey()
		if err != nil {
			return nil, nil, err
		}
		keys, err := keyring.NewLocal(k, d.rand)
		return store.NewMemory(), keys, err
	}
	dyn, wrapper, err := d.aws(ctx, awsstore.Config{
		SubscribersTable: cfg.SubscribersTable, ProfilesTable: cfg.ProfilesTable,
		KMSKeyID: cfg.KMSKeyID, DynamoDBEndpoint: cfg.DynamoDBEndpoint,
	})
	if err != nil {
		return nil, nil, err
	}
	rt.Admin.AddReadinessCheck("dynamodb", dyn.Ready)
	if wrapper == nil {
		k, err := localKey()
		if err != nil {
			return nil, nil, err
		}
		keys, err := keyring.NewLocal(k, d.rand)
		return dyn, keys, err
	}
	// A first data key is created for an empty table, or when the operator
	// says so: a table with subscriptions but no key has lost its key, and
	// a new one would make restoring the old one a second loss.
	hasSubs, err := dyn.HasSubscriptions(ctx)
	if err != nil {
		return nil, nil, err
	}
	created := false
	keys, err := keyring.Open(ctx, wrapper, dyn, keyring.OpenOptions{
		Rand: d.rand, Create: cfg.KeyringBootstrap || !hasSubs,
		Created: func(id string) {
			created = true
			rt.Metrics.Count("keyring.created", 1)
			rt.Logger.Warn("created the first data key of the subscriber secrets", slog.String("key_id", id),
				slog.Bool("bootstrap_flag", cfg.KeyringBootstrap))
		},
	})
	if errors.Is(err, keyring.ErrNoDataKey) {
		return nil, nil, errors.New("hss: the subscribers table holds subscriptions but no data key; " +
			"restore the keyring item (docs/hss.md, Secrets), or set HSS_KEYRING_BOOTSTRAP=true to start over with a new key")
	}
	if err != nil {
		return nil, nil, err
	}
	if cfg.KeyringBootstrap && !created {
		// Left set, the flag would let a later loss of the keyring item
		// pass unnoticed: say so at every start until it is removed.
		rt.Logger.Warn("HSS_KEYRING_BOOTSTRAP is set although a data key exists; remove it")
	}
	return dyn, keys, nil
}

// ensureProfile creates p unless a profile with its ID exists; an operator's
// changes to the default profile survive restarts.
func ensureProfile(ctx context.Context, st store.Store, p *store.ServiceProfile) error {
	_, err := st.CreateProfile(ctx, p)
	if errors.Is(err, store.ErrExists) {
		return nil
	}
	return err
}
