package ftserver

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

// Service is ft-server for runtime.Main.
func Service() runtime.Service[Config] {
	return runtime.Service[Config]{Name: "ft-server", EnvPrefix: "FT_", Configure: Configure, Run: Run}
}

// listen opens the public listener; tests replace it.
var listen = net.Listen

// Run serves cfg until ctx ends. The public listener is plain HTTP: TLS ends
// at the ALB (ADR 0003), and the URIs clients see are https in staging and
// prod (Configure refuses anything else). Uploads still running at shutdown
// get until the runtime's shutdown deadline; one cut off there leaves its
// durable parts, and the client resumes on another task.
func Run(ctx context.Context, rt *runtime.Runtime, cfg Config) error {
	stores, err := openStores(ctx, cfg, rt)
	if err != nil {
		return err
	}
	nonceKey := []byte(cfg.NonceKey.v)
	if len(nonceKey) == 0 {
		// Dev and test only (Configure refuses it in production): one task's
		// nonces are then valid nowhere else, which a single task never
		// notices.
		nonceKey = make([]byte, digest.MinNonceKeySize)
		if _, err := rand.Read(nonceKey); err != nil {
			return err
		}
	}
	ds, err := digest.NewServer(digest.ServerConfig{Realm: cfg.Realm, NonceKey: nonceKey, NonceCounts: stores.nonces})
	if err != nil {
		return err
	}
	srv, err := New(Options{
		UploadURI:            cfg.UploadURI,
		DownloadURI:          cfg.DownloadURI,
		BrandedURI:           cfg.BrandedURI,
		Digest:               ds,
		Credentials:          credentialSource(cfg),
		Metadata:             stores.metadata,
		Blobs:                stores.blobs,
		Logger:               rt.Logger,
		Metrics:              rt.Metrics,
		MaxSize:              cfg.MaxSize,
		MaxThumbnailSize:     cfg.MaxThumbnailSize,
		PartSize:             cfg.PartSize,
		Validity:             cfg.Validity,
		DownloadAuth:         cfg.DownloadAuth,
		UploadsPerMinute:     cfg.UploadsPerMinute,
		MaxConcurrentUploads: cfg.MaxConcurrentUploads,
		IdleTimeout:          cfg.IdleTimeout,
		UploadTimeout:        cfg.UploadTimeout,
		StorageTimeout:       cfg.StorageTimeout,
	})
	if err != nil {
		return err
	}

	ln, err := listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler: srv,
		// No ReadTimeout or WriteTimeout: a 100 MiB transfer over a slow
		// radio link can take many minutes. Bodies get per-read and
		// per-write deadlines from the handler (IdleTimeout, UploadTimeout)
		// instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(rt.Logger.Handler(), slog.LevelWarn),
	}
	served := make(chan error, 1)
	go func() { served <- hs.Serve(ln) }()
	rt.OnShutdown("public listener", hs.Shutdown)

	ticker := time.NewTicker(cfg.SweepInterval)
	defer ticker.Stop()
	sweepDone := make(chan struct{})
	sweepCtx, stopSweep := context.WithCancel(ctx)
	go func() {
		defer close(sweepDone)
		sweep(sweepCtx, srv, ticker.C, rt.Logger)
	}()
	defer func() { stopSweep(); <-sweepDone }()

	rt.Logger.Info("serving file transfer", slog.String("addr", ln.Addr().String()))
	rt.Ready()
	select {
	case <-ctx.Done():
		return nil
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// sweep runs Server.Sweep on every tick until ctx ends.
func sweep(ctx context.Context, srv *Server, tick <-chan time.Time, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		if _, err := srv.Sweep(ctx); err != nil && ctx.Err() == nil {
			srv.metrics.Count("sweep.failed", 1)
			log.Warn("sweep failed", slog.String("error", pii.Redact(err.Error())))
		}
	}
}

type stores struct {
	metadata store.Metadata
	blobs    store.Blobs
	nonces   digest.NonceCountStore
}

func openStores(ctx context.Context, cfg Config, rt *runtime.Runtime) (stores, error) {
	if cfg.Store == StoreMemory {
		return stores{
			metadata: store.NewMemory(),
			blobs:    store.NewMemoryBlobs(minPartSize),
			nonces:   digest.NewMemoryNonceCounts(nil),
		}, nil
	}
	a := cfg.AWS
	s, err := awsstore.New(ctx, awsstore.Config{
		Bucket: a.Bucket, Prefix: a.Prefix, Table: a.Table, SSE: a.SSE, KMSKeyID: a.KMSKeyID,
		S3Endpoint: a.S3Endpoint, DynamoDBEndpoint: a.DynamoDBEndpoint,
	})
	if err != nil {
		return stores{}, err
	}
	rt.Admin.AddReadinessCheck("storage", s.Ready)
	return stores{metadata: s.Metadata, blobs: s.Blobs, nonces: s.NonceCounts}, nil
}

func credentialSource(cfg Config) CredentialSource {
	if cfg.Credentials == CredentialsStatic {
		users := make(map[string]string, len(cfg.StaticUsers))
		for name, password := range cfg.StaticUsers {
			users[name] = password.v
		}
		return NewStaticCredentials(users)
	}
	return NewHSSCredentials(cfg.HSSURL, cfg.HSSToken.v, cfg.Realm, cfg.HSSTimeout)
}
