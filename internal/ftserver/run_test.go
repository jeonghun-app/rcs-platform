package ftserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

func listenLoopback(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

// startRun runs Run with cfg on a loopback listener and returns the public
// address and a channel with Run's result.
func startRun(t *testing.T, h *runtimetest.Harness, cfg Config) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	addrs := make(chan string, 1)
	listen = func(network, _ string) (net.Listener, error) {
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			addrs <- ln.Addr().String()
		}
		return ln, err
	}
	t.Cleanup(func() { listen = net.Listen })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, h.Runtime, cfg) }()
	select {
	case addr := <-addrs:
		return addr, cancel, done
	case err := <-done:
		cancel()
		t.Fatalf("Run returned before listening: %v", err)
	}
	return "", cancel, done
}

func TestRunServesUntilCancelledAndDrainsOnShutdown(t *testing.T) {
	h := runtimetest.New(t, "ft-server")
	cfg, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	addr, cancel, done := startRun(t, h, cfg)
	resp, err := http.Post("http://"+addr+"/ft", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Header.Values("WWW-Authenticate")) != 2 {
		t.Fatalf("pre-check = %d", resp.StatusCode)
	}
	if code, _ := h.Get("/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v", err)
	}
	ctx, stop := h.WithTimeout(time.Minute)
	defer stop()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Post("http://"+addr+"/ft", "", nil); err == nil {
		t.Fatal("the public listener still answers after shutdown")
	}
}

func TestRunWiresTheAWSStoresAndTheHSS(t *testing.T) {
	h := runtimetest.New(t, "ft-server")
	cfg, err := configure(with(devEnv,
		"FT_STORE", "aws", "FT_S3_BUCKET", "bucket", "FT_S3_ENDPOINT", "http://127.0.0.1:1", "FT_DYNAMODB_ENDPOINT", "http://127.0.0.1:1",
		"FT_CREDENTIALS", "hss", "FT_HSS_URL", "http://127.0.0.1:1", "FT_HSS_TOKEN", "t", "FT_STATIC_USERS", "",
		"FT_NONCE_KEY", "0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_REGION", "us-east-1")
	addr, cancel, done := startRun(t, h, cfg)
	defer func() { cancel(); <-done }()
	resp, err := http.Post("http://"+addr+"/ft", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("pre-check = %d", resp.StatusCode)
	}
}

func TestRunFailsWhenItCannotListen(t *testing.T) {
	h := runtimetest.New(t, "ft-server")
	cfg, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	listen = func(string, string) (net.Listener, error) { return nil, errors.New("address in use") }
	t.Cleanup(func() { listen = net.Listen })
	if err := Run(t.Context(), h.Runtime, cfg); err == nil {
		t.Fatal("Run without a listener succeeded")
	}
}

// failingMetadata fails ListExpired like a table that is unreachable.
type failingMetadata struct{ store.Metadata }

func (failingMetadata) ListExpired(context.Context, time.Time, int) ([]store.Record, error) {
	return nil, errors.New("table unreachable")
}

func TestSweepRunsOnEveryTickAndReportsFailures(t *testing.T) {
	e := newEnv(t)
	e.user(alice).uploadFile("old", "x")
	e.clock.Advance(e.opts.Validity + time.Second)
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); sweep(ctx, e.srv, tick, e.h.Runtime.Logger) }()
	tick <- time.Time{}
	tick <- time.Time{} // the first sweep has finished once the second tick is taken
	cancel()
	<-done
	if e.metric("sweep.expired") != 1 {
		t.Fatalf("sweep.expired = %v", e.metric("sweep.expired"))
	}

	f := newEnv(t, func(o *Options) { o.Metadata = failingMetadata{store.NewMemory()} })
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	go func() { defer close(done); sweep(ctx, f.srv, tick, f.h.Runtime.Logger) }()
	tick <- time.Time{}
	tick <- time.Time{}
	cancel()
	<-done
	if f.metric("sweep.failed") < 1 || len(f.h.Logs("sweep failed")) < 1 {
		t.Fatal("sweep failure not reported")
	}
}
