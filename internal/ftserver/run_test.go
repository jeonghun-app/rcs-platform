package ftserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	goruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ftserver/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
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

// waitReady returns once the runtime has logged "ready", yielding to the
// goroutine running Run; it fails the test after ten seconds.
func waitReady(t *testing.T, h *runtimetest.Harness) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for len(h.Logs("ready")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run never reported ready")
		}
		goruntime.Gosched()
	}
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
	// Run reports ready just after it starts serving, which is after the
	// listener exists: wait for the "ready" line rather than racing it.
	waitReady(t, h)
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

// The production wiring, end to end: Run in staging builds the HSS client
// with runtime.InternalDialer, so an HSS URL that is (or resolves to) a
// loopback address gets no request and no token, while in test, which runs
// the HSS on loopback, the same lookup reaches it (#87).
func TestRunInStagingNeverSendsTheHSSTokenToALoopbackAddress(t *testing.T) {
	for env, wantReached := range map[runtime.Environment]int{runtime.Staging: 0, runtime.Test: 1} {
		t.Run(string(env), func(t *testing.T) {
			var reached atomic.Int32
			hss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				http.NotFound(w, r)
			}))
			defer hss.Close()
			cfg, err := configure(with(devEnv, "FT_CREDENTIALS", "hss", "FT_HSS_URL", hss.URL, "FT_HSS_TOKEN", "provisioning-token", "FT_STATIC_USERS", ""))
			if err != nil {
				t.Fatal(err)
			}
			h := runtimetest.New(t, "ft-server")
			h.Runtime.Environment = env
			addr, cancel, done := startRun(t, h, cfg)
			defer func() { cancel(); <-done }()
			resp, err := http.Post("http://"+addr+"/ft", "", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			var ch digest.Challenge
			for _, v := range resp.Header.Values("WWW-Authenticate") {
				if c, err := digest.ParseChallenge(v); err == nil && c.Algorithm == digest.SHA256 {
					ch = c
				}
			}
			c, err := digest.Respond(ch, digest.ClientParams{Username: alice, Password: []byte(password), Method: http.MethodPost,
				URI: "/ft", CNonce: "cnonce-1", NC: 1})
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/ft", nil)
			req.Header.Set("Authorization", c.Header())
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := int(reached.Load()); got != wantReached {
				t.Fatalf("the HSS got %d requests, want %d (status %d)", got, wantReached, resp.StatusCode)
			}
			if strings.Contains(h.Output(), "provisioning-token") {
				t.Fatalf("the token was logged:\n%s", h.Output())
			}
		})
	}
}
