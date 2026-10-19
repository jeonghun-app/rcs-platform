package ftserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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

// inCI reports whether the tests run in CI, where make passes the CI
// variable into the toolchain container. "false" and "0" mean not.
func inCI() bool {
	v := os.Getenv("CI")
	return v != "" && v != "false" && v != "0"
}

// privateIPv4 returns an RFC 1918 address of this host, such as a
// container's eth0. Without one the test is skipped, except in CI (the CI
// variable, which make passes into the toolchain container), where a skip
// would go unseen without -v and leave the production dial untested (#119).
func privateIPv4(t *testing.T) netip.Addr {
	t.Helper()
	skip := t.Skipf
	if inCI() {
		skip = t.Fatalf
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		skip("no interface addresses: %v", err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && runtime.IsPrivateAddr(p.Addr()) {
			return p.Addr()
		}
	}
	skip("this host has no RFC 1918 address to put the HSS on")
	return netip.Addr{}
}

// authenticateOnce makes the pre-check POST, answers its SHA-256 challenge
// as alice and returns the status of the signed request.
func authenticateOnce(t *testing.T, addr string) int {
	t.Helper()
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
	return resp.StatusCode
}

// The production wiring, end to end: Run in staging builds the HSS client
// with runtime.InternalDialer, so an HSS URL that is (or resolves to) a
// loopback address gets no request and no token, and the client is told to
// retry, while an HSS at a private address is reached and the user
// authenticated, as in test, which runs the HSS on loopback (#87, #114).
func TestRunInStagingReachesTheHSSOnlyAtAPrivateAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     runtime.Environment
		host    func(*testing.T) string
		reached int32
		refused bool
	}{
		{"staging, loopback", runtime.Staging, func(*testing.T) string { return "127.0.0.1" }, 0, true},
		{"staging, private", runtime.Staging, func(t *testing.T) string { return privateIPv4(t).String() }, 1, false},
		{"test, loopback", runtime.Test, func(*testing.T) string { return "127.0.0.1" }, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Int32
			ln, err := net.Listen("tcp", net.JoinHostPort(tc.host(t), "0"))
			if err != nil {
				t.Fatal(err)
			}
			hss := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Add(1)
				fmt.Fprint(w, credentialJSON(t, digest.SHA256, alice))
			}))
			hss.Listener.Close()
			hss.Listener = ln
			hss.Start()
			defer hss.Close()
			cfg, err := configure(with(devEnv, "FT_CREDENTIALS", "hss", "FT_HSS_URL", hss.URL, "FT_HSS_TOKEN", "provisioning-token", "FT_STATIC_USERS", ""))
			if err != nil {
				t.Fatal(err)
			}
			h := runtimetest.New(t, "ft-server")
			h.Runtime.Environment = tc.env
			addr, cancel, done := startRun(t, h, cfg)
			defer func() { cancel(); <-done }()
			status := authenticateOnce(t, addr)
			if got := reached.Load(); got != tc.reached {
				t.Fatalf("the HSS got %d requests, want %d (status %d)", got, tc.reached, status)
			}
			failures := h.Logs("credential lookup failed")
			if tc.refused {
				// Refused by the dialer, not for another reason: the
				// lookup failed with ErrAddressNotPrivate and the client
				// is told to retry.
				if status != http.StatusServiceUnavailable || len(failures) != 1 ||
					!strings.Contains(fmt.Sprint(failures[0]["error"]), runtime.ErrAddressNotPrivate.Error()) {
					t.Fatalf("status %d, lookup failures %v, want 503 and ErrAddressNotPrivate", status, failures)
				}
			} else if status != http.StatusNoContent || len(failures) != 0 {
				t.Fatalf("status %d, lookup failures %v, want alice authenticated", status, failures)
			}
			if strings.Contains(h.Output(), "provisioning-token") {
				t.Fatalf("the token was logged:\n%s", h.Output())
			}
		})
	}
}

// The production wiring gives the dialer FT_HSS_TIMEOUT: http.Client's
// Timeout answers the caller in time, but the transport dials with a
// context the request's end does not cancel, so without it a dial to an
// address that never answers would hold a connection slot long after
// (#119; QA's test from the reviews of #116 and #123). 10.255.255.1 hangs
// on this host and CI runners. Where it is refused at once instead, the
// test cannot see the dial timeout, and says so: it skips, or in CI fails.
//
// The production dialer is wrapped to see when it returns. A dialer bound
// by FT_HSS_TIMEOUT returns no sooner than that after it began, since a
// deadline never fires early, and one given DefaultHSSTimeout instead
// returns sooner than the 3 s here. A dial that took more than 6 s past
// FT_HSS_TIMEOUT has a longer timeout, such as DefaultDrainTimeout (10 s)
// or DefaultIdleTimeout (30 s); 6 s is room for a loaded host, which made
// the dial leave its stack 1.3 s late (#158). One that has not returned
// after 30 s is unbounded, and runs until the kernel gives up on the
// connection after minutes (review of #172).
func TestTheProductionHSSDialEndsWithinTheHSSTimeout(t *testing.T) {
	const hssTimeout = 3 * time.Second
	if DefaultHSSTimeout >= hssTimeout {
		t.Fatalf("DefaultHSSTimeout %v is not below the %v this test uses", DefaultHSSTimeout, hssTimeout)
	}
	cfg := Config{Credentials: CredentialsHSS, HSSURL: mustURL("http://10.255.255.1:8081"), HSSTimeout: hssTimeout, MaxLookups: 1, Realm: realm}
	src := credentialSource(cfg, true).(*HSSCredentials)
	transport := src.client.Transport.(*http.Transport)
	dial := transport.DialContext
	if dial == nil {
		t.Fatal("the production HSS client has no dialer of its own")
	}
	took := make(chan time.Duration, 1)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		start := time.Now()
		c, err := dial(ctx, network, address)
		select {
		case took <- time.Since(start):
		default:
		}
		return c, err
	}
	_, err := src.Lookup(t.Context(), alice, digest.SHA256)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		msg := "10.255.255.1 did not hang here (%v), so this test cannot see the dial timeout"
		if inCI() {
			t.Fatalf(msg, err)
		}
		t.Skipf(msg, err)
	}
	select {
	case d := <-took:
		if d < hssTimeout {
			t.Fatalf("the dial gave up after %v, before the %v FT_HSS_TIMEOUT: it has another timeout", d, hssTimeout)
		}
		if d > hssTimeout+6*time.Second {
			t.Fatalf("the dial gave up after %v, long after the %v FT_HSS_TIMEOUT: it has another timeout", d, hssTimeout)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("the dial still runs 30s after it began, with a %v FT_HSS_TIMEOUT", hssTimeout)
	}
}
