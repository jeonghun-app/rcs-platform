package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/buildinfo"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

type testConfig struct {
	store string
}

func configureTest(s *Settings) testConfig {
	c := testConfig{store: s.Env.String("STORE", "dynamodb")}
	s.ForbidInProduction(c.store == "memory", "TESTSVC_STORE=memory keeps state in one task")
	return c
}

func testService(run func(ctx context.Context, rt *Runtime, cfg testConfig) error) Service[testConfig] {
	return Service[testConfig]{Name: "testsvc", EnvPrefix: "TESTSVC_", Configure: configureTest, Run: run}
}

func waitForStop(ctx context.Context, _ *Runtime, _ testConfig) error {
	<-ctx.Done()
	return nil
}

// harness runs a service in the background on a loopback admin listener.
type harness struct {
	t       *testing.T
	out     *lockedBuffer
	timers  *fakeTimers
	cancel  context.CancelFunc
	exit    chan int
	adminCh chan string
}

func startService(t *testing.T, env envMap, svc Service[testConfig]) *harness {
	t.Helper()
	restoreDefaults(t)
	h := &harness{t: t, out: &lockedBuffer{}, timers: newFakeTimers(), exit: make(chan int, 1), adminCh: make(chan string, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	t.Cleanup(cancel)
	p := Process{
		LookupEnv: env.lookup,
		Stdout:    h.out,
		Listen: func(network, _ string) (net.Listener, error) {
			ln, err := net.Listen(network, "127.0.0.1:0")
			if err == nil {
				h.adminCh <- ln.Addr().String()
			}
			return ln, err
		},
		Now:   func() time.Time { return epoch },
		After: h.timers.After,
	}
	go func() { h.exit <- Run(ctx, svc, p) }()
	return h
}

func (h *harness) adminURL(path string) string {
	h.t.Helper()
	select {
	case addr := <-h.adminCh:
		h.adminCh <- addr
		return "http://" + addr + path
	case code := <-h.exit:
		h.t.Fatalf("Run exited with %d before listening:\n%s", code, h.out.String())
	}
	return ""
}

func (h *harness) wait() int {
	h.t.Helper()
	return <-h.exit
}

func httpGet(t *testing.T, u string) int {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// testPIIKey is an HMAC key of the minimum length, for environments that need
// one.
var testPIIKey = strings.Repeat("k", 32)

func devEnv() envMap {
	return envMap{"RCS_ENV": "dev", "RCS_SHUTDOWN_TIMEOUT": "7s", "RCS_PII_HMAC_KEY": testPIIKey}
}

const missingKeyReason = "RCS_PII_HMAC_KEY is unset: log hints would show the last two characters of each identifier"

const testShutdownTimeout = 7 * time.Second

func TestVersionFlagPrintsTheBuildInfoString(t *testing.T) {
	var out bytes.Buffer
	code := Run(context.Background(), testService(waitForStop), Process{Args: []string{"-version"}, Stdout: &out})
	if code != ExitOK || out.String() != buildinfo.String("testsvc")+"\n" {
		t.Fatalf("-version: %d %q", code, out.String())
	}
}

func TestVersionNeedsNoConfiguration(t *testing.T) {
	var out bytes.Buffer
	code := Run(context.Background(), testService(waitForStop), Process{
		Args: []string{"-version"}, Stdout: &out, LookupEnv: envMap{"RCS_ENV": "nonsense"}.lookup,
	})
	if code != ExitOK {
		t.Fatalf("-version with a bad environment: %d", code)
	}
}

func TestBadArgumentsAreUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"-nope"}, {"extra"}, {"-version", "-healthcheck"}} {
		var stderr bytes.Buffer
		if code := Run(context.Background(), testService(waitForStop), Process{Args: args, Stderr: &stderr}); code != ExitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
		if stderr.Len() == 0 {
			t.Errorf("%q: nothing on stderr", args)
		}
	}
	if code := Run(context.Background(), testService(waitForStop), Process{Args: []string{"-h"}}); code != ExitOK {
		t.Errorf("-h: exit %d", code)
	}
}

func adminEnvFor(t *testing.T, srv *httptest.Server) envMap {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return envMap{"RCS_ADMIN_ADDR": u.Host}
}

func TestHealthcheckSucceedsOnlyOn200(t *testing.T) {
	for status, want := range map[int]int{200: ExitOK, 503: ExitFailure, 302: ExitFailure, 404: ExitFailure} {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ok" {
				return // 200: following the redirect would turn failure into success
			}
			gotPath = r.URL.Path
			if status == 302 {
				w.Header().Set("Location", "/ok")
			}
			w.WriteHeader(status)
		}))
		var stderr bytes.Buffer
		code := Run(context.Background(), testService(waitForStop), Process{
			Args: []string{"-healthcheck"}, LookupEnv: adminEnvFor(t, srv).lookup, Stderr: &stderr,
		})
		srv.Close()
		if code != want || gotPath != "/healthz" {
			t.Errorf("status %d: exit %d, path %q, stderr %q", status, code, gotPath, stderr.String())
		}
	}
}

func TestHealthcheckGivesUpAfterThreeSeconds(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
	}))
	defer srv.Close()
	defer close(release)
	timers := newFakeTimers()
	go func() {
		<-entered
		timers.Fire(3 * time.Second)
	}()
	code := Run(context.Background(), testService(waitForStop), Process{
		Args: []string{"-healthcheck"}, LookupEnv: adminEnvFor(t, srv).lookup, After: timers.After,
	})
	if code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	if !slices.Contains(timers.Made(), 3*time.Second) {
		t.Fatalf("timers made: %v", timers.Made())
	}
}

func TestHealthcheckFailsWhenNothingListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	code := Run(context.Background(), testService(waitForStop), Process{
		Args: []string{"-healthcheck"}, LookupEnv: envMap{"RCS_ADMIN_ADDR": addr}.lookup,
	})
	if code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
}

// ProxyFromEnvironment never proxies loopback, so an end-to-end test against
// 127.0.0.1 could not tell; the probe can also target a non-loopback admin
// address, where a proxy would matter.
func TestHealthcheckIgnoresProxySettings(t *testing.T) {
	c := probeClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatalf("probe transport = %#v, want one without a proxy", c.Transport)
	}
	if err := c.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("probe follows redirects: %v", err)
	}
}

func TestHealthcheckRefusesABadAdminAddress(t *testing.T) {
	var stderr bytes.Buffer
	code := Run(context.Background(), testService(waitForStop), Process{
		Args: []string{"-healthcheck"}, LookupEnv: envMap{"RCS_ADMIN_ADDR": "admin:8080"}.lookup, Stderr: &stderr,
	})
	if code != ExitFailure || !strings.Contains(stderr.String(), "RCS_ADMIN_ADDR") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}

func TestConfigurationProblemsAreReportedTogetherBeforeAnythingStarts(t *testing.T) {
	restoreDefaults(t)
	var out lockedBuffer
	listened := false
	svc := testService(func(context.Context, *Runtime, testConfig) error {
		t.Error("Run was called")
		return nil
	})
	svc.Configure = func(s *Settings) testConfig {
		s.Env.Int("PORT", 5060)
		s.Shared.RequiredString("IMS_DOMAIN")
		return testConfig{}
	}
	code := Run(context.Background(), svc, Process{
		LookupEnv: envMap{"RCS_ENV": "prod", "RCS_PII_HMAC_KEY": testPIIKey, "RCS_LOG_LEVEL": "chatty", "TESTSVC_PORT": "fivethousand"}.lookup,
		Stdout:    &out,
		Listen: func(string, string) (net.Listener, error) {
			listened = true
			return nil, errors.New("unexpected")
		},
	})
	if code != ExitFailure || listened {
		t.Fatalf("exit %d, listened %v", code, listened)
	}
	rec := record(t, out.String(), "configuration rejected")
	got := toStrings(rec["problems"])
	want := []string{
		"RCS_LOG_LEVEL: not one of debug, info, warn, error",
		"TESTSVC_PORT: not a base-10 integer in range",
		"RCS_IMS_DOMAIN: required",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("problems = %q\nwant %q", got, want)
	}
	if strings.Contains(out.String(), "fivethousand") || strings.Contains(out.String(), "chatty") {
		t.Fatalf("values were echoed: %s", out.String())
	}
	if rec["service"] != "testsvc" {
		t.Fatalf("record = %v", rec)
	}
}

func TestProductionRefusesEveryUnsafeSetting(t *testing.T) {
	for _, env := range []string{"staging", "prod"} {
		restoreDefaults(t)
		var out lockedBuffer
		svc := testService(waitForStop)
		svc.Configure = func(s *Settings) testConfig {
			s.ForbidInProduction(true, "TESTSVC_STORE=memory keeps state in one task")
			s.ForbidInProduction(false, "this one is fine")
			s.ForbidInProduction(true, "TESTSVC_TLS=false sends SIP in clear")
			return testConfig{}
		}
		code := Run(context.Background(), svc, Process{LookupEnv: envMap{"RCS_ENV": env, "RCS_PII_HMAC_KEY": testPIIKey}.lookup, Stdout: &out})
		if code != ExitFailure {
			t.Fatalf("%s: exit %d", env, code)
		}
		got := toStrings(record(t, out.String(), "configuration rejected")["problems"])
		want := []string{
			"refused in " + env + ": TESTSVC_STORE=memory keeps state in one task",
			"refused in " + env + ": TESTSVC_TLS=false sends SIP in clear",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: problems = %q", env, got)
		}
	}
}

func TestStagingAndProdRequireThePIIHMACKey(t *testing.T) {
	for _, env := range []string{"staging", "prod"} {
		restoreDefaults(t)
		var out lockedBuffer
		code := Run(context.Background(), testService(waitForStop), Process{LookupEnv: envMap{"RCS_ENV": env}.lookup, Stdout: &out})
		if code != ExitFailure {
			t.Fatalf("%s without a key: exit %d", env, code)
		}
		got := toStrings(record(t, out.String(), "configuration rejected")["problems"])
		if want := []string{"refused in " + env + ": " + missingKeyReason}; !slices.Equal(got, want) {
			t.Fatalf("%s: problems = %q", env, got)
		}
	}

	h := startService(t, envMap{"RCS_ENV": "prod", "RCS_SHUTDOWN_TIMEOUT": "7s", "RCS_PII_HMAC_KEY": testPIIKey}, testService(waitForStop))
	if code := httpGet(t, h.adminURL("/healthz")); code != 200 {
		t.Fatalf("prod with a key: healthz %d", code)
	}
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("prod with a key: exit %d:\n%s", code, h.out.String())
	}
}

func TestAShortPIIKeyIsReportedOnceNotAlsoAsMissing(t *testing.T) {
	restoreDefaults(t)
	var out lockedBuffer
	code := Run(context.Background(), testService(waitForStop), Process{LookupEnv: envMap{"RCS_ENV": "prod", "RCS_PII_HMAC_KEY": "short"}.lookup, Stdout: &out})
	got := toStrings(record(t, out.String(), "configuration rejected")["problems"])
	if code != ExitFailure || !slices.Equal(got, []string{"RCS_PII_HMAC_KEY: shorter than 32 bytes"}) {
		t.Fatalf("exit %d, problems %q", code, got)
	}
}

func TestDevelopmentWithoutThePIIHMACKeyStartsAndWarns(t *testing.T) {
	h := startService(t, envMap{"RCS_ENV": "dev", "RCS_SHUTDOWN_TIMEOUT": "7s"}, testService(waitForStop))
	if code := httpGet(t, h.adminURL("/healthz")); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	got := toStrings(record(t, h.out.String(), "production-unsafe settings in use")["reasons"])
	if !slices.Equal(got, []string{missingKeyReason}) {
		t.Fatalf("reasons = %q", got)
	}
}

func TestDevelopmentStartsWithUnsafeSettingsAndWarns(t *testing.T) {
	env := devEnv()
	env["TESTSVC_STORE"] = "memory"
	h := startService(t, env, testService(waitForStop))
	if code := httpGet(t, h.adminURL("/healthz")); code != 200 {
		t.Fatalf("healthz = %d", code)
	}
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, h.out.String())
	}
	got := toStrings(record(t, h.out.String(), "production-unsafe settings in use")["reasons"])
	if !slices.Equal(got, []string{"TESTSVC_STORE=memory keeps state in one task"}) {
		t.Fatalf("reasons = %q", got)
	}
}

func TestServiceGetsItsConfigurationAndTheRuntime(t *testing.T) {
	env := devEnv()
	env["TESTSVC_STORE"] = "memory"
	env["RCS_METRICS_NAMESPACE"] = "RCS/test"
	env["RCS_PII_HMAC_KEY"] = strings.Repeat("k", 32)
	got := make(chan testConfig, 1)
	h := startService(t, env, testService(func(ctx context.Context, rt *Runtime, cfg testConfig) error {
		got <- cfg
		rt.Metrics.Count("boot", 1)
		rt.Logger.Info("redacted", pii.URI("from", "tel:+15550100001"))
		<-ctx.Done()
		return nil
	}))
	if cfg := <-got; cfg.store != "memory" {
		t.Fatalf("cfg = %+v", cfg)
	}
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	out := h.out.String()
	var metric map[string]any
	for _, rec := range records(t, out) {
		if _, ok := rec["boot"]; ok {
			metric = rec
		}
	}
	if metric == nil || metric["Service"] != "testsvc" || !strings.Contains(out, `"Namespace":"RCS/test"`) {
		t.Fatalf("metric line missing or wrong in:\n%s", out)
	}
	keyed := pii.NewRedactor([]byte(strings.Repeat("k", 32))).Redact("tel:+15550100001")
	if record(t, out, "redacted")["from"] != keyed {
		t.Fatalf("pii default is not keyed from RCS_PII_HMAC_KEY:\n%s", out)
	}
	if rec := record(t, out, "started"); rec["environment"] != "dev" || rec["version"] != buildinfo.Version {
		t.Fatalf("started record = %v", rec)
	}
}

func TestShutdownMarksNotReadyRunsHooksInReverseAndExitsZero(t *testing.T) {
	var mu sync.Mutex
	var order []string
	note := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, s)
	}
	ready := make(chan struct{})
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("store", func(context.Context) error { note("store"); return nil })
		rt.OnShutdown("listener", func(context.Context) error { note("listener"); return nil })
		rt.Admin.AddReadinessCheck("store", func(context.Context) error { return nil })
		rt.Ready()
		close(ready)
		<-ctx.Done()
		note("run returned")
		return ctx.Err()
	}))
	<-ready
	u := h.adminURL("/readyz")
	if code := httpGet(t, u); code != 200 {
		t.Fatalf("readyz before shutdown = %d", code)
	}
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d:\n%s", code, h.out.String())
	}
	if want := []string{"run returned", "listener", "store"}; !slices.Equal(order, want) {
		t.Fatalf("order = %q, want %q", order, want)
	}
	if !hasRecord(t, h.out.String(), "stopped") {
		t.Fatalf("no stopped record:\n%s", h.out.String())
	}
	if !slices.Contains(h.timers.Made(), testShutdownTimeout) {
		t.Fatalf("no shutdown deadline of RCS_SHUTDOWN_TIMEOUT: %v", h.timers.Made())
	}
}

func TestReadyzIsStartingUntilRunCallsReady(t *testing.T) {
	initDone, ready := make(chan struct{}), make(chan struct{})
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		<-initDone
		rt.Ready()
		close(ready)
		<-ctx.Done()
		return nil
	}))
	u := h.adminURL("/readyz")
	before := httpGet(t, u)
	close(initDone)
	<-ready
	after := httpGet(t, u)
	h.cancel()
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if before != 503 || after != 200 {
		t.Fatalf("readyz before Ready %d, after %d", before, after)
	}
	if !hasRecord(t, h.out.String(), "ready") {
		t.Fatalf("no ready record:\n%s", h.out.String())
	}
}

func TestReadyzIs503WhileDraining(t *testing.T) {
	ready := make(chan struct{})
	draining := make(chan struct{})
	finish := make(chan struct{})
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("drain", func(context.Context) error {
			close(draining)
			<-finish
			return nil
		})
		close(ready)
		<-ctx.Done()
		return nil
	}))
	<-ready
	u := h.adminURL("")
	h.cancel()
	<-draining
	readyz, healthz := httpGet(t, u+"/readyz"), httpGet(t, u+"/healthz")
	close(finish)
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if readyz != 503 || healthz != 200 {
		t.Fatalf("while draining: readyz %d, healthz %d", readyz, healthz)
	}
}

func TestSIGTERMStopsTheService(t *testing.T) {
	ready := make(chan struct{})
	h := startService(t, devEnv(), testService(func(ctx context.Context, _ *Runtime, _ testConfig) error {
		close(ready)
		<-ctx.Done()
		return nil
	}))
	<-ready
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !hasRecord(t, h.out.String(), "stopping: shutdown requested") {
		t.Fatalf("log:\n%s", h.out.String())
	}
}

func TestAFailingServiceStillRunsItsHooksAndExitsNonZero(t *testing.T) {
	hookRan := make(chan struct{}, 1)
	h := startService(t, devEnv(), testService(func(_ context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("store", func(context.Context) error { hookRan <- struct{}{}; return nil })
		return errors.New("listen tcp :5060: address already in use")
	}))
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	select {
	case <-hookRan:
	default:
		t.Fatal("hook did not run")
	}
	if rec := record(t, h.out.String(), "stopping: service failed"); !strings.Contains(rec["error"].(string), "address already in use") {
		t.Fatalf("record = %v", rec)
	}
}

func TestAServiceReturningNilBeforeASignalExitsZero(t *testing.T) {
	h := startService(t, devEnv(), testService(func(context.Context, *Runtime, testConfig) error { return nil }))
	if code := h.wait(); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !hasRecord(t, h.out.String(), "stopping: service returned") {
		t.Fatalf("log:\n%s", h.out.String())
	}
}

func TestAServiceErrorWhileStoppingIsAFailure(t *testing.T) {
	ready := make(chan struct{})
	h := startService(t, devEnv(), testService(func(ctx context.Context, _ *Runtime, _ testConfig) error {
		close(ready)
		<-ctx.Done()
		return errors.New("flush failed")
	}))
	<-ready
	h.cancel()
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	if !hasRecord(t, h.out.String(), "service failed while stopping") {
		t.Fatalf("log:\n%s", h.out.String())
	}
}

func TestAFailingHookMakesTheExitNonZeroButLaterHooksRun(t *testing.T) {
	ready := make(chan struct{})
	storeClosed := make(chan struct{}, 1)
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("store", func(context.Context) error { storeClosed <- struct{}{}; return nil })
		rt.OnShutdown("flows", func(context.Context) error { return errors.New("close flow sip:alice.smith@ims.example") })
		close(ready)
		<-ctx.Done()
		return nil
	}))
	<-ready
	h.cancel()
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	select {
	case <-storeClosed:
	default:
		t.Fatal("the hook after the failing one did not run")
	}
	rec := record(t, h.out.String(), "shutdown hook failed")
	if rec["hook"] != "flows" || strings.Contains(rec["error"].(string), "alice.smith") {
		t.Fatalf("record = %v", rec)
	}
}

func TestAPanickingHookFailsAndTheOthersStillRun(t *testing.T) {
	ready := make(chan struct{})
	storeClosed := make(chan struct{}, 1)
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("store", func(context.Context) error { storeClosed <- struct{}{}; return nil })
		rt.OnShutdown("flows", func(context.Context) error { panic("closing flow for sip:+15550100001@ims.example") })
		close(ready)
		<-ctx.Done()
		return nil
	}))
	<-ready
	h.cancel()
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	select {
	case <-storeClosed:
	default:
		t.Fatal("the hook after the panicking one did not run")
	}
	rec := record(t, h.out.String(), "shutdown hook failed")
	if rec["hook"] != "flows" || !strings.Contains(rec["error"].(string), "panic: closing flow") || strings.Contains(h.out.String(), "15550100001") {
		t.Fatalf("record = %v", rec)
	}
}

func TestAHookStillRunningAtTheDeadlineIsAbandonedAndTheRestSkipped(t *testing.T) {
	ready := make(chan struct{})
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var storeRan atomic.Bool
	h := startService(t, devEnv(), testService(func(ctx context.Context, rt *Runtime, _ testConfig) error {
		rt.OnShutdown("store", func(context.Context) error { storeRan.Store(true); return nil })
		rt.OnShutdown("flows", func(context.Context) error {
			close(entered)
			<-release // ignores its context, as a buggy hook would
			return nil
		})
		close(ready)
		<-ctx.Done()
		return nil
	}))
	<-ready
	h.cancel()
	<-entered
	h.timers.Fire(testShutdownTimeout)
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	if storeRan.Load() {
		t.Fatal("a hook ran after the deadline")
	}
	out := h.out.String()
	if record(t, out, "shutdown hook did not finish before the deadline")["hook"] != "flows" ||
		record(t, out, "shutdown hook skipped: deadline passed")["hook"] != "store" {
		t.Fatalf("log:\n%s", out)
	}
}

func TestAServiceThatIgnoresCancellationIsAbandonedAtTheDeadline(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := startService(t, devEnv(), testService(func(context.Context, *Runtime, testConfig) error {
		close(ready)
		<-release
		return nil
	}))
	<-ready
	h.cancel()
	h.timers.WaitFor(testShutdownTimeout)
	h.timers.Fire(testShutdownTimeout)
	if code := h.wait(); code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	if !hasRecord(t, h.out.String(), "service did not stop before the shutdown deadline") {
		t.Fatalf("log:\n%s", h.out.String())
	}
}

func TestAdminListenFailureStopsStartup(t *testing.T) {
	restoreDefaults(t)
	var out lockedBuffer
	code := Run(context.Background(), testService(waitForStop), Process{
		LookupEnv: devEnv().lookup,
		Stdout:    &out,
		Listen: func(string, string) (net.Listener, error) {
			return nil, errors.New("listen tcp :8080: bind: address already in use")
		},
	})
	if code != ExitFailure || !hasRecord(t, out.String(), "admin listener failed") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}

func TestAdminServerFailureStopsTheService(t *testing.T) {
	restoreDefaults(t)
	var out lockedBuffer
	stopped := make(chan struct{})
	code := Run(context.Background(), testService(func(ctx context.Context, _ *Runtime, _ testConfig) error {
		<-ctx.Done()
		close(stopped)
		return nil
	}), Process{
		LookupEnv: devEnv().lookup,
		Stdout:    &out,
		Listen: func(string, string) (net.Listener, error) {
			return failingListener{}, nil
		},
	})
	if code != ExitFailure || !hasRecord(t, out.String(), "stopping: admin server failed") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	<-stopped
}

func TestInvalidServiceDefinitionsPanic(t *testing.T) {
	good := testService(waitForStop)
	for name, svc := range map[string]Service[testConfig]{
		"no name":          {EnvPrefix: "X_", Configure: good.Configure, Run: good.Run},
		"lowercase prefix": {Name: "x", EnvPrefix: "x_", Configure: good.Configure, Run: good.Run},
		"no underscore":    {Name: "x", EnvPrefix: "X", Configure: good.Configure, Run: good.Run},
		"shared prefix":    {Name: "x", EnvPrefix: "RCS_", Configure: good.Configure, Run: good.Run},
		"inside shared":    {Name: "rcs-as", EnvPrefix: "RCS_AS_", Configure: good.Configure, Run: good.Run},
		"no configure":     {Name: "x", EnvPrefix: "X_", Run: good.Run},
		"no run":           {Name: "x", EnvPrefix: "X_", Configure: good.Configure},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			Run(context.Background(), svc, Process{Args: []string{"-version"}})
		}()
	}
}

// failingListener makes http.Server.Serve fail at once.
type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
