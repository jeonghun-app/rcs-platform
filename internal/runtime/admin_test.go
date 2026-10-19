package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	// Registers handlers on http.DefaultServeMux, which the admin server must
	// not serve.
	_ "net/http/pprof"
)

// fakeNow is a clock a test moves by hand.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeNow) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeNow) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// testAdmin returns an Admin past "starting", on a clock that only moves when
// the test moves it.
func testAdmin(log *slog.Logger) (*Admin, *fakeNow, *fakeTimers) {
	clock, timers := &fakeNow{t: epoch}, newFakeTimers()
	a := newAdmin(log, clock.Now, timers.After)
	a.markReady()
	return a, clock, timers
}

func get(t *testing.T, h http.Handler, method, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var body map[string]any
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: body %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, body
}

func TestHealthzIsAlwaysOK(t *testing.T) {
	a := newAdmin(discardLogger(), time.Now, newFakeTimers().After)
	if code, body := get(t, a, "GET", "/healthz"); code != 200 || body["status"] != "ok" {
		t.Fatalf("healthz while starting = %d %v", code, body)
	}
	a.markReady()
	a.AddReadinessCheck("store", func(context.Context) error { return errors.New("down") })
	a.stop()
	if code, body := get(t, a, "GET", "/healthz"); code != 200 || body["status"] != "ok" {
		t.Fatalf("healthz = %d %v", code, body)
	}
	if code, _ := get(t, a, "HEAD", "/healthz"); code != 200 {
		t.Fatalf("HEAD healthz = %d", code)
	}
}

func TestReadyzIsStartingUntilTheServiceIsReady(t *testing.T) {
	a := newAdmin(discardLogger(), time.Now, newFakeTimers().After)
	var calls atomic.Int32
	a.AddReadinessCheck("store", func(context.Context) error { calls.Add(1); return nil })
	if code, body := get(t, a, "GET", "/readyz"); code != 503 || body["status"] != "starting" {
		t.Fatalf("readyz before ready = %d %v", code, body)
	}
	if calls.Load() != 0 {
		t.Fatal("checks ran while starting")
	}
	if !a.markReady() || a.markReady() {
		t.Fatal("markReady should report only the first call")
	}
	if code, body := get(t, a, "GET", "/readyz"); code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz after ready = %d %v", code, body)
	}
}

func TestReadyzIsOKWhenEveryCheckPasses(t *testing.T) {
	a, clock, _ := testAdmin(discardLogger())
	if code, body := get(t, a, "GET", "/readyz"); code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz with no checks = %d %v", code, body)
	}
	a.AddReadinessCheck("store", func(context.Context) error { return nil })
	a.AddReadinessCheck("hss", func(context.Context) error { return nil })
	clock.Advance(readinessCacheTTL)
	if code, body := get(t, a, "GET", "/readyz"); code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz = %d %v", code, body)
	}
}

func TestReadyzNamesFailingChecksWithoutTheirErrors(t *testing.T) {
	var logs bytes.Buffer
	a, _, _ := testAdmin(NewLogger(&logs, "scscf", "dev", slog.LevelInfo))
	a.AddReadinessCheck("store", func(context.Context) error {
		return errors.New("dial tcp 10.0.9.9:8000: table registrations-prod unreachable for sip:+15550100001@ims.example")
	})
	a.AddReadinessCheck("clock", func(context.Context) error { return nil })
	a.AddReadinessCheck("hss", func(context.Context) error { return errors.New("no Diameter peer") })

	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Fatalf("code = %d", rec.Code)
	}
	var body struct {
		Status  string   `json:"status"`
		Failing []string `json:"failing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "not ready" || !slices.Equal(body.Failing, []string{"store", "hss"}) {
		t.Fatalf("body = %+v", body)
	}
	for _, leak := range []string{"10.0.9.9", "registrations-prod", "Diameter"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("response leaks %q: %s", leak, rec.Body.String())
		}
	}
	// The operator still learns why, from the log, with identifiers masked.
	if !strings.Contains(logs.String(), "registrations-prod") || strings.Contains(logs.String(), "15550100001") {
		t.Fatalf("log = %s", logs.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("readiness may be cached: %v", rec.Header())
	}
}

func TestACheckThatHangsIsReportedWhenTheReadinessDeadlinePasses(t *testing.T) {
	a, _, timers := testAdmin(discardLogger())
	entered := make(chan struct{})
	a.AddReadinessCheck("broken", func(context.Context) error { return errors.New("refused") })
	a.AddReadinessCheck("slow", func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	go func() {
		<-entered
		timers.Fire(readinessTimeout)
	}()
	code, body := get(t, a, "GET", "/readyz")
	if code != 503 || !slices.Equal(toStrings(body["failing"]), []string{"broken", "slow"}) {
		t.Fatalf("readyz = %d %v", code, body)
	}
}

func TestAPanickingCheckFailsWithoutStoppingTheProcess(t *testing.T) {
	var logs lockedBuffer
	a, _, _ := testAdmin(NewLogger(&logs, "pcscf", "dev", slog.LevelInfo))
	var client *http.Client
	a.AddReadinessCheck("store", func(context.Context) error {
		_ = client.Timeout // nil pointer, as an uninitialised dependency would be
		return nil
	})
	a.AddReadinessCheck("panics-with-pii", func(context.Context) error { panic("bad contact sip:+15550100001@ims.example") })
	a.AddReadinessCheck("hss", func(context.Context) error { return nil })
	code, body := get(t, a, "GET", "/readyz")
	if code != 503 || !slices.Equal(toStrings(body["failing"]), []string{"store", "panics-with-pii"}) {
		t.Fatalf("readyz = %d %v", code, body)
	}
	if strings.Contains(logs.String(), "15550100001") {
		t.Fatalf("panic value logged unredacted: %s", logs.String())
	}
	rec := record(t, logs.String(), "readiness check failing")
	if rec["check"] != "store" || !strings.Contains(rec["error"].(string), "nil pointer") {
		t.Fatalf("record = %v", rec)
	}
}

func TestConcurrentReadyzRequestsShareOneEvaluation(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	var calls atomic.Int32
	release := make(chan struct{})
	a.AddReadinessCheck("store", func(context.Context) error {
		calls.Add(1)
		<-release
		return nil
	})
	const n = 20
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			code, _ := get(t, a, "GET", "/readyz")
			codes <- code
		})
	}
	close(release)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != 200 {
			t.Fatalf("a request got %d", code)
		}
	}
	// The clock does not move, so every request either joined the one
	// evaluation or was answered from its cached result.
	if got := calls.Load(); got != 1 {
		t.Fatalf("check ran %d times for %d requests", got, n)
	}
}

func TestReadinessResultsAreCachedForOneSecond(t *testing.T) {
	a, clock, _ := testAdmin(discardLogger())
	var calls atomic.Int32
	var down atomic.Bool
	a.AddReadinessCheck("store", func(context.Context) error {
		calls.Add(1)
		if down.Load() {
			return errors.New("down")
		}
		return nil
	})
	get(t, a, "GET", "/readyz")
	down.Store(true)
	clock.Advance(readinessCacheTTL - time.Millisecond)
	if code, _ := get(t, a, "GET", "/readyz"); code != 200 || calls.Load() != 1 {
		t.Fatalf("within the TTL: code %d, %d calls", code, calls.Load())
	}
	clock.Advance(time.Millisecond)
	if code, _ := get(t, a, "GET", "/readyz"); code != 503 || calls.Load() != 2 {
		t.Fatalf("after the TTL: code %d, %d calls", code, calls.Load())
	}
}

func TestAddingACheckInvalidatesTheCachedResult(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	get(t, a, "GET", "/readyz")
	a.AddReadinessCheck("store", func(context.Context) error { return errors.New("down") })
	if code, _ := get(t, a, "GET", "/readyz"); code != 503 {
		t.Fatalf("new failing check hidden by the cache: %d", code)
	}
}

func TestACheckAddedDuringAnEvaluationIsNotHiddenByItsResult(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	release, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	a.AddReadinessCheck("slow", func(context.Context) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	first := make(chan int)
	go func() { c, _ := get(t, a, "GET", "/readyz"); first <- c }()
	<-entered
	a.AddReadinessCheck("store", func(context.Context) error { return errors.New("down") })
	close(release)
	if code := <-first; code != 200 {
		t.Fatalf("the waiting request got %d; it asked before the new check existed", code)
	}
	if code, body := get(t, a, "GET", "/readyz"); code != 503 || !slices.Equal(toStrings(body["failing"]), []string{"store"}) {
		t.Fatalf("new failing check hidden by the in-flight evaluation: %d %v", code, body)
	}
}

func TestReadinessIsLoggedOnlyWhenACheckChangesState(t *testing.T) {
	var logs lockedBuffer
	a, clock, _ := testAdmin(NewLogger(&logs, "hss", "dev", slog.LevelInfo))
	var down atomic.Bool
	a.AddReadinessCheck("store", func(context.Context) error {
		if down.Load() {
			return errors.New("down")
		}
		return nil
	})
	poll := func() {
		get(t, a, "GET", "/readyz")
		clock.Advance(readinessCacheTTL)
	}
	poll() // passing from the start: nothing to say
	down.Store(true)
	poll()
	poll()
	poll()
	down.Store(false)
	poll()
	poll()
	out := logs.String()
	if n := strings.Count(out, "readiness check failing"); n != 1 {
		t.Fatalf("%d failing records, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "readiness check passing again"); n != 1 {
		t.Fatalf("%d recovery records, want 1:\n%s", n, out)
	}
}

func TestAReadyzCallerThatGoesAwayDoesNotCancelTheEvaluation(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	entered, release := make(chan struct{}), make(chan struct{})
	var sawCancel atomic.Bool
	a.AddReadinessCheck("store", func(ctx context.Context) error {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			sawCancel.Store(true)
		}
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		a.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil).WithContext(ctx))
		close(done)
	}()
	<-entered
	cancel()
	<-done
	if rec.Code != 503 {
		t.Fatalf("abandoned request = %d", rec.Code)
	}
	close(release)
	// The next caller gets the shared evaluation's answer: it was not
	// cancelled with the first caller.
	if code, _ := get(t, a, "GET", "/readyz"); code != 200 || sawCancel.Load() {
		t.Fatalf("evaluation was cancelled with its first caller: code %d", code)
	}
}

func TestReadyzFailsOnceStopping(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	a.AddReadinessCheck("store", func(context.Context) error { return nil })
	a.stop()
	if code, body := get(t, a, "GET", "/readyz"); code != 503 || body["status"] != "stopping" {
		t.Fatalf("readyz while stopping = %d %v", code, body)
	}
}

func TestAdminServesNothingUnmounted(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	for _, path := range []string{"/", "/debug/pprof/", "/debug/pprof/heap", "/metrics", "/healthz/x", "/readyz/"} {
		if code, _ := get(t, a, "GET", path); code != 404 {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
	if code, _ := get(t, a, "POST", "/healthz"); code != 405 {
		t.Errorf("POST /healthz = %d, want 405", code)
	}
}

func TestMountedHandlersAreServed(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	a.Handle("GET /v1/bindings", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "bindings")
	}))
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/bindings", nil))
	if rec.Code != 200 || rec.Body.String() != "bindings" {
		t.Fatalf("mounted handler = %d %q", rec.Code, rec.Body.String())
	}
}

func TestBadReadinessChecksPanic(t *testing.T) {
	a, _, _ := testAdmin(discardLogger())
	a.AddReadinessCheck("store", func(context.Context) error { return nil })
	for name, add := range map[string]func(){
		"duplicate": func() { a.AddReadinessCheck("store", func(context.Context) error { return nil }) },
		"no name":   func() { a.AddReadinessCheck("", func(context.Context) error { return nil }) },
		"no func":   func() { a.AddReadinessCheck("x", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			add()
		}()
	}
}

func toStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out
}

func TestHealthzWaitsForReadyWhenTheServiceAsksForIt(t *testing.T) {
	a := newAdmin(discardLogger(), time.Now, newFakeTimers().After)
	a.liveAfterReady = true
	if code, body := get(t, a, "GET", "/healthz"); code != 503 || body["status"] != "starting" {
		t.Fatalf("healthz while starting = %d %v, want 503 starting", code, body)
	}
	a.markReady()
	if code, body := get(t, a, "GET", "/healthz"); code != 200 || body["status"] != "ok" {
		t.Fatalf("healthz once ready = %d %v", code, body)
	}
	// A failing dependency or a drain does not make a ready process dead.
	a.AddReadinessCheck("store", func(context.Context) error { return errors.New("down") })
	a.stop()
	if code, _ := get(t, a, "GET", "/healthz"); code != 200 {
		t.Fatalf("healthz while draining = %d", code)
	}
}
