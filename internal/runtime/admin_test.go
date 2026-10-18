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
	"testing"

	// Registers handlers on http.DefaultServeMux, which the admin server must
	// not serve.
	_ "net/http/pprof"
)

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
	a := newAdmin(discardLogger(), newFakeTimers().After)
	a.AddReadinessCheck("store", func(context.Context) error { return errors.New("down") })
	a.stop()
	if code, body := get(t, a, "GET", "/healthz"); code != 200 || body["status"] != "ok" {
		t.Fatalf("healthz = %d %v", code, body)
	}
	if code, _ := get(t, a, "HEAD", "/healthz"); code != 200 {
		t.Fatalf("HEAD healthz = %d", code)
	}
}

func TestReadyzIsOKWhenEveryCheckPasses(t *testing.T) {
	a := newAdmin(discardLogger(), newFakeTimers().After)
	if code, body := get(t, a, "GET", "/readyz"); code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz with no checks = %d %v", code, body)
	}
	a.AddReadinessCheck("store", func(context.Context) error { return nil })
	a.AddReadinessCheck("hss", func(context.Context) error { return nil })
	if code, body := get(t, a, "GET", "/readyz"); code != 200 || body["status"] != "ready" {
		t.Fatalf("readyz = %d %v", code, body)
	}
}

func TestReadyzNamesFailingChecksWithoutTheirErrors(t *testing.T) {
	var logs bytes.Buffer
	a := newAdmin(NewLogger(&logs, "scscf", "dev", slog.LevelInfo), newFakeTimers().After)
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
	timers := newFakeTimers()
	a := newAdmin(discardLogger(), timers.After)
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

func TestReadyzFailsOnceStopping(t *testing.T) {
	a := newAdmin(discardLogger(), newFakeTimers().After)
	a.AddReadinessCheck("store", func(context.Context) error { return nil })
	a.stop()
	if code, body := get(t, a, "GET", "/readyz"); code != 503 || body["status"] != "stopping" {
		t.Fatalf("readyz while stopping = %d %v", code, body)
	}
}

func TestAdminServesNothingUnmounted(t *testing.T) {
	a := newAdmin(discardLogger(), newFakeTimers().After)
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
	a := newAdmin(discardLogger(), newFakeTimers().After)
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
	a := newAdmin(discardLogger(), newFakeTimers().After)
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
