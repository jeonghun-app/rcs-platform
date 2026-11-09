package maap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

func TestServiceIsNamedForLogsAndMetrics(t *testing.T) {
	if s := Service(); s.Name != "maap" || s.EnvPrefix != "MAAP_" {
		t.Fatalf("Service() = %q, %q", s.Name, s.EnvPrefix)
	}
}

func TestRunServesTheInternalListenerAndHealthUntilStopped(t *testing.T) {
	cfg, err := configure(with(devEnv, "MAAP_OPERATOR_TOKEN", operatorToken))
	if err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "maap")
	if code, _ := h.Get("/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz before Run = %d, want 503", code)
	}
	listening := make(chan net.Listener, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, h.Runtime, cfg, deps{listen: func(network, _ string) (net.Listener, error) {
			ln, err := net.Listen(network, "127.0.0.1:0")
			if err == nil {
				listening <- ln
			}
			return ln, err
		}})
	}()
	addr := (<-listening).Addr().String()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if code, _ := h.Get("/readyz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never answered 200")
		}
	}
	if code, _ := h.Get("/healthz"); code != http.StatusOK {
		t.Errorf("/healthz = %d", code)
	}
	// A transport of its own ignores any proxy in the environment.
	resp, err := (&http.Client{Transport: &http.Transport{}}).Get("http://" + addr + "/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("internal listener answered %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run = %v", err)
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		_ = c.Close()
		t.Error("the internal listener is still open after shutdown")
	}
}

func TestRunFailsWhenItsListenerCannotOpen(t *testing.T) {
	cfg, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "maap")
	err = run(context.Background(), h.Runtime, cfg, deps{listen: func(string, string) (net.Listener, error) {
		return nil, errors.New("address in use")
	}})
	if err == nil {
		t.Fatal("run started without its listener")
	}
	if code, _ := h.Get("/readyz"); code == http.StatusOK {
		t.Error("ready without a listener")
	}
}
