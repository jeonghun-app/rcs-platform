package maap

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

// readyRegistry is a registry in memory with the readiness check of the
// DynamoDB one, failing until ready is set.
type readyRegistry struct {
	*store.MemoryRegistry
	ready atomic.Bool
}

func (r *readyRegistry) Ready(context.Context) error {
	if !r.ready.Load() {
		return errors.New("table not active")
	}
	return nil
}

func TestServiceIsNamedForLogsAndMetrics(t *testing.T) {
	if s := Service(); s.Name != "maap" || s.EnvPrefix != "MAAP_" {
		t.Fatalf("Service() = %q, %q", s.Name, s.EnvPrefix)
	}
}

func TestRunServesTheRegistryAndIsReadyOnlyWithIt(t *testing.T) {
	cfg, err := configure(with(devEnv, "MAAP_OPERATOR_TOKEN", operatorToken, "MAAP_WEBHOOK_PORTS", "8080"))
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
	registry := &readyRegistry{MemoryRegistry: store.NewMemoryRegistry()}
	go func() {
		done <- run(ctx, h.Runtime, cfg, deps{registry: registry, listen: func(network, _ string) (net.Listener, error) {
			ln, err := net.Listen(network, "127.0.0.1:0")
			if err == nil {
				listening <- ln
			}
			return ln, err
		}})
	}()
	addr := (<-listening).Addr().String()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if code, body := h.Get("/readyz"); code == http.StatusServiceUnavailable && strings.Contains(body, "dynamodb-registry") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never reported the registry failing")
		}
	}
	registry.ready.Store(true)
	h.Advance(2 * time.Second) // past the cached answer
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
	client := &http.Client{Transport: &http.Transport{}}
	resp, err := client.Get("http://" + addr + "/v1/unknown")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("internal listener answered %d, Cache-Control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	// The registry's routes are mounted over the registry given, with the
	// settings' domain and webhook rules: http on a listed port, in dev.
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/chatbots", strings.NewReader(
		`{"id":"cb-1","uri":"sip:bot-1@`+botDomain+`","webhook":{"url":"http://bot.example.com:8080/hook"}}`))
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Content-Type", "application/json")
	if resp, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, err := registry.Chatbot(context.Background(), "cb-1"); resp.StatusCode != http.StatusCreated || err != nil {
		t.Errorf("POST /v1/chatbots = %d, %v", resp.StatusCode, err)
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
	err = run(context.Background(), h.Runtime, cfg, deps{registry: store.NewMemoryRegistry(), listen: func(string, string) (net.Listener, error) {
		return nil, errors.New("address in use")
	}})
	if err == nil {
		t.Fatal("run started without its listener")
	}
	if code, _ := h.Get("/readyz"); code == http.StatusOK {
		t.Error("ready without a listener")
	}
}
