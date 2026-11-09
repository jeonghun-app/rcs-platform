package maap

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store/storetest"
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

// readySubscribers is a table in memory with the readiness check of the
// DynamoDB one, ready with its registry.
type readySubscribers struct {
	*store.MemorySubscribers
	registry *readyRegistry
}

func (s readySubscribers) Ready(ctx context.Context) error { return s.registry.Ready(ctx) }

// deletions records the chatbots its credentials' DeleteChatbot is called
// for.
type deletions struct {
	store.Credentials
	ids chan string
}

func (d deletions) DeleteChatbot(ctx context.Context, id string) error {
	d.ids <- id
	return d.Credentials.DeleteChatbot(ctx, id)
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
	creds := deletions{registry.Credentials(), make(chan string, 1)}
	subs := readySubscribers{store.NewMemorySubscribers(), registry}
	go func() {
		done <- run(ctx, h.Runtime, cfg, deps{registry: registry, credentials: creds, subscribers: subs, listen: func(network, _ string) (net.Listener, error) {
			ln, err := net.Listen(network, "127.0.0.1:0")
			if err == nil {
				listening <- ln
			}
			return ln, err
		}})
	}()
	addr := (<-listening).Addr().String()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if code, body := h.Get("/readyz"); code == http.StatusServiceUnavailable && strings.Contains(body, "dynamodb-registry") &&
			strings.Contains(body, "dynamodb-subscribers") {
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
	// settings' domain and webhook rules: http on a listed port, at a
	// private address, in dev.
	req, _ := http.NewRequest("POST", "http://"+addr+"/v1/chatbots", strings.NewReader(
		`{"id":"cb-1","uri":"sip:bot-1@`+botDomain+`","webhook":{"url":"http://10.0.0.5:8080/hook"}}`))
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Content-Type", "application/json")
	if resp, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, err := registry.Chatbot(context.Background(), "cb-1"); resp.StatusCode != http.StatusCreated || err != nil {
		t.Errorf("POST /v1/chatbots = %d, %v", resp.StatusCode, err)
	}
	// The credential routes are mounted over the credentials given, and
	// deleting the chatbot runs their deletion and leaves none, nor any
	// alias of the chatbot (#742 review).
	alias, err := subs.Alias(context.Background(), storetest.Alias("cb-1", storetest.Subscriber, false, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		method, path string
		want         int
	}{{"POST", "/v1/chatbots/cb-1/credentials", http.StatusCreated}, {"DELETE", "/v1/chatbots/cb-1", http.StatusNoContent}} {
		req, _ := http.NewRequest(step.method, "http://"+addr+step.path, nil)
		req.Header.Set("Authorization", "Bearer "+operatorToken)
		if resp, err = client.Do(req); err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != step.want {
			t.Errorf("%s %s = %d", step.method, step.path, resp.StatusCode)
		}
	}
	select {
	case id := <-creds.ids:
		if id != "cb-1" {
			t.Errorf("credentials deleted for %q", id)
		}
	default:
		t.Error("the deletion skipped the credentials' deleter")
	}
	if left, err := creds.ChatbotCredentials(context.Background(), "cb-1"); len(left) != 0 || err != nil {
		t.Errorf("credentials left: %v, %v", left, err)
	}
	if _, err := subs.Resolve(context.Background(), "cb-1", alias.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the alias is left: %v", err)
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
	m := store.NewMemoryRegistry()
	err = run(context.Background(), h.Runtime, cfg, deps{registry: m, credentials: m.Credentials(), subscribers: store.NewMemorySubscribers(), listen: func(string, string) (net.Listener, error) {
		return nil, errors.New("address in use")
	}})
	if err == nil {
		t.Fatal("run started without its listener")
	}
	if code, _ := h.Get("/readyz"); code == http.StatusOK {
		t.Error("ready without a listener")
	}
}

// Without stores given, Run opens both tables, by the names the settings
// give, at the endpoint they give: /readyz describes each.
func TestRunOpensTheTablesTheSettingsName(t *testing.T) {
	for k, v := range map[string]string{
		"AWS_REGION": "us-east-1", "AWS_ACCESS_KEY_ID": "local", "AWS_SECRET_ACCESS_KEY": "local",
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": "/nonexistent", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent",
		"HTTP_PROXY": "", "HTTPS_PROXY": "", "NO_PROXY": "*",
	} {
		t.Setenv(k, v)
	}
	var mu sync.Mutex
	described := map[string]bool{}
	ddb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ TableName string }
		if r.Header.Get("X-Amz-Target") != "DynamoDB_20120810.DescribeTable" || json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		mu.Lock()
		described[in.TableName] = true
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE"}}`))
	}))
	defer ddb.Close()
	cfg, err := configure(with(devEnv, "MAAP_DYNAMODB_ENDPOINT", ddb.URL, "MAAP_REGISTRY_TABLE", "bots-x", "MAAP_SUBSCRIBERS_TABLE", "aliases-x"))
	if err != nil {
		t.Fatal(err)
	}
	h := runtimetest.New(t, "maap")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, h.Runtime, cfg, deps{listen: func(network, _ string) (net.Listener, error) { return net.Listen(network, "127.0.0.1:0") }})
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if code, _ := h.Get("/readyz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never answered 200")
		}
		h.Advance(2 * time.Second)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := h.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !described["bots-x"] || !described["aliases-x"] || len(described) != 2 {
		t.Fatalf("described %v", described)
	}
}
