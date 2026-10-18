package hss

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/rand"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

// loopback records the addresses Run listens on.
type loopback struct {
	mu    sync.Mutex
	addrs []string
	ready chan struct{}
}

func (l *loopback) listen(network, _ string) (net.Listener, error) {
	ln, err := net.Listen(network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.addrs = append(l.addrs, ln.Addr().String())
	if len(l.addrs) == 2 {
		close(l.ready)
	}
	l.mu.Unlock()
	return ln, nil
}

// memoryAWS stands in for DynamoDB and KMS.
type memoryAWS struct {
	*store.Memory
	readyErr error
}

func (m *memoryAWS) Ready(context.Context) error { return m.readyErr }

// xorWrapper is a toy master key.
type xorWrapper struct{}

func (xorWrapper) GenerateDataKey(context.Context) ([]byte, []byte, error) {
	k := make([]byte, keyring.DataKeySize)
	_, _ = rand.Read(k)
	return k, xorBytes(k), nil
}

func (xorWrapper) Unwrap(_ context.Context, w []byte) ([]byte, error) { return xorBytes(w), nil }

func xorBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ 0x5a
	}
	return out
}

func startRun(t *testing.T, cfg Config, d deps) (*runtimetest.Harness, []string, context.CancelFunc, <-chan error) {
	t.Helper()
	h := runtimetest.New(t, "hss")
	lb := &loopback{ready: make(chan struct{})}
	d.listen = lb.listen
	if d.rand == nil {
		d.rand = rand.Reader
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, h.Runtime, cfg, d) }()
	select {
	case <-lb.ready:
	case err := <-done:
		cancel()
		t.Fatalf("Run returned before listening: %v", err)
	case <-time.After(realWait):
		cancel()
		t.Fatal("Run did not listen")
	}
	// Ready is called after the listeners; wait for it.
	deadline := time.Now().Add(realWait)
	for {
		if code, _ := h.Get("/readyz"); code == http.StatusOK || time.Now().After(deadline) {
			break
		}
		h.Advance(time.Second)
		time.Sleep(time.Millisecond)
	}
	return h, lb.addrs, cancel, done
}

func TestRunServesCxAndTheAPIUntilCancelled(t *testing.T) {
	cfg, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	h, addrs, cancel, done := startRun(t, cfg, defaultDeps())
	diameterAddr, apiAddr := addrs[0], addrs[1]

	conf := nodeConfig(t, "scscf-1.rcs.local", nil)
	client, err := diameter.NewNode(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Shutdown(context.Background()) }()
	peer, err := client.Connect(diameter.PeerConfig{Address: diameterAddr})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(realWait)
	for !peer.Available() {
		if time.Now().After(deadline) {
			t.Fatal("no capabilities exchange with the HSS")
		}
		time.Sleep(time.Millisecond)
	}
	if host := peer.Host(); !strings.HasPrefix(host, "hss-") || !strings.HasSuffix(host, ".rcs.local") || len(host) != len("hss-0123456789ab.rcs.local") {
		t.Errorf("Origin-Host = %q, want hss-<12 hex>.rcs.local", host)
	}
	r := &cx.UAR{Request: cx.Request{DestinationRealm: domain}, UserName: impi1, PublicIdentity: impu1, VisitedNetworkIdentifier: []byte(domain)}
	msg, err := r.Message(client)
	if err != nil {
		t.Fatal(err)
	}
	ans, err := peer.Send(context.Background(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if uaa, err := cx.ParseUAA(ans); err != nil || uaa.Result != exp(cx.ErrorUserUnknown) {
		t.Fatalf("UAA = %+v, %v", uaa, err)
	}

	req, _ := http.NewRequest("GET", "http://"+apiAddr+"/v1/service-profiles/"+DefaultProfileID, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("default profile = %d", resp.StatusCode)
	}
	// The API is not on the admin port, and the admin port serves no API.
	if code, _ := h.Get("/v1/service-profiles/" + DefaultProfileID); code != http.StatusNotFound {
		t.Errorf("admin port serves the API: %d", code)
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
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Error("the API still answers after shutdown")
	}
}

func TestRunUsesDynamoDBAndKMSWhenConfigured(t *testing.T) {
	cfg, err := configure(with(devEnv, "HSS_STORE", "dynamodb", "HSS_KMS_KEY_ID", "alias/hss", "HSS_DIAMETER_HOST", "hss-1.rcs.local"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &memoryAWS{Memory: store.NewMemory()}
	var got awsstore.Config
	d := defaultDeps()
	d.aws = func(_ context.Context, c awsstore.Config) (readyStore, keyring.Wrapper, error) {
		got = c
		return backend, xorWrapper{}, nil
	}
	h, _, cancel, done := startRun(t, cfg, d)
	defer func() { cancel(); <-done }()
	if got.SubscribersTable != "subscribers" || got.ProfilesTable != "service-profiles" || got.KMSKeyID != "alias/hss" {
		t.Errorf("aws config = %+v", got)
	}
	keys, err := backend.DataKeys(context.Background())
	if err != nil || len(keys) != 1 {
		t.Fatalf("data keys = %v, %v", keys, err)
	}
	if _, err := backend.Profile(context.Background(), DefaultProfileID); err != nil {
		t.Errorf("default profile: %v", err)
	}
	if code, _ := h.Get("/readyz"); code != http.StatusOK {
		t.Errorf("/readyz = %d", code)
	}
}

func TestRunFailsWhenItCannotStart(t *testing.T) {
	dyn, err := configure(with(devEnv, "HSS_STORE", "dynamodb", "HSS_KMS_KEY_ID", "alias/hss"))
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	for name, c := range map[string]struct {
		cfg Config
		d   func(*deps)
	}{
		"AWS configuration": {dyn, func(d *deps) {
			d.aws = func(context.Context, awsstore.Config) (readyStore, keyring.Wrapper, error) { return nil, nil, boom }
		}},
		"KMS": {dyn, func(d *deps) {
			d.aws = func(context.Context, awsstore.Config) (readyStore, keyring.Wrapper, error) {
				return &memoryAWS{Memory: store.NewMemory()}, failingWrapper{}, nil
			}
		}},
		"listener": {mustConfigure(t, devEnv), func(d *deps) {
			d.listen = func(string, string) (net.Listener, error) { return nil, boom }
		}},
		"randomness": {mustConfigure(t, devEnv), func(d *deps) { d.rand = strings.NewReader("") }},
	} {
		t.Run(name, func(t *testing.T) {
			d := defaultDeps()
			c.d(&d)
			if err := run(context.Background(), runtimetest.New(t, "hss").Runtime, c.cfg, d); err == nil {
				t.Fatal("Run started")
			}
		})
	}
}

type failingWrapper struct{}

func (failingWrapper) GenerateDataKey(context.Context) ([]byte, []byte, error) {
	return nil, nil, errors.New("AccessDenied")
}
func (failingWrapper) Unwrap(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("AccessDenied")
}

func mustConfigure(t *testing.T, env map[string]string) Config {
	t.Helper()
	c, err := configure(env)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
