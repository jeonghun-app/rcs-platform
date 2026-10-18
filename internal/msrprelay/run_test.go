package msrprelay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/dynamostore"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	c, err := configure(with(devEnv, "RELAY_LISTEN_ADDR", "127.0.0.1:0", "RELAY_CONTROL_ADDR", "127.0.0.1:0",
		"RELAY_CORE_NETWORKS", "127.0.0.0/8", "RELAY_DRAIN_TIMEOUT", "10s"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type running struct {
	h               *runtimetest.Harness
	clock           *fakeClock
	as              *fakeAS
	public, control string
	cancel          context.CancelFunc
	done            chan error
}

func startRun(t *testing.T, cfg Config) *running {
	t.Helper()
	r := &running{h: runtimetest.New(t, "msrp-relay"), clock: newFakeClock(), done: make(chan error, 1)}
	r.as = newFakeAS(t, r.clock)
	cfg.CorePorts = append(cfg.CorePorts, r.as.addr.Port())
	addrs := make(chan [2]string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		r.done <- run(ctx, r.h.Runtime, cfg, deps{
			store: store.NewMemory(), clock: r.clock, rand: &sequence{},
			listening: func(p, c net.Addr) { addrs <- [2]string{p.String(), c.String()} },
		})
	}()
	select {
	case a := <-addrs:
		r.public, r.control = a[0], a[1]
	case err := <-r.done:
		t.Fatalf("run = %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("run did not start")
	}
	t.Cleanup(func() {
		cancel()
		r.clock.Advance(time.Hour)
	})
	return r
}

func (r *running) post(t *testing.T, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+r.control+"/v1/bindings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST = %d %v", resp.StatusCode, out)
	}
	return out
}

func TestRunServesTheControlAPIAndTheDataPathThenDrains(t *testing.T) {
	r := startRun(t, testConfig(t))
	eventually(t, "/readyz to answer 200", func() bool { code, _ := r.h.Get("/readyz"); return code == http.StatusOK })
	as := r.as
	b := r.post(t, `{"client_endpoint_path":["`+clientURI+`"],"core_path":["`+as.uri("asrun")+`"],"expires_in":600}`)
	asH := newRecorder()
	as.session(t, "asrun", b["core_path_local"].(string), asH)

	nc, err := net.Dial("tcp", r.public)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	c := &client{conn: cc, nc: nc}
	s, err := c.open(t, b["client_path"].(string), newRecorder())
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	send(t, s, "through Run")
	if m := asH.message(t); string(m.Body) != "through Run" {
		t.Fatalf("rcs-as got %q", m.Body)
	}

	// Metrics are flushed every interval, not per event.
	r.clock.Advance(DefaultMetricsInterval)
	eventually(t, "a metrics flush", func() bool { _, ok := r.h.Metric(mActiveBridges); return ok })
	if v, _ := r.h.Metric(mBindingsCreated); v != 1 {
		t.Fatalf("BindingsCreated = %v", v)
	}
	if v, _ := r.h.Metric(mBytesFromClients); v == 0 {
		t.Fatal("no bytes counted")
	}

	// Stopping: the listener closes, the bridge stays until the drain
	// timeout, then it is closed and Run returns.
	r.cancel()
	r.clock.waitTimer(t, 5*time.Second)
	if c, err := net.Dial("tcp", r.public); err == nil {
		_ = c.Close()
		t.Fatal("a stopping relay accepted a connection")
	}
	send(t, s, "while draining")
	if m := asH.message(t); string(m.Body) != "while draining" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
	r.clock.Advance(5 * time.Second)
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after the drain")
	}
	waitDone(t, cc.Done(), "the client connection")
	if v, _ := r.h.Metric(mClientConnections); v != 1 {
		t.Fatalf("ClientConnections gauge summed to %v over two flushes, want 1 then 0", v)
	}
	if !strings.Contains(r.h.Output(), `"msg":"relaying MSRP"`) {
		t.Fatal("start was not logged")
	}
	if strings.Contains(r.h.Output(), mustURI(t, b["client_path"].(string)).SessionID) {
		t.Fatal("a session id reached the log or the metrics")
	}
}

func TestRunWithoutClientsStopsAtOnce(t *testing.T) {
	r := startRun(t, testConfig(t))
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestRunFailsWhenAListenerCannotOpen(t *testing.T) {
	h := runtimetest.New(t, "msrp-relay")
	cfg := testConfig(t)
	err := run(context.Background(), h.Runtime, cfg, deps{
		store:  store.NewMemory(),
		listen: func(context.Context, string) (net.Listener, error) { return nil, errors.New("address in use") },
	})
	if err == nil || !strings.Contains(err.Error(), "address in use") {
		t.Fatalf("run = %v", err)
	}

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	cfg.ControlAddr = taken.Addr().String()
	var public net.Listener
	err = run(context.Background(), runtimetest.New(t, "msrp-relay").Runtime, cfg, deps{
		store: store.NewMemory(),
		listen: func(ctx context.Context, a string) (net.Listener, error) {
			var err error
			public, err = listenClients(ctx, a)
			return public, err
		},
	})
	if err == nil {
		t.Fatal("run started without its control listener")
	}
	if _, err := public.Accept(); err == nil {
		t.Fatal("the public listener was left open")
	}
}

func TestRunReportsAFailedListener(t *testing.T) {
	h := runtimetest.New(t, "msrp-relay")
	ln, err := listenClients(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- run(context.Background(), h.Runtime, testConfig(t), deps{
			store: store.NewMemory(), clock: newFakeClock(),
			listen:    func(context.Context, string) (net.Listener, error) { return ln, nil },
			listening: func(net.Addr, net.Addr) { _ = ln.Close() },
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("run = %v, want the listener's failure", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not notice its listener failing")
	}
}

func TestReadinessFollowsTheStore(t *testing.T) {
	h := runtimetest.New(t, "msrp-relay")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	go func() {
		_ = run(ctx, h.Runtime, testConfig(t), deps{
			store: unready{store.NewMemory()}, clock: newFakeClock(),
			listening: func(net.Addr, net.Addr) { close(started) },
		})
	}()
	<-started
	eventually(t, "/readyz to name the store", func() bool {
		code, body := h.Get("/readyz")
		return code == http.StatusServiceUnavailable && strings.Contains(body, "binding store")
	})
}

type unready struct{ store.Store }

func (unready) Ready(context.Context) error { return errors.New("table missing") }

func TestOpenStoreFollowsTheSetting(t *testing.T) {
	st, err := openStore(context.Background(), Config{Store: StoreMemory})
	if _, ok := st.(*store.Memory); !ok || err != nil {
		t.Fatalf("memory: %T, %v", st, err)
	}
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	st, err = openStore(context.Background(), Config{Store: StoreDynamoDB, Table: "msrp-bindings", DynamoDBEndpoint: "http://127.0.0.1:1"})
	if _, ok := st.(*dynamostore.Store); !ok || err != nil {
		t.Fatalf("dynamodb: %T, %v", st, err)
	}
}

func TestServiceIsNamedForLogsAndMetrics(t *testing.T) {
	s := Service()
	if s.Name != "msrp-relay" || s.EnvPrefix != "RELAY_" || s.Configure == nil || s.Run == nil {
		t.Fatalf("service %+v", s)
	}
}

func TestEveryStopsWhenAsked(t *testing.T) {
	clock := newFakeClock()
	n := 0
	stop := every(clock, time.Second, func() { n++ })
	clock.Advance(time.Second)
	clock.Advance(time.Second)
	stop()
	clock.Advance(time.Second)
	if n != 2 {
		t.Fatalf("ran %d times, want 2", n)
	}
}

func TestSystemClockIsRealTime(t *testing.T) {
	var c msrp.Clock = systemClock{}
	fired := make(chan struct{})
	c.AfterFunc(time.Millisecond, func() { close(fired) })
	waitDone(t, fired, "the timer")
	if d := time.Since(c.Now()); d < 0 || d > time.Minute {
		t.Fatalf("Now is %v away", d)
	}
}

func TestFlushWritesCountsOnceAndGaugesEveryTime(t *testing.T) {
	h := runtimetest.New(t, "msrp-relay")
	m := newCounters()
	m.add(mBindingsCreated, 2)
	m.refuse(reasonClaimed)
	m.bytesIn.Add(10)
	m.bytesOut.Add(20)
	m.bridges.Add(3)
	m.flush(h.Runtime.Metrics)
	m.flush(h.Runtime.Metrics)
	for name, want := range map[string]float64{
		mBindingsCreated: 2, mRefusedPrefix + reasonClaimed: 1, mBytesFromClients: 10, mBytesToClients: 20,
		mActiveBridges: 6, mClientConnections: 0,
	} {
		if got, ok := h.Metric(name); !ok || got != want {
			t.Fatalf("%s = %v (%v), want %v", name, got, ok, want)
		}
	}
}

func TestMsrpEventsAreCountedByKindAndReason(t *testing.T) {
	m := newCounters()
	on := m.onEvent(mClientPrefix)
	on(msrp.Event{Kind: msrp.EventRefused, Code: 481})
	on(msrp.Event{Kind: msrp.EventDropped, Err: msrp.ErrHandlerBusy})
	on(msrp.Event{Kind: msrp.EventClosed, Err: msrp.ErrKeepAliveTimeout})
	on(msrp.Event{Kind: msrp.EventClosed})
	on(msrp.Event{Kind: msrp.EventClosed, Err: io.EOF})
	for _, name := range []string{"Client.Refused.481", "Client.Dropped.HandlerBusy", "Client.Closed.KeepAliveTimeout", "Client.Closed.None", "Client.Closed.Other"} {
		if m.count(name) != 1 {
			t.Fatalf("%s = %d", name, m.count(name))
		}
	}
}

func TestMeteredConnCountsAndReportsIdleness(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	m := newCounters()
	c := &meteredConn{Conn: a, idle: 10 * time.Millisecond, in: &m.bytesIn, out: &m.bytesOut}
	go func() { _, _ = b.Write([]byte("abc")); _, _ = io.ReadAll(b) }()
	buf := make([]byte, 8)
	if n, err := c.Read(buf); n != 3 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(buf); !errors.Is(err, errIdle) || !c.idled.Load() {
		t.Fatalf("Read after the idle time = %v", err)
	}
	if m.bytesIn.Load() != 3 || m.bytesOut.Load() != 5 {
		t.Fatalf("in %d out %d", m.bytesIn.Load(), m.bytesOut.Load())
	}
}
