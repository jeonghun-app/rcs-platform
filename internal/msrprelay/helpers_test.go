package msrprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// testToken is pcscf's token in tests: 43 characters, the shortest
// accepted in production.
var testToken = strings.Repeat("t", 43)

// Addresses in tests. The client's URI is a name that cannot resolve: the
// relay must never connect to it (ADR 0004).
const (
	publicHost = "relay.example.net"
	clientURI  = "msrp://client.invalid:7777/cl1entse55ion;tcp"
)

var coreHostAddr = netip.MustParseAddr("10.0.2.9")

// fakeClock fires timers only when a test advances it, in due order and on
// the advancing goroutine.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	// armed hears the duration of every timer armed, so a test can wait
	// until the code under test is waiting.
	armed chan time.Duration
}

type fakeTimer struct {
	c       *fakeClock
	when    time.Time
	f       func()
	stopped bool
	fired   bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), armed: make(chan time.Duration, 4096)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) msrp.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, when: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	select {
	case c.armed <- d:
	default:
	}
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	active := !t.stopped && !t.fired
	t.stopped = true
	return active
}

// waitTimer waits until a timer of duration d is armed, so that advancing
// the clock cannot overtake the code under test.
func (c *fakeClock) waitTimer(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-c.armed:
			if got == d {
				return
			}
		case <-deadline:
			t.Fatalf("no %v timer was armed", d)
		}
	}
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	target := c.now
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].when.Before(c.timers[j].when) })
		var due *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.fired && !t.when.After(target) {
				due = t
				break
			}
		}
		if due == nil {
			c.mu.Unlock()
			return
		}
		due.fired = true
		c.mu.Unlock()
		due.f()
	}
}

// sequence is a deterministic source of "random" bytes, so session ids in a
// test are distinct but reproducible.
type sequence struct {
	mu sync.Mutex
	n  byte
}

func (s *sequence) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range p {
		s.n++
		p[i] = s.n
	}
	return len(p), nil
}

// fakeAS plays rcs-as: a passive MSRP endpoint that knows the sessions the
// test registered, the way rcs-as does after answering an INVITE.
type fakeAS struct {
	addr  netip.AddrPort
	reg   *msrp.Registry
	clock *fakeClock
	conns chan *msrp.Conn
}

func newFakeAS(t *testing.T, clock *fakeClock) *fakeAS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	as := &fakeAS{addr: netip.MustParseAddrPort(ln.Addr().String()), reg: &msrp.Registry{}, clock: clock, conns: make(chan *msrp.Conn, 16)}
	var mu sync.Mutex
	var open []*msrp.Conn
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			c, err := msrp.NewPassiveConn(nc, as.reg, msrp.Config{Clock: clock})
			if err != nil {
				_ = nc.Close()
				continue
			}
			mu.Lock()
			open = append(open, c)
			mu.Unlock()
			select {
			case as.conns <- c:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			_ = c.Close()
		}
	})
	return as
}

// uri returns an rcs-as session URI on the fake's address.
func (as *fakeAS) uri(sid string) string {
	return "msrp://" + as.addr.String() + "/" + sid + ";tcp"
}

// session registers an rcs-as session at sid whose peer is the relay's
// core_path_local.
func (as *fakeAS) session(t *testing.T, sid, coreLocal string, h msrp.Handler) *msrp.Session {
	t.Helper()
	s, err := msrp.NewSession(msrp.SessionConfig{Local: mustURI(t, as.uri(sid)), Remote: []msrp.URI{mustURI(t, coreLocal)}, Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	if err := as.reg.Add(s); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustURI(t testing.TB, s string) msrp.URI {
	t.Helper()
	u, err := msrp.ParseURI(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return u
}

// recorder is a Handler that hands what it gets to the test.
type recorder struct {
	msgs    chan *msrp.Message
	reports chan msrp.Report
}

func newRecorder() *recorder {
	return &recorder{msgs: make(chan *msrp.Message, 64), reports: make(chan msrp.Report, 64)}
}

func (h *recorder) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	h.msgs <- m
	return nil
}

func (h *recorder) HandleReport(_ *msrp.Session, r msrp.Report) { h.reports <- r }

func (h *recorder) message(t *testing.T) *msrp.Message {
	t.Helper()
	select {
	case m := <-h.msgs:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message arrived")
		return nil
	}
}

// rig is one or more relay tasks sharing a store, with a control API and a
// fake rcs-as.
type rig struct {
	t       *testing.T
	clock   *fakeClock
	store   store.Store
	as      *fakeAS
	metrics *counters
	control http.Handler
	relays  []*Relay
	addrs   []string
	logs    *bytes.Buffer
	logMu   *sync.Mutex
	// openWait bounds a test client's Open: the rig's store timeout when
	// a test sets one, as the relay's bind makes store calls under it.
	openWait time.Duration
}

type rigOption func(*relayOptions)

// corePorts are ports the rig allows toward the core besides the fake
// rcs-as's own (RELAY_CORE_PORTS).
type extraCorePorts []uint16

func withProxyProtocol(o *relayOptions) { o.ProxyProtocol = true }

// storeTimeout replaces the rig's StoreTimeout, of the control API and of
// every task alike.
type storeTimeout time.Duration

func newRig(t *testing.T, tasks int, opts ...any) *rig {
	t.Helper()
	return newRigWithStore(t, tasks, store.NewMemory(), opts...)
}

// newRigWithStore is newRig over st, which every task and the control API
// share.
func newRigWithStore(t *testing.T, tasks int, st store.Store, opts ...any) *rig {
	t.Helper()
	r := &rig{t: t, clock: newFakeClock(), store: st, metrics: newCounters(), logs: &bytes.Buffer{}, logMu: &sync.Mutex{}}
	r.as = newFakeAS(t, r.clock)
	log := slog.New(slog.NewJSONHandler(lockedWriter{r.logMu, r.logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	public := msrp.URI{Secure: true, Host: publicHost, Port: DefaultPublicPort, Transport: "tcp"}
	rnd := &sequence{}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	ports := []uint16{r.as.addr.Port()}
	stTimeout := 5 * time.Second
	r.openWait = 5 * time.Second
	for _, opt := range opts {
		switch opt := opt.(type) {
		case extraCorePorts:
			ports = append(ports, opt...)
		case storeTimeout:
			stTimeout = time.Duration(opt)
			// A bind makes two store calls, each bounded by stTimeout.
			r.openWait = max(r.openWait, 2*stTimeout)
		case rigOption, func(*relayOptions):
		default:
			t.Fatalf("unknown rig option %T", opt)
		}
	}
	r.control = newControl(controlOptions{
		Store: r.store, StoreTimeout: stTimeout, Public: public, CoreHost: coreHostAddr,
		CoreNetworks: loopback, CorePorts: ports, MaxExpiresIn: DefaultMaxExpiresIn, Tokens: []string{testToken},
		Clock: r.clock, Rand: rnd, Log: log, Metrics: r.metrics,
	})
	for range tasks {
		o := relayOptions{
			// The store timeout is generous: a loaded host must not turn
			// a slow DynamoDB Local answer into a refusal.
			Store: r.store, StoreTimeout: stTimeout, Public: public,
			MaxConnections: 100, MaxConnectionsPerSource: 100, MaxConcurrentBinds: 8, FailedLookupsPerSource: 100,
			PathWait: DefaultPathWait, CoreConnectTimeout: 5 * time.Second, IdleTimeout: time.Minute,
			Dial: coreDialer(loopback, ports, 5*time.Second), Clock: r.clock, Rand: rnd, Log: log, Metrics: r.metrics,
		}
		for _, opt := range opts {
			switch f := opt.(type) {
			case rigOption:
				f(&o)
			case func(*relayOptions):
				f(&o)
			}
		}
		relay, err := newRelay(o)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := listenClients(context.Background(), "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = relay.Serve(ln) }()
		t.Cleanup(relay.Close)
		r.relays = append(r.relays, relay)
		r.addrs = append(r.addrs, ln.Addr().String())
	}
	return r
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (r *rig) logText() string {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	return r.logs.String()
}

// call makes a control API call with pcscf's token and decodes the answer.
func (r *rig) call(method, path string, body any) (int, map[string]any) {
	r.t.Helper()
	return callControl(r.t, r.control, method, path, testToken, body)
}

func callControl(t *testing.T, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		js, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(js)
	}
	req := httptest.NewRequest(method, path, rd)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: answer is not JSON: %q", method, path, rec.Body.String())
		}
	}
	return rec.Code, out
}

// allocated is a binding as pcscf sees it after POST.
type allocated struct {
	id, clientPath, coreLocal string
}

// allocate creates a binding with whatever paths are given.
func (r *rig) allocate(body map[string]any) allocated {
	r.t.Helper()
	if _, ok := body["expires_in"]; !ok {
		body["expires_in"] = 60
	}
	code, out := r.call("POST", "/v1/bindings", body)
	if code != http.StatusCreated {
		r.t.Fatalf("POST = %d %v", code, out)
	}
	return allocated{id: out["id"].(string), clientPath: out["client_path"].(string), coreLocal: out["core_path_local"].(string)}
}

func (r *rig) patch(id string, body map[string]any) {
	r.t.Helper()
	if code, out := r.call("PATCH", "/v1/bindings/"+id, body); code != http.StatusOK {
		r.t.Fatalf("PATCH = %d %v", code, out)
	}
}

// client is a fake RCS client: an active MSRP endpoint on a TCP connection
// to one relay task.
type client struct {
	conn     *msrp.Conn
	nc       net.Conn
	openWait time.Duration
}

// dial connects to relay task i, sending prefix (a PROXY header) first.
func (r *rig) dial(i int, prefix []byte) *client {
	r.t.Helper()
	nc, err := net.Dial("tcp", r.addrs[i])
	if err != nil {
		r.t.Fatal(err)
	}
	if prefix != nil {
		if _, err := nc.Write(prefix); err != nil {
			r.t.Fatal(err)
		}
	}
	c, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = c.Close() })
	return &client{conn: c, nc: nc, openWait: r.openWait}
}

// open binds a client session at the relay URI it was given, as a client
// does with the path in the SDP answer.
func (c *client) open(t *testing.T, relayPath string, h msrp.Handler) (*msrp.Session, error) {
	t.Helper()
	return c.openAs(t, clientURI, relayPath, h)
}

// openAs is open with the client's own URI local, for a second session on
// one connection.
func (c *client) openAs(t *testing.T, local, relayPath string, h msrp.Handler) (*msrp.Session, error) {
	t.Helper()
	s, err := msrp.NewSession(msrp.SessionConfig{Local: mustURI(t, local), Remote: []msrp.URI{mustURI(t, relayPath)}, Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	wait := c.openWait
	if wait == 0 {
		wait = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return s, c.conn.Open(ctx, s)
}

func proxyFrom(src string) []byte {
	return proxyproto.Header{Command: proxyproto.Proxy, Source: netip.MustParseAddrPort(src), Destination: netip.MustParseAddrPort("198.51.100.1:2856")}.Marshal()
}

// statusOf returns the MSRP status an Open failed with, or 0.
func statusOf(err error) int {
	var se *msrp.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// count returns what the metrics hold for name now.
func (m *counters) count(name string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counts[name]
}

// eventually polls cond, which must become true within a few seconds; the
// relay and the peers run on their own goroutines.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitDone(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not end", what)
	}
}
