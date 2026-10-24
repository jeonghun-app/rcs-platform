package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/websocket/wstest"
)

const (
	testDomain = "ims.mnc001.mcc001.3gppnetwork.org"
	testToken  = "test-token-0123456789abcdef0123456789abcdef"
)

// testIMPIKey keys the tests' IMPIs.
var testIMPIKey = secret.NewString("impi-key-0123456789abcdef0123456789abcdef")

// testIMPI is the IMPI of the endpoint called name under testIMPIKey.
func testIMPI(name string) string { return impiOf(nameMAC(testIMPIKey, name), testDomain) }

// fakeClock runs timers when the test says, never by itself.
type fakeClock struct {
	mu     sync.Mutex
	timers []*fakeTimer
}

type fakeTimer struct {
	c       *fakeClock
	d       time.Duration
	f       func()
	stopped bool
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) transaction.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, d: d, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

// pending is the durations of the timers that have neither fired nor
// stopped, in order, the event streams' pings aside.
func (c *fakeClock) pending() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ds []time.Duration
	for _, t := range c.timers {
		if !t.stopped && t.d != pingInterval {
			ds = append(ds, t.d)
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds
}

// fire runs, on the test's goroutine, each pending timer of duration d,
// and reports how many.
func (c *fakeClock) fire(d time.Duration) int {
	c.mu.Lock()
	var due []*fakeTimer
	for _, t := range c.timers {
		if !t.stopped && t.d == d {
			t.stopped = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
	return len(due)
}

// fakeHSS provisions subscribers in order, slot 0 first.
type fakeHSS struct {
	mu    sync.Mutex
	calls map[string]int
	next  int
	fail  error
}

func (h *fakeHSS) Provision(_ context.Context, name string) (Subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail != nil {
		return Subscriber{}, h.fail
	}
	if h.calls == nil {
		h.calls = map[string]int{}
	}
	h.calls[name]++
	digits := fmt.Sprintf("%03d", h.next)
	h.next++
	impi := testIMPI(name)
	creds, err := sipua.DigestCredentials(impi, []byte("password-"+digits))
	if err != nil {
		return Subscriber{}, err
	}
	impu, _ := sip.ParseURI("sip:" + msisdnPrefix + digits + "@" + testDomain)
	tel, _ := sip.ParseURI("tel:" + msisdnPrefix + digits)
	return Subscriber{IMPI: impi, IMPU: impu, Tel: tel, Credentials: creds, InstanceID: instanceOf(impi)}, nil
}

// fakeNet stands in for pcscf, scscf and rcs-as: a MESSAGE to a
// registered number is delivered at once and answered 202, as rcs-as
// answers what it stores; one to a number with no line is stored and
// delivered once the number registers again, or answered offline when
// offline is set (480, as a network without store-and-forward).
type fakeNet struct {
	mu      sync.Mutex
	lines   map[string]*fakeLine
	stored  map[string][]Incoming
	offline int
	// failRegister fails that many registrations with a 403.
	failRegister int
	failRefresh  bool
	expires      time.Duration
	registers    int
	refreshes    int
	// sent is every MESSAGE body sent, by the sender's number.
	sent map[string][][]byte
	// hold, when set, holds each Send until it is closed.
	hold chan struct{}
	// deliverFirst has Register deliver what is stored before it
	// returns, and, when the receiver took any of it, return only once it
	// has sent something back on the new line (or 5 s have passed): the
	// order a network may give a third-party REGISTER's deliveries and the
	// UE's 200.
	deliverFirst bool
	// onSend, when set before the sends, sees each MESSAGE as it is sent.
	onSend func(from string, body []byte)
}

func newFakeNet() *fakeNet {
	return &fakeNet{lines: map[string]*fakeLine{}, stored: map[string][]Incoming{}, sent: map[string][][]byte{}, expires: 3600 * time.Second}
}

func (n *fakeNet) Register(_ context.Context, s Subscriber, receive func(Incoming) int) (Line, time.Duration, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.registers++
	if n.failRegister > 0 {
		n.failRegister--
		return nil, 0, &sipua.StatusError{Method: "REGISTER", Code: 403}
	}
	number, _ := numberOf(s.Tel)
	l := &fakeLine{n: n, sub: s, number: number, receive: receive, done: make(chan struct{})}
	n.lines[number] = l
	stored := n.stored[number]
	delete(n.stored, number)
	if n.deliverFirst && len(stored) > 0 {
		before := len(n.sent[number])
		n.mu.Unlock()
		taken := false
		for _, in := range stored {
			in.Line = l
			taken = n.redeliver(number, in) || taken
		}
		deadline := time.Now().Add(5 * time.Second)
		for taken && len(n.sentBy(number)) == before && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		n.mu.Lock()
		return l, n.expires, nil
	}
	// As rcs-as on the third-party REGISTER: after the 200.
	if len(stored) > 0 {
		go func() {
			for _, in := range stored {
				in.Line = l
				n.redeliver(number, in)
			}
		}()
	}
	return l, n.expires, nil
}

// redeliver gives a stored message to number's line and reports whether
// the line took it; one it answers 480 is stored again, as rcs-as keeps it
// for the next registration.
func (n *fakeNet) redeliver(number string, in Incoming) bool {
	switch in.Line.(*fakeLine).receive(in) {
	case 200:
		return true
	case 480:
		n.mu.Lock()
		n.stored[number] = append(n.stored[number], in)
		n.mu.Unlock()
	}
	return false
}

// storedFor is how many messages wait for number.
func (n *fakeNet) storedFor(number string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.stored[number])
}

func (n *fakeNet) registered(number string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.lines[number]
	return ok
}

// counts is how many REGISTERs and refreshes the network has seen.
func (n *fakeNet) counts() (registers, refreshes int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.registers, n.refreshes
}

// drop fails number's flow, as a closed connection does.
func (n *fakeNet) drop(number string) {
	n.mu.Lock()
	l := n.lines[number]
	delete(n.lines, number)
	n.mu.Unlock()
	if l != nil {
		l.close()
	}
}

func (n *fakeNet) sentBy(number string) [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.sent[number])
}

type fakeLine struct {
	n       *fakeNet
	sub     Subscriber
	number  string
	receive func(Incoming) int
	once    sync.Once
	done    chan struct{}
}

func (l *fakeLine) Refresh(context.Context) (time.Duration, error) {
	l.n.mu.Lock()
	defer l.n.mu.Unlock()
	l.n.refreshes++
	if l.n.failRefresh {
		return 0, &sipua.StatusError{Method: "REGISTER", Code: 500}
	}
	return l.n.expires, nil
}

func (l *fakeLine) Send(ctx context.Context, target sip.URI, body []byte) (int, error) {
	l.n.mu.Lock()
	hold, onSend := l.n.hold, l.n.onSend
	l.n.sent[l.number] = append(l.n.sent[l.number], slices.Clone(body))
	l.n.mu.Unlock()
	if onSend != nil {
		onSend(l.number, body)
	}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	select {
	case <-l.done:
		return 0, sipua.ErrFlowFailed
	default:
	}
	number, ok := numberOf(target)
	if !ok {
		return 404, nil
	}
	// rcs-as names the sender by its tel URI (docs/rcs-as.md).
	in := Incoming{From: l.sub.Tel, ContentType: cpim.ContentType, Body: slices.Clone(body)}
	l.n.mu.Lock()
	to := l.n.lines[number]
	if to == nil {
		if l.n.offline != 0 {
			l.n.mu.Unlock()
			return l.n.offline, nil
		}
		l.n.stored[number] = append(l.n.stored[number], in)
		l.n.mu.Unlock()
		return 202, nil
	}
	l.n.mu.Unlock()
	in.Line = to
	switch code := to.receive(in); code {
	case 200:
	case 480:
		// As rcs-as: the recipient is not reachable now, and the
		// message waits for its next registration.
		l.n.mu.Lock()
		l.n.stored[number] = append(l.n.stored[number], in)
		l.n.mu.Unlock()
	default:
		return code, nil
	}
	return 202, nil
}

func (l *fakeLine) Unregister(context.Context) error {
	l.n.mu.Lock()
	if l.n.lines[l.number] == l {
		delete(l.n.lines, l.number)
	}
	l.n.mu.Unlock()
	l.close()
	return nil
}

func (l *fakeLine) Close() {
	l.n.mu.Lock()
	if l.n.lines[l.number] == l {
		delete(l.n.lines, l.number)
	}
	l.n.mu.Unlock()
	l.close()
}

func (l *fakeLine) close()                { l.once.Do(func() { close(l.done) }) }
func (l *fakeLine) Done() <-chan struct{} { return l.done }

// harness is a bridge on the fakes behind an HTTP server.
type harness struct {
	t     *testing.T
	b     *Bridge
	srv   *httptest.Server
	net   *fakeNet
	hss   *fakeHSS
	clock *fakeClock
}

func newHarness(t *testing.T, change ...func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, net: newFakeNet(), hss: &fakeHSS{}, clock: &fakeClock{}}
	cfg := Config{
		Domain: testDomain, Provisioner: h.hss, SIP: h.net, Token: secret.NewString(testToken),
		Clock: h.clock, Now: func() time.Time { return time.Date(2026, 10, 24, 9, 30, 0, 0, time.UTC) },
	}
	for _, f := range change {
		f(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.b = b
	h.srv = httptest.NewServer(b.Handler())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b.Close(ctx)
		h.srv.Close()
	})
	return h
}

// call sends a request with the token and returns the status and the
// decoded JSON answer.
func (h *harness) call(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	return h.callWith(method, path, "Bearer "+testToken, body)
}

func (h *harness) callWith(method, path, auth string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil && !errors.Is(err, io.EOF) {
		h.t.Fatalf("%s %s: the answer is not JSON: %v", method, path, err)
	}
	return res.StatusCode, out
}

// online creates name online and checks it registered.
func (h *harness) online(name string) map[string]any {
	h.t.Helper()
	status, out := h.call(http.MethodPut, "/v1/endpoints/"+name, map[string]bool{"online": true})
	if status != http.StatusCreated && status != http.StatusOK || out["registered"] != true {
		h.t.Fatalf("PUT %s online answered %d %v", name, status, out)
	}
	return out
}

// events opens an event stream.
func (h *harness) events() *stream {
	h.t.Helper()
	c, _, err := wstest.Dial(h.srv.URL+"/v1/events", http.Header{"Authorization": {"Bearer " + testToken}})
	if err != nil {
		h.t.Fatalf("opening the event stream: %v", err)
	}
	h.t.Cleanup(func() { c.Close(1000) })
	return &stream{t: h.t, c: c}
}

// stream reads events.
type stream struct {
	t *testing.T
	c *wstest.Client
}

// next returns the next event.
func (s *stream) next() map[string]any {
	s.t.Helper()
	p, err := s.c.Next(10 * time.Second)
	if err != nil {
		s.t.Fatalf("reading an event: %v", err)
	}
	var ev map[string]any
	if err := json.Unmarshal(p, &ev); err != nil {
		s.t.Fatalf("an event that is not JSON: %q", p)
	}
	return ev
}

// await returns the next event of type typ for endpoint, skipping others.
func (s *stream) await(typ, endpoint string) map[string]any {
	s.t.Helper()
	for {
		ev := s.next()
		if ev["type"] == typ && ev["endpoint"] == endpoint {
			return ev
		}
	}
}

// eventually waits for cond, which the bridge's goroutines make true.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}
