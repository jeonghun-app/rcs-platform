package messaging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// The identities of the tests, all on .github/allowed-test-identifiers.txt.
const (
	alice        = "tel:+15550100001"
	bob          = "tel:+15550100002"
	carol        = "tel:+15550100003"
	intermediary = "tel:+15550100004"
	self         = "sip:rcs-as.ims.example.net"
	elsewhere    = "sip:mstore.example.org"
)

// hangGuard bounds every wait for something that should happen promptly;
// reaching it fails the test rather than hanging it.
const hangGuard = 10 * time.Second

var conv = Conversation{ID: "f81d4fae7dec11d0a76500a0c91e6bf6", Contribution: "c0ffee01"}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c    *fakeClock
	when time.Time
	// d is the duration the timer was set with, which armed and fire go by.
	d        time.Duration
	f        func()
	inactive bool
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) msrp.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, when: c.now.Add(d), d: d, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	active := !t.inactive
	t.inactive = true
	return active
}

// armed reports whether a live timer set with AfterFunc(d, …) exists. A
// test that advances the clock to fire a timer must first see it armed:
// advancing earlier moves the clock past a timer that does not exist yet,
// which then never fires (#143, #149).
func (c *fakeClock) armed(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.timers {
		if !t.inactive && t.d == d {
			return true
		}
	}
	return false
}

// fire runs every live timer set with AfterFunc(d, …) without moving the
// clock, so a test can fire one timer before others that would come due
// first.
func (c *fakeClock) fire(d time.Duration) {
	c.mu.Lock()
	var due []*fakeTimer
	for _, t := range c.timers {
		if !t.inactive && t.d == d {
			t.inactive = true
			due = append(due, t)
		}
	}
	c.mu.Unlock()
	for _, t := range due {
		t.f()
	}
}

// Advance moves the clock and runs every timer that has come due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	for {
		c.mu.Lock()
		live := c.timers[:0]
		for _, t := range c.timers {
			if !t.inactive {
				live = append(live, t)
			}
		}
		c.timers = live
		sort.SliceStable(live, func(i, j int) bool { return live[i].when.Before(live[j].when) })
		if len(live) == 0 || live[0].when.After(now) {
			c.mu.Unlock()
			return
		}
		due := live[0]
		due.inactive = true
		c.mu.Unlock()
		due.f()
	}
}

// counter records metrics.
type counter struct {
	mu sync.Mutex
	n  map[string]int64
}

func newCounter() *counter { return &counter{n: map[string]int64{}} }

func (c *counter) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n[name] += n
}

// String formats every count, for failure messages.
func (c *counter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprint(c.n)
}

func (c *counter) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

// fakeDeliverer stands in for the SIP layer. pager and invite decide the
// outcome of each attempt; every attempt is also sent on a channel. A
// full channel counts the attempt in overflow rather than block: an
// engine that loops on attempts then fails its test (newRigWith) instead
// of hanging it, workers and Close included.
type fakeDeliverer struct {
	mu       sync.Mutex
	pagerCtx func(context.Context, Delivery) error
	pager    func(Delivery) error
	invite   func(Invitation) error
	pagers   chan Delivery
	invites  chan Invitation
	overflow atomic.Int64
	// discardInvites, set by drainInvites, keeps invitations off the
	// channel for a test that does not look at them: a channel drained
	// alongside can fall behind a burst and count as overflow.
	discardInvites atomic.Bool
}

func newFakeDeliverer() *fakeDeliverer {
	return &fakeDeliverer{pagers: make(chan Delivery, 256), invites: make(chan Invitation, 256)}
}

func (f *fakeDeliverer) Pager(ctx context.Context, d Delivery) error {
	f.mu.Lock()
	h, hc := f.pager, f.pagerCtx
	f.mu.Unlock()
	var err error
	switch {
	case hc != nil:
		err = hc(ctx, d)
	case h != nil:
		err = h(d)
	}
	select {
	case f.pagers <- d:
	default:
		f.overflow.Add(1)
	}
	return err
}

func (f *fakeDeliverer) Invite(_ context.Context, inv Invitation) error {
	f.mu.Lock()
	h := f.invite
	f.mu.Unlock()
	var err error
	if h != nil {
		err = h(inv)
	}
	if f.discardInvites.Load() {
		return err
	}
	select {
	case f.invites <- inv:
	default:
		f.overflow.Add(1)
	}
	return err
}

func (f *fakeDeliverer) onPager(h func(Delivery) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pager = h
}

func (f *fakeDeliverer) onPagerCtx(h func(context.Context, Delivery) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pagerCtx = h
}

func (f *fakeDeliverer) onInvite(h func(Invitation) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invite = h
}

func (f *fakeDeliverer) nextPager(t *testing.T) Delivery {
	t.Helper()
	select {
	case d := <-f.pagers:
		return d
	case <-time.After(hangGuard):
		t.Fatal("no pager-mode delivery")
	}
	return Delivery{}
}

func (f *fakeDeliverer) nextInvite(t *testing.T) Invitation {
	t.Helper()
	select {
	case inv := <-f.invites:
		return inv
	case <-time.After(hangGuard):
		t.Fatal("no invitation")
	}
	return Invitation{}
}

// rig is an engine with its fakes.
type rig struct {
	e     *Engine
	store store.Store
	d     *fakeDeliverer
	clock *fakeClock
	m     *counter
}

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	return newRigWith(t, cfg, store.NewMemory(), newFakeClock())
}

func newRigWith(t *testing.T, cfg Config, st store.Store, clock *fakeClock) *rig {
	t.Helper()
	r := &rig{store: st, d: newFakeDeliverer(), clock: clock, m: newCounter()}
	if cfg.MSRPHost == "" {
		cfg.MSRPHost, cfg.MSRPPort = "127.0.0.1", 2855
	}
	cfg.Clock = clock
	if cfg.Rand == nil {
		cfg.Rand = seeded(1)
	}
	cfg.Self = append(cfg.Self, self)
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	var err error
	r.e, err = New(cfg, st, r.d, r.m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.e.Close()
		if n := r.d.overflow.Load(); n > 0 {
			t.Errorf("%d delivery attempts beyond the fake's channels: the engine looped", n)
		}
	})
	return r
}

func seeded(n uint64) io.Reader { return rand.NewChaCha8([32]byte{byte(n)}) }

// waitFor polls cond, which watches state the engine changes on its own
// goroutines.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(hangGuard)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitProgress is waitFor for a wait that takes as long as the work it
// waits for, on a loaded host longer than hangGuard: it fails only once
// progress, whatever counts the work done, has made no new high for
// hangGuard (#306). Only a new high counts, so work undone and done again,
// a message put back in the queue and taken again say, is not progress
// (code review on #335).
func waitProgress(t *testing.T, what string, cond func() bool, progress func() int64) {
	t.Helper()
	best, since := progress(), time.Now()
	for !cond() {
		if p := progress(); p > best {
			best, since = p, time.Now()
		} else if time.Since(since) > hangGuard {
			t.Fatalf("no progress for %v waiting for %s (at %d, best %d)", hangGuard, what, p, best)
		}
		time.Sleep(time.Millisecond)
	}
}

// queued is how many messages are queued, unclaimed, for recipient.
func (r *rig) queued(t *testing.T, recipient string) int {
	t.Helper()
	ms, err := r.store.Pending(context.Background(), recipient, "", r.clock.Now(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return len(ms)
}

// chat builds a CPIM message the way rcsjta does for 1-to-1 chat: anonymous
// From and To, an IMDN request when d is not zero.
func chat(t testing.TB, id, text string, d imdn.Disposition) []byte {
	t.Helper()
	return cpimMessage(t, cpim.Address{URI: AnonymousURI}, id, text, d)
}

func cpimMessage(t testing.TB, from cpim.Address, id, text string, d imdn.Disposition) []byte {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: <%s>\r\n", from, AnonymousURI)
	if d != 0 {
		fmt.Fprintf(&b, "NS: imdn <%s>\r\nimdn.Message-ID: %s\r\nDateTime: 2026-03-04T05:06:07.000Z\r\nimdn.Disposition-Notification: %s\r\n", imdn.Namespace, id, d)
	}
	fmt.Fprintf(&b, "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", text)
	return []byte(b.String())
}

// receipt builds the notification a recipient sends about message id.
func receipt(t testing.TB, id string, k imdn.Kind, s imdn.Status, route ...string) []byte {
	t.Helper()
	n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: k, Status: s}
	var rt []cpim.Address
	for _, u := range route {
		rt = append(rt, cpim.Address{URI: u})
	}
	m, err := n.Message(imdn.Envelope{
		From: cpim.Address{URI: AnonymousURI}, To: cpim.Address{URI: AnonymousURI},
		Route: rt, MessageID: "r" + id, DateTime: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readNotification parses a delivered notification.
func readNotification(t *testing.T, body []byte) imdn.Notification {
	t.Helper()
	m, err := cpim.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	n, err := imdn.ParseNotificationMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func standalone(sender, recipient string, body []byte) Origin {
	return Origin{Sender: sender, Recipient: recipient, Conversation: conv, Mode: store.Standalone, Pager: true, CPIM: body}
}

func rejected(err error) Reason {
	var r *Rejection
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// client is a fake RCS client: an active MSRP endpoint that msrp-relay's
// connection stands in for, connected over loopback to the engine.
type client struct {
	session *msrp.Session
	got     chan *msrp.Message
	reports chan msrp.Report
	refuse  error
	// answer, when set, is what HandleMessage returns instead of refuse;
	// one that blocks is a client that takes the bytes and processes
	// nothing.
	answer func(*msrp.Message) error
	conn   *msrp.Conn
}

func (c *client) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	c.got <- m
	if c.answer != nil {
		return c.answer(m)
	}
	return c.refuse
}

func (c *client) HandleReport(_ *msrp.Session, r msrp.Report) { c.reports <- r }

func (c *client) next(t *testing.T) *msrp.Message {
	t.Helper()
	select {
	case m := <-c.got:
		return m
	case <-time.After(hangGuard):
		t.Fatal("the client received nothing")
	}
	return nil
}

func (c *client) report(t *testing.T) msrp.Report {
	t.Helper()
	select {
	case r := <-c.reports:
		return r
	case <-time.After(hangGuard):
		t.Fatal("the client received no report")
	}
	return msrp.Report{}
}

// listen serves the engine's MSRP on loopback and returns its port.
func (r *rig) listen(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); _ = r.e.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-served })
	return l
}

var clientSeq int

// connect opens a leg for user and a client session that connects to it,
// as msrp-relay would.
func (r *rig) connect(t *testing.T, l net.Listener, p LegParams) (*Leg, *client) {
	t.Helper()
	return r.connectAnswering(t, l, p, nil)
}

// connectAnswering is connect with a client whose answers are answer's
// (client.answer).
func (r *rig) connectAnswering(t *testing.T, l net.Listener, p LegParams, answer func(*msrp.Message) error) (*Leg, *client) {
	t.Helper()
	local := clientURI()
	p.Remote = []msrp.URI{local}
	if p.Direction == 0 {
		p.Direction = Originating
	}
	leg, err := r.e.OpenLeg(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	c := r.dialAnswering(t, l, local, leg.Local(), answer)
	return leg, c
}

// dial connects a client session at local to the leg at remote, as
// msrp-relay does once the client has connected to it.
func (r *rig) dial(t *testing.T, l net.Listener, local, remote msrp.URI) *client {
	t.Helper()
	return r.dialAnswering(t, l, local, remote, nil)
}

func (r *rig) dialAnswering(t *testing.T, l net.Listener, local, remote msrp.URI, answer func(*msrp.Message) error) *client {
	t.Helper()
	var err error
	c := &client{got: make(chan *msrp.Message, 64), reports: make(chan msrp.Report, 64), answer: answer}
	c.session, err = msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{remote}, Handler: c})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c.conn = conn
	// Bounded, so a rig that never accepts fails here rather than at go
	// test's timeout (#143).
	ctx, cancel := context.WithTimeout(context.Background(), hangGuard)
	defer cancel()
	if err := conn.Open(ctx, c.session); err != nil {
		t.Fatalf("open the client session: %v", err)
	}
	return c
}

// clientURI is a fresh URI for a fake client.
func clientURI() msrp.URI {
	clientSeq++
	return msrp.URI{Host: "127.0.0.1", Port: 40000 + clientSeq, SessionID: fmt.Sprintf("client%d", clientSeq), Transport: "tcp"}
}

// idle reports whether no queue is being delivered or waits to be.
func (r *rig) idle() bool {
	r.e.mu.Lock()
	defer r.e.mu.Unlock()
	if len(r.e.queue) > 0 {
		return false
	}
	for _, x := range r.e.recipients {
		if x.run != runIdle {
			return false
		}
	}
	return true
}

func (c *client) send(t *testing.T, body []byte) {
	t.Helper()
	if _, err := c.session.Send(context.Background(), msrp.Outgoing{ContentType: cpim.ContentType, Body: body, SuccessReport: true}); err != nil {
		t.Fatal(err)
	}
}

// outcome sends body and returns the code that answered it: the refusal
// Send returned, or the code of the report about it.
func (c *client) outcome(t *testing.T, contentType string, body []byte) int {
	t.Helper()
	id, err := c.session.Send(context.Background(), msrp.Outgoing{ContentType: contentType, Body: body, SuccessReport: true})
	var se *msrp.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	if err != nil {
		t.Fatal(err)
	}
	for {
		if r := c.report(t); r.MessageID == id {
			return r.Code
		}
	}
}

var errStore = errors.New("store unavailable")

// failingStore fails every write.
type failingStore struct{ store.Store }

func (failingStore) Enqueue(context.Context, store.Message, store.Limit) error { return errStore }
func (failingStore) RecordSent(context.Context, store.Sent, time.Time) error   { return errStore }

// largeMode does what the SIP layer does for an invitation to a large-mode
// session: offers a leg for its message, has the client connect, answers.
func (r *rig) largeMode(t *testing.T, l net.Listener, inv Invitation) (*client, *Leg) {
	t.Helper()
	leg, err := r.e.Offer(LegParams{User: inv.Recipient, Peer: inv.Peer, Conversation: inv.Conversation,
		Mode: store.Standalone, Direction: Terminating, QueueID: inv.QueueID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = leg.Close() })
	u := clientURI()
	c := r.dial(t, l, u, leg.Local())
	if err := leg.Answer([]msrp.URI{u}); err != nil {
		t.Fatal(err)
	}
	return c, leg
}

func TestArmedMeansSetWithThatDuration(t *testing.T) {
	// QA on #147: a timer set for 10 ms with 5 ms left is not armed(5 ms).
	c := newFakeClock()
	c.AfterFunc(10*time.Millisecond, func() {})
	c.Advance(5 * time.Millisecond)
	if c.armed(5 * time.Millisecond) {
		t.Error("after Advance(5 ms), a timer set by AfterFunc(10 ms) is reported as armed(5 ms)")
	}
	if !c.armed(10 * time.Millisecond) {
		t.Error("a timer set by AfterFunc(10 ms) is not armed(10 ms)")
	}
	fired := 0
	c.AfterFunc(time.Hour, func() { fired++ })
	c.fire(time.Hour)
	c.fire(time.Hour)
	if fired != 1 || c.armed(time.Hour) {
		t.Errorf("fire ran the timer %d times, armed after %v", fired, c.armed(time.Hour))
	}
}
