package group

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
)

// The identities of the tests, all on .github/allowed-test-identifiers.txt.
const (
	alice = "tel:+15550100001"
	bob   = "tel:+15550100002"
	carol = "tel:+15550100003"
	dave  = "tel:+15550100004"
	erin  = "tel:+15550100005"
	host  = "conf.ims.example.net"
)

const hangGuard = 10 * time.Second

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c        *fakeClock
	when     time.Time
	f        func()
	inactive bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)} }

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
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	active := !t.inactive
	t.inactive = true
	return active
}

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

func (c *counter) get(name string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

func (c *counter) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprint(c.n)
}

// notifier records roster updates.
type notifier struct {
	mu      sync.Mutex
	updates []RosterUpdate
}

func (n *notifier) RosterChanged(_ context.Context, u RosterUpdate) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.updates = append(n.updates, u)
}

func (n *notifier) all() []RosterUpdate {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]RosterUpdate(nil), n.updates...)
}

// deliverer stands in for the SIP layer: it counts what the engine asks.
type deliverer struct {
	mu      sync.Mutex
	pagers  int
	invites []messaging.Invitation
}

func (d *deliverer) Pager(context.Context, messaging.Delivery) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pagers++
	return messaging.ErrOffline
}

func (d *deliverer) Invite(_ context.Context, inv messaging.Invitation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.invites = append(d.invites, inv)
	return nil
}

func (d *deliverer) counts() (int, []messaging.Invitation) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pagers, append([]messaging.Invitation(nil), d.invites...)
}

// rig is a group service over an engine, both on memory stores.
type rig struct {
	t      *testing.T
	s      *Service
	e      *messaging.Engine
	queues *store.Memory
	groups groupstore.Store
	clock  *fakeClock
	n      *notifier
	d      *deliverer
	m      *counter
	l      net.Listener
}

func seeded(n uint64) io.Reader { return rand.NewChaCha8([32]byte{byte(n)}) }

func newRig(t *testing.T, cfg Config) *rig {
	t.Helper()
	return newRigWith(t, cfg, messaging.Config{}, store.NewMemory(), groupstore.NewMemory(), newFakeClock(), 1)
}

func newRigWith(t *testing.T, cfg Config, ecfg messaging.Config, queues *store.Memory, groups groupstore.Store, clock *fakeClock, seed uint64) *rig {
	t.Helper()
	r := &rig{t: t, queues: queues, groups: groups, clock: clock, n: &notifier{}, d: &deliverer{}, m: newCounter()}
	ecfg.MSRPHost, ecfg.MSRPPort = "127.0.0.1", 2855
	ecfg.Clock, ecfg.Rand = clock, seeded(seed)
	ecfg.Logger = slog.New(slog.DiscardHandler)
	var err error
	if r.e, err = messaging.New(ecfg, queues, r.d, r.m); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.e.Close)
	cfg.ConferenceHost = host
	cfg.Clock, cfg.Rand = clock, seeded(seed+100)
	if r.s, err = New(cfg, groups, r.e, r.n, r.m); err != nil {
		t.Fatal(err)
	}
	return r
}

// beat runs the Service's heartbeat until the test ends, and returns once
// the first beat is stored.
func (r *rig) beat(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := r.s.StartHeartbeat(ctx)
	t.Cleanup(func() { cancel(); stopped() })
	waitFor(t, "the first heartbeat", func() bool { return r.s.alive(r.clock.Now()) })
}

// pass moves r's clock on by d, a heartbeat at a time, waiting at each
// beat's time for the beat to be stored, so that r stays alive.
func (r *rig) pass(t *testing.T, d time.Duration) {
	t.Helper()
	for d > 0 {
		step := min(d, r.s.cfg.TaskHeartbeat-r.clock.Now().Sub(r.lastBeat())%r.s.cfg.TaskHeartbeat)
		r.clock.Advance(step)
		d -= step
		if r.clock.Now().Sub(r.lastBeat()) >= r.s.cfg.TaskHeartbeat {
			waitFor(t, "the heartbeat", func() bool { return r.lastBeat().Equal(r.clock.Now()) })
		}
	}
}

func (r *rig) lastBeat() time.Time {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.s.lastBeat
}

// owner is uri's stored owner, which a test writing the store directly
// writes under.
func (r *rig) owner(t *testing.T, uri string) groupstore.Owner {
	t.Helper()
	o, err := r.groups.Owner(t.Context(), uri)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// create makes a group of alice and the others, all joined.
func (r *rig) create(others ...string) groupstore.Group {
	r.t.Helper()
	var in []Invitee
	for _, o := range others {
		in = append(in, Invitee{Identity: o})
	}
	g, err := r.s.Create(r.t.Context(), CreateRequest{Creator: alice, CreatorName: "Alice", Invitees: in, Subject: "Lunch", Conversation: "conv-1"})
	if err != nil {
		r.t.Fatal(err)
	}
	for _, o := range others {
		if g, err = r.s.Join(r.t.Context(), g.URI, o, ""); err != nil {
			r.t.Fatal(err)
		}
	}
	return g
}

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

// message builds a CPIM message the way rcsjta does in a group: its own
// address in From, the anonymous URI in To, IMDN asked for when d is set.
func message(t testing.TB, from, id, text string, d imdn.Disposition) []byte {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: <%s>\r\n", cpim.Address{Name: "A Name", URI: from}, messaging.AnonymousURI)
	if d != 0 {
		fmt.Fprintf(&b, "NS: imdn <%s>\r\nimdn.Message-ID: %s\r\nDateTime: 2026-03-04T05:06:07.000Z\r\nimdn.Disposition-Notification: %s\r\n", imdn.Namespace, id, d)
	}
	fmt.Fprintf(&b, "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", text)
	return []byte(b.String())
}

// receipt builds a participant's notification about message id, To the
// author as the notifier's client writes it.
func receipt(t testing.TB, from, to, id string, k imdn.Kind, s imdn.Status) []byte {
	t.Helper()
	n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: k, Status: s}
	m, err := n.Message(imdn.Envelope{From: cpim.Address{URI: from}, To: cpim.Address{URI: to}, MessageID: "r" + id + from[len(from)-2:],
		DateTime: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// client is a participant's MSRP endpoint, connected to its leg with the
// group as msrp-relay's connection would be.
type client struct {
	session *msrp.Session
	got     chan *msrp.Message
	reports chan msrp.Report
	// hold, when set, makes the client take a message only once it is
	// closed: a slow participant.
	hold chan struct{}
}

func (c *client) HandleMessage(_ *msrp.Session, m *msrp.Message) error {
	if c.hold != nil {
		<-c.hold
	}
	c.got <- m
	return nil
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

// send sends body and returns the code that answered it.
func (c *client) send(t *testing.T, body []byte) int {
	t.Helper()
	return c.sendType(t, cpim.ContentType, body)
}

func (c *client) sendType(t *testing.T, contentType string, body []byte) int {
	t.Helper()
	id, err := c.session.Send(context.Background(), msrp.Outgoing{ContentType: contentType, Body: body, SuccessReport: true})
	if se, ok := err.(*msrp.StatusError); ok {
		return se.Code
	}
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case rep := <-c.reports:
			if rep.MessageID == id {
				return rep.Code
			}
		case <-time.After(hangGuard):
			t.Fatal("no report")
		}
	}
}

var clientSeq int

func (r *rig) listen() {
	r.t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); _ = r.e.Serve(ctx, l) }()
	r.t.Cleanup(func() { cancel(); <-served })
	r.l = l
}

// connect opens who's session with group g and its client.
func (r *rig) connect(g groupstore.Group, who string, hold chan struct{}) *client {
	r.t.Helper()
	if r.l == nil {
		r.listen()
	}
	clientSeq++
	local := msrp.URI{Host: "127.0.0.1", Port: 40000 + clientSeq, SessionID: fmt.Sprintf("client%d", clientSeq), Transport: "tcp"}
	leg, err := r.e.OpenLeg(messaging.LegParams{Remote: []msrp.URI{local}, User: who, Peer: g.URI,
		Conversation: messaging.Conversation{ID: g.Conversation, Contribution: "c1"}, Mode: store.Group, Direction: messaging.Originating})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = leg.Close() })
	c := &client{got: make(chan *msrp.Message, 256), reports: make(chan msrp.Report, 256), hold: hold}
	if c.session, err = msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{leg.Local()}, Handler: c}); err != nil {
		r.t.Fatal(err)
	}
	nc, err := net.Dial("tcp", r.l.Addr().String())
	if err != nil {
		r.t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock})
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Open(context.Background(), c.session); err != nil {
		r.t.Fatal(err)
	}
	return c
}

// roster parses a roster update.
func roster(t *testing.T, doc []byte) *conference.Info {
	t.Helper()
	c, err := conference.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var rateOff = messaging.Rate{PerMinute: -1}

func engineConfig() messaging.Config { return messaging.Config{} }
