package sipas

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sdp"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// chatRig is rcs-as with the real engine, on the memory store, and its
// MSRP listener on loopback, between the fake core and a fake msrp-relay.
type chatRig struct {
	a       *as
	metrics *counter
	e       *recordingEngine
	core    *fakeCore
	clock   *fakeClock
	msrp    net.Listener
	store   store.Store
	// groups is the group chat focus, on groupStore, whose reads
	// groupReads counts.
	groups     *group.Service
	groupStore *groupstore.Memory
	groupReads *countingGroups
}

// countingGroups counts the reads of a groups store.
type countingGroups struct {
	groupstore.Store
	gets atomic.Int64
}

func (c *countingGroups) Get(ctx context.Context, uri string, now time.Time) (groupstore.Group, error) {
	c.gets.Add(1)
	return c.Store.Get(ctx, uri, now)
}

// recordingEngine is the engine, with the failed invitations recorded.
type recordingEngine struct {
	*messaging.Engine
	failed chan error
}

func (e *recordingEngine) InviteFailed(inv messaging.Invitation, err error) {
	e.failed <- err
	e.Engine.InviteFailed(inv, err)
}

// nextFailure is the error of the next failed invitation.
func (e *recordingEngine) nextFailure(t *testing.T) error {
	t.Helper()
	select {
	case err := <-e.failed:
		return err
	case <-time.After(waitFor):
		t.Fatal("no invitation failed")
		return nil
	}
}

func newChatRig(t *testing.T, mc messaging.Config, tune ...func(*proxy.Config)) *chatRig {
	t.Helper()
	return newChatRigWith(t, mc, Config{}, tune...)
}

// newChatRigWith is newChatRig with cfg, whose Core, Clock and
// MaxMessageSize it sets.
func newChatRigWith(t *testing.T, mc messaging.Config, cfg Config, tune ...func(*proxy.Config)) *chatRig {
	t.Helper()
	return newChatRigOn(t, mc, cfg, transport.Config{}, tune...)
}

// newChatRigOn is newChatRigWith on a transport configured by tc.
func newChatRigOn(t *testing.T, mc messaging.Config, cfg Config, tc transport.Config, tune ...func(*proxy.Config)) *chatRig {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &chatRig{core: newFakeCore(t), clock: newFakeClock(), msrp: l}
	mc.MSRPHost, mc.MSRPPort, mc.HomeDomain = "127.0.0.1", l.Addr().(*net.TCPAddr).Port, domain
	mc.SenderRate = messaging.Rate{PerMinute: -1}
	mc.Logger = slog.New(slog.DiscardHandler)
	var a *as
	r.metrics = &counter{n: map[string]int64{}}
	r.store = store.NewMemory()
	e, err := messaging.New(mc, r.store, deliverer{&a}, r.metrics)
	if err != nil {
		t.Fatal(err)
	}
	r.e = &recordingEngine{Engine: e, failed: make(chan error, 16)}
	r.groupStore = groupstore.NewMemory()
	r.groupReads = &countingGroups{Store: r.groupStore}
	if r.groups, err = group.New(group.Config{ConferenceHost: confHost, HomeDomain: domain, Clock: r.clock},
		r.groupReads, e, notifier{&a}, r.metrics); err != nil {
		t.Fatal(err)
	}
	if cfg.closeWait == 0 {
		// Most fake cores leave a BYE unanswered: the test's end need not
		// wait the 2 s Close gives a real one.
		cfg.closeWait = 50 * time.Millisecond
	}
	cfg.Core, cfg.Clock, cfg.MaxMessageSize, cfg.Metrics = r.core.uri(), r.clock, messaging.DefaultMaxMessageSize, r.metrics
	a = startASOn(t, r.e, r.groups, cfg, tc, tune...)
	r.a = a
	// Closed before the Server's BYEs and the transport, which carries the
	// answers to the deliveries it waits for.
	t.Cleanup(e.Close)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { defer close(served); _ = e.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-served })
	return r
}

func (r *chatRig) msrpPort() int { return r.msrp.Addr().(*net.TCPAddr).Port }

// The MSRP URIs of the fake relay: one core path per session it anchors.
var relaySessions atomic.Int64

func relayPath() msrp.URI {
	return msrp.URI{Host: "127.0.0.1", Port: 9, SessionID: fmt.Sprintf("relay%d", relaySessions.Add(1)), Transport: "tcp"}
}

// offerSDP is the SDP msrp-relay gives rcs-as for a client's session, on
// the core leg: its core path, with setup (ADR 0004).
func offerSDP(path msrp.URI, setup string, types ...string) string {
	if len(types) == 0 {
		types = []string{cpim.ContentType, messaging.IsComposingType}
	}
	b := "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n" +
		"m=message 9 TCP/MSRP *\r\na=accept-types:" + strings.Join(types, " ") + "\r\na=path:" + path.String() + "\r\n"
	if setup != "" {
		b += "a=setup:" + setup + "\r\n"
	}
	return b + "a=sendrecv\r\n"
}

// chatInvite is alice's INVITE for a chat with bob as scscf sends it to
// rcs-as, its SDP rewritten by pcscf for the relay's core path; its
// Contact is the core's, where rcs-as's requests in the dialog go.
func (r *chatRig) chatInvite(body string, fields ...string) msg {
	return msg{method: "INVITE", uri: bob, body: body, fields: append([]string{
		"P-Asserted-Identity: <" + alice + ">",
		"Contact: <sip:" + r.core.l.Addr().String() + ";transport=tcp>;" + chatTag,
		"Accept-Contact: *;" + chatTag,
		"Conversation-ID: c0nv1", "Contribution-ID: c0ntr1",
		"Content-Type: application/sdp",
	}, fields...)}
}

// answered is the session a 2xx to a client's INVITE set up.
type answered struct {
	res    *sip.Response
	callID string
	tag    string
	path   msrp.URI
	answer *sdp.Session
}

func answeredBy(t *testing.T, res *sip.Response) answered {
	t.Helper()
	if res.StatusCode != 200 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	to, err := res.Header.To()
	if err != nil || to.Tag() == "" {
		t.Fatalf("To %+v, %v", to, err)
	}
	s, err := sdp.Parse(res.Body)
	if err != nil {
		t.Fatalf("SDP answer %q: %v", res.Body, err)
	}
	_, path, _, err := firstMSRP(s, sdp.SetupPassive)
	if err != nil || len(path) != 1 {
		t.Fatalf("path %v, %v", path, err)
	}
	return answered{res: res, callID: res.Header.Get("Call-ID"), tag: to.Tag(), path: path[0], answer: s}
}

// ack acknowledges the 2xx of s.
func (p *peer) ack(s answered) {
	p.t.Helper()
	if _, err := p.try(msg{method: "ACK", uri: bob, toTag: s.tag, callID: s.callID, cseq: 1}); err != nil {
		p.t.Fatal(err)
	}
}

// relayEnd is msrp-relay's end of a leg: the active side, connected to
// rcs-as's MSRP listener (ADR 0004).
type relayEnd struct {
	session *msrp.Session
	conn    *msrp.Conn
	got     chan *msrp.Message
	reports chan msrp.Report
}

func (e *relayEnd) HandleMessage(_ *msrp.Session, m *msrp.Message) error { e.got <- m; return nil }
func (e *relayEnd) HandleReport(_ *msrp.Session, r msrp.Report)          { e.reports <- r }

// connect opens the relay's session at local to the leg at remote.
func (r *chatRig) connect(t *testing.T, local, remote msrp.URI) *relayEnd {
	t.Helper()
	e := &relayEnd{got: make(chan *msrp.Message, 16), reports: make(chan msrp.Report, 16)}
	var err error
	e.session, err = msrp.NewSession(msrp.SessionConfig{Local: local, Remote: []msrp.URI{remote}, Handler: e})
	if err != nil {
		t.Fatal(err)
	}
	nc, err := net.Dial("tcp", r.msrp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if e.conn, err = msrp.NewActiveConn(nc, msrp.Config{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	if err := e.conn.Open(ctx, e.session); err != nil {
		t.Fatalf("open the relay's session: %v", err)
	}
	return e
}

// send sends a chat message and returns the code of its report.
func (e *relayEnd) send(t *testing.T, body string) int {
	t.Helper()
	id, err := e.session.Send(context.Background(), msrp.Outgoing{ContentType: cpim.ContentType, Body: []byte(body), SuccessReport: true})
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case rep := <-e.reports:
			if rep.MessageID == id {
				return rep.Code
			}
		case <-time.After(waitFor):
			t.Fatal("no report")
		}
	}
}

func (e *relayEnd) next(t *testing.T) *msrp.Message {
	t.Helper()
	select {
	case m := <-e.got:
		return m
	case <-time.After(waitFor):
		t.Fatal("the relay received nothing")
		return nil
	}
}

// chatCPIM is a chat message from alice (rcsjta's form).
func chatCPIM(id, text string) string {
	return "From: <" + messaging.AnonymousURI + ">\r\nTo: <" + messaging.AnonymousURI + ">\r\n" +
		"NS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: " + id + "\r\nDateTime: 2026-03-04T05:06:07.000Z\r\n\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" + text
}

// answerInvite is the client's 2xx to rcs-as's INVITE, through pcscf: the
// relay's core path, with setup, and the core as the Contact.
func (r *chatRig) answerInvite(t *testing.T, req *sip.Request, path msrp.URI, setup string, fields ...string) *sip.Response {
	t.Helper()
	res, err := sip.NewResponse(req, 200, "", "bob1")
	if err != nil {
		t.Fatal(err)
	}
	fields = append([]string{"Contact: <sip:" + r.core.l.Addr().String() + ";transport=tcp>", "Content-Type: application/sdp"}, fields...)
	for _, f := range fields {
		name, value, _ := strings.Cut(f, ": ")
		if err := res.Header.Add(name, value); err != nil {
			t.Fatal(err)
		}
	}
	res.Body = []byte(offerSDP(path, setup))
	return res
}

// offered is the MSRP path of rcs-as's offer in req, and its setup.
func offered(t *testing.T, req *sip.Request) (msrp.URI, sdp.Setup) {
	t.Helper()
	s, err := sdp.Parse(req.Body)
	if err != nil {
		t.Fatalf("SDP offer %q: %v", req.Body, err)
	}
	_, path, setup, err := firstMSRP(s, "")
	if err != nil || len(path) != 1 {
		t.Fatalf("path %v, %v", path, err)
	}
	return path[0], setup
}

// counter counts the Server's metrics.
type counter struct {
	mu sync.Mutex
	n  map[string]int64
}

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

// fakeClock runs the session timers when a test says so.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c       *fakeClock
	d       time.Duration
	f       func()
	stopped bool
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) msrp.Timer {
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

// armed are the durations of the timers not stopped or fired, in the
// order they were set.
func (c *fakeClock) armed() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []time.Duration
	for _, t := range c.timers {
		if !t.stopped {
			out = append(out, t.d)
		}
	}
	return out
}

// waitArmed waits until the timers armed are want.
func (c *fakeClock) waitArmed(t *testing.T, want ...time.Duration) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !slices.Equal(c.armed(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("armed %v, want %v", c.armed(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// fire runs every armed timer of duration d, once.
func (c *fakeClock) fire(d time.Duration) {
	c.mu.Lock()
	var run []func()
	for _, t := range c.timers {
		if !t.stopped && t.d == d {
			t.stopped = true
			run = append(run, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range run {
		f()
	}
}
