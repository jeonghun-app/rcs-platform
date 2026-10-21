package msrprelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay/store"
	"github.com/jeonghun-app/rcs-platform/internal/proxyproto"
)

// These tests run the relay end to end over loopback TCP: a fake client
// (internal/msrp, active) connects to the relay, which connects to a fake
// rcs-as (internal/msrp, passive), as in ADR 0004. Timers run on a fake
// clock; only the operating system's own deadlines are real.

func send(t *testing.T, s *msrp.Session, body string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.Send(ctx, msrp.Outgoing{ContentType: "text/plain", Body: []byte(body)}); err != nil {
		t.Fatalf("Send = %v", err)
	}
}

// bridged sets up a complete binding the way the client-originated row of
// ADR 0004 does and connects a client to relay task i.
func (r *rig) bridged(i int, expiresIn int) (allocated, *msrp.Session, *recorder, *msrp.Session, *recorder) {
	r.t.Helper()
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "expires_in": expiresIn})
	asH := newRecorder()
	as := r.as.session(r.t, "as5e55ion", b.coreLocal, asH)
	r.patch(b.id, map[string]any{"core_path": []string{r.as.uri("as5e55ion")}})
	clientH := newRecorder()
	s, err := r.dial(i, nil).open(r.t, b.clientPath, clientH)
	if err != nil {
		r.t.Fatalf("client Open = %v", err)
	}
	return b, s, clientH, as, asH
}

func TestClientOriginatedSessionIsBridgedToRcsAS(t *testing.T) {
	// ADR 0004, first row: the client offers, so pcscf learns the client's
	// path first and rcs-as's from the answer, then the client connects.
	r := newRig(t, 1)
	b, client, clientH, as, asH := r.bridged(0, 60)

	send(t, client, "hello")
	m := asH.message(t)
	if string(m.Body) != "hello" || m.FromPath[0].String() != b.coreLocal || m.ToPath[0].String() != r.as.uri("as5e55ion") {
		t.Fatalf("rcs-as got %q from %v to %v", m.Body, m.FromPath, m.ToPath)
	}
	send(t, as, "back")
	m = clientH.message(t)
	if string(m.Body) != "back" || m.FromPath[0].String() != b.clientPath || m.ToPath[0].String() != clientURI {
		t.Fatalf("client got %q from %v to %v", m.Body, m.FromPath, m.ToPath)
	}
	if got := r.metrics.count(mBindingsClaimed); got != 1 {
		t.Fatalf("BindingsClaimed = %d", got)
	}
	if r.metrics.bridges.Load() != 1 || r.metrics.bytesIn.Load() == 0 || r.metrics.bytesOut.Load() == 0 {
		t.Fatalf("bridges %d, bytes in %d out %d", r.metrics.bridges.Load(), r.metrics.bytesIn.Load(), r.metrics.bytesOut.Load())
	}
}

func TestCoreOriginatedSessionIsBridgedOnceTheClientAnswers(t *testing.T) {
	// ADR 0004, second row: rcs-as offers, so pcscf learns rcs-as's path
	// first and the client's from the answer; the client connects, and the
	// relay connects to rcs-as.
	r := newRig(t, 1)
	asH := newRecorder()
	b := r.allocate(map[string]any{"core_path": []string{r.as.uri("as0ffer5")}})
	as := r.as.session(t, "as0ffer5", b.coreLocal, asH)
	r.patch(b.id, map[string]any{"client_endpoint_path": []string{clientURI}})
	clientH := newRecorder()
	client, err := r.dial(0, nil).open(t, b.clientPath, clientH)
	if err != nil {
		t.Fatalf("client Open = %v", err)
	}
	send(t, as, "offered")
	if m := clientH.message(t); string(m.Body) != "offered" {
		t.Fatalf("client got %q", m.Body)
	}
	send(t, client, "answered")
	if m := asH.message(t); string(m.Body) != "answered" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
}

func TestClientConnectingBeforeItsPathIsRecordedWaitsForIt(t *testing.T) {
	// The client may connect as soon as it has sent its answer, before
	// pcscf has recorded the client's path from that answer.
	r := newRig(t, 1)
	b := r.allocate(map[string]any{"core_path": []string{r.as.uri("asrac3")}})
	asH := newRecorder()
	r.as.session(t, "asrac3", b.coreLocal, asH)
	opened := make(chan error, 1)
	var client *msrp.Session
	go func() {
		var err error
		client, err = r.dial(0, nil).open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	r.clock.waitTimer(t, 25*time.Millisecond)
	r.patch(b.id, map[string]any{"client_endpoint_path": []string{clientURI}})
	r.clock.Advance(25 * time.Millisecond)
	if err := <-opened; err != nil {
		t.Fatalf("client Open = %v", err)
	}
	send(t, client, "raced")
	if m := asH.message(t); string(m.Body) != "raced" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
}

func TestClientPathThatNeverArrivesIsRefused(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.PathWait = 30 * time.Millisecond })
	b := r.allocate(map[string]any{"core_path": []string{r.as.uri("asn3ver")}})
	opened := make(chan error, 1)
	go func() {
		_, err := r.dial(0, nil).open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	r.clock.waitTimer(t, 25*time.Millisecond)
	r.clock.Advance(25 * time.Millisecond)
	r.clock.waitTimer(t, 5*time.Millisecond)
	r.clock.Advance(5 * time.Millisecond)
	if err := <-opened; statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("client Open = %v, want 481", err)
	}
	if got := r.metrics.count(mRefusedPrefix + reasonIncomplete); got != 1 {
		t.Fatalf("Refused.IncompleteBinding = %d", got)
	}
}

func TestAClientRefusedAfterThePathWaitKeepsItsConnection(t *testing.T) {
	// The client's keep-alive interval is shorter than the wait, but while
	// its binding SEND is unanswered it sends nothing more. Each keep-alive
	// would name the session again: another lookup and another wait, or,
	// for a binding already gone, another unknown session toward
	// MaxFailedBinds, which closes the connection before the client reads
	// its 481 (#204).
	r := newRig(t, 1, func(o *relayOptions) { o.PathWait = 30 * time.Millisecond })
	b := r.allocate(map[string]any{"core_path": []string{r.as.uri("ask33p")}})
	nc, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock, KeepAliveInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &client{conn: conn, nc: nc}
	opened := make(chan error, 1)
	go func() {
		_, err := c.open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	r.clock.waitTimer(t, 25*time.Millisecond)
	r.clock.Advance(25 * time.Millisecond)
	r.clock.waitTimer(t, 5*time.Millisecond)
	r.clock.Advance(5 * time.Millisecond)
	if err := <-opened; statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("client Open = %v, want 481", err)
	}
	// Answered after anything sent before it.
	if _, err := c.openAs(t, "msrp://client.invalid:7777/an0th3rse55ion;tcp", "msrps://"+publicHost+":2856/n0such5e55ion;tcp", newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("second Open = %v, want 481", err)
	}
	if got := r.metrics.count(mClientPrefix + "Refused.481"); got != 2 {
		t.Fatalf("Client.Refused.481 = %d, want 2", got)
	}
	if c.conn.Err() != nil {
		t.Fatalf("connection ended: %v", c.conn.Err())
	}
}

func TestAClientNamingAReleasedBindingReads481AndKeepsItsConnection(t *testing.T) {
	// QA on #217, the release step of #204: the lookup of a released
	// binding is slow, and the client's keep-alive interval is short.
	// The client sends its binding SEND alone, so the relay counts one
	// unknown session, not four, and does not close the connection
	// (MaxFailedBinds) with the 481 still queued.
	slow := &flakyStore{block: make(chan struct{}), blocked: make(chan struct{}, 16)}
	r := newRig(t, 1, wrapStore(slow))
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asrel")}})
	if code, _ := r.call("DELETE", "/v1/bindings/"+b.id, nil); code != 204 {
		t.Fatalf("DELETE = %d", code)
	}
	nc, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	conn, err := msrp.NewActiveConn(nc, msrp.Config{Clock: r.clock, KeepAliveInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := &client{conn: conn, nc: nc}
	opened := make(chan error, 1)
	go func() {
		_, err := c.open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	<-slow.blocked // the relay is looking the released binding up
	// Six keep-alive intervals pass meanwhile. The pauses only give a
	// keep-alive, if one were sent, time to reach the relay; the test
	// passes without them.
	for range 6 {
		r.clock.Advance(5 * time.Millisecond)
		time.Sleep(20 * time.Millisecond)
	}
	// Later lookups, if any, are not held.
	slow.mu.Lock()
	block := slow.block
	slow.block = nil
	slow.mu.Unlock()
	close(block)
	if err := <-opened; statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("client Open = %v, want 481", err)
	}
	// Answered after anything sent before it.
	if _, err := c.openAs(t, "msrp://client.invalid:7777/an0th3rse55ion;tcp", "msrps://"+publicHost+":2856/n0such5e55ion;tcp", newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("second Open = %v, want 481", err)
	}
	if got := r.metrics.count(mClientPrefix + "Refused.481"); got != 2 {
		t.Fatalf("Client.Refused.481 = %d, want 2", got)
	}
	if c.conn.Err() != nil {
		t.Fatalf("connection ended: %v", c.conn.Err())
	}
}

func TestSecondConnectionForAClaimedBindingIsRefusedWith403(t *testing.T) {
	r := newRig(t, 1)
	b, client, _, _, asH := r.bridged(0, 60)
	_, err := r.dial(0, nil).open(t, b.clientPath, newRecorder())
	if statusOf(err) != msrp.StatusForbidden {
		t.Fatalf("second Open = %v, want 403 (ADR 0004)", err)
	}
	if got := r.metrics.count(mRefusedPrefix + reasonClaimed); got != 1 {
		t.Fatalf("Refused.AlreadyClaimed = %d", got)
	}
	if !strings.Contains(r.logText(), "refused a second connection for a claimed binding") {
		t.Fatalf("the refusal was not logged:\n%s", r.logText())
	}
	// The first connection is unaffected.
	send(t, client, "still here")
	if m := asH.message(t); string(m.Body) != "still here" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
}

func TestOnlyOneOfTwoRelayTasksClaimsABinding(t *testing.T) {
	// Two tasks share the store, and a client connects to each at once with
	// the same session: one wins, on whichever task, and the other gets 403.
	r := newRig(t, 2)
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}})
	r.as.session(t, "astw0", b.coreLocal, newRecorder())
	r.patch(b.id, map[string]any{"core_path": []string{r.as.uri("astw0")}})
	clients := []*client{r.dial(0, nil), r.dial(1, nil)}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = c.open(t, b.clientPath, newRecorder())
		}()
	}
	wg.Wait()
	won, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case statusOf(err) == msrp.StatusForbidden:
			refused++
		default:
			t.Fatalf("Open = %v", err)
		}
	}
	if won != 1 || refused != 1 {
		t.Fatalf("%d won and %d were refused, want one each", won, refused)
	}
}

func TestExpiredBindingIsRefusedWith481(t *testing.T) {
	r := newRig(t, 1)
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asexp")}, "expires_in": 60})
	r.clock.Advance(60 * time.Second)
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
	if got := r.metrics.count(mRefusedPrefix + reasonUnknownSession); got != 1 {
		t.Fatalf("Refused.UnknownSession = %d", got)
	}
}

func TestUnknownSessionIsRefusedWith481(t *testing.T) {
	r := newRig(t, 1)
	path := "msrps://" + publicHost + ":2856/n0such5e55ion;tcp"
	if _, err := r.dial(0, nil).open(t, path, newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
}

func TestToPathNamingAnotherAuthorityIsRefusedWithoutALookup(t *testing.T) {
	r := newRig(t, 1)
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asauth")}})
	// The right session id at the wrong address, port or scheme is not the
	// URI pcscf handed out (RFC 4975 §6.1).
	u := mustURI(t, b.clientPath)
	for _, other := range []msrp.URI{
		{Secure: true, Host: "other.example.net", Port: u.Port, SessionID: u.SessionID, Transport: "tcp"},
		{Secure: true, Host: u.Host, Port: 2855, SessionID: u.SessionID, Transport: "tcp"},
		{Secure: false, Host: u.Host, Port: u.Port, SessionID: u.SessionID, Transport: "tcp"},
	} {
		if _, err := r.dial(0, nil).open(t, other.String(), newRecorder()); statusOf(err) != msrp.StatusNoSession {
			t.Fatalf("Open %v = %v, want 481", other, err)
		}
	}
	// The binding was not claimed by any of them.
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); statusOf(err) == msrp.StatusForbidden {
		t.Fatal("a wrong URI claimed the binding")
	}
}

func TestBridgeEndsWhenItsBindingExpires(t *testing.T) {
	r := newRig(t, 1)
	_, client, clientH, _, _ := r.bridged(0, 60)
	r.clock.Advance(60 * time.Second)
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
	if got := r.metrics.count(mBindingsExpired); got != 1 {
		t.Fatalf("BindingsExpired = %d", got)
	}
	// What the client sends now is for a session the relay no longer has.
	send(t, client, "too late")
	select {
	case rep := <-clientH.reports:
		if rep.Code != msrp.StatusNoSession {
			t.Fatalf("report %+v, want 481", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no failure report")
	}
}

func TestExtendedBindingKeepsItsBridge(t *testing.T) {
	r := newRig(t, 1)
	b, client, _, _, asH := r.bridged(0, 60)
	r.patch(b.id, map[string]any{"expires_in": 120})
	r.clock.Advance(60 * time.Second)
	send(t, client, "refreshed")
	if m := asH.message(t); string(m.Body) != "refreshed" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
	if r.metrics.bridges.Load() != 1 {
		t.Fatal("the bridge ended although pcscf extended the binding")
	}
	r.clock.Advance(60 * time.Second)
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
}

func TestReleasedBindingEndsItsBridgeAtTheNextCheck(t *testing.T) {
	r := newRig(t, 1)
	b, _, _, _, _ := r.bridged(0, 60)
	if code, _ := r.call("DELETE", "/v1/bindings/"+b.id, nil); code != 204 {
		t.Fatalf("DELETE = %d", code)
	}
	r.clock.Advance(60 * time.Second)
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
}

func TestStoreHiccupAtTheExpiryCheckDoesNotCutTheBridge(t *testing.T) {
	failing := &flakyStore{}
	r := newRig(t, 1, wrapStore(failing))
	_, client, _, _, asH := r.bridged(0, 60)
	failing.failGets(1)
	r.clock.Advance(60 * time.Second)
	send(t, client, "survived")
	if m := asH.message(t); string(m.Body) != "survived" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
	if r.metrics.count(mStoreErrors) != 1 || r.metrics.bridges.Load() != 1 {
		t.Fatalf("store errors %d, bridges %d", r.metrics.count(mStoreErrors), r.metrics.bridges.Load())
	}
	// The retry finds the binding expired.
	r.clock.Advance(expiryRetry)
	eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
}

func TestCoreThatCannotBeReachedIsRefusedWith481(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	r := newRig(t, 1, extraCorePorts{netip.MustParseAddrPort(closed).Port()})
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{"msrp://" + closed + "/g0ne;tcp"}})
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
	if got := r.metrics.count(mRefusedPrefix + reasonCoreUnreachable); got != 1 {
		t.Fatalf("Refused.CoreUnreachable = %d", got)
	}
}

func TestCoreThatDoesNotKnowTheSessionIsRefusedWith481(t *testing.T) {
	r := newRig(t, 1)
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("unkn0wn")}})
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); statusOf(err) != msrp.StatusNoSession {
		t.Fatalf("Open = %v, want 481", err)
	}
}

func TestCoreDialerRefusesAddressesOutsideItsNetworks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// No dial timeout: what is checked is the refusal, which Control makes
	// on the resolved address before any connect, and the 1 s it had also
	// bounded the lookup of localhost, which a loaded host took longer for
	// (#292). Every dial here ends at Control, or at the go test timeout.
	const noTimeout = 0
	dial := coreDialer([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, []uint16{2855}, noTimeout)
	if _, err := dial(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, errCoreNotAllowed) {
		t.Fatalf("dial = %v, want errCoreNotAllowed", err)
	}
	// So is the port, inside the allowed networks.
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if _, err := coreDialer(loopback, []uint16{1}, noTimeout)(context.Background(), "tcp", ln.Addr().String()); !errors.Is(err, errCoreNotAllowed) {
		t.Fatalf("dial to a port outside the list = %v, want errCoreNotAllowed", err)
	}
	// A name is checked on what it resolves to.
	if _, err := dial(context.Background(), "tcp", "localhost:"+strings.Split(ln.Addr().String(), ":")[1]); !errors.Is(err, errCoreNotAllowed) {
		t.Fatalf("dial by name = %v, want errCoreNotAllowed", err)
	}
}

func TestMsrpsCorePathIsNeverDialled(t *testing.T) {
	r := newRig(t, 1)
	if _, err := r.relays[0].dialCore(context.Background(), mustURI(t, "msrps://10.0.1.5:2856/s3cure;tcp")); err == nil {
		t.Fatal("dialled msrps toward rcs-as")
	}
	if _, err := r.relays[0].dialCore(context.Background(), msrp.URI{Host: "10.0.1.5", Transport: "tcp"}); err == nil {
		t.Fatal("dialled a URI without a port")
	}
}

func TestProxyHeaderIsRequiredWhenEnabled(t *testing.T) {
	r := newRig(t, 1, withProxyProtocol)
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asppv2")}})
	r.as.session(t, "asppv2", b.coreLocal, newRecorder())
	if _, err := r.dial(0, nil).open(t, b.clientPath, newRecorder()); err == nil {
		t.Fatal("a connection without a PROXY header was served")
	}
	if got := r.metrics.count(mRefusedPrefix + reasonProxyHeader); got != 1 {
		t.Fatalf("Refused.ProxyHeader = %d", got)
	}
	if _, err := r.dial(0, proxyFrom("192.0.2.10:40000")).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatalf("Open behind a PROXY header = %v", err)
	}
}

func TestProxyLocalHealthCheckIsClosedWithoutARefusal(t *testing.T) {
	r := newRig(t, 1, withProxyProtocol)
	nc, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.Write(proxyproto.Header{Command: proxyproto.Local}.Marshal()); err != nil {
		t.Fatal(err)
	}
	_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := nc.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("health check read %d, %v; want the relay to close", n, err)
	}
	eventually(t, "the health check to be counted", func() bool { return r.metrics.count(mHealthChecks) == 1 })
	if got := r.metrics.count(mRefusedPrefix + reasonProxyHeader); got != 0 {
		t.Fatalf("a health check counted as a refusal: %d", got)
	}
	// A connection that sends nothing at all (a plain TCP check) is closed
	// as quietly.
	quiet, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = quiet.(*net.TCPConn).CloseWrite()
	_ = quiet.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := quiet.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("quiet probe read %v", err)
	}
	_ = quiet.Close()
	if got := r.metrics.count(mRefusedPrefix + reasonProxyHeader); got != 0 {
		t.Fatalf("a quiet probe counted as a refusal: %d", got)
	}
}

func TestConnectionsPerSourceAreCappedByTheProxiedAddress(t *testing.T) {
	r := newRig(t, 1, withProxyProtocol, func(o *relayOptions) { o.MaxConnectionsPerSource = 1 })
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("ascap")}})
	r.as.session(t, "ascap", b.coreLocal, newRecorder())
	if _, err := r.dial(0, proxyFrom("192.0.2.10:40000")).open(t, b.clientPath, newRecorder()); err != nil {
		t.Fatal(err)
	}
	// Every connection reaches the relay from the NLB's address; the cap is
	// on the client's.
	second := r.dial(0, proxyFrom("192.0.2.10:40001"))
	waitDone(t, second.conn.Done(), "the second connection from one source")
	if got := r.metrics.count(mRefusedPrefix + reasonSourceLimit); got != 1 {
		t.Fatalf("Refused.SourceLimit = %d", got)
	}
	other := r.dial(0, proxyFrom("192.0.2.11:40000"))
	if _, err := other.open(t, b.clientPath, newRecorder()); statusOf(err) != msrp.StatusForbidden {
		t.Fatalf("Open from another source = %v, want it served (and refused 403 as a second claim)", err)
	}
}

func TestSourceKeyGroupsAnIPv6SubscribersWholePrefix(t *testing.T) {
	a := sourceKey(netip.MustParseAddr("2001:db8:1:2:aaaa::1"))
	b := sourceKey(netip.MustParseAddr("2001:db8:1:2:bbbb::9"))
	c := sourceKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Fatalf("keys %v %v %v", a, b, c)
	}
	if k := sourceKey(netip.MustParseAddr("192.0.2.10")); k.Bits() != 32 {
		t.Fatalf("IPv4 key %v", k)
	}
}

func TestConnectionLimitClosesNewConnections(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.MaxConnections = 1 })
	first := r.dial(0, nil)
	eventually(t, "the first connection to be admitted", func() bool {
		r.relays[0].mu.Lock()
		defer r.relays[0].mu.Unlock()
		return r.relays[0].admitted == 1
	})
	second := r.dial(0, nil)
	waitDone(t, second.conn.Done(), "the connection over the limit")
	if got := r.metrics.count(mRefusedPrefix + reasonConnectionLimit); got != 1 {
		t.Fatalf("Refused.ConnectionLimit = %d", got)
	}
	select {
	case <-first.conn.Done():
		t.Fatal("the admitted connection was closed")
	default:
	}
}

// closedNotRefused reports whether an Open failed because the relay closed
// the connection, not because it answered. The client's msrp.Conn reports
// its unanswered SEND as a local 408 when the connection goes (RFC 4975
// §10.4), or the closed connection itself, depending on which it notices
// first.
func closedNotRefused(err error) bool {
	return err != nil && (statusOf(err) == 0 || statusOf(err) == msrp.StatusRequestTimeout)
}

// wrapStore makes the relay task use f over the rig's store, which the
// control API keeps using directly.
func wrapStore(f *flakyStore) rigOption {
	return func(o *relayOptions) {
		f.Store = o.Store
		o.Store = f
	}
}

// flakyStore wraps a Store: Get can be made to fail or to block.
type flakyStore struct {
	store.Store
	// gets counts every Get, the store reads the relay makes.
	gets    atomic.Int64
	mu      sync.Mutex
	fails   int
	block   chan struct{}
	blocked chan struct{}
}

func (f *flakyStore) failGets(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fails = n
}

func (f *flakyStore) Get(ctx context.Context, id string, now time.Time) (store.Binding, error) {
	f.gets.Add(1)
	f.mu.Lock()
	fail, block := f.fails > 0, f.block
	if fail {
		f.fails--
	}
	f.mu.Unlock()
	if fail {
		return store.Binding{}, errors.New("flaky: unavailable")
	}
	if block != nil {
		f.blocked <- struct{}{}
		select {
		case <-block:
		case <-ctx.Done():
			return store.Binding{}, ctx.Err()
		}
	}
	return f.Store.Get(ctx, id, now)
}

func TestBindsBeyondTheLimitCloseTheConnection(t *testing.T) {
	slow := &flakyStore{block: make(chan struct{}), blocked: make(chan struct{}, 1)}
	r := newRig(t, 1, wrapStore(slow), func(o *relayOptions) { o.MaxConcurrentBinds = 1 })
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asbusy")}})
	r.as.session(t, "asbusy", b.coreLocal, newRecorder())
	first := make(chan error, 1)
	go func() {
		_, err := r.dial(0, nil).open(t, b.clientPath, newRecorder())
		first <- err
	}()
	<-slow.blocked
	second := r.dial(0, nil)
	opened := make(chan error, 1)
	go func() {
		_, err := second.open(t, b.clientPath, newRecorder())
		opened <- err
	}()
	// The bind waits a moment for a slot, then gives up.
	r.clock.waitTimer(t, bindSlotWait)
	r.clock.Advance(bindSlotWait)
	if err := <-opened; !closedNotRefused(err) {
		t.Fatalf("Open while every bind slot is taken = %v, want the connection closed", err)
	}
	waitDone(t, second.conn.Done(), "the overloaded connection")
	if got := r.metrics.count(mRefusedPrefix + reasonBindOverload); got != 1 {
		t.Fatalf("Refused.BindOverload = %d", got)
	}
	close(slow.block)
	if err := <-first; err != nil {
		t.Fatalf("the waiting bind failed: %v", err)
	}
}

func TestBindWaitsBrieflyForASlot(t *testing.T) {
	slow := &flakyStore{block: make(chan struct{}), blocked: make(chan struct{}, 2)}
	r := newRig(t, 1, wrapStore(slow), func(o *relayOptions) { o.MaxConcurrentBinds = 1 })
	var paths []string
	for _, sid := range []string{"aswait1", "aswait2"} {
		b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri(sid)}})
		r.as.session(t, sid, b.coreLocal, newRecorder())
		paths = append(paths, b.clientPath)
	}
	results := make(chan error, 2)
	go func() {
		_, err := r.dial(0, nil).open(t, paths[0], newRecorder())
		results <- err
	}()
	<-slow.blocked
	go func() {
		_, err := r.dial(0, nil).open(t, paths[1], newRecorder())
		results <- err
	}()
	r.clock.waitTimer(t, bindSlotWait)
	// The slot frees before the wait is over: the second bind proceeds.
	close(slow.block)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("Open = %v", err)
		}
	}
	if got := r.metrics.count(mRefusedPrefix + reasonBindOverload); got != 0 {
		t.Fatalf("Refused.BindOverload = %d", got)
	}
}

func TestStoreTimeoutClosesTheConnection(t *testing.T) {
	r := newRig(t, 1, wrapStore(&flakyStore{block: make(chan struct{}), blocked: make(chan struct{}, 1)}),
		func(o *relayOptions) { o.StoreTimeout = 20 * time.Millisecond })
	b := r.allocate(map[string]any{"client_endpoint_path": []string{clientURI}, "core_path": []string{r.as.uri("asslow")}})
	c := r.dial(0, nil)
	if _, err := c.open(t, b.clientPath, newRecorder()); !closedNotRefused(err) {
		t.Fatalf("Open = %v, want the connection closed rather than an MSRP refusal", err)
	}
	waitDone(t, c.conn.Done(), "the connection")
	if r.metrics.count(mStoreErrors) != 1 || r.metrics.count(mRefusedPrefix+reasonStore) != 1 {
		t.Fatalf("StoreErrors %d, Refused.StoreUnavailable %d", r.metrics.count(mStoreErrors), r.metrics.count(mRefusedPrefix+reasonStore))
	}
	if !strings.Contains(r.logText(), "binding lookup failed") {
		t.Fatal("the store failure was not logged")
	}
}

func TestRequestsForUnknownSessionsEndTheConnectionAtTheLimit(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.Edge.MaxFailedBinds = 2 })
	c := r.dial(0, nil)
	for i, sid := range []string{"gu3ss1", "gu3ss2"} {
		if _, err := c.open(t, "msrps://"+publicHost+":2856/"+sid+";tcp", newRecorder()); statusOf(err) != msrp.StatusNoSession {
			t.Fatalf("guess %d = %v, want 481", i, err)
		}
	}
	_, _ = c.open(t, "msrps://"+publicHost+":2856/gu3ss3;tcp", newRecorder())
	waitDone(t, c.conn.Done(), "the guessing connection")
	eventually(t, "the close to be counted", func() bool {
		return r.metrics.count(mClientPrefix+"Closed.TooManyUnknownSessions") == 1
	})
}

// A client that pipelines requests for unknown sessions past the limit
// reads the 481s the relay owed it before an end of stream, not a reset,
// though the relay had not read everything it sent (#219, from QA on
// #217).
func TestAClientOverTheUnknownSessionLimitStillReadsItsAnswers(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.Edge.MaxFailedBinds = 2 })
	nc, err := net.Dial("tcp", r.addrs[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	var reqs strings.Builder
	for _, tid := range []string{"gues1", "gues2", "gues3", "gues4", "gues5", "gues6"} {
		reqs.WriteString("MSRP " + tid + " SEND\r\nTo-Path: msrps://" + publicHost + ":2856/gu3ss" + tid + ";tcp\r\n" +
			"From-Path: " + clientURI + "\r\nMessage-ID: " + tid + "\r\n-------" + tid + "$\r\n")
	}
	// Unread input past the reader's buffer, in the same Write: closing
	// with it unread would reset the connection, so only the half-close
	// through meteredConn delivers the 481s (QA on #237).
	reqs.WriteString(strings.Repeat("z", 256<<10))
	if _, err := nc.Write([]byte(reqs.String())); err != nil {
		t.Fatal(err)
	}
	_ = nc.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(nc)
	if err != nil {
		t.Fatalf("after %q: %v, want the end of the stream", got, err)
	}
	for _, tid := range []string{"gues1", "gues2"} {
		if !strings.Contains(string(got), "MSRP "+tid+" 481") {
			t.Errorf("no 481 for %s in %q", tid, got)
		}
	}
	_ = nc.(*net.TCPConn).CloseWrite()
	eventually(t, "the close to be counted", func() bool {
		return r.metrics.count(mClientPrefix+"Closed.TooManyUnknownSessions") == 1
	})
}

// A connection the relay refuses for too many unknown sessions is counted
// for that alone, whatever ends its wait for the client meanwhile: the
// idle timeout, or the first-bind timer (#237).
func TestARefusedConnectionIsCountedOnce(t *testing.T) {
	for name, c := range map[string]struct {
		idle  time.Duration
		after func(r *rig)
	}{
		// 1 s: the idle timer also covers the client's pause between
		// connecting and writing, which a loaded host can make long (QA on
		// #237).
		"idle during the flush": {idle: time.Second},
		"first-bind timer during the flush": {idle: time.Minute, after: func(r *rig) {
			r.clock.Advance(time.Hour)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, 1, func(o *relayOptions) { o.Edge.MaxFailedBinds = 2; o.IdleTimeout = c.idle })
			nc, err := net.Dial("tcp", r.addrs[0])
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = nc.Close() })
			var reqs strings.Builder
			for _, tid := range []string{"once1", "once2", "once3"} {
				reqs.WriteString("MSRP " + tid + " SEND\r\nTo-Path: msrps://" + publicHost + ":2856/gu3ss" + tid + ";tcp\r\n" +
					"From-Path: " + clientURI + "\r\nMessage-ID: " + tid + "\r\n-------" + tid + "$\r\n")
			}
			if _, err := nc.Write([]byte(reqs.String())); err != nil {
				t.Fatal(err)
			}
			// The client reads to the end of the stream and never closes
			// its side, so the relay waits for it.
			_ = nc.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadAll(nc); err != nil {
				t.Fatal(err)
			}
			if c.after != nil {
				c.after(r)
			}
			eventually(t, "the close to be counted", func() bool {
				return r.metrics.count(mClientPrefix+"Closed.TooManyUnknownSessions") == 1 && r.metrics.conns.Load() == 0
			})
			if idle, unbound := r.metrics.count(mIdleClosed), r.metrics.count(mUnboundClosed); idle != 0 || unbound != 0 {
				t.Fatalf("also counted idle %d, unbound %d", idle, unbound)
			}
		})
	}
}

func TestIdleClientConnectionIsClosed(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.IdleTimeout = 20 * time.Millisecond })
	c := r.dial(0, nil)
	waitDone(t, c.conn.Done(), "the idle connection")
	eventually(t, "the idle close to be counted", func() bool { return r.metrics.count(mIdleClosed) == 1 })
}

func TestDrainKeepsBridgesUntilTheTimeoutThenClosesThem(t *testing.T) {
	r := newRig(t, 1)
	_, client, _, _, asH := r.bridged(0, 600)
	drained := make(chan struct{})
	go func() {
		r.relays[0].Drain(context.Background(), 10*time.Second)
		close(drained)
	}()
	r.clock.waitTimer(t, 5*time.Second)
	if c, err := net.Dial("tcp", r.addrs[0]); err == nil {
		_ = c.Close()
		t.Fatal("a draining relay accepted a connection")
	}
	send(t, client, "draining")
	if m := asH.message(t); string(m.Body) != "draining" {
		t.Fatalf("rcs-as got %q", m.Body)
	}
	// Halfway through, what is left starts to be closed.
	r.clock.Advance(5 * time.Second)
	waitDone(t, drained, "Drain")
	if r.metrics.bridges.Load() != 0 {
		eventually(t, "the bridge to end", func() bool { return r.metrics.bridges.Load() == 0 })
	}
}

func TestDrainEndsAsSoonAsTheLastClientLeaves(t *testing.T) {
	r := newRig(t, 1)
	c := r.dial(0, nil)
	eventually(t, "the connection to be admitted", func() bool {
		r.relays[0].mu.Lock()
		defer r.relays[0].mu.Unlock()
		return r.relays[0].admitted == 1
	})
	drained := make(chan struct{})
	go func() {
		r.relays[0].Drain(context.Background(), time.Hour)
		close(drained)
	}()
	r.clock.waitTimer(t, 30*time.Minute)
	_ = c.conn.Close()
	waitDone(t, drained, "Drain")
}

func TestServeOnADrainedRelayReturnsAtOnce(t *testing.T) {
	r := newRig(t, 1)
	r.relays[0].Drain(context.Background(), time.Second)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.relays[0].Serve(ln); err != nil {
		t.Fatalf("Serve = %v", err)
	}
	if _, err := ln.Accept(); err == nil {
		t.Fatal("the listener was left open")
	}
}

func TestServeReportsAListenerClosedUnderIt(t *testing.T) {
	r := newRig(t, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- r.relays[0].Serve(ln) }()
	eventually(t, "Serve to register the listener", func() bool {
		r.relays[0].mu.Lock()
		defer r.relays[0].mu.Unlock()
		return len(r.relays[0].listeners) == 2
	})
	_ = ln.Close()
	if err := <-served; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve = %v, want net.ErrClosed", err)
	}
}

// A client connection passes a half-close through, which internal/msrp
// uses to deliver the answers it owes before closing (#219), and says so
// when the connection underneath cannot.
func TestAClientConnectionHalfClosesWhenItsSocketCan(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		nc, err := l.Accept()
		if err == nil {
			accepted <- nc
		}
	}()
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	nc := <-accepted
	t.Cleanup(func() { _ = nc.Close() })
	mc := &meteredConn{Conn: nc, in: &atomic.Int64{}, out: &atomic.Int64{}}
	if err := mc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite = %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("the peer read %d, %v, want the end of the stream", n, err)
	}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	if err := (&meteredConn{Conn: a}).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseWrite on a pipe = %v", err)
	}
}

func TestAKeepAliveTheRelayCouldNotBuildIsCountedAndLogged(t *testing.T) {
	// Code review on #222: the relay failing to build a keep-alive is
	// counted and logged, with the side and nothing else.
	var buf bytes.Buffer
	m := newCounters()
	on := logged(slog.New(slog.NewJSONHandler(&buf, nil)), "client", m.onEvent(mClientPrefix))
	on(msrp.Event{Kind: msrp.EventDropped, Method: msrp.MethodSend, Err: msrp.ErrKeepAliveNotSent})
	on(msrp.Event{Kind: msrp.EventDropped, Method: msrp.MethodSend, Err: msrp.ErrHandlerBusy})
	if got := m.count(mClientPrefix + "Dropped.KeepAliveNotSent"); got != 1 {
		t.Fatalf("Client.Dropped.KeepAliveNotSent = %d", got)
	}
	if lines := strings.Count(buf.String(), "\n"); lines != 1 || !strings.Contains(buf.String(), `"side":"client"`) {
		t.Fatalf("log %q, want one line with the side", buf.String())
	}
}
