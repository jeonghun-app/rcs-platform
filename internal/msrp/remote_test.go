package msrp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// A session offered before its answer: the peer connects and binds first,
// then the path arrives (ADR 0004, rcs-as offering through msrp-relay).
func TestASessionWhosePathComesLaterBindsAndSendsOnceItIsSet(t *testing.T) {
	l := tcpListen(t)
	reg := &Registry{}
	bobH := newRecorder()
	bob, err := NewSession(SessionConfig{Local: mustURI(t, asURI), RemoteLater: true, Handler: bobH})
	if err != nil {
		t.Fatal(err)
	}
	if bob.Remote() != nil {
		t.Fatalf("Remote before SetRemote = %v", bob.Remote())
	}
	if err := reg.Add(bob); err != nil {
		t.Fatal(err)
	}
	go func() {
		nc, err := l.Accept()
		if err == nil {
			_, _ = NewPassiveConn(nc, reg, Config{})
		}
	}()
	nc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ac, err := NewActiveConn(nc, Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ac.Close() })
	aliceH := newRecorder()
	alice := newTestSession(t, clientURI, asURI, aliceH)
	if err := ac.Open(context.Background(), alice); err != nil {
		t.Fatalf("binding before the path is known: %v", err)
	}

	// The peer can already send; this side's Send waits for the path.
	if _, err := alice.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("early")}); err != nil {
		t.Fatal(err)
	}
	if m := bobH.message(t); string(m.Body) != "early" {
		t.Fatalf("got %q", m.Body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err = bob.Send(ctx, Outgoing{ContentType: "text/plain", Body: []byte("too soon")})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Send before SetRemote = %v", err)
	}
	sent := make(chan error, 1)
	go func() {
		_, err := bob.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("reply")})
		sent <- err
	}()
	if err := bob.SetRemote([]URI{mustURI(t, clientURI)}); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if m := aliceH.message(t); string(m.Body) != "reply" {
		t.Fatalf("got %q", m.Body)
	}
	if !bob.Remote()[0].Equal(mustURI(t, clientURI)) {
		t.Fatalf("Remote = %v", bob.Remote())
	}
	if err := bob.SetRemote([]URI{mustURI(t, clientURI)}); err == nil {
		t.Fatal("the path was set twice")
	}
}

func TestAPathSetLaterMustBeValidAndAClosedSessionStopsWaiting(t *testing.T) {
	s, err := NewSession(SessionConfig{Local: mustURI(t, asURI), RemoteLater: true, Handler: newRecorder()})
	if err != nil {
		t.Fatal(err)
	}
	if s.SetRemote(nil) == nil || s.SetRemote([]URI{{}}) == nil {
		t.Fatal("an empty or invalid path was accepted")
	}
	waited := make(chan error, 1)
	go func() {
		_, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: []byte("x")})
		waited <- err
	}()
	_ = s.Close()
	select {
	case err := <-waited:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("Send on a closed session = %v", err)
		}
	case <-time.After(hangGuard):
		t.Fatal("Send kept waiting after Close")
	}
}

func TestOnlyARemoteLaterSessionMayLackItsPath(t *testing.T) {
	if _, err := NewSession(SessionConfig{Local: mustURI(t, asURI), Handler: newRecorder()}); err == nil {
		t.Fatal("a session without a path was created")
	}
	s, err := NewSession(SessionConfig{Local: mustURI(t, clientURI), RemoteLater: true, Handler: newRecorder()})
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs := net.Pipe()
	defer theirs.Close()
	c, err := NewActiveConn(ours, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Open(context.Background(), s); err == nil {
		t.Fatal("an active session opened without the peer's path")
	}
}
