package msrp

import (
	"context"
	"errors"
	"testing"
	"time"
)

// probed is an active connection over a raw peer with cfg and
// ProbeOnTimeout set, and one session open on it.
func probed(t *testing.T, cfg Config) (*fakeClock, *Conn, *wirePeer, *Session) {
	t.Helper()
	clock := newFakeClock()
	cfg.Clock, cfg.ProbeOnTimeout = clock, true
	c, p := activeWithPeer(t, cfg)
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	return clock, c, p, s
}

// sendUnanswered sends a chunk on s that the peer reads and leaves
// unanswered.
func sendUnanswered(t *testing.T, s *Session, p *wirePeer) {
	t.Helper()
	if _, err := s.Send(context.Background(), Outgoing{ContentType: "text/plain", Body: BodyOf([]byte("x"))}); err != nil {
		t.Fatal(err)
	}
	if m := p.next(t); !m.HasBody() {
		t.Fatalf("got %+v, want the chunk", m)
	}
}

// expectProbe reads the next message and checks it is a probe: a bodiless
// SEND.
func expectProbe(t *testing.T, p *wirePeer) *Message {
	t.Helper()
	m := p.next(t)
	if !m.IsRequest() || m.Method != MethodSend || m.HasBody() || m.ByteRange == nil || *m.ByteRange != (ByteRange{1, 0, 0}) {
		t.Fatalf("got %+v, want a probe", m)
	}
	return m
}

// synced sends a request from the peer to the client session and expects
// its 200 as the next message: everything the connection sent before it
// has been read, and every answer the peer sent before it handled.
func synced(t *testing.T, p *wirePeer, tid string) {
	t.Helper()
	p.sendMessage(t, &Message{TransactionID: tid, Method: MethodSend, ToPath: []URI{mustURI(t, clientURI)},
		FromPath: []URI{mustURI(t, asURI)}, MessageID: tid})
	expectResponse(t, p, tid, StatusOK)
}

// A request that times out sends a probe at once, and a probe left
// unanswered for ProbeTimeout, not TransactionTimeout, fails the
// connection with ErrPathStalled, and its sessions with it (#517).
func TestAnUnansweredProbeFailsTheConnection(t *testing.T) {
	const probeTimeout = 3 * time.Second
	clock, c, p, s := probed(t, Config{ProbeTimeout: probeTimeout})
	sendUnanswered(t, s, p)
	clock.Advance(DefaultTransactionTimeout)
	expectProbe(t, p)
	clock.Advance(probeTimeout - time.Nanosecond)
	if c.Err() != nil {
		t.Fatalf("failed before ProbeTimeout: %v", c.Err())
	}
	clock.Advance(time.Nanosecond)
	waitDone(t, c.Done(), "connection")
	if !errors.Is(c.Err(), ErrPathStalled) || !errors.Is(s.Err(), ErrConnClosed) {
		t.Fatalf("connection %v, session %v", c.Err(), s.Err())
	}
	p.closed(t)
}

// Any answer to the probe keeps the connection and its other sessions: the
// request that timed out was slow at the far end, as a relay makes it for a
// slow client. A later timeout probes again.
func TestAnAnsweredProbeKeepsTheConnection(t *testing.T) {
	clock, c, p, s := probed(t, Config{})
	other := newTestSession(t, "msrp://client.example.com:7777/other;tcp", asURI, newRecorder())
	openWithPeer(t, c, p, other)
	sendUnanswered(t, s, p)
	clock.Advance(DefaultTransactionTimeout)
	p.respond(t, expectProbe(t, p), StatusOK)
	synced(t, p, "sync0001") // the answer has been handled
	clock.Advance(DefaultProbeTimeout)
	if c.Err() != nil || other.Err() != nil {
		t.Fatalf("connection %v, other session %v", c.Err(), other.Err())
	}
	sendUnanswered(t, s, p)
	clock.Advance(DefaultTransactionTimeout)
	p.respond(t, expectProbe(t, p), StatusOK)
	synced(t, p, "sync0002")
}

// Requests that time out together send one probe: one is in flight per
// connection at a time.
func TestOneProbeIsInFlightAtATime(t *testing.T) {
	clock, c, p, s := probed(t, Config{})
	for range 3 {
		sendUnanswered(t, s, p)
	}
	clock.Advance(DefaultTransactionTimeout)
	probe := expectProbe(t, p)
	synced(t, p, "sync0003") // nothing else, no second probe, was sent before it
	p.respond(t, probe, StatusOK)
	synced(t, p, "sync0004")
	if c.Err() != nil {
		t.Fatal(c.Err())
	}
}

// Without ProbeOnTimeout a timeout sends no probe, as before #517.
func TestNoProbeIsSentUnlessAsked(t *testing.T) {
	clock := newFakeClock()
	c, p := activeWithPeer(t, Config{Clock: clock})
	s := newTestSession(t, clientURI, asURI, newRecorder())
	openWithPeer(t, c, p, s)
	sendUnanswered(t, s, p)
	clock.Advance(DefaultTransactionTimeout)
	synced(t, p, "sync0005")
	clock.Advance(DefaultProbeTimeout)
	if c.Err() != nil {
		t.Fatal(c.Err())
	}
}
