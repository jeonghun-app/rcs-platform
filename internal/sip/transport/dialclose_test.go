package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// heldDialer reports each dial on dialing and holds it until its context
// ends, as a peer that never answers the SYN.
type heldDialer struct{ dialing chan struct{} }

func (d heldDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.dialing <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// Close cuts a dial in progress (#462): the send dialling fails with
// ErrClosed at once, not after DialTimeout, which is an hour here, and no
// dial error is counted. A second send to the peer fails the same way,
// whether it waits for that dial or comes after Close.
func TestCloseCutsADialInProgress(t *testing.T) {
	dialer := heldDialer{dialing: make(chan struct{}, 1)}
	tr, _ := newTransport(t, Config{Dialer: dialer, DialTimeout: time.Hour})
	dst := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.1:5060")}
	errs := make(chan error, 2)
	send := func(branch string) {
		_, err := tr.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch="+branch), dst)
		errs <- err
	}
	go send("z9hG4bK1")
	<-dialer.dialing
	go send("z9hG4bK2")
	closed := make(chan error, 1)
	go func() { closed <- tr.Close() }()
	for range 2 {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrClosed) {
				t.Errorf("SendRequest = %v, want ErrClosed", err)
			}
		case <-time.After(30 * time.Second): // a hang guard; DialTimeout is an hour
			t.Fatal("a send still waits for the dial after Close")
		}
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if s := tr.Stats(); s.DialErrors != 0 || s.Dialed != 0 {
		t.Errorf("stats = %+v, want no dial and no dial error", s)
	}
}

// silentDialer connects at once to a peer that never reads, so a TLS
// handshake over it waits until its context ends.
type silentDialer struct{ dialed chan net.Conn }

func (d silentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	c, far := net.Pipe()
	d.dialed <- far
	return c, nil
}

// So does a TLS handshake in progress.
func TestCloseCutsATLSHandshakeInProgress(t *testing.T) {
	dialer := silentDialer{dialed: make(chan net.Conn, 1)}
	tr, _ := newTransport(t, Config{Dialer: dialer, DialTimeout: time.Hour})
	dst := Destination{Network: TLS, Addr: netip.MustParseAddrPort("192.0.2.1:5061"), ServerName: "core.example.net"}
	errs := make(chan error, 1)
	go func() {
		_, err := tr.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TLS placeholder.invalid;branch=z9hG4bK1"), dst)
		errs <- err
	}()
	far := <-dialer.dialed
	defer far.Close()
	closed := make(chan error, 1)
	go func() { closed <- tr.Close() }()
	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("SendRequest = %v, want ErrClosed", err)
		}
	case <-time.After(30 * time.Second): // a hang guard; DialTimeout is an hour
		t.Fatal("the send still waits for the handshake after Close")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if s := tr.Stats(); s.DialErrors != 0 {
		t.Errorf("DialErrors = %d, want 0", s.DialErrors)
	}
}

// A request too large for UDP is tried over TCP first (RFC 3261 §18.1.1);
// when Close cuts that dial, it fails with ErrClosed rather than falling
// back to the UDP socket Close is shutting (code review of #474).
func TestCloseCutsTheTCPAttemptOfALargeUDPRequest(t *testing.T) {
	dialer := heldDialer{dialing: make(chan struct{}, 1)}
	tr, _ := newTransport(t, Config{Dialer: dialer, DialTimeout: time.Hour})
	listen(t, tr, ListenerConfig{Network: UDP})
	req := newRequest(t, "MESSAGE", "SIP/2.0/UDP placeholder.invalid;branch=z9hG4bK1")
	req.Body = bytes.Repeat([]byte("x"), udpMTULimit)
	errs := make(chan error, 1)
	go func() {
		_, err := tr.SendRequest(req, Destination{Network: UDP, Addr: netip.MustParseAddrPort("192.0.2.1:5060")})
		errs <- err
	}()
	<-dialer.dialing
	closed := make(chan error, 1)
	go func() { closed <- tr.Close() }()
	select {
	case err := <-errs:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("SendRequest = %v, want ErrClosed", err)
		}
	case <-time.After(30 * time.Second): // a hang guard; DialTimeout is an hour
		t.Fatal("the send still waits for the dial after Close")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if s := tr.Stats(); s.WriteErrors != 0 || s.DialErrors != 0 {
		t.Errorf("WriteErrors = %d, DialErrors = %d, want 0", s.WriteErrors, s.DialErrors)
	}
}

// A dial that runs out its own DialTimeout is a dial error, not ErrClosed:
// only Close's cancellation is (code review of #474).
func TestADialPastDialTimeoutIsADialError(t *testing.T) {
	dialer := heldDialer{dialing: make(chan struct{}, 1)}
	tr, _ := newTransport(t, Config{Dialer: dialer, DialTimeout: time.Millisecond})
	dst := Destination{Network: TCP, Addr: netip.MustParseAddrPort("192.0.2.1:5060")}
	_, err := tr.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bK1"), dst)
	if err == nil || errors.Is(err, ErrClosed) {
		t.Errorf("SendRequest = %v, want a dial error", err)
	}
	if s := tr.Stats(); s.DialErrors != 1 {
		t.Errorf("DialErrors = %d, want 1", s.DialErrors)
	}
}
