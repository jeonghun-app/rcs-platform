package transport

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// panicDialer panics on its first dial once release is closed, as a
// dialer with a bug on one path, and dials the address for real after
// that. The first dial is taken with a compare-and-swap, so a second
// caller never waits on it.
type panicDialer struct {
	dialing chan struct{}
	release chan struct{}
	taken   atomic.Bool
}

func (d *panicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.taken.CompareAndSwap(false, true) {
		d.dialing <- struct{}{}
		<-d.release
		panic("dialer bug")
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// A dial that panics releases its peer (#582). The send that dialled gets
// the panic, as a caller that contains it (#471) expects; a send that
// waited for that dial fails at once rather than waiting for ever; the
// next send dials again and goes out; and Close returns. DialTimeout is
// an hour, so no timer ends any wait.
func TestADialThatPanicsReleasesItsPeer(t *testing.T) {
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	dialer := &panicDialer{dialing: make(chan struct{}, 1), release: make(chan struct{})}
	client, _ := newTransport(t, Config{Dialer: dialer, DialTimeout: time.Hour})
	dst := Destination{Network: TCP, Addr: addr}
	send := func(branch string) error {
		_, err := client.SendRequest(newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch="+branch), dst)
		return err
	}
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = send("z9hG4bK-panic-1")
	}()
	select {
	case <-dialer.dialing:
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("the first send did not dial")
	}
	waited := make(chan error, 1)
	go func() { waited <- send("z9hG4bK-panic-2") }()
	eventually(t, "the second send to wait for the first one's dial", func() bool { return parkedIn("(*Transport).waitDial") })
	close(dialer.release)

	select {
	case p := <-panicked:
		if p == nil {
			t.Fatal("the send that dialled did not panic")
		}
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("the send that dialled did not return")
	}
	select {
	case err := <-waited:
		if !errors.Is(err, errDialPanicked) {
			t.Fatalf("the send that waited got %v, want errDialPanicked", err)
		}
	case <-time.After(30 * time.Second): // a hang guard; DialTimeout is an hour
		t.Fatal("the send that waited for the dial still waits after it panicked")
	}
	if err := send("z9hG4bK-panic-3"); err != nil {
		t.Fatalf("a send after the panic: %v", err)
	}
	if v := topVia(t, rec.next(t).Message); v.Branch() != "z9hG4bK-panic-3" {
		t.Fatalf("the peer got branch %s, want the third send", v.Branch())
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("Close did not return")
	}
}

// A send waiting for another's dial gives up with it: at Close, and at
// DialTimeout, which bounds the dial too, even were the dial never to end
// (#582).
func TestASendWaitingForADialHonoursItsBounds(t *testing.T) {
	for name, closing := range map[string]bool{"DialTimeout": false, "Close": true} {
		t.Run(name, func(t *testing.T) {
			timeout := time.Hour
			if !closing {
				timeout = 200 * time.Millisecond
			}
			tr, _ := newTransport(t, Config{Dialer: heldDialer{dialing: make(chan struct{}, 1)}, DialTimeout: timeout})
			d := &dialCall{done: make(chan struct{})} // a dial that never ends
			start := time.Now()
			if closing {
				go func() {
					// Off the test's goroutine, so no Fatal: Close comes
					// once the wait has begun, or after the hang guard.
					for deadline := time.Now().Add(waitFor); !parkedIn("(*Transport).waitDial") && time.Now().Before(deadline); {
						time.Sleep(time.Millisecond)
					}
					_ = tr.Close()
				}()
			}
			got := make(chan error, 1)
			go func() {
				_, err := tr.waitDial(TCP, d)
				got <- err
			}()
			var err error
			select {
			case err = <-got:
			case <-time.After(30 * time.Second): // a hang guard
				t.Fatal("waitDial still waits")
			}
			switch {
			case closing && !errors.Is(err, ErrClosed):
				t.Fatalf("waitDial = %v, want ErrClosed", err)
			case !closing && !errors.Is(err, context.DeadlineExceeded):
				t.Fatalf("waitDial = %v, want a deadline", err)
			case !closing && time.Since(start) < timeout:
				t.Fatalf("waitDial gave up after %v, before DialTimeout %v", time.Since(start), timeout)
			}
		})
	}
}
