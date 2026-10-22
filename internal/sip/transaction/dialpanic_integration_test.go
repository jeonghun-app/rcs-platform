package transaction

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// firstDialPanics panics on its first dial once release is closed, and
// dials for real after that. The first dial is taken with a
// compare-and-swap, so no other caller waits on it.
type firstDialPanics struct {
	dialing chan struct{}
	release chan struct{}
	taken   atomic.Bool
}

func (d *firstDialPanics) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.taken.CompareAndSwap(false, true) {
		d.dialing <- struct{}{}
		<-d.release
		panic("dialer bug")
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, addr)
}

// The chain of #582 end to end, over real transports. The first Request's
// dial panics while a second Request waits for that dial, holding its
// transaction's lock. The panic reaches the first caller; the second
// Request fails at once rather than waiting for ever; a third Request, and
// the first one's branch sent again, get their 200; and Layer.Close, which
// takes every transaction's lock, returns. DialTimeout is an hour, so no
// timer ends a wait. Before #582 the second Request and Close hung.
func TestALayerOutlivesADialThatPanics(t *testing.T) {
	server := newEndpoint(t, transport.TCP, transport.Config{})
	dialer := &firstDialPanics{dialing: make(chan struct{}, 1), release: make(chan struct{})}
	client := newEndpoint(t, transport.TCP, transport.Config{Dialer: dialer, DialTimeout: time.Hour})
	dst := transport.Destination{Network: transport.TCP, Addr: server.addr}
	responses := make(chan *sip.Response, 8)
	handler := func(res *sip.Response, _ error) {
		if res != nil {
			responses <- res
		}
	}
	request := func(branch string) error {
		_, err := client.layer.Request(newOutgoing(t, transport.TCP, "OPTIONS", branch, "", 1), dst, handler)
		return err
	}

	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = request("z9hG4bK-chain-1")
	}()
	select {
	case <-dialer.dialing:
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("the first Request did not dial")
	}
	waited := make(chan error, 1)
	go func() { waited <- request("z9hG4bK-chain-2") }()
	// The dialling Request and the one waiting for its dial: both are
	// parked under streamTo (in waitDial since #582).
	for deadline := time.Now().Add(waitFor); parkedUnder("(*Transport).streamTo") < 2; {
		if time.Now().After(deadline) {
			t.Fatal("the second Request never waited for the first one's dial")
		}
		time.Sleep(time.Millisecond)
	}
	close(dialer.release)

	select {
	case p := <-panicked:
		if p == nil {
			t.Fatal("the first Request did not pass the dial's panic on")
		}
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("the first Request did not return")
	}
	select {
	case err := <-waited:
		if err == nil || !strings.Contains(err.Error(), "panicked") {
			t.Fatalf("the second Request got %v, want the dial's panic reported", err)
		}
	case <-time.After(30 * time.Second): // a hang guard; DialTimeout is an hour
		t.Fatal("the second Request still waits for the dial that panicked")
	}
	for _, branch := range []string{"z9hG4bK-chain-3", "z9hG4bK-chain-1"} {
		if err := request(branch); err != nil {
			t.Fatalf("Request %s after the panic: %v", branch, err)
		}
		awaitResponse(t, responses, 200)
	}
	closed := make(chan struct{})
	go func() { client.layer.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(30 * time.Second): // a hang guard
		t.Fatal("Layer.Close did not return")
	}
}

// parkedUnder is how many goroutines are blocked with fn on their stack.
func parkedUnder(fn string) int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, fn) && (strings.Contains(g, "[select") || strings.Contains(g, "[chan receive")) {
			count++
		}
	}
	return count
}
