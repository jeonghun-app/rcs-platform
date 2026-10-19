package msrprelay

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func TestUserTimeoutIsSetOnTCPSockets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	nc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if err := setUserTimeout(nc, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	raw, err := nc.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var gerr error
	_ = raw.Control(func(fd uintptr) { got, gerr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout) })
	if gerr != nil || got != 60000 {
		t.Fatalf("TCP_USER_TIMEOUT = %d ms, %v; want 60000", got, gerr)
	}
	// Anything that is not a TCP socket, such as a pipe in tests, is left
	// alone.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := setUserTimeout(a, time.Second); err != nil {
		t.Fatalf("pipe: %v", err)
	}
}

func TestAcceptedClientSocketsGetTheUserTimeout(t *testing.T) {
	r := newRig(t, 1, func(o *relayOptions) { o.UserTimeout = 7 * time.Second })
	c := r.dial(0, nil)
	_ = c
	var got int
	eventually(t, "the relay to set the option", func() bool {
		r.relays[0].mu.Lock()
		defer r.relays[0].mu.Unlock()
		for nc := range r.relays[0].conns {
			raw, err := nc.(*net.TCPConn).SyscallConn()
			if err != nil {
				return false
			}
			_ = raw.Control(func(fd uintptr) { got, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout) })
		}
		return got == 7000
	})
}
