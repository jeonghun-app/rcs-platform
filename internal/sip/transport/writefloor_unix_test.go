//go:build unix

package transport

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// sendBuffer is c's SO_SNDBUF as the kernel reports it.
func sendBuffer(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	var serr error
	if err := raw.Control(func(fd uintptr) { n, serr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF) }); err != nil {
		t.Fatal(err)
	}
	if serr != nil {
		t.Fatal(serr)
	}
	return n
}

// capSendBuffer gives a TCP connection the send buffer the floor was measured
// with: what the kernel reports for 128 KiB asked for directly.
func TestCapSendBufferAsksFor128KiB(t *testing.T) {
	capped, reference := tcpPair(t), tcpPair(t)
	capSendBuffer(capped)
	if err := reference.SetWriteBuffer(128 << 10); err != nil {
		t.Fatal(err)
	}
	if got, want := sendBuffer(t, capped), sendBuffer(t, reference); got != want {
		t.Fatalf("SO_SNDBUF %d after capSendBuffer, want %d as for 128 KiB", got, want)
	}
}

// Every stream flow has that send buffer, accepted and dialed alike: the
// floor holds only if both paths apply it (QA and code review of #370).
func TestEveryStreamFlowHasTheCappedSendBuffer(t *testing.T) {
	reference := tcpPair(t)
	if err := reference.SetWriteBuffer(128 << 10); err != nil {
		t.Fatal(err)
	}
	want := sendBuffer(t, reference)
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, ListenerConfig{Network: TCP})
	client, _ := newTransport(t, Config{})
	req := newRequest(t, "OPTIONS", "SIP/2.0/TCP placeholder.invalid;branch=z9hG4bKfloor")
	if _, err := client.SendRequest(req, Destination{Network: TCP, Addr: addr}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rec:
	case <-time.After(waitFor):
		t.Fatal("the request did not arrive")
	}
	dialed := client.flows.peer(reuseKey{network: TCP, remote: addr})
	accepted := server.flows.streams()
	if dialed == nil || len(accepted) != 1 {
		t.Fatalf("dialed %v, accepted %d", dialed != nil, len(accepted))
	}
	for name, f := range map[string]*flow{"dialed": dialed, "accepted": accepted[0]} {
		tc, ok := f.conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("%s flow: conn is %T", name, f.conn)
		}
		if got := sendBuffer(t, tc); got != want {
			t.Errorf("%s flow: SO_SNDBUF %d, want %d", name, got, want)
		}
	}
}
