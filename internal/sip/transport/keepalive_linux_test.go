//go:build linux

package transport

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// keepAliveOf reads SO_KEEPALIVE and TCP_KEEPIDLE (in seconds) of the server
// side of the connection a client opened to the listener at addr.
func keepAliveOf(t *testing.T, lc ListenerConfig) (on bool, idle int) {
	t.Helper()
	server, rec := newTransport(t, Config{})
	addr := listen(t, server, lc)
	c := dialRaw(t, addr)
	c.Write([]byte(rawRequest("OPTIONS", "Via: SIP/2.0/TCP a.example.com;branch=z9hG4bK1")))
	f := server.flows.lookup(rec.next(t).Source.Flow)
	raw, err := f.conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var keep int
	raw.Control(func(fd uintptr) {
		keep, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		idle, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
	})
	return keep == 1, idle
}

func TestClientFacingListenersSendNoTCPKeepAliveProbes(t *testing.T) {
	if on, _ := keepAliveOf(t, ListenerConfig{Network: TCP, ClientFacing: true}); on {
		t.Fatal("SO_KEEPALIVE is on")
	}
}

func TestCoreListenersProbeEvery15Seconds(t *testing.T) {
	if on, idle := keepAliveOf(t, ListenerConfig{Network: TCP}); !on || idle != 15 {
		t.Fatalf("SO_KEEPALIVE %v, TCP_KEEPIDLE %d", on, idle)
	}
}

func TestListenerKeepAliveCanBeSetExplicitly(t *testing.T) {
	ka := &net.KeepAliveConfig{Enable: true, Idle: 300 * time.Second, Interval: 30 * time.Second, Count: 3}
	if on, idle := keepAliveOf(t, ListenerConfig{Network: TCP, ClientFacing: true, KeepAlive: ka}); !on || idle != 300 {
		t.Fatalf("SO_KEEPALIVE %v, TCP_KEEPIDLE %d", on, idle)
	}
}
