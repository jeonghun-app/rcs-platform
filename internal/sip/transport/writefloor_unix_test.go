//go:build unix

package transport

import (
	"net"
	"syscall"
	"testing"
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
