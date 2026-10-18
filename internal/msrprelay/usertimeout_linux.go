package msrprelay

import (
	"net"
	"syscall"
	"time"
)

// tcpUserTimeout is TCP_USER_TIMEOUT from linux/tcp.h. It is the same on
// every architecture, but package syscall defines it only for some.
const tcpUserTimeout = 0x12

// setUserTimeout bounds how long data the relay sent may stay unacknowledged
// before the kernel gives the connection up: the user timeout of RFC 5482
// §1, TCP_USER_TIMEOUT on Linux. Without it, a client that vanishes while
// rcs-as sends to it only chunks nobody answers (Failure-Report no or
// partial) is held until the kernel's retransmissions run out, about 15
// minutes with the default tcp_retries2, and neither the keep-alive (the
// session is not quiet) nor the write timeout (the send buffer never fills)
// notices. Kernel keep-alive stays off (ADR 0003): this option sends nothing
// of its own.
func setUserTimeout(nc net.Conn, d time.Duration) error {
	tc, ok := nc.(*net.TCPConn)
	if !ok || d <= 0 {
		return nil
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeout, int(d/time.Millisecond))
	})
	if err != nil {
		return err
	}
	return serr
}
