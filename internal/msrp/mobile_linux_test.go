//go:build linux

package msrp

import (
	"net"
	"syscall"
)

// mobileDialer dials with the segment size and receive buffer of a mobile
// link rather than loopback's, so that a slow reader shows steady progress.
func mobileDialer() *net.Dialer {
	return &net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var err error
		cerr := rc.Control(func(fd uintptr) {
			if err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, 1400); err != nil {
				return
			}
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 16<<10)
		})
		if cerr != nil {
			return cerr
		}
		return err
	}}
}

// linkMSS is a real link's segment size, which the rig's sockets take
// instead of loopback's 64 KiB (#140).
const linkMSS = 1400

// rigListenConfig listens with linkMSS, which the connections it accepts
// keep, and which bounds what either end of them sends. On loopback a
// sender's segment grows toward 64 KiB, as large as half the biggest window
// it has seen; a receive buffer that later shrinks leaves a window smaller
// than one segment. Linux then sends nothing, and the probe that would send
// the part that fits is put off by every ACK the peer's own traffic brings,
// so a connection carrying traffic both ways stands still for good (#140).
// A real link's segment is far smaller than any window the rig's buffers
// leave.
func rigListenConfig() net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var err error
		if cerr := rc.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, linkMSS)
		}); cerr != nil {
			return cerr
		}
		return err
	}}
}
