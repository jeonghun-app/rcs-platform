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
