//go:build linux

package transaction

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// linkMSS is a real link's segment size, which the burst tests' connections
// take instead of loopback's 64 KiB (#616, as #509 did for the msrp rig).
const linkMSS = 1400

// linkDialer dials with linkMSS. TCP_MAXSEG on one end bounds the segments
// both ends send: the other end learns it from the SYN.
func linkDialer() transport.Dialer {
	return &net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var err error
		if cerr := rc.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, linkMSS)
		}); cerr != nil {
			return cerr
		}
		return err
	}}
}

// keptDialer dials with d and hands over the connection it opened.
type keptDialer struct {
	d     transport.Dialer
	conns chan net.Conn
}

func (k *keptDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := k.d.DialContext(ctx, network, addr)
	if err == nil {
		select {
		case k.conns <- c:
		default:
		}
	}
	return c, err
}

// The two-way burst completes when A's receive buffer shrinks to 4 KiB
// (8 KiB as the kernel doubles it) partway through, with a real link's
// segment size. On loopback's 64 KiB segment the window then falls below
// one segment while traffic flows both ways, and Linux sends next to
// nothing: CI's #616, at about 7 transactions a second, which this test
// without linkDialer shows. The bound is short for that reason: the burst
// takes about a second, the stall over a minute.
func TestTwoWayInviteBurstOutlastsAShrunkReceiveBuffer(t *testing.T) {
	total := 1200
	if raceEnabled {
		total = 300
	}
	dialer := &keptDialer{d: linkDialer(), conns: make(chan net.Conn, 1)}
	twoWayBurst(t, 486, total, dialer, 30*time.Second, func() {
		nc := <-dialer.conns
		raw, err := nc.(*net.TCPConn).SyscallConn()
		if err != nil {
			t.Error(err)
			return
		}
		_ = raw.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<10); err != nil {
				t.Error(err)
			}
		})
	})
}
