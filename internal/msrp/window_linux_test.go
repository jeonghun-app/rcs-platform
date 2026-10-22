//go:build linux && !386

package msrp

// linux/386 has no getsockopt system call of its own, as in
// kernelstate_linux_test.go.

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// setReceiveBuffer sets the receive buffer of an open TCP connection.
func setReceiveBuffer(nc net.Conn, n int) error {
	raw, err := nc.(*net.TCPConn).SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, n)
	}); err != nil {
		return err
	}
	return serr
}

// sendMSS is the largest segment an open TCP connection sends now.
func sendMSS(nc net.Conn) (uint32, error) {
	raw, err := nc.(*net.TCPConn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var ti syscall.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(ti))
		if _, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&size)), 0); e != 0 {
			serr = e
		}
	}); err != nil {
		return 0, err
	}
	return ti.Snd_mss, serr
}

// #140: the rig's shared connection stood still for good in CI, the relay
// core's socket empty and rcs-as's holding a megabyte it never sent, with
// nothing in flight and no probe. On loopback a segment is up to 64 KiB, and
// rcs-as's had grown to about that when the core's receive buffer shrank,
// leaving a window too small for one segment. Linux then sends nothing; the
// probe that would send the part that fits is put off by every ACK that the
// core's own traffic brings, and the chats every 10 ms bring one long before
// it is due. The rig's sockets take a real link's segment size instead
// (rigListen). This shrinks the core's buffer as CI found it, while chats go
// one way and files the other, and needs the next bind and the files still
// to go through. Without linkMSS that fails most times, not every time
// (presumably a lull in the ACKs lets the probe go), so the test also
// checks the cause: neither end of the connection sends a segment larger
// than linkMSS.
func TestTheRigsSharedConnectionCarriesOnPastAShrunkWindow(t *testing.T) {
	rig := newRelayRigTCP(t, Config{}, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var clients []*countingHandler
	for n := range 2 {
		as, cl, rp := rig.addUser(t, n, &countingHandler{delay: time.Millisecond})
		h := &countingHandler{}
		cs, _ := rig.dialClient(t, cl, rp, h)
		clients = append(clients, h)
		go func() {
			for ctx.Err() == nil {
				if _, err := cs.Send(ctx, Outgoing{ContentType: "text/plain", Body: BodyOf(bodyOf(200))}); err != nil {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		sendMany(ctx, as, 1, 100, 1<<20, false)
	}
	pushed := func() int64 { return clients[0].octets.Load() + clients[1].octets.Load() }
	waitPushed(t, pushed, 1<<20)
	// 4 KiB, which Linux doubles: a window of a few KiB, below the 32 KiB
	// or more a loopback segment has grown to by now, above linkMSS.
	if err := setReceiveBuffer(rig.coreConn(t).nc, 4<<10); err != nil {
		t.Fatal(err)
	}
	from := pushed()
	_, cl, rp := rig.addUser(t, 2, &countingHandler{})
	rig.dialClient(t, cl, rp, &countingHandler{})
	waitPushed(t, pushed, from+1<<20)
	ends := []roleConn{{"relay core", rig.coreConn(t)}}
	rig.diagMu.Lock()
	for _, rc := range rig.conns {
		if rc.role == "rcs-as" {
			ends = append(ends, rc)
		}
	}
	rig.diagMu.Unlock()
	if len(ends) != 2 {
		t.Fatalf("the shared connection has %d ends", len(ends))
	}
	for _, end := range ends {
		mss, err := sendMSS(end.c.nc)
		if err != nil {
			t.Fatal(err)
		}
		if mss > linkMSS {
			t.Errorf("%s sends segments of %d octets, above linkMSS (%d): a shrunk window can fall below one", end.role, mss, linkMSS)
		}
	}
}

// waitPushed waits until pushed reaches want, failing only once it has not
// moved for hangGuard: a loaded host is slow, a stalled connection still.
func waitPushed(t *testing.T, pushed func() int64, want int64) {
	t.Helper()
	last, since := pushed(), time.Now()
	for p := last; p < want; p = pushed() {
		if p != last {
			last, since = p, time.Now()
		}
		if time.Since(since) > hangGuard {
			t.Fatalf("the files stood still at %d octets of %d for %v", p, want, hangGuard)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
