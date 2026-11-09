//go:build linux

package transaction

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// linkMSS is a real link's segment size, which the burst tests' connections
// take instead of loopback's 64 KiB (#616, as #509 did for the msrp rig).
const linkMSS = 1400

// The segment sizes of a VPC: with the usual MTU of 1500, and with jumbo
// frames (MTU 9001), which an ENI has by default (#623).
const (
	vpcMSS   = 1448
	jumboMSS = 8949
)

// linkDialer dials with linkMSS.
func linkDialer() transport.Dialer { return segmentDialer(linkMSS) }

// segmentDialer dials with mss. TCP_MAXSEG on one end bounds the segments
// both ends send: the other end learns it from the SYN.
func segmentDialer(mss int) transport.Dialer {
	return &net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var err error
		if cerr := rc.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
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

// shrinkReceiveBuffer sets nc's receive buffer to 4 KiB (8 KiB as the
// kernel doubles it), after its window has been large.
func shrinkReceiveBuffer(t *testing.T, nc net.Conn) {
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
}

// The two-way burst completes when A's receive buffer shrinks to 4 KiB
// (8 KiB as the kernel doubles it) partway through, with a real link's
// segment size. On loopback's 64 KiB segment the window then falls below
// one segment while traffic flows both ways, and Linux sends next to
// nothing: CI's #616, at about 7 transactions a second, which this test
// without linkDialer shows. The bound is short for that reason: the burst
// takes about a second, the stall over a minute. At the segment size of a
// VPC with an MTU of 1500 it completes over its one connection too, at the
// default MaxQueueAge: even the kernel's smallest buffer leaves a window of
// several segments there (#623).
func TestTwoWayInviteBurstOutlastsAShrunkReceiveBuffer(t *testing.T) {
	total := 1200
	if raceEnabled {
		total = 300
	}
	for _, mss := range []int{linkMSS, vpcMSS} {
		t.Run(strconv.Itoa(mss), func(t *testing.T) {
			dialer := &keptDialer{d: segmentDialer(mss), conns: make(chan net.Conn, 1)}
			twoWayBurst(t, 486, total, dialer, 30*time.Second, func() { shrinkReceiveBuffer(t, <-dialer.conns) })
		})
	}
}

// #623: at jumbo frames' segment size the same shrink stalls the connection
// in the kernel. B's queue toward A stays at its limit and moves about a
// message a second, so its writer never misses WriteTimeout. The queue-age
// rule resets the connection once B's oldest output has waited MaxQueueAge,
// and a second round of INVITEs both ways then completes over new
// connections. The transactions whose messages the reset dropped are not
// waited for: they end at Timer B or F either way. WriteTimeout stays at
// the burst's 30 s, so only the queue-age rule can end the stall;
// MaxQueueAge is 3 s rather than the default 32 s to keep the test short.
// At the default the reset came about 35 s after the shrink.
func TestAJumboConnectionStalledByAShrunkWindowIsResetAndTheNextSendsComplete(t *testing.T) {
	total := 1200
	if raceEnabled {
		total = 300
	}
	type end struct {
		tr   *transport.Transport
		l    *Layer
		tu   *sourceTU
		addr netip.AddrPort
	}
	mk := func(d transport.Dialer) end {
		e := end{tu: &sourceTU{code: 486, first: make(chan transport.Source, 1)}}
		var layer atomic.Pointer[Layer]
		tr, err := transport.New(transport.Config{
			WriteTimeout: burstWriteTimeout, MaxQueueAge: 3 * time.Second, Dialer: d,
			// As the services do: a transaction sent over a flow that
			// closes ends at once.
			OnFlowClosed: func(id transport.FlowID, _ transport.FlowInfo) { layer.Load().FlowClosed(id) },
		}, func(in transport.Inbound) { layer.Load().Receive(in) })
		if err != nil {
			t.Fatal(err)
		}
		e.tr = tr
		e.l = mustNew(t, tr, e.tu, Config{T1: burstT1})
		layer.Store(e.l)
		if e.addr, err = tr.Listen(transport.ListenerConfig{Network: transport.TCP, Addr: "127.0.0.1:0"}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { e.l.Close(); tr.Close() })
		return e
	}
	dialer := &keptDialer{d: segmentDialer(jumboMSS), conns: make(chan net.Conn, 1)}
	a, b := mk(dialer), mk(nil)
	toB := transport.Destination{Network: transport.TCP, Addr: b.addr}
	body := []byte(strings.Repeat("a=x\r\n", 32<<10/5)) // 32 KiB

	var ended atomic.Int64
	collect := func(res *sip.Response, err error) {
		if err != nil || res.StatusCode >= 200 {
			ended.Add(1)
		}
	}
	if _, err := a.l.Request(burstInvite(t, "a", 0, body), toB, collect); err != nil {
		t.Fatal(err)
	}
	toA := transport.Destination{Flow: (<-b.tu.first).Flow}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	send := func(l *Layer, side string, dst transport.Destination, from int) {
		defer wg.Done()
		for i := from; i < total; i += 4 {
			select {
			case <-stop:
				return
			default:
			}
			// Sends fail once the reset has closed the flow they use.
			_, _ = l.Request(burstInvite(t, side, i, body), dst, collect)
		}
	}
	for w := range 4 {
		wg.Add(2)
		go send(a.l, "a", toB, 1+w)
		go send(b.l, "b", toA, w)
	}
	stopSenders := func() {
		close(stop)
		select {
		case <-wgDone(&wg):
		case <-time.After(2 * burstWriteTimeout):
			t.Error("the senders did not stop")
		}
	}

	waitBurst(t, "a tenth of the burst", func() bool { return ended.Load() >= int64(2*total/10) })
	shrinkReceiveBuffer(t, <-dialer.conns)
	if !waitBurst(t, "B's stall reset", func() bool { return b.tr.Stats().WriteStalls > 0 }) {
		t.Errorf("%d of %d transactions ended; A %+v; B %+v", ended.Load(), 2*total, a.tr.Stats(), b.tr.Stats())
		stopSenders()
		return
	}
	stopSenders()

	// The next round, each side to the other's address.
	const round = 10
	var answered sync.WaitGroup
	var finals atomic.Int64
	answered.Add(2 * round)
	for i := range round {
		for _, s := range []struct {
			l    *Layer
			side string
			dst  transport.Destination
		}{{a.l, "a2", toB}, {b.l, "b2", transport.Destination{Network: transport.TCP, Addr: a.addr}}} {
			var once sync.Once
			if _, err := s.l.Request(burstInvite(t, s.side, i, body), s.dst, func(res *sip.Response, err error) {
				if err != nil || res.StatusCode >= 200 {
					if err == nil && res.StatusCode == 486 {
						finals.Add(1)
					}
					once.Do(answered.Done)
				}
			}); err != nil {
				t.Fatalf("%s: %v", s.side, err)
			}
		}
	}
	select {
	case <-wgDone(&answered):
	case <-time.After(burstWriteTimeout):
		t.Fatalf("%d of %d INVITEs after the reset answered", finals.Load(), 2*round)
	}
	as, bs := a.tr.Stats(), b.tr.Stats()
	if finals.Load() != 2*round || bs.WriteStalls != 1 || as.WriteStalls != 0 || as.Dialed != 2 || bs.Dialed != 1 {
		t.Errorf("%d of %d INVITEs after the reset answered 486; A %+v; B %+v", finals.Load(), 2*round, as, bs)
	}
}

// waitBurst waits until cond holds, for at most a minute, and reports
// whether it did. A stall in the kernel never ends on its own, so the bound
// only turns a test that would hang into a failure.
func waitBurst(t *testing.T, what string, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for !cond() {
		if time.Now().After(deadline) {
			t.Errorf("timed out waiting for %s", what)
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}
