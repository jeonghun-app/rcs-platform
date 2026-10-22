package scscf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// These are #439 QA's and code review's second-round probes of the stop,
// kept as tests: each holds the stop with a peer that does not answer, at
// a step where only a bounded wait lets it end within its budget.

// codeDPR is the Diameter command code of Disconnect-Peer (RFC 6733 §5.4).
const codeDPR = 282

// dprConn is a connection to the HSS that counts the DPRs scscf writes and,
// with swallow, drops them, as an HSS that never answers would. It reads
// the Diameter header's length and code, and keeps any other message.
type dprConn struct {
	net.Conn
	swallow bool
	seen    *atomic.Int64
	mu      sync.Mutex
}

func (c *dprConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var keep []byte
	dropped := false
	for off := 0; off < len(b); {
		if off+20 > len(b) {
			keep = append(keep, b[off:]...)
			break
		}
		l := int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
		if l < 20 || off+l > len(b) {
			keep = append(keep, b[off:]...)
			break
		}
		code := int(b[off+5])<<16 | int(b[off+6])<<8 | int(b[off+7])
		if request := b[off+4]&0x80 != 0; request && code == codeDPR {
			c.seen.Add(1)
			if c.swallow {
				dropped = true
				off += l
				continue
			}
		}
		keep = append(keep, b[off:off+l]...)
		off += l
	}
	if !dropped {
		return c.Conn.Write(b)
	}
	if len(keep) > 0 {
		if _, err := c.Conn.Write(keep); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// dprDial dials hss with connections that count its DPRs in seen and,
// with swallow, drop them.
func dprDial(hss *diameterHSS, swallow bool, seen *atomic.Int64) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dl net.Dialer
		c, err := dl.DialContext(ctx, network, hss.addr)
		if err != nil {
			return nil, err
		}
		return &dprConn{Conn: c, swallow: swallow, seen: seen}, nil
	}
}

// TestAStopDoesNotWaitForTheGoodbyeOfAnHSSThatDoesNotAnswer: an HSS that
// never answers the DPR holds the stop to its budget, not to the Cx
// request timeout.
func TestAStopDoesNotWaitForTheGoodbyeOfAnHSSThatDoesNotAnswer(t *testing.T) {
	hss := startHSS(t)
	var dprs atomic.Int64
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.CxTimeout = 25 * time.Second
		d.dial = dprDial(hss, true, &dprs)
	})
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
	if dprs.Load() == 0 {
		t.Fatal("no DPR was written: the test tested nothing")
	}
}

// firstOnlyCore is a P-CSCF core listener that answers the first request it
// gets 200 and reads the rest without answering: one that took a
// SUBSCRIBE's first NOTIFY and then stalled.
func firstOnlyCore(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var got atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := sip.NewReader(bufio.NewReader(c), sip.Limits{})
				for {
					m, err := r.ReadMessage()
					if err != nil {
						return
					}
					req, ok := m.(*sip.Request)
					if !ok || got.Add(1) != 1 {
						continue
					}
					if res, err := sip.NewResponse(req, 200, "", "pcscf1"); err == nil {
						if b, err := res.Bytes(); err == nil {
							_, _ = c.Write(b)
						}
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), &got
}

// TestAStopLeavesChangeNOTIFYsAfterAnAnsweredFirstOne: the first NOTIFY
// is answered and the change NOTIFYs queued after it are not; the stop
// waits for them no longer than its budget, though each may wait a minute.
// The wait for the queue is the notifier's, apart from the first NOTIFYs'.
func TestAStopLeavesChangeNOTIFYsAfterAnAnsweredFirstOne(t *testing.T) {
	hss := startHSS(t)
	addr, got := firstOnlyCore(t)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, _ *deps) { c.NotifyTimeout = time.Minute })
	p := dialSCSCF(t, r)
	dv := deviceAt(addr, 1)
	p.registerFully(t, dv, 600)
	p.subscribeReg(t, dv.path, addr, "sub-first-only")
	waitFor(t, "first NOTIFY", func() bool { return got.Load() >= 1 })
	for n := 2; n <= 4; n++ {
		p.registerFully(t, deviceAt(addr, n), 600)
	}
	waitFor(t, "a change NOTIFY", func() bool { return got.Load() >= 2 })
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
}

// blackholeDialer opens connections, but every one to addr waits for its
// context to end, as a dial to a stopped task's address does inside the
// VPC, where the SYN is dropped. dialled counts those.
type blackholeDialer struct {
	addr    string
	dialled atomic.Int64
}

func (b *blackholeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != b.addr {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	b.dialled.Add(1)
	<-ctx.Done()
	return nil, errors.New("the dial timed out")
}

// TestAStopEndsWithinItsBudgetWithAThirdPartyREGISTERStillDialling (#439
// code review): a set's third-party REGISTERs go one after the other to a
// server whose address drops the SYN, each dial lasting the dial timeout.
// The one dialling when the stop gives up neither ends with its context nor
// with the transport's Close (#462); closeMargin is longer than the dial
// timeout, so it still ends before the stop's deadline. The stop is timed
// so that, with a closeMargin of 1 s, a dial would begin just before the
// waits end and run 1.8 s past the deadline.
func TestAStopEndsWithinItsBudgetWithAThirdPartyREGISTERStillDialling(t *testing.T) {
	const dialTimeout = 2500 * time.Millisecond
	hss := startHSS(t)
	dialer := &blackholeDialer{addr: "127.0.0.1:9"}
	uri := "sip:" + dialer.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.MaxThirdParty = 1
		d.sipDialer, d.dialTimeout = dialer, dialTimeout
	})
	p := dialSCSCF(t, r)
	p.registerFully(t, deviceAt("127.0.0.1:5070", 1), 600)
	waitFor(t, "first dial", func() bool { return dialer.dialled.Load() == 1 })
	dialStart := time.Now()
	for n := 2; n <= 4; n++ {
		p.registerFully(t, deviceAt("127.0.0.1:5070", n), 600)
	}
	// The dials begin at dialStart plus multiples of dialTimeout: the
	// third at 5 s. With the stop at 0.7 s, it begins 4.3 s after the
	// stop, before waits that end at 4.5 s with a closeMargin of 1 s, and
	// after those that end at 2.5 s with 3 s.
	time.Sleep(time.Until(dialStart.Add(700 * time.Millisecond)))
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
	if got, _ := r.h.Metric("routing.third_party.dropped_at_stop"); got == 0 {
		t.Error("nothing was dropped at the stop: the test tested nothing")
	}
}

// syncBuffer is a buffer the runtime's goroutines may write at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestTheWorstStopEndsBeforeTheRuntimesDeadline (#439 QA): through
// runtime.Run, with RCS_SHUTDOWN_TIMEOUT just DrainTimeout plus
// stopMargin, as the default drain has it, the stop meets everything at
// once: an INVITE ringing toward a P-CSCF that never answers, which holds
// the drain to its end; a third-party REGISTER at a silent server; NOTIFYs
// at the silent P-CSCF; and an HSS that never answers the DPR. The runtime
// says whether the service stopped before its deadline, which needs no
// wall-clock bound in the test.
func TestTheWorstStopEndsBeforeTheRuntimesDeadline(t *testing.T) {
	hss := startHSS(t)
	as := startSilentPeer(t)
	silent := startSilentPeer(t)
	uri := "sip:" + as.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	var dprs atomic.Int64
	cfg := testConfig()
	cfg.DrainTimeout = 2 * time.Second
	cfg.NotifyTimeout = time.Minute
	cfg.ThirdPartyTimeout = time.Minute
	cfg.CxTimeout = 25 * time.Second
	shutdown := cfg.DrainTimeout + stopMargin
	listening := make(chan netip.AddrPort, 1)
	d := deps{
		rand:      newSeededRand(7),
		store:     state.NewMemory(),
		discovery: staticDiscovery{netip.MustParseAddr("127.0.0.1")},
		dial:      dprDial(hss, true, &dprs),
		listening: func(a netip.AddrPort) { listening <- a },
		allow:     func(a netip.Addr) bool { return a.IsLoopback() },
	}
	svc := runtime.Service[ServiceConfig]{
		Name: "scscf", EnvPrefix: "SCSCF_",
		Configure: func(*runtime.Settings) ServiceConfig { return cfg },
		Run:       func(ctx context.Context, rt *runtime.Runtime, c ServiceConfig) error { return run(ctx, rt, c, d) },
	}
	env := map[string]string{"RCS_ENV": "dev", "RCS_SHUTDOWN_TIMEOUT": shutdown.String()}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status := make(chan int, 1)
	go func() {
		status <- runtime.Run(ctx, svc, runtime.Process{
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			Stdout:    &out, Stderr: &out,
			Listen: func(network, _ string) (net.Listener, error) { return net.Listen(network, "127.0.0.1:0") },
		})
	}()
	var core netip.AddrPort
	select {
	case core = <-listening:
	case s := <-status:
		t.Fatalf("the runtime ended with %d: %s", s, out.String())
	case <-time.After(realWait):
		t.Fatal("scscf did not start")
	}
	p := dialSCSCF(t, &running{core: core})
	dv := deviceAt(silent.addr, 1)
	// A REGISTER before the HSS connection is up is answered 480.
	waitFor(t, "a registration", func() bool {
		res := p.registerDevice(t, dv, 600, firstAuthorization)
		if res.StatusCode != 401 {
			return false
		}
		return p.registerDevice(t, dv, 600, answer(t, res, nil)).StatusCode == 200
	})
	p.subscribeReg(t, dv.path, silent.addr, "worst-sub")
	for n := 2; n <= 4; n++ {
		p.registerFully(t, deviceAt(silent.addr, n), 600)
	}
	waitFor(t, "third-party REGISTER at the server", func() bool { return as.got.Load() > 0 })
	waitFor(t, "NOTIFY at the P-CSCF", func() bool { return silent.got.Load() > 0 })
	before := silent.got.Load()
	invite := strings.Join([]string{
		"INVITE " + impu + " SIP/2.0",
		"Via: SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-worst-inv",
		"Max-Forwards: 69",
		"From: <sip:+15550100002@" + realm + ">;tag=caller", "To: <" + impu + ">",
		"Call-ID: worst-inv", "CSeq: 1 INVITE",
		"Contact: <sip:caller@127.0.0.1:5070;transport=tcp>",
		"Content-Length: 0",
	}, "\r\n") + "\r\n\r\n"
	if _, err := p.c.Write([]byte(invite)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the INVITE at the P-CSCF", func() bool { return silent.got.Load() > before })
	cancel()
	select {
	case s := <-status:
		if s != runtime.ExitOK {
			t.Errorf("exit %d: the stop overran RCS_SHUTDOWN_TIMEOUT (%v):\n%s", s, shutdown, out.String())
		}
	case <-time.After(stopWait):
		t.Fatal("the runtime did not return")
	}
	if dprs.Load() == 0 {
		t.Error("no DPR was written: the Cx client was closed with no time left")
	}
}
