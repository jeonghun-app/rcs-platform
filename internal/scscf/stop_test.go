package scscf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
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

// TestTheStopKeepsReturnMarginForItsReturn (#502, #549 code review): run
// sets the stop's deadline returnMargin inside its budget, DrainTimeout
// plus stopMargin, and gives the goodbye, its last wait, that deadline. The
// deadlines are read, not the clock, which a loaded host stretches past any
// margin; TestTheStopMarginsLeaveEveryStepItsTime guards the margin's size.
func TestTheStopKeepsReturnMarginForItsReturn(t *testing.T) {
	hss := startHSS(t)
	var dprs atomic.Int64
	var begun, stopBy, deadline time.Time
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.CxTimeout = 25 * time.Second
		d.dial = dprDial(hss, true, &dprs)
		d.stopping = func(b, s time.Time) { begun, stopBy = b, s }
		d.goodbyeAt = func(dl time.Time) { deadline = dl }
	})
	stopAfterCxOpen(t, r, hss)
	want := testConfig().DrainTimeout + stopMargin - returnMargin
	if got := stopBy.Sub(begun); got != want {
		t.Errorf("the stop's deadline is %v after it began, want %v", got, want)
	}
	// Nothing held the stop, so the goodbye is reached long before.
	if !deadline.Equal(stopBy) {
		t.Errorf("the goodbye's deadline is %v from the stop's, want the stop's", deadline.Sub(stopBy))
	}
	if dprs.Load() == 0 {
		t.Errorf("no DPR was written; %s", cxLog(r))
	}
}

// TestTheGoodbyeHasStopByOrItsFloor: on time, the goodbye's deadline is the
// stop's; reached later than goodbyeFloor before it, the goodbye still has
// goodbyeFloor (#549 code review).
func TestTheGoodbyeHasStopByOrItsFloor(t *testing.T) {
	stopBy := time.Date(2031, 1, 1, 0, 0, 10, 0, time.UTC)
	for _, c := range []struct {
		now, want time.Time
	}{
		{stopBy.Add(-time.Second), stopBy},
		{stopBy.Add(-goodbyeFloor), stopBy},
		{stopBy.Add(-goodbyeFloor / 2), stopBy.Add(goodbyeFloor / 2)},
		{stopBy.Add(lateWake), stopBy.Add(lateWake + goodbyeFloor)},
	} {
		if got := goodbyeDeadline(stopBy, c.now); !got.Equal(c.want) {
			t.Errorf("reached %v before the stop's deadline: %v, want %v", stopBy.Sub(c.now), got.Sub(stopBy), c.want.Sub(stopBy))
		}
	}
}

// TestAGoodbyeReachedLateStillSendsItsDPR (#549 code review): a stop held
// past its deadline before the goodbye, as a host that did not run the
// process does, still writes the DPR, in the goodbye's floor.
func TestAGoodbyeReachedLateStillSendsItsDPR(t *testing.T) {
	hss := startHSS(t)
	var dprs atomic.Int64
	var stopBy, released, deadline time.Time
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.CxTimeout = 25 * time.Second
		d.dial = dprDial(hss, true, &dprs)
		d.stopping = func(_, s time.Time) { stopBy = s }
		d.goodbye = func() {
			time.Sleep(time.Until(stopBy.Add(goodbyeFloor)))
			released = time.Now()
		}
		d.goodbyeAt = func(dl time.Time) { deadline = dl }
	})
	stopAfterCxOpen(t, r, hss)
	// The floor from when the stop was let go: a host may run it later
	// still, which only moves the deadline on, so the bound above is loose.
	if left := deadline.Sub(released); left < goodbyeFloor || left > goodbyeFloor+time.Second {
		t.Errorf("reached %v past the stop's deadline, the goodbye had %v, want its floor of %v", released.Sub(stopBy), left, goodbyeFloor)
	}
	if dprs.Load() == 0 {
		t.Errorf("no DPR was written: the goodbye had no time once reached late; %s", cxLog(r))
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
	checkStopTook(t, stopAfterCxOpen(t, r, hss))
	if dprs.Load() == 0 {
		t.Fatalf("no DPR was written: the test tested nothing; %s", cxLog(r))
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
// The one dialling when the stop gives up does not end with its context
// (#462), but the transport's Close cuts it (#474), so the stop ends before
// its deadline although the dial timeout, 10 s, is far longer than the
// stop's budget: without the cut, the stop would wait for the dial (#549
// code review).
func TestAStopEndsWithinItsBudgetWithAThirdPartyREGISTERStillDialling(t *testing.T) {
	const dialTimeout = 10 * time.Second
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
	// The first dial began at dialStart. With the stop at 0.7 s, it is
	// under way when the waits end, 2.5 s after the stop, and the transport
	// closes; uncut, it would end 9.3 s after the stop.
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
	var returned atomic.Int64
	svc := runtime.Service[ServiceConfig]{
		Name: "scscf", EnvPrefix: "SCSCF_",
		Configure: func(*runtime.Settings) ServiceConfig { return cfg },
		Run: func(ctx context.Context, rt *runtime.Runtime, c ServiceConfig) error {
			err := run(ctx, rt, c, d)
			returned.Store(time.Now().UnixNano())
			return err
		},
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
	cancelled := time.Now()
	cancel()
	select {
	case s := <-status:
		if s != runtime.ExitOK {
			t.Errorf("exit %d: the stop overran RCS_SHUTDOWN_TIMEOUT (%v):\n%s", s, shutdown, out.String())
		}
		// run itself returns before the deadline, which the exit status
		// shows only when the runtime's timer is on time (#479). It ends
		// its own work returnMargin inside it, so that the closes after
		// and a late end of its last wait fit (#502); without the margin it
		// returns past the deadline, every time.
		if took := time.Duration(returned.Load() - cancelled.UnixNano()); took >= shutdown {
			t.Errorf("run returned %v after the cancel, at or past the deadline of %v", took, shutdown)
		}
	case <-time.After(stopWait):
		t.Fatal("the runtime did not return")
	}
	if dprs.Load() == 0 {
		t.Error("no DPR was written: the Cx client was closed with no time left")
	}
}

// stubbornDialer opens connections, but one to addr ignores its context,
// even once the transport's Close cancels it, and returns only when
// released: the slowest return a send the router gave up on can have.
type stubbornDialer struct {
	addr     string
	dialling chan struct{}
	release  chan struct{}
}

func (s *stubbornDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != s.addr {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	s.dialling <- struct{}{}
	<-s.release
	return nil, errors.New("the dial timed out")
}

// TestTheCxGoodbyeHasItsTimeWhateverTheRouterWaitsFor (#502): a
// third-party REGISTER whose dial returns only past the stop's deadline
// holds the router's wait to its end, which comes goodbyeMargin before the
// deadline, so the Cx client still says goodbye (DPR). The dial returns
// within the budget, so the stop ends within it.
func TestTheCxGoodbyeHasItsTimeWhateverTheRouterWaitsFor(t *testing.T) {
	hss := startHSS(t)
	dialer := &stubbornDialer{addr: "127.0.0.1:9", dialling: make(chan struct{}, 1), release: make(chan struct{})}
	uri := "sip:" + dialer.addr + ";transport=tcp"
	hss.asURI.Store(&uri)
	var dprs atomic.Int64
	r := startSCSCFWith(t, hss, state.NewMemory(), 1, func(_ *ServiceConfig, d *deps) {
		d.sipDialer = dialer
		d.dial = dprDial(hss, false, &dprs)
	})
	p := dialSCSCF(t, r)
	p.registerFully(t, deviceAt("127.0.0.1:5070", 1), 600)
	recv(t, dialer.dialling)
	// Past the stop's deadline, budget less returnMargin, and within the
	// budget: the router's wait, ended at the deadline, would leave the
	// Cx client no time.
	budget := testConfig().DrainTimeout + stopMargin
	start := time.Now()
	release := time.AfterFunc(budget-returnMargin/2, func() { close(dialer.release) })
	defer release.Stop()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	checkStopTook(t, time.Since(start))
	if dprs.Load() == 0 {
		t.Error("no DPR went to the HSS: the router's wait took the Cx client's time")
	}
}

// TestTheStopMarginsLeaveEveryStepItsTime: steps 3 and 4 have part of
// stopMargin, step 5 has time for the sends before the goodbye's, and the
// return holds the late end of a wait on a loaded host, lateWake as
// measured, and the goodbye's floor (docs/scscf.md, Stop; #502). A dial need
// not fit in the sends' time: the transport's Close cuts it (#474,
// TestAStopEndsWithinItsBudgetWithAThirdPartyREGISTERStillDialling).
func TestTheStopMarginsLeaveEveryStepItsTime(t *testing.T) {
	if closeMargin <= goodbyeMargin || returnMargin+closeMargin >= stopMargin ||
		returnMargin < lateWake+goodbyeFloor || goodbyeFloor >= goodbyeMargin {
		t.Errorf("closeMargin %v, goodbyeMargin %v, returnMargin %v, stopMargin %v, lateWake %v, goodbyeFloor %v",
			closeMargin, goodbyeMargin, returnMargin, stopMargin, lateWake, goodbyeFloor)
	}
}

// stopAfterCxOpen stops r once its Cx connection to hss is open on both
// sides: the HSS stub has it available, and scscf's /readyz says so, looked
// at past its cache. A test that counts the stop's DPR needs that
// connection at the goodbye (#587). The wait is bounded by realWait, and
// ends as soon as the connection is seen open.
func stopAfterCxOpen(t *testing.T, r *running, hss *diameterHSS) time.Duration {
	t.Helper()
	deadline := time.Now().Add(realWait)
	for {
		peers := hss.node.Peers()
		open := len(peers) > 0 && peers[0].Available()
		if open {
			r.h.Advance(2 * time.Second)
			if code, _ := r.h.Get("/readyz"); code == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the Cx connection did not open: %s", cxLog(r))
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	return time.Since(start)
}

// cxLog is what scscf logged of its Diameter connections, for a test that
// found no DPR to say whether the connection was open at the stop.
func cxLog(r *running) string {
	var out []string
	for _, msg := range []string{"diameter peer open", "diameter peer closed", "diameter peer connection failed",
		"diameter connection closed before capabilities exchange completed", "cxclient: HSS task added", "cxclient: HSS task removed"} {
		if n := len(r.h.Logs(msg)); n > 0 {
			out = append(out, fmt.Sprintf("%q x%d", msg, n))
		}
	}
	return strings.Join(out, ", ")
}
