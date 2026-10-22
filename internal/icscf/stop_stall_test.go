package icscf

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// #338, as #323 for pcscf: a core peer that stops reading leaves responses in
// its connection's send queue, and senders waiting for room in it. The stop
// closes the connections instead of waiting for those writes: none of them
// fails on its WriteTimeout, which is set long here so that filling the queue
// on a loaded host cannot trip it either. TestAStopAnswersARequestLeftInProgress500
// checks the stop's own waits against the margin.
func TestAStopDoesNotWaitOnACorePeerThatStoppedReading(t *testing.T) {
	const writeTimeout = time.Minute
	hss := startHSS(t)
	scscf := startSCSCF(t)
	var tr *transport.Transport
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, d *deps) {
		c.DrainTimeout = 200 * time.Millisecond
		d.writeTimeout = writeTimeout
		d.transport = func(t *transport.Transport) { tr = t }
	})
	fillCoreQueue(t, tr, func() (net.Conn, error) { return net.Dial("tcp", r.core.String()) }, every(30*time.Second), writeTimeout, r.h.Records)
	failed := tr.Stats().WriteErrors
	// Only a hang guard, past the write deadline so that a stop that waits
	// for it still returns and fails below.
	r.stopWithin(writeTimeout + 30*time.Second)
	if n := tr.Stats().WriteErrors - failed; n != 0 {
		t.Errorf("%d writes to the core peer failed on their deadline during the stop, which waited for them", n)
	}
	for _, rec := range r.h.Records() {
		if rec["level"] == "ERROR" || rec["level"] == "WARN" {
			t.Errorf("logged at the stop: %v", rec)
		}
	}
}

// fillCoreQueue fills tr's send queue toward a core peer that sends
// requests over a connection from dial and never reads, until no further
// 403 fits, whatever its size, and leaves the connection open. The fill is
// judged by progress, and a failure says what happened to the connection.
//
// A connection on which the queue has not moved off 0 bytes for the
// patience of its attempt is closed and the fill starts again on a new one,
// up to three: on a loaded host the kernel can stall both ends of one, the
// requests unsent and icscf waiting to read them, before any answer is
// queued (QA of #434, #459). Each such stall is logged with the kernel's TCP
// drop counters, which are the network namespace's, not the connection's. A
// queue that stops once it holds bytes fails at once: icscf stopped
// answering, which is no precondition to retry.
func fillCoreQueue(t testing.TB, tr stats, dial func() (net.Conn, error), patience func(attempt int) time.Duration, writeTimeout time.Duration, logged func() []map[string]any) {
	t.Helper()
	full := transport.DefaultSendQueueBytes - 64<<10
	for attempt := 1; ; attempt++ {
		before := tcpDrops()
		nc, err := dial()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { nc.Close() })
		if tc, ok := nc.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(4096)
		}
		_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
		writeErr := make(chan error, 1)
		go fillWith(nc, tr, full, writeErr)
		last, lastAt := 0, time.Now()
		for tr.Stats().QueuedBytes < full {
			select {
			case err := <-writeErr:
				t.Fatalf("the requests stopped going out with %d bytes queued: %v; %+v; logged %v", tr.Stats().QueuedBytes, err, tr.Stats(), logged())
			default:
			}
			n := tr.Stats().QueuedBytes
			if n != last {
				last, lastAt = n, time.Now()
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if time.Since(lastAt) <= patience(attempt) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			if n != 0 || attempt == 3 {
				t.Fatalf("the core connection's send queue holds %d bytes, want %d, and has not changed for %v (attempt %d); %+v; kernel (namespace-wide) %v", n, full, patience(attempt), attempt, tr.Stats(), tcpDropsSince(before))
			}
			t.Logf("the fill made no progress for %v on connection %d; kernel (namespace-wide) %v; again on a new one", patience(attempt), attempt, tcpDropsSince(before))
			_ = nc.Close()
			<-writeErr // the filler ends with the connection
			break
		}
		if tr.Stats().QueuedBytes >= full {
			return
		}
	}
}

// every gives each attempt of fillCoreQueue the same patience.
func every(d time.Duration) func(int) time.Duration { return func(int) time.Duration { return d } }

// A first connection the kernel stalls, its writes blocked and nothing
// queued, does not fail the fill: it starts again on a new one (#459). The
// faked stall gets 5 s, the real connection after it the 30 s of the stop
// test, so a loaded host does not move the fill on to a third.
func TestTheFillStartsAgainOnAStalledConnection(t *testing.T) {
	hss := startHSS(t)
	scscf := startSCSCF(t)
	var tr *transport.Transport
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, d *deps) {
		d.writeTimeout = time.Minute
		d.transport = func(t *transport.Transport) { tr = t }
	})
	dials := 0
	fillCoreQueue(t, tr, func() (net.Conn, error) {
		dials++
		nc, err := net.Dial("tcp", r.core.String())
		if err != nil || dials > 1 {
			return nc, err
		}
		return &stalledConn{Conn: nc, closed: make(chan struct{})}, nil
	}, func(attempt int) time.Duration {
		if attempt == 1 {
			return 5 * time.Second
		}
		return 30 * time.Second
	}, time.Minute, r.h.Records)
	if dials != 2 {
		t.Errorf("filled after %d connections, want 2", dials)
	}
}

// stalledConn is a connection whose writes block until it is closed, as
// when the kernel moves nothing.
type stalledConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *stalledConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stalledConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// stats is what fillCoreQueue reads of the transport.
type stats interface{ Stats() transport.Stats }

// heldQueue is a transport whose send queue holds 100 bytes and never
// moves, as when icscf stops answering partway through a fill.
type heldQueue struct{}

func (heldQueue) Stats() transport.Stats { return transport.Stats{QueuedBytes: 100} }

// A queue that stops once it holds bytes fails the fill on that connection,
// with no new one (code review of #470): the retry is for a connection the
// kernel stalled before any answer was queued, not for icscf stopping.
func TestTheFillDoesNotStartAgainOnceTheQueueHoldsBytes(t *testing.T) {
	dials := 0
	ft := &fatalRecorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fillCoreQueue(ft, heldQueue{}, func() (net.Conn, error) {
			dials++
			near, far := net.Pipe()
			go func() { _, _ = io.Copy(io.Discard, far) }()
			t.Cleanup(func() { far.Close() })
			return near, nil
		}, every(100*time.Millisecond), time.Minute, func() []map[string]any { return nil })
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second): // a hang guard; the patience is 100 ms
		t.Fatal("the fill neither failed nor finished on a queue that never moves")
	}
	if !strings.Contains(ft.fatal, "holds 100 bytes") || dials != 1 {
		t.Errorf("after %d connections the fill failed with %q, want a stall on the first", dials, ft.fatal)
	}
}

// fatalRecorder is t, but records its first Fatal and ends the goroutine
// instead of the test, so that a test can check a helper fails.
type fatalRecorder struct {
	testing.TB
	fatal string
}

func (r *fatalRecorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (r *fatalRecorder) Fatal(args ...any) {
	r.fatal = fmt.Sprint(args...)
	runtime.Goexit()
}

// fillWith sends requests over nc, each answered 403 at once, until tr's
// queued bytes reach full, or until a write fails, which it sends on errs.
func fillWith(nc net.Conn, tr stats, full int, errs chan<- error) {
	// A Route to a host that is no S-CSCF is refused 403 at once, without the
	// HSS (#337); the 403 carries the request's long Via.
	pad := strings.Repeat("z", 3000)
	for i := 0; ; i++ {
		text := fmt.Sprintf("MESSAGE %s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s;branch=z9hG4bK-stall-%d;p=%s\r\n"+
			"Max-Forwards: 70\r\nRoute: <sip:192.0.2.66:5060;transport=tcp;lr>\r\n"+
			"To: <%s>\r\nFrom: <sip:+15550100002@%s>;tag=f1\r\n"+
			"Call-ID: icscf-stall-%d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n",
			tel1, nc.LocalAddr(), i, pad, tel1, home, i)
		if _, err := io.WriteString(nc, text); err != nil {
			errs <- err
			return
		}
		// Stop once the queue is full: the requests still on their way
		// keep senders waiting for room in it, and more would pile up
		// answers the transaction caps send without waiting, which
		// overflow the queue and close the connection.
		if tr.Stats().QueuedBytes >= full {
			return
		}
	}
}

// tcpDrops reads the kernel's counters of TCP segments dropped for want of
// receive or backlog room, which a stalled fill points to.
func tcpDrops() map[string]int64 {
	b, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(b), "\n")
	out := map[string]int64{}
	for i := 0; i+1 < len(lines); i += 2 {
		names, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		if len(names) == 0 || names[0] != "TcpExt:" || len(values) != len(names) {
			continue
		}
		for k, name := range names[1:] {
			switch name {
			case "TCPBacklogDrop", "TCPRcvQDrop", "PruneCalled", "RcvPruned", "TCPZeroWindowDrop", "TCPMemoryPressures":
				n, _ := strconv.ParseInt(values[k+1], 10, 64)
				out[name] = n
			}
		}
	}
	return out
}

// tcpDropsSince returns how far each counter of tcpDrops moved from before.
func tcpDropsSince(before map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range tcpDrops() {
		out[k] = v - before[k]
	}
	return out
}
