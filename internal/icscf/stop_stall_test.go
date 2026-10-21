package icscf

import (
	"fmt"
	"io"
	"net"
	"strings"
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
	nc, err := net.Dial("tcp", r.core.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	if tc, ok := nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	// A Route to a host that is no S-CSCF is refused 403 at once, without the
	// HSS (#337); the 403 carries the request's long Via.
	pad := strings.Repeat("z", 3000)
	writeErr := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			text := fmt.Sprintf("MESSAGE %s SIP/2.0\r\n"+
				"Via: SIP/2.0/TCP %s;branch=z9hG4bK-stall-%d;p=%s\r\n"+
				"Max-Forwards: 70\r\nRoute: <sip:192.0.2.66:5060;transport=tcp;lr>\r\n"+
				"To: <%s>\r\nFrom: <sip:+15550100002@%s>;tag=f1\r\n"+
				"Call-ID: icscf-stall-%d\r\nCSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n",
				tel1, nc.LocalAddr(), i, pad, tel1, home, i)
			if _, err := io.WriteString(nc, text); err != nil {
				writeErr <- err
				return
			}
			// Stop once the queue is full: the requests still on their
			// way keep senders waiting for room in it, and more would
			// pile up answers the transaction caps send without waiting,
			// which overflow the queue and close the connection.
			if tr.Stats().QueuedBytes >= transport.DefaultSendQueueBytes-64<<10 {
				return
			}
		}
	}()
	// Full: no further 403 fits, whatever its size. The fill is judged by
	// progress, and a failure says what happened to the connection.
	full := transport.DefaultSendQueueBytes - 64<<10
	last, lastAt := 0, time.Now()
	for tr.Stats().QueuedBytes < full {
		select {
		case err := <-writeErr:
			t.Fatalf("the requests stopped going out with %d bytes queued: %v; %+v; logged %v", tr.Stats().QueuedBytes, err, tr.Stats(), r.h.Records())
		default:
		}
		if n := tr.Stats().QueuedBytes; n != last {
			last, lastAt = n, time.Now()
		} else if time.Since(lastAt) > 30*time.Second {
			t.Fatalf("the core connection's send queue holds %d bytes, want %d, and has not changed for 30 s; %+v", n, full, tr.Stats())
		}
		time.Sleep(10 * time.Millisecond)
	}
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
