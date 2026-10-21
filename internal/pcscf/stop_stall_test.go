package pcscf

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// #323, from QA's probe on #293: a core peer that stops reading leaves
// responses in its connection's send queue, and senders waiting for room in
// it. The stop closes the connections instead of waiting for those writes:
// none of them fails on its WriteTimeout, which is set long here so that
// filling the queue on a loaded host cannot trip it either (review of #366).
// TestTheStopWaitsFitTheMargin checks the stop's own waits against the
// margin.
func TestAStopDoesNotWaitOnACorePeerThatStoppedReading(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.DrainTimeout = 200 * time.Millisecond
	const writeTimeout = time.Minute
	var pc *pcscf
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }, writeTimeout: writeTimeout})
	tr := pc.flows.(*transport.Transport)
	core := dial(t, s.core, nil)
	if tc, ok := core.nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	// Requests for a flow that does not exist are answered 430 at once. They
	// are sent until the stop closes the connection, so the queue stays full
	// and senders wait for room in it.
	pad := strings.Repeat("z", 3000)
	_ = core.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	go func() {
		for i := 0; ; i++ {
			text := coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("stall-%d", i), "", 1, "X-Pad: "+pad)
			// The answer carries the Via, so a long one makes it large.
			text = strings.Replace(text, "\r\nMax-Forwards", ";p="+pad+"\r\nMax-Forwards", 1)
			if _, err := io.WriteString(core.nc, text); err != nil {
				return
			}
		}
	}()
	// Full: no further 430 fits, whatever its size.
	full := transport.DefaultSendQueueBytes - 64<<10
	for deadline := time.Now().Add(writeTimeout / 2); tr.Stats().QueuedBytes < full; {
		if time.Now().After(deadline) {
			t.Fatalf("the core connection's send queue holds %d bytes, want %d", tr.Stats().QueuedBytes, full)
		}
		time.Sleep(10 * time.Millisecond)
	}
	failed := tr.Stats().WriteErrors
	// Only a hang guard, past the write deadline so that a stop that waits
	// for it still returns and fails below: the stop's own waits take 4 s,
	// and a loaded host may stretch them.
	s.stopWithin(writeTimeout + 30*time.Second)
	if n := tr.Stats().WriteErrors - failed; n != 0 {
		t.Errorf("%d writes to the core peer failed on their deadline during the stop, which waited for them", n)
	}
	// Closing the proxy after the transport sends nothing and reports no
	// failure of its own.
	for _, r := range s.h.Records() {
		if r["level"] == "ERROR" || r["level"] == "WARN" {
			t.Errorf("logged at the stop: %v", r)
		}
	}
}
