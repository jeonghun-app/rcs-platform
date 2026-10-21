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
// it. The stop still ends inside the stop margin after the drain, rather than
// waiting out the transport's WriteTimeout.
func TestAStopWithACorePeerThatStoppedReadingStaysInsideTheMargin(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	cfg.DrainTimeout = 200 * time.Millisecond
	var pc *pcscf
	s := start(t, cfg, deps{lookup: icscfLookup("127.0.0.1"), started: func(p *pcscf) { pc = p }})
	tr := pc.flows.(*transport.Transport)
	core := dial(t, s.core, nil)
	if tc, ok := core.nc.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4096)
	}
	// Requests for a flow that does not exist are answered 430 at once.
	pad := strings.Repeat("z", 3000)
	_ = core.nc.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for i := range 6000 {
		text := coreRequest("MESSAGE", "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("stall-%d", i), "", 1, "X-Pad: "+pad)
		// The answer carries the Via, so a long one makes it large.
		text = strings.Replace(text, "\r\nMax-Forwards", ";p="+pad+"\r\nMax-Forwards", 1)
		if _, err := io.WriteString(core.nc, text); err != nil {
			break // pcscf has stopped reading too; its queue is full
		}
	}
	for deadline := time.Now().Add(waitFor); tr.Stats().QueuedBytes == 0; {
		if time.Now().After(deadline) {
			t.Fatal("the core connection's send queue never filled")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	s.stop()
	if took := time.Since(start); took > cfg.DrainTimeout+stopMargin {
		t.Errorf("the stop took %v with a core peer that does not read, past the drain and the %v margin", took, stopMargin)
	}
	// Closing the proxy after the transport sends nothing and reports no
	// failure of its own.
	for _, r := range s.h.Records() {
		if r["level"] == "ERROR" || r["level"] == "WARN" {
			t.Errorf("logged at the stop: %v", r)
		}
	}
}
