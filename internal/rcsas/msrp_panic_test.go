package rcsas

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

// panicOnceListener gives its first connection a Read that panics, as a
// bug in reading the peer's input would on the connection's goroutine.
type panicOnceListener struct {
	net.Listener
	n atomic.Int32
}

func (l *panicOnceListener) Accept() (net.Conn, error) {
	nc, err := l.Listener.Accept()
	if err == nil && l.n.Add(1) == 1 {
		return readPanics{nc}, nil
	}
	return nc, err
}

type readPanics struct{ net.Conn }

func (readPanics) Read([]byte) (int, error) { panic("msrp-secret read") }

// A panic on an MSRP connection's reading goroutine in rcs-as is counted in
// rcs-as's metrics as msrp.callback_panics, without its value, and rcs-as
// goes on serving: run gives the engine's MSRP its guard (QA of #471,
// which wrote this test).
func TestRcsAsCountsItsMSRPPanics(t *testing.T) {
	core := newCoreStub(t)
	cfg, err := configure(with(devEnv, "RCSAS_SIP_HOST", "127.0.0.1", "RCSAS_MSRP_HOST", "127.0.0.1",
		"RCSAS_CORE_URI", "sip:"+core.l.Addr().String()+";transport=tcp;lr"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SIPListenAddr = "127.0.0.1:0"
	ml, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := deps{}
	cfg.Messaging.MSRPPort, d.msrp = ml.Addr().(*net.TCPAddr).Port, &panicOnceListener{Listener: ml}
	h := runtimetest.New(t, "rcs-as")
	ctx, cancel := context.WithCancel(context.Background())
	listening := make(chan struct{}, 1)
	done := make(chan error, 1)
	d.store = store.NewMemory()
	d.groups = groupstore.NewMemory()
	d.listening = func(netip.AddrPort) { listening <- struct{}{} }
	go func() { done <- run(ctx, h.Runtime, cfg, d) }()
	defer func() { cancel(); <-done }()
	select {
	case <-listening:
	case <-time.After(waitFor):
		t.Fatal("not listening")
	}
	for i := range 2 {
		c, err := net.Dial("tcp", ml.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
	}
	deadline := time.Now().Add(waitFor)
	for {
		if v, ok := h.Metric(msrp.MetricCallbackPanics); ok {
			if v != 1 {
				t.Errorf("%s = %v", msrp.MetricCallbackPanics, v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never written", msrp.MetricCallbackPanics)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(h.Output(), "msrp-secret") {
		t.Error("output holds the value")
	}
	if !strings.Contains(h.Output(), "rcs-as: an MSRP callback panicked") {
		t.Errorf("no log line:\n%s", h.Output())
	}
}
