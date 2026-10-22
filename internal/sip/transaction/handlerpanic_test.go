package transaction

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

type lockedLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type panicCounts struct {
	mu sync.Mutex
	n  map[string]int64
}

func (c *panicCounts) Count(name string, n int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int64{}
	}
	c.n[name] += n
}

// A response handler that panics ends only that call (#445): the calls
// after it still come, so the TU still hears how the transaction ended,
// and the panic is counted and logged without the response in it.
func TestAPanicInAResponseHandlerEndsOnlyThatCall(t *testing.T) {
	var logs lockedLog
	counts := &panicCounts{}
	h := newHarness(t, transport.TCP, Config{Logger: slog.New(slog.NewTextHandler(&logs, nil)), Metrics: counts})
	var got []string
	tx, err := h.layer.Request(request(t, "INVITE", "z9hG4bKp1"), transport.Destination{Network: transport.TCP}, func(res *sip.Response, err error) {
		if res != nil {
			got = append(got, label(res))
			if res.StatusCode == 180 {
				panic("handler-secret " + res.Header.Get("From"))
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(response(t, tx.Request(), 180))
	h.receive(response(t, tx.Request(), 486))
	check(t, "handler calls", got, []string{"180", "486"})
	if n := h.layer.Stats().HandlerPanics; n != 1 {
		t.Errorf("HandlerPanics = %d, want 1", n)
	}
	if n := counts.n[MetricHandlerPanics]; n != 1 {
		t.Errorf("%s = %d, want 1", MetricHandlerPanics, n)
	}
	out := logs.String()
	if !strings.Contains(out, "hook=ResponseHandler") {
		t.Errorf("the log does not name the handler:\n%s", out)
	}
	if strings.Contains(out, "handler-secret") || strings.Contains(out, "alice@") {
		t.Errorf("the log holds the panic's value:\n%s", out)
	}
}
