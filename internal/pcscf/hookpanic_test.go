package pcscf

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// panicOnceRouter panics on its first request, quoting the message, and
// refuses the next ones with 403.
type panicOnceRouter struct{ n atomic.Int64 }

func (r *panicOnceRouter) Route(_ context.Context, req *proxy.Request) proxy.Decision {
	if r.n.Add(1) == 1 {
		panic("hook-secret " + req.Message.Header.Get("From"))
	}
	return proxy.Decision{Status: 403}
}

// pcscf gives its proxy its metrics (#428, QA of #436): a Router that
// panics gets the request a 500, the next request is served, and
// proxy.hook_panics reaches the service's metrics, without the message in
// the output.
func TestAHookPanicIsCountedInPcscfsMetrics(t *testing.T) {
	s := start(t, testConfig(), deps{router: &panicOnceRouter{}})
	c := dial(t, s.client, nil)
	if res, err := c.tryWith(); err != nil || res.StatusCode != 500 {
		t.Fatalf("first request: %v, %v; want 500", res, err)
	}
	if res, err := c.tryWith(); err != nil || res.StatusCode != 403 {
		t.Fatalf("next request: %v, %v; want the Router's 403", res, err)
	}
	// The metrics are flushed on their own schedule.
	deadline := time.Now().Add(waitFor)
	for {
		if v, ok := s.h.Metric(proxy.MetricHookPanics); ok {
			if v != 1 {
				t.Errorf("%s = %v, want 1", proxy.MetricHookPanics, v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never written", proxy.MetricHookPanics)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, secret := range []string{"hook-secret", "15550100001", "3gppnetwork"} {
		if strings.Contains(s.h.Output(), secret) {
			t.Errorf("the output holds %q", secret)
		}
	}
}
