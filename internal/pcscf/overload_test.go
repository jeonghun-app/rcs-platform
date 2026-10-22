package pcscf

import (
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// pcscf exports one overload counter, sip.overloaded, for #56's alarms
// (#467): a request the transaction layer refuses at its byte cap and one
// the proxy refuses at its own are both counted, on the sweep's record.
func TestEveryOverloadRefusalIsCountedAsSipOverloaded(t *testing.T) {
	for name, d := range map[string]deps{
		"the layer's cap":   {serverTransactionBytes: 64},
		"the proxy's bound": {contextBytes: 64},
	} {
		t.Run(name, func(t *testing.T) {
			d.sweep = time.Millisecond
			s := start(t, testConfig(), d)
			c := dial(t, s.client, nil)
			if res, err := c.tryWith(); err != nil || res.StatusCode != 503 {
				t.Fatalf("request: %v, %v; want 503", res, err)
			}
			deadline := time.Now().Add(waitFor)
			for {
				if v, ok := s.h.Metric(proxy.MetricOverloaded); ok {
					if v != 1 {
						t.Errorf("%s = %v, want 1", proxy.MetricOverloaded, v)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s never written", proxy.MetricOverloaded)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
