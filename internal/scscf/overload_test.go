package scscf

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// unchallenged is a first REGISTER's Authorization, before any challenge.
var unchallenged = fmt.Sprintf(`Digest username="%s", realm="%s", nonce="", uri="sip:%s", response=""`, impi, realm, realm)

// scscf exports one overload counter, sip.overloaded, for #56's alarm, as
// icscf and pcscf do (#467): a request the transaction layer refuses at its
// byte cap and one the proxy refuses at its own, which charges a header
// twice, are both counted.
func TestEveryOverloadRefusalIsCountedAsSipOverloaded(t *testing.T) {
	for name, tt := range map[string]struct {
		capBytes int64
		pad      int
		layer    bool // the layer refuses, not the proxy
	}{
		"the layer's cap": {capBytes: 64, layer: true},
		// The layer charges this REGISTER about 8.6 KB and admits it
		// below 14000; the proxy, the header twice, refuses it.
		"the proxy's bound": {capBytes: 14000, pad: 8000},
	} {
		t.Run(name, func(t *testing.T) {
			var px atomic.Pointer[proxy.Proxy]
			r := startSCSCFWith(t, startHSS(t), state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
				c.MaxServerTransactionBytes = tt.capBytes
				d.metricsEvery = time.Millisecond
				d.proxy = func(p *proxy.Proxy) { px.Store(p) }
			})
			path := "sip:flow-token@127.0.0.1:5070;transport=tcp;lr;ob"
			if tt.pad > 0 {
				path += ";pad=" + strings.Repeat("x", tt.pad)
			}
			if res := dialSCSCF(t, r).registerVia(t, unchallenged, path); res.StatusCode != 503 {
				t.Fatalf("REGISTER: %d, want 503", res.StatusCode)
			}
			if rejected, overloaded := px.Load().Layer().Stats().ServerTransactionsRejected, px.Load().Stats().Overloaded; (rejected == 1) != tt.layer || rejected+overloaded != 1 {
				t.Fatalf("layer refused %d, proxy %d; want the %s's", rejected, overloaded, map[bool]string{true: "layer", false: "proxy"}[tt.layer])
			}
			deadline := time.Now().Add(realWait)
			for {
				if v, ok := r.h.Metric(proxy.MetricOverloaded); ok {
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

// A refusal since the last record is counted at the stop, so the last
// minute before a task ends is not lost.
func TestTheLastOverloadIsCountedAtTheStop(t *testing.T) {
	r := startSCSCFWith(t, startHSS(t), state.NewMemory(), 1, func(c *ServiceConfig, d *deps) {
		c.MaxServerTransactionBytes = 64
		d.metricsEvery = time.Hour
	})
	if res := dialSCSCF(t, r).registerVia(t, unchallenged, "sip:flow-token@127.0.0.1:5070;transport=tcp;lr;ob"); res.StatusCode != 503 {
		t.Fatalf("REGISTER: %d, want 503", res.StatusCode)
	}
	if _, ok := r.h.Metric(proxy.MetricOverloaded); ok {
		t.Fatalf("%s written before the stop, with an hour between records", proxy.MetricOverloaded)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if v, ok := r.h.Metric(proxy.MetricOverloaded); !ok || v != 1 {
		t.Errorf("%s = %v (%v) after the stop, want 1", proxy.MetricOverloaded, v, ok)
	}
}
