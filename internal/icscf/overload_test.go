package icscf

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// icscf exports one overload counter, sip.overloaded, for #56's alarm
// (#467): a request the transaction layer refuses at its byte cap and one
// the proxy refuses at its own, which charges a header twice, are both
// counted.
func TestEveryOverloadRefusalIsCountedAsSipOverloaded(t *testing.T) {
	for name, tt := range map[string]struct {
		capBytes int64
		pad      int
		layer    bool // the layer refuses, not the proxy
	}{
		"the layer's cap": {capBytes: 64, pad: 0, layer: true},
		// The layer charges this request about 4 KiB and admits it
		// below 8000; the proxy, the header twice, refuses it up to
		// about 16000.
		"the proxy's bound": {capBytes: 12000, pad: 4000, layer: false},
	} {
		t.Run(name, func(t *testing.T) {
			hss := startHSS(t)
			scscf := startSCSCF(t)
			hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
			var px atomic.Pointer[proxy.Proxy]
			r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, d *deps) {
				c.MaxServerTransactionBytes = tt.capBytes
				d.metricsEvery = time.Millisecond
				d.proxy = func(p *proxy.Proxy) { px.Store(p) }
			})
			r.waitReady(t)
			fields := []string{"From: <sip:+15550100002@" + home + ">;tag=f1", "To: <" + tel1 + ">"}
			if tt.pad > 0 {
				fields = append(fields, "X-Pad: "+strings.Repeat("x", tt.pad))
			}
			if res := r.send(t, "MESSAGE", tel1, fields...); res.StatusCode != 503 {
				t.Fatalf("MESSAGE: %d, want 503", res.StatusCode)
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
	hss := startHSS(t)
	scscf := startSCSCF(t)
	hss.answer = func(uint32) (cx.Result, string) { return cx.ResultCode(diameter.ResultSuccess), scscf.uri() }
	r := startICSCF(t, hss, []SCSCF{{URI: mustURI(scscf.uri())}}, func(c *ServiceConfig, d *deps) {
		c.MaxServerTransactionBytes = 64
		d.metricsEvery = time.Hour
	})
	r.waitReady(t)
	if res := r.send(t, "MESSAGE", tel1, "From: <sip:+15550100002@"+home+">;tag=f1", "To: <"+tel1+">"); res.StatusCode != 503 {
		t.Fatalf("MESSAGE: %d, want 503", res.StatusCode)
	}
	if _, ok := r.h.Metric(proxy.MetricOverloaded); ok {
		t.Fatalf("%s written before the stop, with an hour between records", proxy.MetricOverloaded)
	}
	r.stop()
	if v, ok := r.h.Metric(proxy.MetricOverloaded); !ok || v != 1 {
		t.Errorf("%s = %v (%v) after the stop, want 1", proxy.MetricOverloaded, v, ok)
	}
}
