package proxy

import (
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// OverloadMeter counts what the proxy refused since the last Record, once:
// none when nothing more was refused, and each new refusal on the next
// Record (#467).
func TestTheOverloadMeterCountsEachRefusalOnce(t *testing.T) {
	m := &countingMetrics{}
	h := newHarness(t, Config{MaxContextBytes: 64})
	var om OverloadMeter
	om.Record(m, h.p)
	if n := m.count(MetricOverloaded); n != 0 {
		t.Fatalf("%s = %d before any refusal", MetricOverloaded, n)
	}
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	check(t, "upstream", h.upstream(), codes(503))
	om.Record(m, h.p)
	om.Record(m, h.p)
	if n := m.count(MetricOverloaded); n != 1 {
		t.Fatalf("%s = %d after one refusal recorded twice, want 1", MetricOverloaded, n)
	}
	h.receive(request(t, "MESSAGE", "sip:bob@example.com", "Via: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKup-2", "Call-ID: call-2@192.0.2.10"))
	om.Record(m, h.p)
	if n := m.count(MetricOverloaded); n != 2 {
		t.Fatalf("%s = %d after a second refusal, want 2", MetricOverloaded, n)
	}
	if got := h.p.Overloaded(); got != 2 {
		t.Errorf("Overloaded = %d, want 2", got)
	}
}

// The layer's refusals at its caps count too.
func TestOverloadedCountsTheLayersRefusals(t *testing.T) {
	m := &countingMetrics{}
	h := newHarness(t, Config{Transaction: transaction.Config{MaxServerTransactionBytes: 64}})
	h.receive(request(t, "MESSAGE", "sip:bob@example.com"))
	check(t, "upstream", h.upstream(), codes(503))
	if n := h.p.Layer().Stats().ServerTransactionsRejected; n != 1 {
		t.Fatalf("the layer refused %d, want 1", n)
	}
	var om OverloadMeter
	om.Record(m, h.p)
	if n := m.count(MetricOverloaded); n != 1 {
		t.Fatalf("%s = %d after the layer's refusal, want 1", MetricOverloaded, n)
	}
}
