package pcscf

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Each refusal is counted by its reason, in a metric of its own (#16 AC 6):
// a name from a fixed set, never anything of the client's.
func TestEachRefusalIsCountedByItsReason(t *testing.T) {
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	fresh := func() (*pcscf, *metricReader) {
		p, _ := newTestPcscf(clock)
		return p, runtimeHarnessMetrics(t, p)
	}
	register := func(p *pcscf, flow transport.FlowID, text string) proxy.Decision {
		return p.Route(context.Background(), clientRequest(t, text, flow))
	}
	for _, tt := range []struct {
		metric string
		run    func(t *testing.T, p *pcscf)
	}{
		{metricRegisterRate, func(t *testing.T, p *pcscf) {
			p.registers = newLimiter(1, 1, clock.now)
			register(p, "F", registerText(outboundContact))
			register(p, "F", registerText(outboundContact))
		}},
		{metricRegisterMalformed, func(t *testing.T, p *pcscf) {
			register(p, "F", strings.Replace(registerText(outboundContact), "To: <"+aliceIMPU+">", "To: <<", 1))
		}},
		{metricRegisterPending, func(t *testing.T, p *pcscf) {
			p.registry.perClient = 1
			register(p, "F1", registerText(outboundContact))
			register(p, "F2", registerText(outboundContact))
		}},
		{metricRegisterFull, func(t *testing.T, p *pcscf) {
			p.registry = newRegistry(1, clock.now)
			d := register(p, "F1", registerText(outboundContact))
			d.OnResponse(context.Background(), parseResponse(t, okText(outboundContact+";expires=3600")))
			register(p, "F2", registerText(outboundContact))
		}},
		{metricRegisterNoICSCF, func(t *testing.T, p *pcscf) {
			p.icscfs = icscfAt(nil)
			register(p, "F", registerText(outboundContact))
		}},
		{metricRequestRate, func(t *testing.T, p *pcscf) {
			registerAlice(t, p, "FLOW-A", "Service-Route: "+scscfRoute)
			p.initials = newLimiter(1, 1, clock.now)
			p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A"))
			p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A"))
		}},
		{metricRequestNoRoute, func(t *testing.T, p *pcscf) {
			registerAlice(t, p, "FLOW-A")
			p.Route(context.Background(), clientRequest(t, initialText("MESSAGE"), "FLOW-A"))
		}},
		{metricInDialogRate, func(t *testing.T, p *pcscf) {
			p.initials = newLimiter(1, 1, clock.now)
			for range 2 {
				p.Route(context.Background(), inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
			}
		}},
		{metricInDialogRoute, func(t *testing.T, p *pcscf) {
			p.Route(context.Background(), inDialogFrom(t, []string{clientEnt}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
		}},
		{metricInDialogUnresolved, func(t *testing.T, p *pcscf) {
			p.resolve = coreResolver{dns: &proxy.DNSResolver{Namespace: p.cfg.Namespace, Allow: allowCore(p.cfg), Logger: p.log,
				Lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, &net.DNSError{Err: "i/o timeout", Name: "scscf.rcs.internal", IsTimeout: true}
				}}}
			p.Route(context.Background(), inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
		}},
		{metricTerminatingFlow, func(t *testing.T, p *pcscf) {
			p.Route(context.Background(), fromCore(t, "INVITE", false, []string{"sip:OLD-TOKEN@10.0.2.9:5070;transport=tcp;lr"}))
		}},
		{metricTerminatingRoute, func(t *testing.T, p *pcscf) {
			p.clientFlow = func(id transport.FlowID) bool { return id == "FLOW-A" }
			p.Route(context.Background(), fromCore(t, "BYE", true, []string{pathEntry, "sip:" + publicHost + ":5060;transport=tcp;lr"}))
		}},
	} {
		t.Run(tt.metric, func(t *testing.T) {
			p, m := fresh()
			tt.run(t, p)
			if !m.count(tt.metric, 1) {
				t.Errorf("not counted once:\n%s", m.out.String())
			}
		})
	}
}

// A flow refused past the total or past its client's share is counted by
// which.
func TestARefusedFlowIsCountedByItsLimit(t *testing.T) {
	f := newFlows(2, 1)
	var got []string
	f.refused = func(metric string) { got = append(got, metric) }
	info := func(addr string) transport.FlowInfo {
		return transport.FlowInfo{Listener: clientListener, Addr: netip.MustParseAddrPort(addr)}
	}
	f.admit("A", info("192.0.2.10:1"))
	f.admit("B", info("192.0.2.10:2"))
	f.admit("C", info("192.0.2.11:1"))
	f.admit("D", info("192.0.2.12:1"))
	if strings.Join(got, ",") != metricFlowsRefusedPerAddr+","+metricFlowsRefusedTotal || f.size() != 2 {
		t.Errorf("refused %q, %d flows", got, f.size())
	}
}

// The transport's queue counters and the transaction layer's go out under
// the names infra/platform.yaml's alarms read (#56, #170): gauges as they
// are, counts as the change since the last sweep.
func TestTheLayersCountersGoOutUnderTheAlarmsNames(t *testing.T) {
	var out strings.Builder
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	m := runtime.NewMetrics(&out, "RCS", "pcscf", clock.now, nil)
	var lm layerMetrics
	lm.record(m, transport.Stats{QueuedBytes: 10, BudgetSheds: 2, BudgetRefusals: 3, ResponseFlowCloses: 1},
		transaction.Stats{ServerTransactionBytes: 7, ServerTransactionsRejected: 4, RefusalAcksAbsorbed: 1})
	lm.record(m, transport.Stats{QueuedBytes: 20, BudgetSheds: 5, BudgetRefusals: 3, ResponseFlowCloses: 1},
		transaction.Stats{ServerTransactionBytes: 9, ServerTransactionsRejected: 6, RefusalAcksAbsorbed: 3})
	m.Flush()
	for _, want := range []string{`"QueuedBytes":20`, `"BudgetSheds":5`, `"BudgetRefusals":3`, `"ResponseFlowCloses":1`,
		`"ServerTransactionBytes":9`, `"ServerTransactionsRejected":6`, `"RefusalAcksAbsorbed":3`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, out.String())
		}
	}
	lm.record(nil, transport.Stats{}, transaction.Stats{})
}

// run's sweep reports the client flows and the registrations held, and the
// layers' counters.
func TestRunsSweepReportsFlowsAndRegistrations(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	h := runtimetest.New(t, "pcscf")
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	s := startWith(t, h, cfg, deps{sweep: 5 * time.Millisecond})
	if res := registerOver(t, dial(t, s.client, nil)); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	for _, name := range []string{metricFlows, metricRegistrations} {
		waitMetric(t, h, name, 1)
	}
	if _, ok := h.Metric("QueuedBytes"); !ok {
		t.Error("no QueuedBytes")
	}
}

// A stop records the layers' counters once more after the drain, so that
// what the last 30 s counted goes out with the runtime's last flush (#345
// code review 4): with a sweep that never runs, the counters still go out.
func TestAStopRecordsTheCountersOnceMore(t *testing.T) {
	h := runtimetest.New(t, "pcscf")
	s := startWith(t, h, testConfig(), deps{sweep: time.Hour})
	_ = dial(t, s.client, nil)
	s.stop()
	h.Runtime.Metrics.Flush()
	for _, name := range []string{"QueuedBytes", "ServerTransactionsRejected", metricFlows} {
		if _, ok := h.Metric(name); !ok {
			t.Errorf("no %s:\n%s", name, h.Output())
		}
	}
}

// waitMetric waits until a flush of h writes want for name; the sweep runs
// on its own clock.
func waitMetric(t *testing.T, h *runtimetest.Harness, name string, want float64) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for {
		for _, v := range h.MetricValues(name) {
			if v == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never %v:\n%s", name, want, h.Output())
		}
		time.Sleep(5 * time.Millisecond)
	}
}
