package pcscf

// QA's tests on #345: the count sites the PR's tests did not reach (its
// six mutants), and the proxy's 430 for a flow that closes under a
// request, end to end (#293).

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// refusalMetrics are the per-reason counts this PR adds; a probe checks that
// the one it provokes moves by exactly 1 and the others stay at 0.
var refusalMetrics = []string{
	metricRegisterRate, metricRegisterPending, metricRegisterFull, metricRegisterMalformed, metricRegisterNoICSCF,
	metricRequestRate, metricRequestNoRoute, metricInDialogRate, metricInDialogRoute, metricInDialogUnresolved,
	metricTerminatingFlow, metricTerminatingRoute, metricFlowsRefusedTotal, metricFlowsRefusedPerAddr,
}

func qaCounts(t *testing.T, h *runtimetest.Harness) map[string]float64 {
	t.Helper()
	h.Runtime.Metrics.Flush()
	out := map[string]float64{}
	for _, rec := range h.Records() {
		if _, ok := rec["_aws"]; !ok {
			continue
		}
		for _, name := range refusalMetrics {
			if v, ok := rec[name].(float64); ok {
				out[name] += v
			}
		}
	}
	return out
}

func qaExpectOnly(t *testing.T, h *runtimetest.Harness, before map[string]float64, metric string) {
	t.Helper()
	after := qaCounts(t, h)
	for _, name := range refusalMetrics {
		want := before[name]
		if name == metric {
			want++
		}
		if after[name] != want {
			t.Errorf("%s: %v, want %v (provoking %s)", name, after[name], want, metric)
		}
	}
}

// The count sites TestEachRefusalIsCountedByItsReason does not reach.
func TestQAEveryRefusalSiteIsCounted(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{t: time.Unix(1_800_000_000, 0)}
	for _, tt := range []struct {
		name, metric string
		run          func(t *testing.T, p *pcscf)
	}{
		{"Bad Contact", metricRegisterMalformed, func(t *testing.T, p *pcscf) {
			p.Route(ctx, clientRequest(t, registerText("<<"), "F"))
		}},
		{"Bad Authorization", metricRegisterMalformed, func(t *testing.T, p *pcscf) {
			p.Route(ctx, clientRequest(t, registerText(outboundContact, "Authorization: Digest =,="), "F"))
		}},
		{"in-dialog to scscf's address", metricInDialogRoute, func(t *testing.T, p *pcscf) {
			p.Route(ctx, inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: <sip:10.0.4.4:5060;transport=tcp;lr>"))
		}},
		{"in-dialog scscf resolving to this task", metricInDialogRoute, func(t *testing.T, p *pcscf) {
			p.resolve = coreResolver{dns: &proxy.DNSResolver{Namespace: p.cfg.Namespace, Allow: allowCore(p.cfg), Logger: p.log,
				Lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr("::ffff:10.0.2.9")}, nil
				}}}
			p.Route(ctx, inDialogFrom(t, []string{clientEnt, coreEntry}, "sip:bob@198.51.100.20", "Route: "+scscfRoute))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, _ := newTestPcscf(clock)
			m := runtimeHarnessMetrics(t, p)
			tt.run(t, p)
			if !m.count(tt.metric, 1) {
				t.Errorf("not counted once:\n%s", m.out.String())
			}
		})
	}
}

// A 430 the proxy makes because the flow closed as the request went is
// counted once at OnFinal; one the client sent over its live flow, and
// another final response, are not (#345 QA minor 4).
func TestQAOnFinalCountsTheProxys430(t *testing.T) {
	ctx := context.Background()
	live := true
	p := newTerminatingPcscf(t)
	p.clientFlow = func(id transport.FlowID) bool { return id == "FLOW-A" && live }
	m := runtimeHarnessMetrics(t, p)
	d := p.Route(ctx, fromCore(t, "INVITE", false, []string{pathEntry}))
	r := fromCore(t, "INVITE", false, nil)
	d.OnFinal(ctx, answer(t, r.Message, 486))
	d.OnFinal(ctx, answer(t, r.Message, statusFlowFailed))
	if m.count(metricTerminatingFlow, 1) {
		t.Fatalf("a 486, or the client's own 430, counted:\n%s", m.out.String())
	}
	live = false
	d.OnFinal(ctx, answer(t, r.Message, statusFlowFailed))
	if !m.count(metricTerminatingFlow, 1) {
		t.Errorf("the proxy's 430 not counted:\n%s", m.out.String())
	}
}

// Gauges: two flows, one registration; the sweep must tell them apart.
func TestQAGaugesTellFlowsFromRegistrations(t *testing.T) {
	icscf := startCoreNode(t, echo200)
	cfg := testConfig()
	cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
	h := runtimetest.New(t, "pcscf")
	s := startWith(t, h, cfg, deps{lookup: icscfLookup("127.0.0.1"), sweep: 5 * time.Millisecond})
	_, _ = registered(t, s, icscf)
	other := dial(t, s.client, nil)
	if res := other.request(); res.StatusCode != 403 {
		t.Fatalf("%d", res.StatusCode)
	}
	waitMetric(t, h, metricFlows, 2)
	waitMetric(t, h, metricRegistrations, 1)
}

// On main + this PR (#293's FlowClosed): the proxy's 430 for a flow that
// closes under a request goes through terminate's OnFinal, and is counted.
func TestQAMergedAFlowClosingUnderARequestIsCounted(t *testing.T) {
	for _, method := range []string{"MESSAGE", "INVITE"} {
		t.Run(method, func(t *testing.T) {
			icscf := startCoreNode(t, echo200)
			cfg := testConfig()
			cfg.ICSCF = mustURI(t, "sip:"+icscf.ln.Addr().String()+";transport=tcp;lr")
			h := runtimetest.New(t, "pcscf")
			s := startWith(t, h, cfg, deps{lookup: icscfLookup("127.0.0.1")})
			c, path := registered(t, s, icscf)
			core := dial(t, s.core, nil)
			text := coreRequest(method, "sip:alice@192.0.2.10:40000;transport=tcp", fmt.Sprintf("qa-close-%d", requests.Add(1)), "", 1, "Route: <"+path+">")
			if method == "INVITE" {
				text = withAudioOffer(text)
			}
			core.write(text)
			_ = c.nextRequest()
			before := qaCounts(t, h)
			_ = c.nc.Close()
			if code, err := finalWithin(core); err != nil || code != 430 {
				t.Fatalf("%d %v", code, err)
			}
			qaExpectOnly(t, h, before, metricTerminatingFlow)
		})
	}
}
