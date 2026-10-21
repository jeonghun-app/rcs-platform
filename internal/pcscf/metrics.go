package pcscf

import (
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The metrics pcscf exports (#16 AC 6; docs/pcscf.md lists them all). The
// only dimension is Service (runtime.Metrics): a reason is part of the
// name, from a fixed set, never an identity, an address or a flow.
const (
	// The refusals of a REGISTER, by reason.
	metricRegisterRate      = "register.refused.rate"
	metricRegisterPending   = "register.refused.pending"
	metricRegisterFull      = "register.refused.registry_full"
	metricRegisterMalformed = "register.refused.malformed"
	metricRegisterNoICSCF   = "register.refused.no_icscf"
	// The refusals of a client's request, outside a dialog and in one.
	metricRequestRate         = "requests.refused.rate"
	metricRequestNoRoute      = "requests.refused.no_service_route"
	metricInDialogRate        = "indialog.refused.rate"
	metricInDialogRoute       = "indialog.refused.route"
	metricInDialogUnresolved  = "indialog.refused.unresolved"
	metricTerminatingFlow     = "terminating.flow_failed"
	metricTerminatingRoute    = "terminating.refused.route"
	metricFlowsRefusedTotal   = "flows.refused.total"
	metricFlowsRefusedPerAddr = "flows.refused.per_client"
	// Gauges, every sweep.
	metricFlows         = "flows.client"
	metricRegistrations = "registrations"
)

// layerMetrics exports the transport's queue counters and the transaction
// layer's, under the names their Stats fields have, which the alarms of
// infra/platform.yaml read (#56, #170): QueuedBytes and
// ServerTransactionBytes as gauges, BudgetSheds, BudgetRefusals,
// ResponseFlowCloses and ServerTransactionsRejected as counts since the
// last sweep.
type layerMetrics struct {
	transport   transport.Stats
	transaction transaction.Stats
}

func (lm *layerMetrics) record(m *runtime.Metrics, ts transport.Stats, xs transaction.Stats) {
	if m == nil {
		return
	}
	m.Gauge("QueuedBytes", int64(ts.QueuedBytes))
	m.Count("BudgetSheds", int64(ts.BudgetSheds-lm.transport.BudgetSheds))
	m.Count("BudgetRefusals", int64(ts.BudgetRefusals-lm.transport.BudgetRefusals))
	m.Count("ResponseFlowCloses", int64(ts.ResponseFlowCloses-lm.transport.ResponseFlowCloses))
	m.Gauge("ServerTransactionBytes", xs.ServerTransactionBytes)
	m.Count("ServerTransactionsRejected", int64(xs.ServerTransactionsRejected-lm.transaction.ServerTransactionsRejected))
	lm.transport, lm.transaction = ts, xs
}
