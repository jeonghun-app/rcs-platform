package proxy

import "sync"

// MetricOverloaded is the one counter a CSCF exports for the requests it
// refused as overloaded, whichever bound refused them (#467): the
// transaction layer at its caps (transaction.Stats.ServerTransactionsRejected)
// and the proxy at MaxContexts or MaxContextBytes (Stats.Overloaded). The
// infra alarms read it by this name.
const MetricOverloaded = "sip.overloaded"

// Overloaded returns the requests refused as overloaded since New, by the
// layer and by the proxy, and the branches the proxy refused for its memory
// bound.
func (p *Proxy) Overloaded() uint64 {
	return p.stats.overloaded.Load() + p.layer.Stats().ServerTransactionsRejected
}

// OverloadMeter counts the increase of a proxy's Overloaded as
// MetricOverloaded, each time a service records it: on its metrics
// schedule, and once more at the stop.
type OverloadMeter struct {
	mu   sync.Mutex
	last uint64
}

// Record counts what p refused since the last Record.
func (o *OverloadMeter) Record(m Metrics, p *Proxy) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := p.Overloaded()
	if n > o.last && m != nil {
		m.Count(MetricOverloaded, int64(n-o.last))
	}
	o.last = n
}
