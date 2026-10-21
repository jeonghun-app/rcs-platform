package pcscf

import (
	"net/netip"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// flows tracks the client flows the transport admitted: how many there are,
// against MaxClientFlows, how many each client holds, against
// MaxFlowsPerIP, and which exist, for the drain. admit and closed are the
// transport's Admit and OnFlowClosed.
type flows struct {
	max, maxPerIP int
	// onClosed, if set, hears about every client flow that closed, and
	// refused, if set, every flow refused, by its metric.
	onClosed func(transport.FlowID)
	refused  func(metric string)

	mu    sync.Mutex
	perIP map[netip.Addr]int
	all   map[transport.FlowID]netip.Addr
}

func newFlows(maxFlows, maxPerIP int) *flows {
	return &flows{max: maxFlows, maxPerIP: maxPerIP, perIP: map[netip.Addr]int{}, all: map[transport.FlowID]netip.Addr{}}
}

// clientKey is what the per-client limit counts by: an IPv4 address, or the
// /64 of an IPv6 one, which a client may hold whole (as msrp-relay counts).
func clientKey(a netip.AddrPort) netip.Addr {
	ip := a.Addr().Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Addr()
	}
	return ip
}

// admit refuses a client flow beyond max in all, which keeps the
// transport's other connections for the core listener (review of #188), or
// beyond maxPerIP from one client. Core flows are not counted: security
// groups admit only platform services there (ADR 0007). It runs on the
// accepting goroutine and does not block.
func (f *flows) admit(id transport.FlowID, info transport.FlowInfo) bool {
	if !fromClient(transport.Source{Listener: info.Listener}) {
		return true
	}
	key := clientKey(info.Addr)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case len(f.all) >= f.max:
		f.refuse(metricFlowsRefusedTotal)
		return false
	case f.perIP[key] >= f.maxPerIP:
		f.refuse(metricFlowsRefusedPerAddr)
		return false
	}
	f.perIP[key]++
	f.all[id] = key
	return true
}

func (f *flows) refuse(metric string) {
	if f.refused != nil {
		f.refused(metric)
	}
}

// size is the number of client flows.
func (f *flows) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.all)
}

// closed forgets a flow that ended.
func (f *flows) closed(id transport.FlowID, _ transport.FlowInfo) {
	f.mu.Lock()
	key, ok := f.all[id]
	if ok {
		delete(f.all, id)
		if f.perIP[key]--; f.perIP[key] <= 0 {
			delete(f.perIP, key)
		}
	}
	f.mu.Unlock()
	if ok && f.onClosed != nil {
		f.onClosed(id)
	}
}

// ids returns the client flows open now.
func (f *flows) ids() []transport.FlowID {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]transport.FlowID, 0, len(f.all))
	for id := range f.all {
		out = append(out, id)
	}
	return out
}
