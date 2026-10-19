package pcscf

import (
	"net/netip"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// flows tracks the client flows the transport admitted: how many each client
// address holds, against MaxFlowsPerIP, and which exist, for the drain.
// admit and closed are the transport's Admit and OnFlowClosed.
type flows struct {
	max int

	mu    sync.Mutex
	perIP map[netip.Addr]int
	all   map[transport.FlowID]netip.Addr
	// refused counts flows admit turned away.
	refused uint64
}

func newFlows(maxPerIP int) *flows {
	return &flows{max: maxPerIP, perIP: map[netip.Addr]int{}, all: map[transport.FlowID]netip.Addr{}}
}

// admit refuses a client flow beyond max from one address. Core flows are
// not counted: security groups admit only platform services there (ADR
// 0007). It runs on the accepting goroutine and does not block.
func (f *flows) admit(id transport.FlowID, info transport.FlowInfo) bool {
	if !fromClient(transport.Source{Listener: info.Listener}) {
		return true
	}
	ip := info.Addr.Addr().Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perIP[ip] >= f.max {
		f.refused++
		return false
	}
	f.perIP[ip]++
	f.all[id] = ip
	return true
}

// closed forgets a flow that ended.
func (f *flows) closed(id transport.FlowID, _ transport.FlowInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.all[id]
	if !ok {
		return
	}
	delete(f.all, id)
	if f.perIP[ip]--; f.perIP[ip] <= 0 {
		delete(f.perIP, ip)
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

// count returns the client flows open now and the flows refused so far.
func (f *flows) count() (open int, refused uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.all), f.refused
}
