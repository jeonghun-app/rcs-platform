package pcscf

import (
	"errors"
	"sync"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// errBindingLimit refuses a session whose MSRP lines would take a flow or
// the task past its relay bindings: each costs the relay a table item and
// a session id, so a client must not be able to make pcscf allocate them
// without bound (#136). The session is answered 503 with Retry-After.
var errBindingLimit = errors.New("pcscf: too many MSRP bindings")

// bindingLimit counts the relay bindings held for each flow and in all.
// Its methods are safe for concurrent use.
type bindingLimit struct {
	perFlow, total int

	mu     sync.Mutex
	byFlow map[transport.FlowID]int
	count  int
}

func newBindingLimit(perFlow, total int) *bindingLimit {
	return &bindingLimit{perFlow: perFlow, total: total, byFlow: map[transport.FlowID]int{}}
}

// take takes n bindings for flow, or none and errBindingLimit if the flow
// or the task would go past its limit.
func (l *bindingLimit) take(flow transport.FlowID, n int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byFlow[flow]+n > l.perFlow || l.count+n > l.total {
		return errBindingLimit
	}
	l.byFlow[flow] += n
	l.count += n
	return nil
}

// give gives back n bindings of flow that take took.
func (l *bindingLimit) give(flow transport.FlowID, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, l.byFlow[flow])
	if l.byFlow[flow] -= n; l.byFlow[flow] <= 0 {
		delete(l.byFlow, flow)
	}
	l.count -= n
}

// held returns the bindings held in all, the gauge that shows none leaks.
func (l *bindingLimit) held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
