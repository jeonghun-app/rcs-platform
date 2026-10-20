package pcscf

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// errBindingLimit refuses a session whose MSRP lines would take a flow or
// the task past its relay bindings: each costs the relay a table item and
// a session id, so a client must not be able to make pcscf allocate them
// without bound (#136). errBindingRate refuses one whose flow has created
// too many in the last minute: the concurrent limit alone lets a client
// that cancels at once drive the relay's writes at its INVITE rate (#248
// security review). Either is answered 503 with Retry-After.
var (
	errBindingLimit = errors.New("pcscf: too many MSRP bindings")
	errBindingRate  = errors.New("pcscf: MSRP bindings created too fast")
)

// bindingLimit counts the relay bindings held for each flow and in all,
// and the bindings each flow creates, in a token bucket of perMinute that
// fills at perMinute a minute. Its methods are safe for concurrent use.
type bindingLimit struct {
	perFlow, total int
	perMinute      float64
	now            func() time.Time

	mu      sync.Mutex
	byFlow  map[transport.FlowID]int
	created map[transport.FlowID]*bucket
	count   int
}

func newBindingLimit(perFlow, total, perMinute int, now func() time.Time) *bindingLimit {
	return &bindingLimit{perFlow: perFlow, total: total, perMinute: float64(perMinute), now: now,
		byFlow: map[transport.FlowID]int{}, created: map[transport.FlowID]*bucket{}}
}

// most is the most bindings one session can ever take: more is refused as
// an offer, not as a wait (#248 code review 2).
func (l *bindingLimit) most() int {
	return min(l.perFlow, l.total, int(l.perMinute))
}

// take takes n bindings for flow. It takes none and returns errBindingLimit
// if the flow or the task would go past its limit, or errBindingRate and
// how long until the flow may create n if it created too many of late.
func (l *bindingLimit) take(flow transport.FlowID, n int) (time.Duration, error) {
	t := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byFlow[flow]+n > l.perFlow || l.count+n > l.total {
		return 0, errBindingLimit
	}
	b := l.created[flow]
	if b == nil {
		b = &bucket{tokens: l.perMinute, at: t}
		l.created[flow] = b
	}
	rate := l.perMinute / 60
	b.tokens = min(l.perMinute, b.tokens+t.Sub(b.at).Seconds()*rate)
	b.at = t
	if b.tokens < float64(n) {
		wait := math.Ceil((float64(n) - b.tokens) / rate)
		return time.Duration(wait) * time.Second, errBindingRate
	}
	b.tokens -= float64(n)
	l.byFlow[flow] += n
	l.count += n
	return 0, nil
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

// forget drops the creation count of a flow that closed.
func (l *bindingLimit) forget(flow transport.FlowID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.created, flow)
}

// sweep drops the creation counts that have filled again, which carry no
// state, as a new one starts full: what forget missed, for a flow whose
// session was allocating as it closed.
func (l *bindingLimit) sweep() {
	t := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for flow, b := range l.created {
		if b.tokens+t.Sub(b.at).Seconds()*l.perMinute/60 >= l.perMinute {
			delete(l.created, flow)
		}
	}
}

// held returns the bindings held in all, the gauge that shows none leaks.
func (l *bindingLimit) held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
