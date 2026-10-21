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

// A share is the bindings one client flow may hold and create for the
// offers of one side: the client's own, or coreOffer, those rcs-as makes
// toward it. The two are counted apart, so that offers coming in cannot
// keep a client from making its own (#315 code review 2, security review);
// only the task's total is shared.
type share struct {
	flow      transport.FlowID
	coreOffer bool
}

// shareLimits are the bindings a share may hold, and create in a minute.
type shareLimits struct {
	perFlow   int
	perMinute float64
}

// bindingLimit counts the relay bindings held for each share and in all,
// and the bindings each share creates, in a token bucket of perMinute that
// fills at perMinute a minute. Its methods are safe for concurrent use.
type bindingLimit struct {
	client, coreOffer shareLimits
	total             int
	now               func() time.Time

	mu      sync.Mutex
	byShare map[share]int
	created map[share]*bucket
	count   int
}

// newBindingLimit limits each share to perFlow bindings and perMinute
// created a minute, and the task to total; coreOfferShare sets other
// limits for rcs-as's offers.
func newBindingLimit(perFlow, total, perMinute int, now func() time.Time) *bindingLimit {
	sl := shareLimits{perFlow: perFlow, perMinute: float64(perMinute)}
	return &bindingLimit{client: sl, coreOffer: sl, total: total, now: now,
		byShare: map[share]int{}, created: map[share]*bucket{}}
}

// coreOfferShare limits the share of rcs-as's offers toward a flow to
// perFlow bindings and perMinute created a minute.
func (l *bindingLimit) coreOfferShare(perFlow, perMinute int) *bindingLimit {
	l.coreOffer = shareLimits{perFlow: perFlow, perMinute: float64(perMinute)}
	return l
}

func (l *bindingLimit) limitsOf(sh share) shareLimits {
	if sh.coreOffer {
		return l.coreOffer
	}
	return l.client
}

// most is the most bindings one offer, of rcs-as's or not, can ever take:
// more is refused as an offer, not as a wait (#248 code review 2).
func (l *bindingLimit) most(coreOffer bool) int {
	sl := l.limitsOf(share{coreOffer: coreOffer})
	return min(sl.perFlow, l.total, int(sl.perMinute))
}

// take takes n bindings for sh. It takes none and returns errBindingLimit
// if the share or the task would go past its limit, or errBindingRate and
// how long until the share may create n if it created too many of late.
func (l *bindingLimit) take(sh share, n int) (time.Duration, error) {
	t := l.now()
	sl := l.limitsOf(sh)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byShare[sh]+n > sl.perFlow || l.count+n > l.total {
		return 0, errBindingLimit
	}
	b := l.created[sh]
	if b == nil {
		b = &bucket{tokens: sl.perMinute, at: t}
		l.created[sh] = b
	}
	rate := sl.perMinute / 60
	b.tokens = min(sl.perMinute, b.tokens+t.Sub(b.at).Seconds()*rate)
	b.at = t
	if b.tokens < float64(n) {
		wait := math.Ceil((float64(n) - b.tokens) / rate)
		return time.Duration(wait) * time.Second, errBindingRate
	}
	b.tokens -= float64(n)
	l.byShare[sh] += n
	l.count += n
	return 0, nil
}

// give gives back n bindings of sh that take took.
func (l *bindingLimit) give(sh share, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n = min(n, l.byShare[sh])
	if l.byShare[sh] -= n; l.byShare[sh] <= 0 {
		delete(l.byShare, sh)
	}
	l.count -= n
}

// forget drops the creation counts of a flow that closed, of both its
// shares.
func (l *bindingLimit) forget(flow transport.FlowID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.created, share{flow: flow})
	delete(l.created, share{flow: flow, coreOffer: true})
}

// sweep drops the creation counts that have filled again, which carry no
// state, as a new one starts full: what forget missed, for a flow whose
// session was allocating as it closed.
func (l *bindingLimit) sweep() {
	t := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for sh, b := range l.created {
		perMinute := l.limitsOf(sh).perMinute
		if b.tokens+t.Sub(b.at).Seconds()*perMinute/60 >= perMinute {
			delete(l.created, sh)
		}
	}
}

// held returns the bindings held in all, the gauge that shows none leaks.
func (l *bindingLimit) held() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
