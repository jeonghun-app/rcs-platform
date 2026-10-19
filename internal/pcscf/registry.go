package pcscf

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// errRegistryFull refuses a registration beyond PCSCF_MAX_REGISTRATIONS.
var errRegistryFull = errors.New("pcscf: registry full")

// registration is what pcscf keeps of a public identity registered over a
// flow (TS 24.229 §5.2.2.1): the 200 to its REGISTER told it the
// Service-Route to preload on the client's requests (RFC 3608) and the
// identities it may assert (P-Associated-URI, RFC 7315).
type registration struct {
	flow transport.FlowID
	// uri is the registered public identity, the To of the REGISTER, and
	// aor the same as aorKey writes it.
	uri sip.URI
	aor string
	// contacts are the client's contacts on this flow, as the 200 listed
	// them.
	contacts []sip.Contact
	// serviceRoute and associated are the 200's Service-Route and
	// P-Associated-URI; the first associated URI is the default public
	// identity (RFC 7315 §4.1).
	serviceRoute []sip.Address
	associated   []sip.Address
	// outbound says the client registered with RFC 5626 outbound, and
	// keepAlive that it keeps the flow alive (outbound or Via keep).
	outbound, keepAlive bool
	expires             time.Time
	// seq orders a flow's registrations by when they were first saved: the
	// first is the default for a request that names none (TS 24.229
	// §5.2.6.3.3).
	seq uint64
}

// aorKey writes a public identity for comparison: scheme, user and host, the
// host in lower case (RFC 3261 §19.1.4, §10.3 step 5).
func aorKey(u sip.URI) string {
	host := u.Host
	b := make([]byte, 0, len(u.Scheme)+len(u.User)+len(host)+2)
	b = append(b, u.Scheme...)
	b = append(b, ':')
	b = append(b, u.User...)
	b = append(b, '@')
	for i := 0; i < len(host); i++ {
		c := host[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b = append(b, c)
	}
	return string(b)
}

// registry holds the registrations of the flows on this task, in instance
// memory: a flow, and so its registrations, lives on one task (ADR 0005).
// Its methods are safe for concurrent use.
type registry struct {
	max int
	now func() time.Time

	mu     sync.Mutex
	byFlow map[transport.FlowID]map[string]*registration
	count  int
	seq    uint64
}

func newRegistry(maxRegistrations int, now func() time.Time) *registry {
	return &registry{max: maxRegistrations, now: now, byFlow: map[transport.FlowID]map[string]*registration{}}
}

// room reports whether a registration of aor over flow could be saved: it
// exists already, or the registry has room.
func (r *registry) room(flow transport.FlowID, aor string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.byFlow[flow][aor]
	return ok || r.count < r.max
}

// save stores reg, replacing any registration of the same identity over the
// same flow.
func (r *registry) save(reg *registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	regs := r.byFlow[reg.flow]
	if old, ok := regs[reg.aor]; ok {
		reg.seq = old.seq
	} else {
		if r.count >= r.max {
			return errRegistryFull
		}
		if regs == nil {
			regs = map[string]*registration{}
			r.byFlow[reg.flow] = regs
		}
		r.count++
		r.seq++
		reg.seq = r.seq
	}
	regs[reg.aor] = reg
	return nil
}

// remove forgets the registration of aor over flow.
func (r *registry) remove(flow transport.FlowID, aor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(flow, aor)
}

func (r *registry) removeLocked(flow transport.FlowID, aor string) {
	regs := r.byFlow[flow]
	if _, ok := regs[aor]; !ok {
		return
	}
	delete(regs, aor)
	r.count--
	if len(regs) == 0 {
		delete(r.byFlow, flow)
	}
}

// removeFlow forgets every registration over a flow that closed: its
// contacts are gone (RFC 5626 §5.3).
func (r *registry) removeFlow(flow transport.FlowID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count -= len(r.byFlow[flow])
	delete(r.byFlow, flow)
}

// lookup returns the registration of aor over flow if it has not expired.
func (r *registry) lookup(flow transport.FlowID, aor string) (*registration, bool) {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byFlow[flow][aor]
	if !ok {
		return nil, false
	}
	if !t.Before(reg.expires) {
		r.removeLocked(flow, aor)
		return nil, false
	}
	return reg, true
}

// flowRegistrations returns the registrations of flow that have not
// expired, the first saved first.
func (r *registry) flowRegistrations(flow transport.FlowID) []*registration {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*registration
	for aor, reg := range r.byFlow[flow] {
		if !t.Before(reg.expires) {
			r.removeLocked(flow, aor)
			continue
		}
		out = append(out, reg)
	}
	slices.SortFunc(out, func(a, b *registration) int { return cmp.Compare(a.seq, b.seq) })
	return out
}

// sweep forgets every expired registration.
func (r *registry) sweep() {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for flow, regs := range r.byFlow {
		for aor, reg := range regs {
			if !t.Before(reg.expires) {
				r.removeLocked(flow, aor)
			}
		}
	}
}

// size returns how many registrations are kept.
func (r *registry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
