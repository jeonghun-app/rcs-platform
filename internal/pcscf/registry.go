package pcscf

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// errRegistryFull refuses a registration beyond PCSCF_MAX_REGISTRATIONS, and
// errTooManyPending a REGISTER for one more identity from a flow or a client
// that has as many under way as it may.
var (
	errRegistryFull   = errors.New("pcscf: registry full")
	errTooManyPending = errors.New("pcscf: too many registrations under way")
)

// The identities with REGISTERs under way at once are bounded, so that a
// client cannot hold slots by writing new To values while the core is slow
// (QA of #198): maxPendingPerFlow for one flow, since a UE registers one or
// two identities over it, and PCSCF_MAX_PENDING_REGISTERS_PER_IP for one
// client address, an IPv4 address or IPv6 /64 (clientKey), over all its
// flows, which is more since carrier-grade NAT puts many phones behind one
// address. A REGISTER is under way for well under a second when the core is
// well.
const maxPendingPerFlow = 8

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
	// outbound says the client uses RFC 5626 outbound, and once saved that
	// the registrar applied it too; viaKeep that it asked for keep-alive in
	// its Via (RFC 6223); and keepAlive, once saved, that it keeps the flow
	// alive by either.
	outbound, viaKeep, keepAlive bool
	// pathOB says the Path pcscf wrote for the REGISTER has ob: the client
	// asked for outbound, whatever the registrar did (RFC 5626 §5.1).
	pathOB  bool
	expires time.Time
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
//
// Each identity over a flow takes one of max slots while it is registered
// or a REGISTER for it is under way: a REGISTER reserves its slot before it
// is forwarded, so a 200 always finds room and a client is never told it is
// registered when pcscf keeps nothing (QA of #198).
type registry struct {
	max int
	now func() time.Time

	mu     sync.Mutex
	byFlow map[transport.FlowID]map[string]*registration
	// byDefault indexes the registrations by the default public identity
	// of their user (defaultKey), whose reg event subscription they keep.
	byDefault map[string]map[slotKey]struct{}
	pending   map[slotKey]*reservation
	// pendingByFlow and pendingByClient count the reservations of each
	// flow and each client, and perClient bounds the latter.
	pendingByFlow   map[transport.FlowID]int
	pendingByClient map[netip.Addr]int
	perClient       int
	// count is the slots taken: identities with a registration, a
	// reservation or both.
	count int
	// seq numbers the registrations in the order they were first saved.
	seq uint64
}

type slotKey struct {
	flow transport.FlowID
	aor  string
}

// reservation is the REGISTERs under way for one identity over one flow,
// and when the last of them gives up its slot if its final response never
// releases it.
type reservation struct {
	n      int
	until  time.Time
	client netip.Addr
}

func newRegistry(maxRegistrations int, now func() time.Time) *registry {
	return &registry{max: maxRegistrations, now: now,
		byFlow: map[transport.FlowID]map[string]*registration{}, pending: map[slotKey]*reservation{},
		byDefault:     map[string]map[slotKey]struct{}{},
		pendingByFlow: map[transport.FlowID]int{}, pendingByClient: map[netip.Addr]int{},
		perClient: DefaultMaxPendingRegistersPerIP}
}

// holdsLocked reports whether k has a slot. mu must be held.
func (r *registry) holdsLocked(k slotKey) bool {
	_, saved := r.byFlow[k.flow][k.aor]
	_, reserved := r.pending[k]
	return saved || reserved
}

// reserve takes the slot of a REGISTER of aor over flow from client, a
// clientKey, until release or until: errRegistryFull if the registry has no
// room, errTooManyPending if the flow or the client has as many other
// identities under way as it may. An identity that has its slot already keeps it.
func (r *registry) reserve(flow transport.FlowID, aor string, client netip.Addr, until time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := slotKey{flow, aor}
	res := r.pending[k]
	if res == nil && (r.pendingByFlow[flow] >= maxPendingPerFlow || r.pendingByClient[client] >= r.perClient) {
		return errTooManyPending
	}
	if !r.holdsLocked(k) {
		if r.count >= r.max {
			return errRegistryFull
		}
		r.count++
	}
	if res == nil {
		res = &reservation{client: client}
		r.pending[k] = res
		r.pendingByFlow[flow]++
		r.pendingByClient[client]++
	}
	res.n++
	if until.After(res.until) {
		res.until = until
	}
	return nil
}

// release ends a reservation of reserve. The slot stays taken if the
// identity is registered.
func (r *registry) release(flow transport.FlowID, aor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := slotKey{flow, aor}
	res := r.pending[k]
	if res == nil {
		return
	}
	if res.n--; res.n > 0 {
		return
	}
	r.dropReservationLocked(k)
}

// dropReservationLocked forgets k's reservation, and frees its slot if it is
// not registered. mu must be held.
func (r *registry) dropReservationLocked(k slotKey) {
	if res := r.pending[k]; res != nil {
		if r.pendingByClient[res.client]--; r.pendingByClient[res.client] <= 0 {
			delete(r.pendingByClient, res.client)
		}
		if r.pendingByFlow[k.flow]--; r.pendingByFlow[k.flow] <= 0 {
			delete(r.pendingByFlow, k.flow)
		}
	}
	delete(r.pending, k)
	if _, saved := r.byFlow[k.flow][k.aor]; !saved {
		r.count--
	}
}

// save stores reg, replacing any registration of the same identity over the
// same flow, whose place in the order it keeps. It takes a slot if the
// identity has none, as when a reservation lapsed.
func (r *registry) save(reg *registration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := slotKey{reg.flow, reg.aor}
	if !r.holdsLocked(k) {
		if r.count >= r.max {
			return errRegistryFull
		}
		r.count++
	}
	regs := r.byFlow[reg.flow]
	if regs == nil {
		regs = map[string]*registration{}
		r.byFlow[reg.flow] = regs
	}
	if old, ok := regs[reg.aor]; ok {
		reg.seq = old.seq
		r.unindexLocked(old)
	} else {
		r.seq++
		reg.seq = r.seq
	}
	regs[reg.aor] = reg
	r.indexLocked(reg)
	return nil
}

// replace puts changed in the place of old, if old is still the
// registration of its identity over its flow: a REGISTER's 200 saved since
// wins.
func (r *registry) replace(old, changed *registration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byFlow[old.flow][old.aor] != old {
		return
	}
	changed.seq = old.seq
	r.unindexLocked(old)
	r.byFlow[old.flow][old.aor] = changed
	r.indexLocked(changed)
}

func (r *registry) indexLocked(reg *registration) {
	key := defaultKey(reg)
	set := r.byDefault[key]
	if set == nil {
		set = map[slotKey]struct{}{}
		r.byDefault[key] = set
	}
	set[slotKey{reg.flow, reg.aor}] = struct{}{}
}

func (r *registry) unindexLocked(reg *registration) {
	key := defaultKey(reg)
	delete(r.byDefault[key], slotKey{reg.flow, reg.aor})
	if len(r.byDefault[key]) == 0 {
		delete(r.byDefault, key)
	}
}

// ofDefault returns the registrations of the user whose default public
// identity is key, as defaultKey writes it, that have not expired.
func (r *registry) ofDefault(key string) []*registration {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*registration
	for k := range r.byDefault[key] {
		if reg := r.byFlow[k.flow][k.aor]; reg != nil && t.Before(reg.expires) {
			out = append(out, reg)
		}
	}
	return out
}

// defaults returns, for every user with a registration that has not
// expired, the one that expires last, keyed by defaultKey: the one whose
// Path a reg event SUBSCRIBE for that user asserts.
func (r *registry) defaults() map[string]*registration {
	t := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*registration, len(r.byDefault))
	for key, set := range r.byDefault {
		for k := range set {
			reg := r.byFlow[k.flow][k.aor]
			if reg == nil || !t.Before(reg.expires) {
				continue
			}
			if best := out[key]; best == nil || reg.expires.After(best.expires) {
				out[key] = reg
			}
		}
	}
	return out
}

// remove forgets the registration of aor over flow.
func (r *registry) remove(flow transport.FlowID, aor string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.removeLocked(flow, aor)
}

func (r *registry) removeLocked(flow transport.FlowID, aor string) {
	regs := r.byFlow[flow]
	reg, ok := regs[aor]
	if !ok {
		return
	}
	r.unindexLocked(reg)
	delete(regs, aor)
	if len(regs) == 0 {
		delete(r.byFlow, flow)
	}
	if _, reserved := r.pending[slotKey{flow, aor}]; !reserved {
		r.count--
	}
}

// removeFlow forgets every registration over a flow that closed: its
// contacts are gone (RFC 5626 §5.3). A REGISTER still under way keeps its
// slot until its response; registered drops what its 200 would save.
func (r *registry) removeFlow(flow transport.FlowID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for aor := range r.byFlow[flow] {
		r.removeLocked(flow, aor)
	}
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

// sweep forgets every expired registration, and every reservation whose
// REGISTER never released it.
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
	for k, res := range r.pending {
		if !t.Before(res.until) {
			r.dropReservationLocked(k)
		}
	}
}

// size returns how many slots are taken: registrations, and REGISTERs under
// way for identities not yet registered.
func (r *registry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
