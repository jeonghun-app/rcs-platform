package routing

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
)

// storeRetryAfter is the Retry-After of a 500 for a store failure, in
// seconds: DynamoDB throttling and timeouts pass within seconds.
const storeRetryAfter = "5"

// saveAttempts bounds how often ending a binding is read and applied again
// after losing to another write of the set's record.
const saveAttempts = 3

// Terminating routes a request outside a dialog to the user its
// Request-URI names (TS 24.229 §5.4.3.3): along the user's terminating iFC
// chain, then to the live bindings of the user's implicit registration set
// that the caller's preferences accept, each along its Path, the S-CSCF
// recording the route; of the flows of one instance only the latest at a
// time (RFC 5626 §7), the next if that one's edge proxy answers 430. A user
// with no record here is looked up in the HSS (Config.Registrar) and served
// as unregistered, by the iFC of that state. It is 404 for a
// Request-URI that is no public identity, a barred one or one the HSS does
// not know, 480 for a user without a live binding the preferences accept,
// 400 for more than maxPreferences of them or one that requires something
// and does not parse, and 500 with Retry-After for a store or HSS that
// cannot be asked. For a request that sets up a dialog the S-CSCF's
// Record-Route value signs the dialog's hops (recorder).
func (rt *Router) Terminating(ctx context.Context, r *proxy.Request) proxy.Decision {
	return rt.decide(r.Message, rt.terminating(ctx, r), true)
}

func (rt *Router) terminating(ctx context.Context, r *proxy.Request) step {
	impu, ok := identity.CanonicalIMPU(r.Message.URI.String())
	if !ok {
		rt.count("routing.terminating.not_found")
		return answer(404, "Not Found")
	}
	if _, err := preferencesOf(r.Message); err != nil {
		// Refused before the chain, as at its end (toContacts).
		return rt.badPreferences(err)
	}
	now := rt.cfg.Now()
	set, err := rt.served(ctx, impu, now)
	switch {
	case errors.Is(err, errBarred):
		rt.count("routing.terminating.barred")
		return answer(404, "Not Found")
	case errors.Is(err, registrar.ErrUnknownUser):
		rt.count("routing.terminating.not_found")
		return answer(404, "Not Found")
	case errors.Is(err, errEnding):
		rt.count("routing.terminating.not_registered")
		return answer(480, "Temporarily Unavailable")
	case errors.Is(err, registrar.ErrServedElsewhere):
		// §5.4.3.3 would have a 305 name the other S-CSCF; every instance
		// shares one name here (ADR 0005), so the I-CSCF's choice and the
		// HSS's disagree only for a moment, which 480 lets the caller wait
		// out.
		rt.count("routing.terminating.served_elsewhere")
		return answer(480, "Temporarily Unavailable")
	case err != nil:
		rt.internalLog("looking up the served user", err)
		return rt.unavailable(r.Message)
	}
	pos := position{served: impu, scase: ifc.TerminatingRegistered, registered: true, priority: -1}
	if len(live(set, now)) == 0 {
		pos.scase, pos.registered = ifc.TerminatingUnregistered, false
	}
	// A request from an application server that sent it for its user names
	// the user in P-Served-User (#137); one from a P-CSCF never does, and
	// pcscf removes any a client wrote (ADR 0007 §7).
	pos.kept = r.Message.Header.Has("P-Served-User") && !rt.fromEdgeProxy(r.Message)
	return rt.next(ctx, r.Message, pos, set, rt.toContacts(r.Message, set))
}

// formsDialog reports whether a request of method sets up a dialog, the
// S-CSCF recording its route (RFC 3261 §12.1, RFC 6665, RFC 3515), as
// pcscf's does. A standalone request, such as OPTIONS or MESSAGE, is not
// recorded: no proxy records it, so its hop toward the caller would be a
// Contact nobody checked, which a signature would then vouch for (#322).
func formsDialog(method string) bool {
	return method == "INVITE" || method == "SUBSCRIBE" || method == "REFER"
}

// badPreferences answers a request whose caller preferences are refused.
func (rt *Router) badPreferences(err error) step {
	if errors.Is(err, errTooManyPreferences) {
		rt.count("routing.terminating.too_many_preferences")
		return answer(400, "Too Many Caller Preferences")
	}
	rt.count("routing.terminating.bad_preference")
	return answer(400, "Bad Caller Preference")
}

// errBarred is the lookup of a barred identity, errEnding that of one whose
// set has a record here that is neither registered nor unregistered: its
// bindings expired, or it is being deregistered, and a sweep ends it.
var (
	errBarred = errors.New("routing: the identity is barred")
	errEnding = errors.New("routing: the identity's set is being deregistered")
)

// served is the record of impu's set for a terminating request: as lookup
// finds it, or, without one, the record of the unregistered user the HSS
// makes of impu (registrar.Registrar.Unregistered).
func (rt *Router) served(ctx context.Context, impu string, now time.Time) (*state.Registration, error) {
	set, err := rt.lookup(ctx, impu, now)
	if err != nil || set != nil {
		return set, err
	}
	set, err = rt.cfg.Registrar.Unregistered(ctx, impu)
	if err != nil {
		return nil, err
	}
	rt.count("routing.terminating.unregistered_user")
	// The registrar returns a record of the set it finds saved already, by
	// a REGISTER say, which may no longer list impu.
	switch id, ok := inSet(set, impu); {
	case !ok:
		return nil, errEnding
	case id.Barred:
		return nil, errBarred
	}
	return set, nil
}

// inSet is impu's entry in set's identities.
func inSet(set *state.Registration, impu string) (state.SetIdentity, bool) {
	i := slices.IndexFunc(set.Identities, func(s state.SetIdentity) bool { return s.IMPU == impu })
	if i < 0 {
		return state.SetIdentity{}, false
	}
	return set.Identities[i], true
}

// lookup is the record of impu's set if the user is served here: the
// record impu's item names lists impu and has a live binding, or is the
// record of an unregistered user (state.Registration.Unregistered) that
// has not ended. An item naming another incarnation of the record, which
// an interrupted REGISTER can leave (#196), still finds it, and is
// repaired in the background. It is nil without a record listing impu,
// errBarred for a barred identity, and errEnding for a record that is
// neither, as one a deregistration holds (Deregistering) or one whose
// bindings expired.
func (rt *Router) lookup(ctx context.Context, impu string, now time.Time) (*state.Registration, error) {
	id, err := rt.cfg.Store.Identity(ctx, impu, now)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	set, err := rt.cfg.Store.Registration(ctx, id.Set)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	sid, ok := inSet(set, impu)
	switch {
	case !ok:
		return nil, nil
	case sid.Barred:
		// Barred whether or not the set is registered: rcs-as gives up a
		// message only on 404 or 604 (#279), and keeps it on a 480.
		return nil, errBarred
	case len(live(set, now)) > 0:
	case set.Deregistering.IsZero() && set.Unregistered.After(now):
	default:
		return nil, errEnding
	}
	if id.Incarnation != set.Incarnation {
		rt.repair(ctx, id, set)
	}
	return set, nil
}

// repair points id at set's incarnation, in the background and under the
// version read: a REGISTER that points it meanwhile wins.
func (rt *Router) repair(ctx context.Context, id *state.Identity, set *state.Registration) {
	want := *id
	want.Incarnation = set.Incarnation
	ctx = context.WithoutCancel(ctx)
	rt.stop.Lock()
	defer rt.stop.Unlock()
	if rt.stopped {
		// The set's next REGISTER points it.
		return
	}
	rt.repairs.Add(1)
	go func() {
		defer rt.repairs.Done()
		ctx, cancel := rt.bounded(ctx, rt.cfg.RepairTimeout)
		defer cancel()
		var err error
		if !rt.cfg.Panics.Run("routing: identity repair", func() { _, err = rt.cfg.Store.SaveIdentity(ctx, &want, rt.cfg.Now()) }) || err != nil {
			rt.count("routing.identity_repair_failed")
			return
		}
		rt.count("routing.identity_repaired")
	}()
}

// live are set's bindings that have not expired at now.
func live(set *state.Registration, now time.Time) []state.Contact {
	var out []state.Contact
	for _, c := range set.Contacts {
		if !c.Expired(now) {
			out = append(out, c)
		}
	}
	return out
}

// toContacts is the end of a terminating request's iFC chain: the live
// bindings of set the caller's preferences accept, with the Request-URI the
// request came with in P-Called-Party-ID, which the contact's replaces
// (§5.4.3.3); 480 without one.
func (rt *Router) toContacts(req *sip.Request, set *state.Registration) func(context.Context) step {
	return func(context.Context) step {
		bindings := live(set, rt.cfg.Now())
		if len(bindings) == 0 {
			rt.count("routing.terminating.not_registered")
			return answer(480, "Temporarily Unavailable")
		}
		prefs, err := preferencesOf(req)
		if err != nil {
			return rt.badPreferences(err)
		}
		var ops int
		called := sip.Address{URI: req.URI}.String()
		d := &delivery{rt: rt, key: set.Key, candidates: prefs.accepted(bindings, &ops), called: called, invite: req.Method == "INVITE"}
		hops := d.hops(d.targets(onePerInstance(d.candidates)))
		if len(hops) == 0 {
			rt.count("routing.terminating.no_contact")
			return answer(480, "Temporarily Unavailable")
		}
		rt.count("routing.terminating")
		return step{hops: hops}
	}
}

// delivery is one terminating request's forwarding: the set's bindings it
// may use, and which of them it has tried.
type delivery struct {
	rt         *Router
	key        state.SetKey
	candidates []state.Contact
	// called is the P-Called-Party-ID of every branch.
	called string
	// invite says the request is an INVITE.
	invite bool

	mu    sync.Mutex
	tried map[string]state.Contact
}

// onePerInstance is cs with, of the bindings of each instance, only the one
// registered last (the latest expiry), as RFC 5626 §7 sends to one flow of
// an instance at a time. Bindings without an instance are all kept.
func onePerInstance(cs []state.Contact) []state.Contact {
	latest := map[string]int{}
	for i, c := range cs {
		if c.InstanceID == "" {
			continue
		}
		if j, ok := latest[c.InstanceID]; !ok || c.Expires.After(cs[j].Expires) {
			latest[c.InstanceID] = i
		}
	}
	var out []state.Contact
	for i, c := range cs {
		if c.InstanceID == "" || latest[c.InstanceID] == i {
			out = append(out, c)
		}
	}
	return out
}

// targets are the targets of cs that this delivery has not tried, each the
// binding's contact along its Path. A binding whose stored URI or Path does
// not parse is left out and counted: the registrar stored what it parsed,
// so it cannot happen but on a damaged item.
func (d *delivery) targets(cs []state.Contact) []proxy.Target {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tried == nil {
		d.tried = map[string]state.Contact{}
	}
	var out []proxy.Target
	for _, c := range cs {
		t, ok := targetOf(c)
		if !ok {
			d.rt.count("routing.terminating.bad_binding")
			continue
		}
		k := keyOf(t)
		if _, done := d.tried[k]; done {
			continue
		}
		d.tried[k] = c
		out = append(out, t)
	}
	return out
}

// hops are the hops to ts.
func (d *delivery) hops(ts []proxy.Target) []hop {
	out := make([]hop, 0, len(ts))
	for _, t := range ts {
		out = append(out, hop{target: t, prepare: d.prepare, failed: d.failed})
	}
	return out
}

func (d *delivery) prepare(_ context.Context, req *sip.Request) error {
	// The S-CSCF's own toward application servers; pcscf would remove it.
	req.Header.Del("P-Served-User")
	return req.Header.Set("P-Called-Party-ID", d.called)
}

func targetOf(c state.Contact) (proxy.Target, bool) {
	u, err := sip.ParseURI(c.URI)
	if err != nil {
		return proxy.Target{}, false
	}
	t := proxy.Target{URI: u, Q: c.Q}
	for _, p := range c.Path {
		a, err := sip.ParseAddress(p)
		if err != nil {
			return proxy.Target{}, false
		}
		t.Routes = append(t.Routes, a)
	}
	return t, true
}

// keyOf names a target by its contact and first route, which tell the
// bindings of one URI over two flows apart.
func keyOf(t proxy.Target) string {
	k := t.URI.String()
	if len(t.Routes) > 0 {
		k += "|" + t.Routes[0].URI.String()
	}
	return k
}

// failed acts on a branch that failed: one its edge proxy answered 430 Flow
// Failed went to a flow that is gone (RFC 5626 §5.3), so its binding is
// ended, and the request is tried over the instance's latest flow not tried
// yet (§7). An INVITE the device answered with a provisional response
// (BranchFailure.Progress) is not: the device has it, and would take the
// same INVITE over its other flow for a merged request (RFC 3261 §8.2.2.2)
// or ring again (#14, #293).
func (d *delivery) failed(ctx context.Context, f proxy.BranchFailure) step {
	if f.Response == nil || f.Response.StatusCode != 430 {
		return step{}
	}
	d.mu.Lock()
	gone, ok := d.tried[keyOf(f.Target)]
	d.mu.Unlock()
	if !ok {
		return step{}
	}
	d.rt.count("routing.terminating.flow_failed")
	d.rt.endBinding(ctx, d.key, gone)
	if gone.InstanceID == "" {
		return step{}
	}
	if d.invite && f.Progress {
		d.rt.count("routing.terminating.not_retried_after_progress")
		return step{}
	}
	d.mu.Lock()
	var rest []state.Contact
	for _, c := range d.candidates {
		t, ok := targetOf(c)
		if _, done := d.tried[keyOf(t)]; ok && !done && c.InstanceID == gone.InstanceID {
			rest = append(rest, c)
		}
	}
	d.mu.Unlock()
	return step{hops: d.hops(d.targets(onePerInstance(rest)))}
}

// endBinding ends the binding of c in the record of k, as if it had
// expired: routing stops using it at once, and the sweep removes it as it
// removes any expired binding, telling the HSS and the reg event
// subscribers if it was the set's last (registrar.Sweep).
func (rt *Router) endBinding(ctx context.Context, k state.SetKey, c state.Contact) {
	for range saveAttempts {
		now := rt.cfg.Now()
		set, err := rt.cfg.Store.Registration(ctx, k)
		if errors.Is(err, state.ErrNotFound) {
			return
		}
		if err != nil {
			rt.internalLog("reading a set to end a binding", err)
			return
		}
		i := slices.IndexFunc(set.Contacts, func(o state.Contact) bool { return sameBinding(o, c) })
		if i < 0 || set.Contacts[i].Expired(now) || !set.Deregistering.IsZero() {
			return
		}
		next := set.Clone()
		next.Contacts[i].Expires = now
		_, err = rt.cfg.Store.SaveRegistration(ctx, next)
		switch {
		case err == nil:
			rt.count("routing.terminating.binding_ended")
			return
		case errors.Is(err, state.ErrNotFound):
			return
		case !errors.Is(err, state.ErrConflict):
			rt.internalLog("ending a binding", err)
			return
		}
	}
	rt.count("routing.terminating.binding_kept_changing")
}

// sameBinding reports whether a and b are one binding: the same contact
// over the same flow, registered by the same REGISTER sequence.
func sameBinding(a, b state.Contact) bool {
	return a.URI == b.URI && slices.Equal(a.Path, b.Path) && a.InstanceID == b.InstanceID && a.RegID == b.RegID
}
