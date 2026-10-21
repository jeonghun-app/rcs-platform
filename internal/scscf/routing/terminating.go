package routing

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
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
// Request-URI names (TS 24.229 §5.4.3.3): to the live bindings of the
// user's implicit registration set that the caller's preferences accept,
// each along its Path, the S-CSCF recording the route; of the flows of one
// instance only the latest at a time (RFC 5626 §7), the next if that one's
// edge proxy answers 430. It is 404 for a
// Request-URI that is no public identity or is a barred one, 480 for a user
// without a live binding the preferences accept, and 500 with Retry-After
// for a store that cannot be read.
func (rt *Router) Terminating(ctx context.Context, r *proxy.Request) proxy.Decision {
	impu, ok := identity.CanonicalIMPU(r.Message.URI.String())
	if !ok {
		rt.count("routing.terminating.not_found")
		return proxy.Decision{Status: 404, Reason: "Not Found"}
	}
	now := rt.cfg.Now()
	set, err := rt.lookup(ctx, impu, now)
	switch {
	case errors.Is(err, errBarred):
		rt.count("routing.terminating.barred")
		return proxy.Decision{Status: 404, Reason: "Not Found"}
	case err != nil:
		rt.internalLog("looking up the served user", err)
		return rt.unavailable(r.Message)
	case set == nil:
		rt.count("routing.terminating.not_registered")
		return proxy.Decision{Status: 480, Reason: "Temporarily Unavailable"}
	}
	d := &delivery{rt: rt, key: set.Key, candidates: accepted(live(set, now), r.Message)}
	targets := d.targets(onePerInstance(d.candidates))
	if len(targets) == 0 {
		rt.count("routing.terminating.no_contact")
		return proxy.Decision{Status: 480, Reason: "Temporarily Unavailable"}
	}
	rt.count("routing.terminating")
	called := sip.Address{URI: r.Message.URI}.String()
	return proxy.Decision{
		Targets:     targets,
		RecordRoute: []sip.Address{rt.cfg.RecordRoute},
		Prepare: func(_ context.Context, _ proxy.Target, req *sip.Request) error {
			// The Request-URI the request came with, which the contact's
			// Request-URI replaces (§5.4.3.3).
			return req.Header.Set("P-Called-Party-ID", called)
		},
		OnBranchFailure: d.failed,
	}
}

// errBarred is the lookup of a barred identity.
var errBarred = errors.New("routing: the identity is barred")

// lookup is the record of impu's set if the user is registered: the record
// impu's item names lists impu and has a live binding, which a record that
// a deregistration holds (Deregistering) never has. An item naming another incarnation of the record, which an
// interrupted REGISTER can leave (#196), still finds it, and is repaired in
// the background. It is nil without such a record, and errBarred for a
// barred identity.
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
	i := slices.IndexFunc(set.Identities, func(s state.SetIdentity) bool { return s.IMPU == impu })
	if i < 0 || len(live(set, now)) == 0 {
		return nil, nil
	}
	if set.Identities[i].Barred {
		return nil, errBarred
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
	rt.repairs.Add(1)
	go func() {
		defer rt.repairs.Done()
		ctx, cancel := context.WithTimeout(ctx, rt.cfg.RepairTimeout)
		defer cancel()
		if _, err := rt.cfg.Store.SaveIdentity(ctx, &want, rt.cfg.Now()); err != nil {
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

// delivery is one terminating request's forwarding: the set's bindings it
// may use, and which of them it has tried.
type delivery struct {
	rt         *Router
	key        state.SetKey
	candidates []state.Contact

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
// yet (§7).
func (d *delivery) failed(ctx context.Context, f proxy.BranchFailure) []proxy.Target {
	if f.Response == nil || f.Response.StatusCode != 430 {
		return nil
	}
	d.mu.Lock()
	gone, ok := d.tried[keyOf(f.Target)]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	d.rt.count("routing.terminating.flow_failed")
	d.rt.endBinding(ctx, d.key, gone)
	if gone.InstanceID == "" {
		return nil
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
	return d.targets(onePerInstance(rest))
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

// unavailable answers req 500 with Retry-After: the store failed, and the
// caller may try again soon (RFC 3261 §21.5.1).
func (rt *Router) unavailable(req *sip.Request) proxy.Decision {
	tag, err := rt.ids.Tag()
	if err != nil {
		return proxy.Decision{Status: 500}
	}
	res, err := sip.NewResponse(req, 500, "Server Internal Error", tag)
	if err != nil {
		return proxy.Decision{Status: 500}
	}
	_ = res.Header.Set("Retry-After", storeRetryAfter)
	return proxy.Decision{Response: res}
}
