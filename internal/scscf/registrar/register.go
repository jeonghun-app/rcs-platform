package registrar

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// saveAttempts bounds how often a save that lost to another instance is
// read and applied again.
const saveAttempts = 3

// register runs a REGISTER: once authenticated, the bindings of r.impu
// change, and with them those of every identity of its implicit registration
// set.
func (g *Registrar) register(ctx context.Context, req *sip.Request, r *register) (*sip.Response, *failure) {
	cur, f := g.read(ctx, r.impu)
	if f != nil {
		return nil, f
	}
	registered := isRegistered(cur)
	own := registered && cur.IMPI == r.impi
	if f := g.authenticate(ctx, r, own); f != nil {
		if f.code == 401 && r.outbound {
			// TS 24.229 §5.4.1.2.1: the 401 already says outbound applies.
			f.fields = append(f.fields, [2]string{"Require", "outbound"})
		}
		return nil, f
	}
	if registered && !own {
		// One public identity shared by two private ones (TS 23.228 §4.3.3.4)
		// is not supported yet. Refused only now, so that whether an identity
		// is registered is told to no one unauthenticated, and as any other
		// refusal is.
		return nil, refuse(403, "Forbidden")
	}
	if len(r.contacts) == 0 && !r.star {
		// RFC 3261 §10.2.3: a query.
		var bindings []state.Contact
		if registered {
			now := g.cfg.Now()
			bindings = slices.DeleteFunc(slices.Clone(cur.Contacts), func(c state.Contact) bool { return c.Expired(now) })
		}
		return g.ok(req, r, bindings, nil), nil
	}
	ops, f := prepare(r, limitsOf(g.cfg))
	if f != nil {
		return nil, f
	}
	for range saveAttempts {
		now := g.cfg.Now()
		var old []state.Contact
		if registered {
			old = cur.Contacts
		}
		next, f := applyDelta(old, r, ops, now)
		if f != nil {
			return nil, f
		}
		var err error
		var set *implicitSet
		switch {
		case len(next) == 0 && registered:
			err = g.deregister(ctx, r, ops, cur)
		case len(next) == 0:
			// Nothing was registered and nothing is: no assignment to make.
		default:
			// What the store would refuse is refused before the HSS hears of
			// the registration.
			probe := &state.Registration{IMPU: r.impu, IMPI: r.impi, DefaultIMPU: r.impu, Contacts: next}
			if probe.Validate() != nil {
				return nil, refuse(400, "Contact beyond the registrar's limits")
			}
			set, next, err = g.assign(ctx, r, ops, cur, registered, next)
		}
		var fl *failure
		switch {
		case errors.As(err, &fl):
			return nil, fl
		case errors.Is(err, state.ErrConflict), errors.Is(err, state.ErrExists):
			// Another instance changed the registration since it was read.
			if cur, f = g.read(ctx, r.impu); f != nil {
				return nil, f
			}
			registered = isRegistered(cur)
			continue
		case err != nil:
			return nil, g.internal("saving the registration", err)
		}
		g.count("registrar.registered")
		return g.ok(req, r, next, set), nil
	}
	return nil, g.internal("saving the registration", errors.New("lost every attempt to another instance"))
}

// isRegistered reports whether r has bindings, rather than being absent, a
// deregistration's lease, or an unregistered user's record.
func isRegistered(r *state.Registration) bool {
	return r != nil && len(r.Contacts) > 0 && r.Unregistered.IsZero()
}

// applied reports whether r's REGISTER has been applied to reg already: a
// binding carries its Call-ID and CSeq, which identify the request. A save
// that DynamoDB applied but whose response was lost comes back from the SDK's
// retry as a conflict, and is recognised this way.
func applied(reg *state.Registration, r *register) bool {
	return reg != nil && slices.ContainsFunc(reg.Contacts, func(c state.Contact) bool {
		return c.CallID == r.callID && c.CSeq == r.cseq
	})
}

// read returns the registration of impu, nil if there is none.
func (g *Registrar) read(ctx context.Context, impu string) (*state.Registration, *failure) {
	cur, err := g.cfg.Store.Registration(ctx, impu)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, g.internal("reading the registration", err)
	}
	return cur, nil
}

// implicitSet is the implicit registration set of the registered identity,
// from its User-Data: every identity in order, and the default one, the first
// that is not barred (TS 24.229 §5.4.1.2.2F).
type implicitSet struct {
	identities []setIdentity
	defaultID  string
}

type setIdentity struct {
	impu   string
	barred bool
}

func parseSet(userData []byte) (*implicitSet, error) {
	sub, err := ifc.ParseSubscription(userData)
	if err != nil {
		return nil, err
	}
	set := &implicitSet{}
	for _, sp := range sub.ServiceProfiles {
		for _, p := range sp.PublicIdentities {
			if p.IdentityType != ifc.IdentityPublicUser {
				continue
			}
			impu, ok := identity.CanonicalIMPU(p.Identity)
			if !ok {
				continue
			}
			set.identities = append(set.identities, setIdentity{impu: impu, barred: p.BarringIndication})
			if set.defaultID == "" && !p.BarringIndication {
				set.defaultID = impu
			}
		}
	}
	if set.defaultID == "" {
		return nil, errors.New("User-Data without an identity that is not barred")
	}
	return set, nil
}

func (s *implicitSet) has(impu string) bool {
	for _, id := range s.identities {
		if id.impu == impu {
			return true
		}
	}
	return false
}

// assign tells the HSS this S-CSCF serves r.impi (SAR REGISTRATION or
// RE_REGISTRATION, TS 29.228 §6.1.2), keeps the set's profile, and saves the
// bindings of every identity of the set. It returns the set and r.impu's
// bindings as saved.
func (g *Registrar) assign(ctx context.Context, r *register, ops []contactOp, cur *state.Registration, registered bool, bindings []state.Contact) (*implicitSet, []state.Contact, error) {
	sar := &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.Registration}
	var stored *state.Profile
	if registered {
		sar.AssignmentType = cx.ReRegistration
		// A re-registration needs the profile again only if this S-CSCF
		// lost it.
		p, err := g.cfg.Store.Profile(ctx, cur.ProfileKey(), g.cfg.Now())
		switch {
		case err == nil:
			stored = p
			sar.UserDataAlreadyAvailable = cx.UserDataAlreadyAvailable
		case !errors.Is(err, state.ErrNotFound):
			return nil, nil, err
		}
	}
	saa, err := g.cfg.HSS.SAR(ctx, sar)
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	if f := g.cxFailure("SAR", res, err); f != nil {
		return nil, nil, f
	}
	received := g.cfg.Now()
	userData := saa.UserData
	if len(userData) == 0 && stored != nil {
		userData = stored.UserData
	}
	set, err := parseSet(userData)
	if err != nil || !set.has(r.impu) {
		return nil, nil, g.internal("reading the implicit registration set", err)
	}
	key := state.ProfileKey{IMPI: r.impi, IMPU: set.defaultID}
	last := latestExpiry(bindings)
	keep := last.Add(state.ProfileGrace)
	switch {
	case len(saa.UserData) > 0:
		err := g.cfg.Store.SaveProfile(ctx, &state.Profile{Key: key, UserData: saa.UserData, Received: received, KeepUntil: keep})
		// A later PPR stored first: it is the newer profile.
		if err != nil && !errors.Is(err, state.ErrConflict) {
			return nil, nil, err
		}
		if cur != nil && cur.DefaultIMPU != "" && cur.ProfileKey() != key {
			// The set's default identity changed: the profile under the
			// old one would only wait for its KeepUntil.
			if err := g.cfg.Store.DeleteProfile(ctx, cur.ProfileKey()); err != nil {
				return nil, nil, err
			}
		}
	case stored.KeepDue(last):
		if err := g.cfg.Store.KeepProfile(ctx, key, keep, received); err != nil && !errors.Is(err, state.ErrNotFound) {
			return nil, nil, err
		}
	}
	saved, err := g.save(ctx, r, ops, cur, registered, set, bindings)
	if err != nil {
		return nil, nil, err
	}
	return set, saved, nil
}

// save stores bindings for r.impu, conditional on cur, and then applies r to
// every other identity of the set (TS 23.228 §5.2.1a), each under its own
// version. A loss on r.impu is reported, so that register reads it again.
func (g *Registrar) save(ctx context.Context, r *register, ops []contactOp, cur *state.Registration, registered bool, set *implicitSet, bindings []state.Contact) ([]state.Contact, error) {
	n := &state.Registration{IMPU: r.impu, IMPI: r.impi, DefaultIMPU: set.defaultID, Contacts: bindings}
	if cur != nil {
		n.Version = cur.Version
	}
	saved, err := g.cfg.Store.SaveRegistration(ctx, n)
	if errors.Is(err, state.ErrConflict) || errors.Is(err, state.ErrExists) {
		if again, f := g.read(ctx, r.impu); f == nil && applied(again, r) {
			saved, err = again, nil
		}
	}
	if errors.Is(err, state.ErrInvalid) && !registered {
		// Validate let through what the store refused: the HSS must not
		// keep a registration no sweep will ever end.
		g.unassign(ctx, r)
	}
	if err != nil {
		return nil, err
	}
	now := g.cfg.Now()
	for _, id := range set.identities {
		if id.impu == r.impu {
			continue
		}
		if _, err := g.applyTo(ctx, r, ops, id.impu, set.defaultID, now); err != nil {
			return nil, err
		}
	}
	return saved.Contacts, nil
}

// applyTo applies r's contacts to impu's current bindings, under the version
// read, and reports whether impu keeps bindings. One that another private
// identity registered, or that a newer REGISTER of the same UA reached
// first, is left alone.
func (g *Registrar) applyTo(ctx context.Context, r *register, ops []contactOp, impu, defaultID string, now time.Time) (bool, error) {
	for range saveAttempts {
		o, f := g.read(ctx, impu)
		if f != nil {
			return false, f
		}
		if o != nil && o.IMPI != r.impi && len(o.Contacts) > 0 {
			return true, nil
		}
		if applied(o, r) {
			return true, nil
		}
		var base []state.Contact
		if o != nil {
			base = o.Contacts
		}
		n, fl := applyDelta(base, r, ops, now)
		if fl != nil {
			return o != nil && live(o, now), nil
		}
		var err error
		switch {
		case len(n) > 0:
			next := &state.Registration{IMPU: impu, IMPI: r.impi, DefaultIMPU: defaultID, Contacts: n}
			if o != nil {
				next.Version = o.Version
			}
			_, err = g.cfg.Store.SaveRegistration(ctx, next)
		case o != nil:
			err = g.cfg.Store.DeleteRegistration(ctx, o)
		}
		switch {
		case errors.Is(err, state.ErrConflict), errors.Is(err, state.ErrExists):
			continue
		case errors.Is(err, state.ErrNotFound):
			return false, nil
		case err != nil:
			return false, err
		}
		return len(n) > 0, nil
	}
	return false, errors.New("registrar: an identity of the set kept changing")
}

// unassign tells the HSS that a registration it accepted could not be kept
// (SAR USER_DEREGISTRATION). A failure is only counted: the client gets a
// 500 either way, and registers again.
func (g *Registrar) unassign(ctx context.Context, r *register) {
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.UserDeregistration})
	if err != nil || saa == nil || cxclient.Classify(saa.Result) != cxclient.Success {
		g.count("registrar.hss_failed")
	}
}

// deregister ends the registration of r.impu's set after its last binding
// was removed: SAR USER_DEREGISTRATION, then r is applied to every identity
// of the set, each under the version read before the SAR, and the profile
// goes only if no identity kept bindings and it is still the one read
// (DeleteProfileIf). So a REGISTER of another device that lands meanwhile, on
// any identity of the set, keeps its bindings and its profile. The bindings
// stay if the HSS cannot be told, so the client's retry, or the sweep at
// their expiry, tells it later.
func (g *Registrar) deregister(ctx context.Context, r *register, ops []contactOp, cur *state.Registration) error {
	now := g.cfg.Now()
	listed, err := g.cfg.Store.RegistrationsOf(ctx, r.impi)
	if err != nil {
		return err
	}
	var others []*state.Registration
	for _, o := range listed {
		if o.DefaultIMPU == cur.DefaultIMPU && o.IMPU != r.impu {
			others = append(others, o)
		}
	}
	profile, err := g.cfg.Store.Profile(ctx, cur.ProfileKey(), now)
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.UserDeregistration})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	if f := g.cxFailure("SAR", res, err); f != nil {
		return f
	}
	if err := g.cfg.Store.DeleteRegistration(ctx, cur); err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	kept := false
	for _, o := range others {
		k, err := g.removeFrom(ctx, r, ops, o, now)
		if err != nil {
			return err
		}
		kept = kept || k
	}
	g.count("registrar.deregistered")
	if kept || profile == nil {
		return nil
	}
	if err := g.cfg.Store.DeleteProfileIf(ctx, cur.ProfileKey(), profile.Received); err != nil && !errors.Is(err, state.ErrConflict) {
		return err
	}
	return nil
}

// removeFrom applies a deregistration to o, under the version it was read
// with, reading it again if it changed, and reports whether it keeps
// bindings.
func (g *Registrar) removeFrom(ctx context.Context, r *register, ops []contactOp, o *state.Registration, now time.Time) (bool, error) {
	for range saveAttempts {
		n, f := applyDelta(o.Contacts, r, ops, now)
		if f != nil {
			// A newer REGISTER of the same UA reached it, or it never had
			// these bindings.
			return live(o, now), nil
		}
		var err error
		if len(n) == 0 {
			err = g.cfg.Store.DeleteRegistration(ctx, o)
		} else {
			next := o.Clone()
			next.Contacts = n
			_, err = g.cfg.Store.SaveRegistration(ctx, next)
		}
		switch {
		case errors.Is(err, state.ErrConflict):
			var fl *failure
			if o, fl = g.read(ctx, o.IMPU); fl != nil {
				return false, fl
			}
			if o == nil {
				return false, nil
			}
			continue
		case errors.Is(err, state.ErrNotFound):
			return false, nil
		case err != nil:
			return false, err
		}
		return len(n) > 0, nil
	}
	return true, errors.New("registrar: an identity of the set kept changing")
}

// live reports whether r still serves terminating requests at now: a
// binding that has not expired, or an unregistered state that has not ended.
func live(r *state.Registration, now time.Time) bool {
	for _, c := range r.Contacts {
		if !c.Expired(now) {
			return true
		}
	}
	return r.Unregistered.After(now)
}

func latestExpiry(bindings []state.Contact) time.Time {
	var t time.Time
	for _, c := range bindings {
		if c.Expires.After(t) {
			t = c.Expires
		}
	}
	return t
}

// ok is the 200 to an accepted REGISTER (RFC 3261 §10.3 step 8, TS 24.229
// §5.4.1.2.2F): the bindings, the Path as received, and for a registration
// the Service-Route back to this S-CSCF and the set's identities.
func (g *Registrar) ok(req *sip.Request, r *register, bindings []state.Contact, set *implicitSet) *sip.Response {
	res := g.response(req, 200, "")
	now := g.cfg.Now()
	var fields [][2]string
	for _, c := range bindings {
		fields = append(fields, [2]string{"Contact", contactField(c, now)})
	}
	for _, p := range r.path {
		fields = append(fields, [2]string{"Path", p})
	}
	if set != nil {
		u := g.cfg.ServiceRoute
		u.Params = append(sip.Params(nil), u.Params...)
		u.Params.SetFlag("lr")
		u.Params.SetFlag("orig")
		fields = append(fields, [2]string{"Service-Route", "<" + u.String() + ">"})
		for _, id := range set.identities {
			if !id.barred && id.impu == set.defaultID {
				fields = append(fields, [2]string{"P-Associated-URI", "<" + id.impu + ">"})
			}
		}
		for _, id := range set.identities {
			if !id.barred && id.impu != set.defaultID {
				fields = append(fields, [2]string{"P-Associated-URI", "<" + id.impu + ">"})
			}
		}
		if r.outbound {
			// RFC 5626 §6: the registrar applied outbound to a contact of
			// this request.
			fields = append(fields, [2]string{"Require", "outbound"})
		}
	}
	for _, kv := range fields {
		if err := res.Header.Add(kv[0], kv[1]); err != nil {
			return g.fail(req, g.internal("building the 200", err))
		}
	}
	return res
}
