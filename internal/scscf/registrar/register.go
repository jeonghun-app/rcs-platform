package registrar

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// saveAttempts bounds how often a save that lost to another instance is
// read and applied again.
const saveAttempts = 3

// register runs an authenticated REGISTER: the bindings of r.impu change, and
// with them those of every identity of its implicit registration set.
func (g *Registrar) register(ctx context.Context, req *sip.Request, r *register) (*sip.Response, *failure) {
	cur, f := g.read(ctx, r.impu)
	if f != nil {
		return nil, f
	}
	registered := cur != nil && len(cur.Contacts) > 0 && cur.Unregistered.IsZero()
	if registered && cur.IMPI != r.impi {
		// One public identity shared by two private ones (TS 23.228 §4.3.3.4)
		// is not supported yet.
		return nil, refuse(403, "Registered by another private identity")
	}
	if f := g.authenticate(ctx, r, registered); f != nil {
		return nil, f
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
	lim := limitsOf(g.cfg)
	for range saveAttempts {
		now := g.cfg.Now()
		var old []state.Contact
		if registered {
			old = cur.Contacts
		}
		next, f := applyContacts(old, r, now, lim)
		if f != nil {
			return nil, f
		}
		var err error
		var set *implicitSet
		switch {
		case len(next) == 0 && registered:
			err = g.deregister(ctx, r, cur)
		case len(next) == 0:
			// Nothing was registered and nothing is: no assignment to make.
		default:
			set, err = g.assign(ctx, r, cur, registered, next)
		}
		var fl *failure
		switch {
		case errors.As(err, &fl):
			return nil, fl
		case errors.Is(err, state.ErrConflict), errors.Is(err, state.ErrExists), errors.Is(err, state.ErrNotFound):
			// Another instance changed the registration since it was read.
			if cur, f = g.read(ctx, r.impu); f != nil {
				return nil, f
			}
			registered = cur != nil && len(cur.Contacts) > 0 && cur.Unregistered.IsZero()
			continue
		case err != nil:
			return nil, g.internal("saving the registration", err)
		}
		g.count("registrar.registered")
		return g.ok(req, r, next, set), nil
	}
	return nil, g.internal("saving the registration", errors.New("lost every attempt to another instance"))
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
// that is not barred (TS 24.229 §5.4.1.2.2).
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
// bindings of every identity of the set.
func (g *Registrar) assign(ctx context.Context, r *register, cur *state.Registration, registered bool, bindings []state.Contact) (*implicitSet, error) {
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
			return nil, err
		}
	}
	saa, err := g.cfg.HSS.SAR(ctx, sar)
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	if f := g.cxFailure("SAR", res, err); f != nil {
		return nil, f
	}
	received := g.cfg.Now()
	userData := saa.UserData
	if len(userData) == 0 && stored != nil {
		userData = stored.UserData
	}
	set, err := parseSet(userData)
	if err != nil || !set.has(r.impu) {
		return nil, g.internal("reading the implicit registration set", err)
	}
	key := state.ProfileKey{IMPI: r.impi, IMPU: set.defaultID}
	keep := latestExpiry(bindings).Add(state.ProfileGrace)
	switch {
	case len(saa.UserData) > 0:
		err := g.cfg.Store.SaveProfile(ctx, &state.Profile{Key: key, UserData: saa.UserData, Received: received, KeepUntil: keep})
		// A later PPR stored first: it is the newer profile.
		if err != nil && !errors.Is(err, state.ErrConflict) {
			return nil, err
		}
		if cur != nil && cur.DefaultIMPU != "" && cur.ProfileKey() != key {
			// The set's default identity changed: the profile under the
			// old one would only wait for its KeepUntil.
			if err := g.cfg.Store.DeleteProfile(ctx, cur.ProfileKey()); err != nil {
				return nil, err
			}
		}
	case stored.KeepDue(received):
		if err := g.cfg.Store.KeepProfile(ctx, key, keep, received); err != nil && !errors.Is(err, state.ErrNotFound) {
			return nil, err
		}
	}
	if err := g.save(ctx, r, cur, set, bindings); err != nil {
		return nil, err
	}
	return set, nil
}

// save stores bindings for r.impu, conditional on cur, and then for every
// other identity of the set, which are registered with it (TS 23.228
// §5.2.1a). An identity of the set saved by another instance meanwhile is
// read again; r.impu losing is reported, so that register reads it again.
func (g *Registrar) save(ctx context.Context, r *register, cur *state.Registration, set *implicitSet, bindings []state.Contact) error {
	if _, err := g.cfg.Store.SaveRegistration(ctx, g.next(cur, r, r.impu, set, bindings)); err != nil {
		return err
	}
	for _, id := range set.identities {
		if id.impu == r.impu {
			continue
		}
		var err error
		for range saveAttempts {
			var other *state.Registration
			other, err = g.cfg.Store.Registration(ctx, id.impu)
			if errors.Is(err, state.ErrNotFound) {
				other, err = nil, nil
			}
			if err != nil {
				return err
			}
			_, err = g.cfg.Store.SaveRegistration(ctx, g.next(other, r, id.impu, set, bindings))
			if !errors.Is(err, state.ErrConflict) && !errors.Is(err, state.ErrExists) {
				break
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// next is the registration of impu after r: cur's version, with the set's
// bindings, out of any unregistered state or deregistration lease.
func (g *Registrar) next(cur *state.Registration, r *register, impu string, set *implicitSet, bindings []state.Contact) *state.Registration {
	n := &state.Registration{IMPU: impu, IMPI: r.impi, DefaultIMPU: set.defaultID, Contacts: bindings}
	if cur != nil {
		n.Version = cur.Version
	}
	return n
}

// deregister ends the registration of r.impu's set after its last binding
// was removed: SAR USER_DEREGISTRATION, then the set's registrations and its
// profile go. The bindings stay if the HSS cannot be told, so the client's
// retry, or the sweep at their expiry, tells it later.
func (g *Registrar) deregister(ctx context.Context, r *register, cur *state.Registration) error {
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.UserDeregistration})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	if f := g.cxFailure("SAR", res, err); f != nil {
		return f
	}
	if err := g.cfg.Store.DeleteRegistration(ctx, cur); err != nil {
		return err
	}
	others, err := g.cfg.Store.RegistrationsOf(ctx, r.impi)
	if err != nil {
		return err
	}
	for _, o := range others {
		if o.DefaultIMPU != cur.DefaultIMPU || o.IMPU == r.impu {
			continue
		}
		// One saved meanwhile by a REGISTER of its own keeps its bindings.
		if err := g.cfg.Store.DeleteRegistration(ctx, o); err != nil && !errors.Is(err, state.ErrConflict) && !errors.Is(err, state.ErrNotFound) {
			return err
		}
	}
	g.count("registrar.deregistered")
	return g.cfg.Store.DeleteProfile(ctx, cur.ProfileKey())
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
// §5.4.1.2.2): the bindings, the Path as received, and for a registration
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
		if outbound, _ := outboundPath(r.path); outbound && usesOutbound(bindings) {
			// RFC 5626 §6: the registrar applied outbound to this request.
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

func usesOutbound(bindings []state.Contact) bool {
	for _, c := range bindings {
		if c.RegID != 0 {
			return true
		}
	}
	return false
}
