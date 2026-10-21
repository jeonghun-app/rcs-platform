package registrar

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// saveAttempts bounds how often a save that lost to another instance is
// read and applied again.
const saveAttempts = 3

// register runs a REGISTER: once authenticated, the bindings of r.impu's
// implicit registration set change. The set is one record, read through the
// identity's item, and every change is one save of it conditional on the
// version read; a save that loses reads the record again and applies the
// request to what won.
func (g *Registrar) register(ctx context.Context, req *sip.Request, r *register) (*sip.Response, *failure) {
	cur, id, f := g.setOf(ctx, r.impu)
	if f != nil {
		return nil, f
	}
	registered := isRegistered(cur)
	own := registered && cur.Key.IMPI == r.impi
	r.flow = pathFlow(r.path)
	r.registeredFlow = own && overRegisteredFlow(cur, r.flow, g.cfg.Now())
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
	conflicted := false
	for range saveAttempts {
		now := g.cfg.Now()
		var old []state.Contact
		if registered {
			old = cur.Contacts
		}
		next, f := applyDelta(old, r, ops, now)
		if f != nil && f.code == 481 && conflicted {
			// What this request removes is gone: its own save was applied
			// but reported lost, or another removed it first. Either way
			// the bindings are as the client asked.
			return g.ok(req, r, old, nil), nil
		}
		if f != nil {
			return nil, f
		}
		var err error
		var saved *state.Registration
		var ended *state.Profile
		setEnded := false
		switch {
		case len(next) == 0 && registered:
			ended, setEnded, err = g.deregister(ctx, r, cur)
		case len(next) == 0:
			// Nothing was registered and nothing is: no assignment to make.
		default:
			// What the store would refuse is refused before the HSS hears of
			// the registration.
			probe := &state.Registration{
				Key: state.SetKey{IMPI: r.impi, IMPU: r.impu}, Incarnation: 1,
				Identities: []state.SetIdentity{{IMPU: r.impu}}, Contacts: next,
			}
			if probe.Validate() != nil {
				return nil, refuse(400, "Contact beyond the registrar's limits")
			}
			saved, err = g.assign(ctx, r, cur, id, registered, next)
		}
		var fl *failure
		var moved *movedError
		switch {
		case errors.As(err, &fl):
			return nil, fl
		case errors.As(err, &moved):
			// The set's record is under another key than the identity named:
			// the HSS changed its default identity, or another instance
			// created the record first.
			if cur, f = g.set(ctx, moved.key); f != nil {
				return nil, f
			}
		case errors.Is(err, state.ErrConflict), errors.Is(err, state.ErrExists), errors.Is(err, state.ErrNotFound):
			// Another instance changed or deregistered the set since it was
			// read: read it again, which may make this an initial
			// registration.
			if cur, id, f = g.setOf(ctx, r.impu); f != nil {
				return nil, f
			}
		case err != nil:
			return nil, g.internal("saving the registration", err)
		default:
			g.count("registrar.registered")
			if saved == nil {
				res := g.ok(req, r, nil, nil)
				if setEnded {
					// The set's last binding went: the servers hear it
					// ended, for every identity it was registered under,
					// without a body, which §5.4.1.7 g) gives only to an
					// initial registration and a refresh.
					for _, impu := range registeredIdentities(cur, r.impu) {
						tp := registeredFor(cur.Key, impu, ifc.DeRegistration, nil, now)
						tp.Profile = ended
						g.cfg.ThirdParty.Registered(ctx, tp)
					}
				}
				return res, nil
			}
			var before *state.Registration
			t := ifc.InitialRegistration
			if registered {
				before, t = cur, ifc.ReRegistration
			}
			g.cfg.Events.Changed(ctx, before, saved, regevent.Registered)
			res := g.ok(req, r, saved.Contacts, saved)
			if res.StatusCode == 200 {
				tp := registeredFor(saved.Key, r.impu, t, saved.Contacts, now)
				tp.Request, tp.Response = req, res
				g.cfg.ThirdParty.Registered(ctx, tp)
			}
			return res, nil
		}
		registered = isRegistered(cur)
		conflicted = true
	}
	return nil, g.internal("saving the registration", errors.New("lost every attempt to another instance"))
}

// movedError reports that the set a registration is for has its record under
// key, which the caller reads before trying again.
type movedError struct{ key state.SetKey }

func (*movedError) Error() string { return "registrar: the set's record is under another key" }

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

// setOf returns the record of the set impu belongs to and impu's item, nil if
// impu names no set or the set has no record.
func (g *Registrar) setOf(ctx context.Context, impu string) (*state.Registration, *state.Identity, *failure) {
	id, err := g.cfg.Store.Identity(ctx, impu, g.cfg.Now())
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil, nil
	case err != nil:
		return nil, nil, g.internal("reading the identity", err)
	}
	reg, f := g.set(ctx, id.Set)
	return reg, id, f
}

// set returns the record of the set k, nil if there is none.
func (g *Registrar) set(ctx context.Context, k state.SetKey) (*state.Registration, *failure) {
	cur, err := g.cfg.Store.Registration(ctx, k)
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
	identities []state.SetIdentity
	defaultID  string
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
			if !ok || set.has(impu) {
				continue
			}
			set.identities = append(set.identities, state.SetIdentity{IMPU: impu, Barred: p.BarringIndication})
			if set.defaultID == "" && !p.BarringIndication {
				set.defaultID = impu
			}
		}
	}
	if set.defaultID == "" || len(set.identities) > state.MaxIdentities {
		return nil, errors.New("User-Data without an identity that is not barred, or with too many")
	}
	return set, nil
}

func (s *implicitSet) has(impu string) bool {
	return slices.ContainsFunc(s.identities, func(id state.SetIdentity) bool { return id.IMPU == impu })
}

// assign tells the HSS this S-CSCF serves r.impi (SAR REGISTRATION or
// RE_REGISTRATION, TS 29.228 §6.1.2), keeps the set's profile, and saves the
// set's record with bindings, conditional on cur. A record created anew gets
// a fresh incarnation. Every identity of the set is pointed at the record
// when it was not registered (a deregistration may have deleted the items
// meanwhile), when the set changed, and when id, r.impu's item, is due to be
// kept longer.
func (g *Registrar) assign(ctx context.Context, r *register, cur *state.Registration, id *state.Identity, registered bool, bindings []state.Contact) (*state.Registration, error) {
	sar := &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.Registration}
	var stored *state.Profile
	if registered {
		sar.AssignmentType = cx.ReRegistration
		// A re-registration needs the profile again only if this S-CSCF
		// lost it.
		p, err := g.cfg.Store.Profile(ctx, cur.Key, g.cfg.Now())
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
	key := state.SetKey{IMPI: r.impi, IMPU: set.defaultID}
	if cur == nil || cur.Key != key {
		// The record under key may exist already, created by another
		// instance or under the HSS's new default identity: apply this
		// request to it instead.
		if other, f := g.set(ctx, key); f != nil {
			return nil, f
		} else if other != nil {
			return nil, &movedError{key: key}
		}
	}
	last := latestExpiry(bindings)
	keep := last.Add(state.ProfileGrace)
	switch {
	case len(saa.UserData) > 0:
		err := g.cfg.Store.SaveProfile(ctx, &state.Profile{Key: key, UserData: saa.UserData, Received: received, KeepUntil: keep})
		// A later PPR stored first: it is the newer profile.
		if err != nil && !errors.Is(err, state.ErrConflict) {
			return nil, err
		}
	case stored.KeepDue(last):
		if err := g.cfg.Store.KeepProfile(ctx, key, keep, received); err != nil && !errors.Is(err, state.ErrNotFound) {
			return nil, err
		}
	}
	n := &state.Registration{Key: key, Identities: set.identities, Contacts: bindings, RegisteredAs: []string{r.impu}}
	if cur != nil && cur.Key == key {
		n.Incarnation, n.Version = cur.Incarnation, cur.Version
		if registered {
			// The servers hear of the set's end under every identity a
			// REGISTER of it was told under, which are still the set's.
			n.RegisteredAs = withRegistered(cur.RegisteredAs, r.impu, set.identities)
		}
	}
	if cur == nil || cur.Key != key || !cur.Deregistering.IsZero() {
		// A record taken over from a deregistration's lease is a new
		// incarnation (state.Registration.Incarnation): the deregistration
		// deletes the identities that name the one it claimed.
		if n.Incarnation, err = g.incarnation(); err != nil {
			return nil, err
		}
	}
	// A record with a new incarnation or new identities is committed by its
	// save, so its identities are pointed at it first: a failure in between
	// leaves no record, and the retry, an initial registration again, points
	// them all. An item naming a record never saved is as good as none.
	ahead := cur == nil || n.Incarnation != cur.Incarnation || !slices.Equal(cur.Identities, n.Identities)
	if ahead {
		// Another REGISTER of the set may commit first; the attempt that
		// follows then repairs what this one pointed elsewhere.
		r.pointedAhead = true
		if err := g.pointAhead(ctx, n, keep); err != nil {
			return nil, err
		}
	}
	saved, err := g.cfg.Store.SaveRegistration(ctx, n)
	if errors.Is(err, state.ErrConflict) || errors.Is(err, state.ErrExists) {
		if again, f := g.set(ctx, key); f == nil && applied(again, r) {
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
	// Otherwise every identity of the set is pointed again, repaired or
	// kept longer, when an earlier attempt of this request pointed them at
	// a record that lost, or when r.impu's own item shows the need: missing,
	// naming another record or incarnation, or due to be kept (KeepDue).
	if !ahead && (r.pointedAhead || !registered || id == nil || id.Set != saved.Key || id.Incarnation != saved.Incarnation || id.KeepDue(last)) {
		if err := g.point(ctx, saved, keep); err != nil {
			return nil, err
		}
	}
	if cur != nil && cur.Key != key {
		// The HSS moved the set to another default identity: the record and
		// profile under the old one would only wait for a sweep.
		g.dropOld(ctx, cur)
	}
	return saved, nil
}

// incarnation draws a set record's incarnation, never 0.
func (g *Registrar) incarnation() (int64, error) {
	var b [8]byte
	if _, err := g.cfg.Rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(b[:])>>1) | 1, nil
}

// point makes every identity of reg name it, under the version read, kept
// at least until keep (the set's last binding expiry plus ProfileGrace, as
// its profile).
func (g *Registrar) point(ctx context.Context, reg *state.Registration, keep time.Time) error {
	for _, id := range reg.Identities {
		want := state.Identity{IMPU: id.IMPU, Set: reg.Key, Incarnation: reg.Incarnation, Barred: id.Barred, KeepUntil: keep}
		if err := g.pointOne(ctx, want); err != nil {
			return err
		}
	}
	return nil
}

// pointAhead points reg's identities ahead of its save, as point does, but
// leaves an item naming another, saved and live record of the same set: the
// REGISTER of another device of the user committed it first, and this
// one's save then fails with ErrExists and its retry applies to that record.
// Taking the item would leave it naming a record that, if this save fails
// for another reason, is never saved (#196 QA).
func (g *Registrar) pointAhead(ctx context.Context, reg *state.Registration, keep time.Time) error {
	for _, id := range reg.Identities {
		want := state.Identity{IMPU: id.IMPU, Set: reg.Key, Incarnation: reg.Incarnation, Barred: id.Barred, KeepUntil: keep}
		if err := g.pointOneAhead(ctx, want); err != nil {
			return err
		}
	}
	return nil
}

func (g *Registrar) pointOneAhead(ctx context.Context, want state.Identity) error {
	cur, err := g.cfg.Store.Identity(ctx, want.IMPU, g.cfg.Now())
	switch {
	case errors.Is(err, state.ErrNotFound):
	case err != nil:
		return err
	case cur.Set == want.Set && cur.Incarnation != want.Incarnation:
		other, f := g.set(ctx, cur.Set)
		if f != nil {
			return f
		}
		if other != nil && other.Incarnation == cur.Incarnation && other.Deregistering.IsZero() && live(other, g.cfg.Now()) {
			return nil
		}
	}
	return g.pointOne(ctx, want)
}

func (g *Registrar) pointOne(ctx context.Context, want state.Identity) error {
	for range saveAttempts {
		now := g.cfg.Now()
		cur, err := g.cfg.Store.Identity(ctx, want.IMPU, now)
		switch {
		case errors.Is(err, state.ErrNotFound):
			want.Version = 0
		case err != nil:
			return err
		case cur.Set == want.Set && cur.Incarnation == want.Incarnation && cur.Barred == want.Barred:
			if !want.KeepUntil.After(cur.KeepUntil) {
				return nil
			}
			err := g.cfg.Store.KeepIdentity(ctx, want.IMPU, want.KeepUntil, now)
			if !errors.Is(err, state.ErrNotFound) {
				return err
			}
			// Deleted meanwhile: saved anew on the next attempt.
			continue
		default:
			want.Version = cur.Version
			if cur.Set == want.Set && cur.KeepUntil.After(want.KeepUntil) {
				// Kept longer for this set already, as by a PPR.
				want.KeepUntil = cur.KeepUntil
			}
		}
		_, err = g.cfg.Store.SaveIdentity(ctx, &want, now)
		if !errors.Is(err, state.ErrConflict) && !errors.Is(err, state.ErrExists) && !errors.Is(err, state.ErrNotFound) {
			return err
		}
	}
	return errors.New("registrar: an identity kept changing")
}

// unpoint deletes the items of the identities that still name reg's
// incarnation, under the version read: one a new record of the set took
// meanwhile stays. It returns what it could not delete, which a deregistration
// leaves to the sweep after its lease and, failing that, to the items'
// KeepUntil.
func (g *Registrar) unpoint(ctx context.Context, reg *state.Registration) error {
	var errs error
	for _, id := range reg.Identities {
		errs = errors.Join(errs, g.unpointOne(ctx, reg, id.IMPU))
	}
	return errs
}

func (g *Registrar) unpointOne(ctx context.Context, reg *state.Registration, impu string) error {
	for range saveAttempts {
		cur, err := g.cfg.Store.Identity(ctx, impu, g.cfg.Now())
		switch {
		case errors.Is(err, state.ErrNotFound):
			return nil
		case err != nil:
			return err
		case cur.Set != reg.Key || cur.Incarnation != reg.Incarnation:
			return nil
		}
		err = g.cfg.Store.DeleteIdentity(ctx, cur)
		switch {
		case errors.Is(err, state.ErrConflict):
			// Changed since it was read: read it again.
		case errors.Is(err, state.ErrNotFound):
			return nil
		default:
			return err
		}
	}
	return errors.New("registrar: an identity kept changing")
}

// dropOld deletes the record and profile of a set the HSS moved to another
// default identity, unless another instance changed the record since. The
// record goes first here: it is live, not leased, and an identity it named
// is pointed at the new record already or else goes at its KeepUntil.
func (g *Registrar) dropOld(ctx context.Context, old *state.Registration) {
	if err := g.cfg.Store.DeleteRegistration(ctx, old); err != nil {
		return
	}
	if err := g.unpoint(ctx, old); err != nil {
		g.internal("deleting a moved set's identities", err)
	}
	if err := g.cfg.Store.DeleteProfile(ctx, old.Key); err != nil {
		g.internal("deleting a moved set's profile", err)
	}
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

// deregister ends the registration of r.impu's set after its last binding was
// removed. The record is first claimed for a lease without bindings, as a
// sweep claims one, so that a REGISTER of another device that lands meanwhile
// sees no registration and registers afresh; then SAR USER_DEREGISTRATION,
// and endSet. If the HSS cannot be told, the bindings are put back, or, if
// another instance changed the record meanwhile, a sweep tells the HSS after
// the lease.
func (g *Registrar) deregister(ctx context.Context, r *register, cur *state.Registration) (*state.Profile, bool, error) {
	now := g.cfg.Now()
	profile, err := g.cfg.Store.Profile(ctx, cur.Key, now)
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return nil, false, err
	}
	lease := cur.Clone()
	lease.Contacts, lease.Deregistering = nil, now.Add(state.SweepLease)
	claimed, err := g.cfg.Store.SaveRegistration(ctx, lease)
	if errors.Is(err, state.ErrConflict) {
		// A save DynamoDB applied but whose answer was lost comes back from
		// the SDK's resend as a conflict. If the record holds this lease,
		// the claim is this one's, and the HSS must still be told: answering
		// as if another had taken it would give the client a 200 that no
		// SAR backs.
		if again, f := g.set(ctx, cur.Key); f == nil && leasedBy(again, lease) {
			claimed, err = again, nil
		}
	}
	if err != nil {
		return nil, false, err
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{UserName: r.impi, PublicIdentities: []string{r.impu}, AssignmentType: cx.UserDeregistration})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	if f := g.cxFailure("SAR", res, err); f != nil {
		g.putBack(ctx, claimed, cur.Contacts)
		return nil, false, f
	}
	g.count("registrar.deregistered")
	// The HSS has the deregistration: the subscribers learn of it whatever
	// is left to clean up (TS 24.229 §5.4.2.1.2), before the record goes.
	if err := g.cfg.Events.Ended(ctx, cur, regevent.Unregistered); err != nil {
		g.internal("ending a deregistered set's subscriptions", err)
		g.count("registrar.deregistration_left_to_sweep")
		return profile, false, nil
	}
	ended, err := g.endSet(ctx, claimed, profile)
	if err != nil {
		// The HSS has taken the deregistration, so the client's is done:
		// what is left of the set holds the lease, and the sweep after it
		// finishes, as it does for an instance that stopped here.
		g.internal("finishing a deregistration", err)
		g.count("registrar.deregistration_left_to_sweep")
	}
	return profile, ended, nil
}

// putBack gives a set claimed for a deregistration that the HSS could not be
// told of its bindings back, under a new incarnation, as any record brought
// back from a lease (state.Registration.Incarnation), and points every
// identity at it. The record goes first here, unlike a registration's: only
// a save under the claimed version shows that no REGISTER took the set over
// meanwhile, whose identities pointing first would undo. If an identity then
// cannot be pointed, the record is claimed again, for the sweep after the
// lease to finish the deregistration the client asked for; failing the save,
// the lease stands for it already.
func (g *Registrar) putBack(ctx context.Context, claimed *state.Registration, bindings []state.Contact) {
	back := claimed.Clone()
	back.Contacts, back.Deregistering = bindings, time.Time{}
	inc, err := g.incarnation()
	if err != nil {
		g.count("registrar.deregistration_left_to_sweep")
		return
	}
	back.Incarnation = inc
	saved, err := g.cfg.Store.SaveRegistration(ctx, back)
	if errors.Is(err, state.ErrConflict) {
		// Applied with its answer lost, as register and deregister read
		// again (#196 QA): the record is back and holds no lease, so no
		// sweep would come for its identities.
		if again, f := g.set(ctx, back.Key); f == nil && putBackBy(again, back) {
			saved, err = again, nil
		}
	}
	if err != nil {
		g.count("registrar.deregistration_left_to_sweep")
		return
	}
	if err := g.point(ctx, saved, latestExpiry(bindings).Add(state.ProfileGrace)); err == nil {
		return
	}
	g.count("registrar.deregistration_left_to_sweep")
	lease := saved.Clone()
	lease.Contacts, lease.Deregistering = nil, g.cfg.Now().Add(state.SweepLease)
	if _, err := g.cfg.Store.SaveRegistration(ctx, lease); err != nil {
		g.internal("claiming a set put back half-pointed", err)
	}
}

// putBackBy reports whether reg is the record back was saved as: the same
// incarnation, no lease and back's bindings.
func putBackBy(reg, back *state.Registration) bool {
	return reg != nil && reg.Incarnation == back.Incarnation && reg.Deregistering.IsZero() &&
		slices.EqualFunc(reg.Contacts, back.Contacts, func(a, b state.Contact) bool { return a.CallID == b.CallID && a.CSeq == b.CSeq && a.URI == b.URI })
}

// leasedBy reports whether reg is the record lease was saved as: the same
// incarnation, no bindings and lease's Deregistering, which holds the time
// it was claimed.
func leasedBy(reg, lease *state.Registration) bool {
	return reg != nil && reg.Incarnation == lease.Incarnation && len(reg.Contacts) == 0 &&
		reg.Deregistering.Equal(lease.Deregistering)
}

// endSet finishes a deregistration the HSS has taken, of a set claimed for a
// lease without bindings: the record is read again, and if another device
// registered meanwhile, the HSS is told the set is assigned again (SAR
// REGISTRATION), since its SAR may have crossed the deregistration's.
// Otherwise the identity items that name its incarnation go, then, if still
// the one read (received), its profile, and last the record, under the
// version claimed (state.SweepRegistrations): cut short before that, the
// record keeps its lease and a sweep after it does the rest. A record already
// gone was deleted after its items, by this deregistration (a delete applied
// but reported lost) or another. It reports whether the set ended, which the
// application servers are then told of: not when another device registered
// it meanwhile, whose REGISTER told them, nor when another deregistration
// claimed it, which tells them itself (#379 code review).
func (g *Registrar) endSet(ctx context.Context, claimed *state.Registration, profile *state.Profile) (bool, error) {
	for range saveAttempts {
		now := g.cfg.Now()
		again, f := g.set(ctx, claimed.Key)
		switch {
		case f != nil:
			return false, f
		case again == nil:
			return true, nil
		case live(again, now) && again.Deregistering.IsZero():
			// A REGISTER that took the set over from the lease saved a
			// record without one (assign). A lease that is live only by
			// an unregistered user's state, which it keeps, is not one
			// (#394 code review).
			return false, g.reassign(ctx, again)
		case again.Version != claimed.Version:
			// Another deregistration claimed it since: it finishes.
			return false, nil
		}
		if err := g.unpoint(ctx, again); err != nil {
			return false, err
		}
		if profile != nil {
			if err := g.cfg.Store.DeleteProfileIf(ctx, again.Key, profile.Received); err != nil && !errors.Is(err, state.ErrConflict) {
				return false, err
			}
		}
		err := g.cfg.Store.DeleteRegistration(ctx, again)
		switch {
		case errors.Is(err, state.ErrConflict):
			// Changed since it was read, or deleted with the answer lost:
			// read again.
			continue
		case errors.Is(err, state.ErrNotFound), err == nil:
			return true, nil
		}
		return false, err
	}
	return false, errors.New("registrar: the set kept changing while it was deregistered")
}

// reassertBackoff is how long after a failed reassign a sweep tells the HSS
// again; the sweep doubles it at each failure.
const reassertBackoff = time.Minute

// reassign tells the HSS again that this S-CSCF serves reg's set, after a
// deregistration that a REGISTER of another device overtook, and points the
// set's identities at the record again, which the deregistration may have
// deleted. If the HSS cannot be told, the record is marked (Reassert) for a
// sweep to try again: the HSS may otherwise hold the set as deregistered
// while its devices are registered here.
func (g *Registrar) reassign(ctx context.Context, reg *state.Registration) error {
	g.count("registrar.reassigned")
	if err := g.point(ctx, reg, latestExpiry(reg.Contacts).Add(state.ProfileGrace)); err != nil {
		return err
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{
		UserName: reg.Key.IMPI, PublicIdentities: []string{reg.Key.IMPU},
		AssignmentType: cx.Registration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable,
	})
	if err == nil && saa != nil && cxclient.Classify(saa.Result) == cxclient.Success {
		return nil
	}
	g.count("registrar.hss_failed")
	g.count("registrar.reassert_failed")
	return g.markReassert(ctx, reg)
}

// markReassert sets reg's Reassert, under the version read, unless the
// record is no longer live or already marked.
func (g *Registrar) markReassert(ctx context.Context, reg *state.Registration) error {
	for range saveAttempts {
		now := g.cfg.Now()
		if !live(reg, now) || !reg.Reassert.IsZero() {
			return nil
		}
		next := reg.Clone()
		next.Reassert, next.ReassertAttempts = now.Add(reassertBackoff), 1
		_, err := g.cfg.Store.SaveRegistration(ctx, next)
		if !errors.Is(err, state.ErrConflict) {
			return err
		}
		again, f := g.set(ctx, reg.Key)
		if f != nil {
			return f
		}
		if again == nil {
			return nil
		}
		reg = again
	}
	return errors.New("registrar: the set kept changing while it was marked")
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
func (g *Registrar) ok(req *sip.Request, r *register, bindings []state.Contact, set *state.Registration) *sip.Response {
	res := g.response(req, 200, "")
	now := g.cfg.Now()
	var fields [][2]string
	for _, c := range bindings {
		fields = append(fields, [2]string{"Contact", contactField(c, now)})
	}
	for _, p := range r.path {
		fields = append(fields, [2]string{"Path", p})
	}
	if set != nil && len(bindings) > 0 {
		u := g.cfg.ServiceRoute
		u.Params = append(sip.Params(nil), u.Params...)
		if _, ok := u.Param("transport"); !ok {
			// pcscf resolves a route without it as UDP, and reaches the
			// core over TCP only (#208).
			u.Params.Set("transport", "tcp")
		}
		u.Params.SetFlag("lr")
		u.Params.SetFlag("orig")
		fields = append(fields, [2]string{"Service-Route", "<" + u.String() + ">"})
		fields = append(fields, [2]string{"P-Associated-URI", "<" + set.Key.IMPU + ">"})
		for _, id := range set.Identities {
			if !id.Barred && id.IMPU != set.Key.IMPU {
				fields = append(fields, [2]string{"P-Associated-URI", "<" + id.IMPU + ">"})
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
