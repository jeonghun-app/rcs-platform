package registrar

import (
	"context"
	"errors"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// Errors of Unregistered.
var (
	// ErrUnknownUser means the HSS knows no user by the identity.
	ErrUnknownUser = errors.New("registrar: unknown user")
	// ErrServedElsewhere means another S-CSCF serves the user.
	ErrServedElsewhere = errors.New("registrar: the user is served by another S-CSCF")
	// ErrHSSUnavailable means the HSS could not be asked.
	ErrHSSUnavailable = errors.New("registrar: the HSS is unavailable")
)

// Unregistered makes impu, an identity with no record here, an unregistered
// user served by this S-CSCF, for a terminating request to it (TS 24.229
// §5.4.3.3): SAR UNREGISTERED_USER (TS 29.228 §6.1.2), which names the user
// and returns the profile, then a record of the user's implicit set without
// bindings, its Unregistered UnregisteredTTL ahead, with the profile and
// the identities pointing at it, as a REGISTER saves them. Later requests
// find the record until a sweep ends that state with the HSS, and a REGISTER
// turns it into a registration. A record another request saved meanwhile is
// returned with the SAA's profile applied (applySAAProfile); if it is a
// registration, the HSS, which the SAR made hold the user unregistered, is
// told again (reassign).
//
// It fails with ErrUnknownUser, ErrServedElsewhere or ErrHSSUnavailable for
// what the HSS answered, or with the store's error.
func (g *Registrar) Unregistered(ctx context.Context, impu string) (*state.Registration, error) {
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{PublicIdentities: []string{impu}, AssignmentType: cx.UnregisteredUser})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	o := cxclient.Classify(res)
	if err != nil {
		o = cxclient.ErrorOutcome(err)
	}
	switch o {
	case cxclient.Success:
	case cxclient.UserUnknown, cxclient.IdentitiesDontMatch:
		g.count("registrar.unregistered_unknown")
		return nil, ErrUnknownUser
	case cxclient.ServedElsewhere:
		return nil, ErrServedElsewhere
	case cxclient.Unavailable:
		g.count("registrar.hss_unavailable")
		return nil, ErrHSSUnavailable
	default:
		g.count("registrar.hss_failed")
		return nil, errors.New("registrar: SAR UNREGISTERED_USER failed: " + o.String())
	}
	received := g.cfg.Now()
	set, err := parseSet(saa.UserData)
	if err != nil || !set.has(impu) || saa.UserName == "" {
		g.internal("reading an unregistered user's profile", err)
		return nil, errors.New("registrar: the SAA names no user or set of the identity")
	}
	key := state.SetKey{IMPI: saa.UserName, IMPU: set.defaultID}
	if cur, f := g.set(ctx, key); f != nil {
		return nil, f
	} else if cur != nil {
		// The SAA's profile may be newer than the record's (#536).
		cur = g.applySAAProfile(ctx, cur, saa.UserData)
		if isRegistered(cur) {
			// The set is registered here after all, and only impu's item
			// was missing (a REGISTER cut short between its save and its
			// pointers, a PPR meanwhile): the SAR just made the HSS hold
			// the user unregistered. Its items are pointed and the HSS is
			// told again, as after a deregistration a REGISTER overtook
			// (#359 security review).
			g.count("registrar.unregistered_was_registered")
			if err := g.reassign(ctx, cur); err != nil {
				g.internal("telling the HSS again of a registered set", err)
			}
		}
		return cur, nil
	}
	until := received.Add(g.cfg.UnregisteredTTL)
	keep := until.Add(state.ProfileGrace)
	err = g.cfg.Store.SaveProfile(ctx, &state.Profile{Key: key, UserData: saa.UserData, Received: received, KeepUntil: keep})
	if err != nil && !errors.Is(err, state.ErrConflict) {
		return nil, err
	}
	inc, err := g.incarnation()
	if err != nil {
		return nil, err
	}
	n := &state.Registration{Key: key, Incarnation: inc, Identities: set.identities, Unregistered: until.Truncate(time.Second)}
	if err := g.pointAhead(ctx, n, keep); err != nil {
		return nil, err
	}
	saved, err := g.cfg.Store.SaveRegistration(ctx, n)
	if errors.Is(err, state.ErrExists) {
		// Another request, or a REGISTER, saved the set first.
		if cur, f := g.set(ctx, key); f == nil && cur != nil {
			return cur, nil
		}
	}
	if err != nil {
		return nil, err
	}
	g.count("registrar.unregistered")
	return saved, nil
}
