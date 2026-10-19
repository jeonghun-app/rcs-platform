package registrar

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

var (
	resultSuccess        = cx.ResultCode(diameter.ResultSuccess)
	resultUnableToComply = cx.ResultCode(diameter.ResultUnableToComply)
)

// HandleRTR answers a Registration-Termination-Request (TS 29.228 §6.1.3),
// for cxclient.Config.OnRTR: the registrations of the identities it names,
// with their implicit sets, or of every identity of its private identity,
// are deleted with their profiles. Unregistered users' records go the same
// way. With SERVER_CHANGE the user registers again elsewhere, possibly with
// another default identity, so the profile goes by the key the registration
// names (ProfileKey) rather than any the RTR implies.
//
// The registrations are listed through an index, which may miss one saved
// within the last moments; the sweep deregisters that one when it expires.
func (g *Registrar) HandleRTR(ctx context.Context, r *cx.RTR) cx.Result {
	regs, err := g.cfg.Store.RegistrationsOf(ctx, r.UserName)
	if err != nil {
		g.log.Error("registrar: RTR: listing registrations", slog.String("error", err.Error()))
		return resultUnableToComply
	}
	sets := map[string]bool{}
	for _, reg := range regs {
		if len(r.PublicIdentities) == 0 || named(r.PublicIdentities, reg.IMPU) {
			sets[reg.DefaultIMPU] = true
		}
	}
	keys := map[state.ProfileKey]bool{}
	for _, reg := range regs {
		if !sets[reg.DefaultIMPU] {
			continue
		}
		if err := g.deleteRegistration(ctx, reg); err != nil {
			g.log.Error("registrar: RTR: deleting a registration", slog.String("error", err.Error()))
			return resultUnableToComply
		}
		keys[reg.ProfileKey()] = true
	}
	for k := range keys {
		if err := g.cfg.Store.DeleteProfile(ctx, k); err != nil {
			g.log.Error("registrar: RTR: deleting a profile", slog.String("error", err.Error()))
			return resultUnableToComply
		}
	}
	g.cfg.Metrics.Count("registrar.rtr_deregistered", int64(len(keys)))
	return resultSuccess
}

// named reports whether impu is in list, compared in canonical form.
func named(list []string, impu string) bool {
	for _, s := range list {
		if c, ok := identity.CanonicalIMPU(s); ok && c == impu {
			return true
		}
	}
	return false
}

// deleteRegistration deletes reg, reading it again if it changed since it
// was listed. One already gone is no error.
func (g *Registrar) deleteRegistration(ctx context.Context, reg *state.Registration) error {
	for range saveAttempts {
		err := g.cfg.Store.DeleteRegistration(ctx, reg)
		if !errors.Is(err, state.ErrConflict) {
			if errors.Is(err, state.ErrNotFound) {
				return nil
			}
			return err
		}
		if reg, err = g.cfg.Store.Registration(ctx, reg.IMPU); errors.Is(err, state.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
	}
	return errors.New("registrar: the registration kept changing")
}

// HandlePPR answers a Push-Profile-Request (TS 29.228 §6.2.2), for
// cxclient.Config.OnPPR. Its User-Data is one implicit registration set's,
// stored under that set's key only, so the user's other sets keep theirs.
// The set may have changed: the registrations of its identities follow its
// default identity, an identity added to it is registered like the others,
// one removed from it is deregistered, and the profile under a former
// default identity is deleted.
//
// A PPR for a user with no registration of the set here is answered
// DIAMETER_ERROR_USER_UNKNOWN, which tells the HSS this S-CSCF lost the user
// (TS 29.228 §6.2.2.1); User-Data the S-CSCF cannot read is answered
// DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA, and the HSS deregisters the user.
func (g *Registrar) HandlePPR(ctx context.Context, r *cx.PPR) cx.Result {
	if len(r.UserData) == 0 {
		// Charging information or a new Digest credential only: the S-CSCF
		// keeps neither, a challenge asks the HSS afresh.
		return resultSuccess
	}
	received := g.cfg.Now()
	if len(r.UserData) > state.MaxUserData {
		return cx.ExperimentalResult(cx.ErrorTooMuchData)
	}
	set, err := parseSet(r.UserData)
	if err != nil {
		g.count("registrar.ppr_refused")
		return cx.ExperimentalResult(cx.ErrorNotSupportedUserData)
	}
	regs, err := g.cfg.Store.RegistrationsOf(ctx, r.UserName)
	if err != nil {
		g.log.Error("registrar: PPR: listing registrations", slog.String("error", err.Error()))
		return resultUnableToComply
	}
	// The set's registrations: its identities', and those that named one of
	// its identities as their default, which an identity removed from the
	// set still does.
	oldDefaults := map[string]bool{}
	var members []*state.Registration
	for _, reg := range regs {
		if set.has(reg.IMPU) {
			members = append(members, reg)
			oldDefaults[reg.DefaultIMPU] = true
		}
	}
	if len(members) == 0 {
		g.count("registrar.ppr_unknown")
		return cx.ExperimentalResult(cx.ErrorUserUnknown)
	}
	key := state.ProfileKey{IMPI: r.UserName, IMPU: set.defaultID}
	p := &state.Profile{Key: key, UserData: r.UserData, Received: received, KeepUntil: keepUntil(members).Add(state.ProfileGrace)}
	if err := g.cfg.Store.SaveProfile(ctx, p); err != nil && !errors.Is(err, state.ErrConflict) {
		// ErrConflict: an SAA that arrived after this PPR was stored first,
		// and it is the newer.
		g.log.Error("registrar: PPR: saving the profile", slog.String("error", err.Error()))
		return resultUnableToComply
	}
	if err := g.reconcile(ctx, r.UserName, set, regs, members, oldDefaults); err != nil {
		g.log.Error("registrar: PPR: updating the set", slog.String("error", err.Error()))
		return resultUnableToComply
	}
	g.count("registrar.ppr_stored")
	return resultSuccess
}

// keepUntil is the latest time any of regs serves terminating requests.
func keepUntil(regs []*state.Registration) (t time.Time) {
	for _, r := range regs {
		if e := latestExpiry(r.Contacts); e.After(t) {
			t = e
		}
		if r.Unregistered.After(t) {
			t = r.Unregistered
		}
	}
	return t
}

// reconcile makes the registrations of impi match set (see HandlePPR).
func (g *Registrar) reconcile(ctx context.Context, impi string, set *implicitSet, regs, members []*state.Registration, oldDefaults map[string]bool) error {
	// The bindings an added identity gets: those of a member, all of which
	// hold the same.
	template := members[0]
	for _, id := range set.identities {
		i := slices.IndexFunc(regs, func(r *state.Registration) bool { return r.IMPU == id.impu })
		var cur *state.Registration
		if i >= 0 {
			cur = regs[i]
			if cur.DefaultIMPU == set.defaultID {
				continue
			}
		}
		next := &state.Registration{
			IMPU: id.impu, IMPI: impi, DefaultIMPU: set.defaultID,
			Contacts: template.Contacts, Unregistered: template.Unregistered,
		}
		if cur != nil {
			next = cur.Clone()
			next.DefaultIMPU = set.defaultID
		}
		if _, err := g.cfg.Store.SaveRegistration(ctx, next); err != nil && !errors.Is(err, state.ErrConflict) && !errors.Is(err, state.ErrExists) {
			// A conflict means a REGISTER saved it meanwhile, with the set
			// as its SAA had it.
			return err
		}
	}
	for _, reg := range regs {
		if oldDefaults[reg.DefaultIMPU] && !set.has(reg.IMPU) {
			if err := g.deleteRegistration(ctx, reg); err != nil {
				return err
			}
		}
	}
	for d := range oldDefaults {
		if d != set.defaultID {
			if err := g.cfg.Store.DeleteProfile(ctx, state.ProfileKey{IMPI: impi, IMPU: d}); err != nil {
				return err
			}
		}
	}
	return nil
}
