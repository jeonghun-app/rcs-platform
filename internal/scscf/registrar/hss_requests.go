package registrar

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

var (
	resultSuccess        = cx.ResultCode(diameter.ResultSuccess)
	resultUnableToComply = cx.ResultCode(diameter.ResultUnableToComply)
	// resultTooBusy is a protocol error (RFC 6733 §7.1.3), which the HSS
	// sends again to another S-CSCF peer (internal/hss, push.go).
	resultTooBusy = cx.ResultCode(diameter.ResultTooBusy)
)

// HandleRTR answers a Registration-Termination-Request (TS 29.228 §6.1.3),
// for cxclient.Config.OnRTR. The sets of the identities it names, or every
// set of its private identity, and of its Associated-Identities as well
// (§6.1.3.1), end: their records, the identities that name them, and their
// profiles. Unregistered users' records end the same way, and with
// REMOVE_SCSCF they are the only ones that do: that reason takes back what an
// unregistered user left assigned (TS 29.229 §6.3.16). A SERVER_CHANGE ends
// the profile by the key the record names, so nothing stays under a default
// identity the HSS is about to change.
//
// A private identity's sets are listed through an index, which may miss one
// saved within the last moments; the sweep deregisters that one when it
// expires.
func (g *Registrar) HandleRTR(ctx context.Context, r *cx.RTR) cx.Result {
	impis := []string{r.UserName}
	for _, a := range r.AssociatedIdentities {
		if !slices.Contains(impis, a) {
			impis = append(impis, a)
		}
	}
	var keys []state.SetKey
	if len(r.PublicIdentities) > 0 {
		for _, s := range r.PublicIdentities {
			impu, ok := identity.CanonicalIMPU(s)
			if !ok {
				continue
			}
			id, err := g.cfg.Store.Identity(ctx, impu, g.cfg.Now())
			switch {
			case errors.Is(err, state.ErrNotFound):
				continue
			case err != nil:
				g.log.Error("registrar: RTR: reading an identity", slog.String("error", err.Error()))
				return resultUnableToComply
			}
			if slices.Contains(impis, id.Set.IMPI) && !slices.Contains(keys, id.Set) {
				keys = append(keys, id.Set)
			}
		}
	} else {
		for _, impi := range impis {
			regs, err := g.cfg.Store.RegistrationsOf(ctx, impi)
			if err != nil {
				g.log.Error("registrar: RTR: listing registrations", slog.String("error", err.Error()))
				return resultUnableToComply
			}
			for _, reg := range regs {
				keys = append(keys, reg.Key)
			}
		}
	}
	// Every set is tried, whatever one of them does: the HSS does not send
	// the RTR again unless told to (#394 code review).
	ended, result := 0, resultSuccess
	for _, k := range keys {
		cause := regevent.Deactivated
		if r.DeregistrationReason.Code == cx.PermanentTermination {
			cause = regevent.Rejected
		}
		done, err := g.endSetNow(ctx, k, r.DeregistrationReason.Code == cx.RemoveSCSCF, cause)
		switch {
		case errors.Is(err, errClaimBusy):
			g.log.Error("registrar: RTR: ending a set", slog.String("error", err.Error()))
			if result == resultSuccess {
				result = resultTooBusy
			}
		case err != nil:
			g.log.Error("registrar: RTR: ending a set", slog.String("error", err.Error()))
			result = resultUnableToComply
		case done:
			ended++
		}
	}
	g.cfg.Metrics.Count("registrar.rtr_deregistered", int64(ended))
	return result
}

// errClaimBusy is a claim of an RTR's lease that the store failed to save
// for a reason that may pass, as a throttled write whose SDK retries are
// spent: the RTR is answered DIAMETER_TOO_BUSY, so that the HSS sends it
// again, rather than leave the set live (#394 code review).
var errClaimBusy = errors.New("registrar: the store did not save an RTR's claim")

// endSetNow ends set k at the HSS's request: it claims the record for a
// deregistration's lease, tells the subscribers (Events.Ended), and then
// removes its identities, its profile if still the one read, and last the
// record, under the version claimed, as every deregistration does
// (endSet); a record that changed meanwhile is read again and ended too.
// Cut short after the claim, by a stop or a store failure, it leaves the
// lease for the sweep to finish, and counts as done. A claim the store
// fails to save is tried again with the record read again, and then is
// errClaimBusy, unless the store refused it as invalid. With
// unregisteredOnly it ends k only as an unregistered user's record, and one
// that a REGISTER turned into a registration meanwhile has its identities
// pointed at it again. It reports whether it ended one.
func (g *Registrar) endSetNow(ctx context.Context, k state.SetKey, unregisteredOnly bool, cause regevent.Cause) (bool, error) {
	touched := false
	var claimErr error
	for attempt := range saveAttempts {
		now := g.cfg.Now()
		reg, f := g.set(ctx, k)
		switch {
		case f != nil:
			return false, f
		case reg == nil:
			return touched, nil
		case unregisteredOnly && (reg.Unregistered.IsZero() || len(reg.Contacts) > 0):
			if touched {
				return false, g.point(ctx, reg, keepUntil(reg).Add(state.ProfileGrace))
			}
			return false, nil
		}
		profile, err := g.cfg.Store.Profile(ctx, k, now)
		if err != nil && !errors.Is(err, state.ErrNotFound) {
			return false, err
		}
		touched = true
		// The record is claimed for a deregistration's lease first, as a
		// user's deregistration claims it (deregister): the HSS does not
		// send the RTR again (its pushes are logged, not retried), so a
		// stop or a store failure from here on leaves the lease, and the
		// sweep after it tells the HSS (which refuses, as it ended the
		// set), calls Ended and deletes the set (#368). The mark says why
		// the set ended, and stays once set: a later RTR of another
		// reason does not make a rejection less of one.
		lease := reg.Clone()
		lease.Contacts, lease.Deregistering = nil, now.Add(state.SweepLease)
		lease.Rejected = reg.Rejected || cause == regevent.Rejected
		claimed, err := g.cfg.Store.SaveRegistration(ctx, lease)
		switch {
		case errors.Is(err, state.ErrConflict):
			continue
		case errors.Is(err, state.ErrInvalid):
			return false, err
		case err != nil:
			// The HSS does not send the RTR again: a write that failed
			// once, its SDK retries spent, often succeeds a moment later
			// (#394 QA), as a listing does (regevent).
			claimErr = err
			if attempt < saveAttempts-1 {
				select {
				case <-time.After(time.Duration(10<<attempt+mathrand.IntN(10)) * time.Millisecond):
				case <-ctx.Done():
					return false, fmt.Errorf("%w: %w", errClaimBusy, ctx.Err())
				}
			}
			continue
		}
		claimErr = nil
		// The subscriptions end before the record does, told of the
		// bindings it had.
		if err := g.cfg.Events.Ended(ctx, reg, cause); err != nil {
			return g.leftToSweep("ending a set's subscriptions for an RTR", err)
		}
		if err := g.unpoint(ctx, reg); err != nil {
			return g.leftToSweep("removing the identities of a set an RTR ends", err)
		}
		if profile != nil {
			// Only the one read: a REGISTER that lands meanwhile saves its
			// own, which this RTR then does not end.
			if err := g.cfg.Store.DeleteProfileIf(ctx, k, profile.Received); err != nil && !errors.Is(err, state.ErrConflict) {
				return g.leftToSweep("removing the profile of a set an RTR ends", err)
			}
		}
		err = g.cfg.Store.DeleteRegistration(ctx, claimed)
		switch {
		case errors.Is(err, state.ErrConflict):
			continue
		case errors.Is(err, state.ErrNotFound), err == nil:
			return true, nil
		}
		return g.leftToSweep("removing a set an RTR ends", err)
	}
	if claimErr != nil {
		return false, fmt.Errorf("%w: %w", errClaimBusy, claimErr)
	}
	return false, errors.New("registrar: the set kept changing")
}

// leftToSweep is endSetNow cut short by err after its claim: the lease
// stands, and the sweep after it finishes the set, so the RTR has done its
// part.
func (g *Registrar) leftToSweep(what string, err error) (bool, error) {
	g.internal(what, err)
	g.count("registrar.rtr_left_to_sweep")
	return true, nil
}

// HandlePPR answers a Push-Profile-Request (TS 29.228 §6.2.2), for
// cxclient.Config.OnPPR. Its User-Data is one implicit registration set's,
// stored under that set's key only, so the user's other sets keep theirs. A
// PPR never changes a set's default identity, which the HSS does with RTR
// SERVER_CHANGE, so the set is the record under the default the User-Data
// names. Its identities follow the User-Data: one that moved in from
// another set is pointed at this one, and one that left is unpointed if it
// still names this set; the set it moved to points it on its own PPR.
//
// A PPR for a set without a live record here, of a private identity with no
// live record here at all, is answered DIAMETER_ERROR_USER_UNKNOWN, which
// tells the HSS this S-CSCF lost the user (TS 29.228 §6.2.2.1); one of a
// user who has another set live here, UNABLE_TO_COMPLY. User-Data the
// S-CSCF cannot read is DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA and too much
// of it DIAMETER_ERROR_TOO_MUCH_DATA, after which the HSS deregisters the
// user.
func (g *Registrar) HandlePPR(ctx context.Context, r *cx.PPR) cx.Result {
	if len(r.UserData) == 0 {
		// Charging information or a new Digest credential only: the S-CSCF
		// keeps neither, a challenge asks the HSS afresh.
		return resultSuccess
	}
	if len(r.UserData) > state.MaxUserData {
		g.count("registrar.ppr_refused")
		return cx.ExperimentalResult(cx.ErrorTooMuchData)
	}
	set, err := parseSet(r.UserData)
	if err != nil {
		g.count("registrar.ppr_refused")
		return cx.ExperimentalResult(cx.ErrorNotSupportedUserData)
	}
	key := state.SetKey{IMPI: r.UserName, IMPU: set.defaultID}
	received := g.cfg.Now()
	for range saveAttempts {
		reg, f := g.set(ctx, key)
		if f != nil {
			return resultUnableToComply
		}
		if reg == nil || !live(reg, received) {
			return g.notServed(ctx, r.UserName, received)
		}
		p := &state.Profile{Key: key, UserData: r.UserData, Received: received, KeepUntil: keepUntil(reg).Add(state.ProfileGrace)}
		if err := g.cfg.Store.SaveProfile(ctx, p); err != nil && !errors.Is(err, state.ErrConflict) {
			// ErrConflict: an SAA that arrived after this PPR was stored first,
			// and it is the newer.
			g.log.Error("registrar: PPR: saving the profile", slog.String("error", err.Error()))
			return resultUnableToComply
		}
		if slices.Equal(reg.Identities, set.identities) {
			g.count("registrar.ppr_stored")
			return resultSuccess
		}
		next := reg.Clone()
		next.Identities = set.identities
		saved, err := g.cfg.Store.SaveRegistration(ctx, next)
		switch {
		case errors.Is(err, state.ErrConflict), errors.Is(err, state.ErrNotFound):
			// A REGISTER or a deregistration changed the set: apply this to
			// what it left.
			continue
		case err != nil:
			g.log.Error("registrar: PPR: saving the set", slog.String("error", err.Error()))
			return resultUnableToComply
		}
		if err := g.point(ctx, saved, p.KeepUntil); err != nil {
			g.log.Error("registrar: PPR: pointing the identities", slog.String("error", err.Error()))
			return resultUnableToComply
		}
		left := *reg
		left.Identities = slices.DeleteFunc(slices.Clone(reg.Identities), func(id state.SetIdentity) bool {
			return slices.ContainsFunc(set.identities, func(n state.SetIdentity) bool { return n.IMPU == id.IMPU })
		})
		if err := g.unpoint(ctx, &left); err != nil {
			// The set is stored as the PPR says; an identity that left it
			// and still names it goes at its KeepUntil.
			g.log.Error("registrar: PPR: unpointing the identities that left", slog.String("error", err.Error()))
			g.count("registrar.ppr_unpoint_failed")
		}
		g.cfg.Events.Changed(ctx, reg, saved, regevent.Changed)
		g.count("registrar.ppr_stored")
		return resultSuccess
	}
	return resultUnableToComply
}

// notServed answers a PPR for a set without a live record here: 5001, which
// makes the HSS mark the user not registered (TS 29.228 §6.2.2.1), only if
// no set of the user is live here either.
func (g *Registrar) notServed(ctx context.Context, impi string, now time.Time) cx.Result {
	regs, err := g.cfg.Store.RegistrationsOf(ctx, impi)
	if err != nil {
		return resultUnableToComply
	}
	if !slices.ContainsFunc(regs, func(r *state.Registration) bool { return live(r, now) }) {
		g.count("registrar.ppr_unknown")
		return cx.ExperimentalResult(cx.ErrorUserUnknown)
	}
	g.count("registrar.ppr_other_set")
	return resultUnableToComply
}

// keepUntil is the latest time reg serves terminating requests.
func keepUntil(reg *state.Registration) time.Time {
	t := latestExpiry(reg.Contacts)
	if reg.Unregistered.After(t) {
		t = reg.Unregistered
	}
	return t
}
