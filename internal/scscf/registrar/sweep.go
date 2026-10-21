package registrar

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// Defaults of RunSweeps.
const (
	DefaultSweepInterval = 10 * time.Second
	DefaultSweepLimit    = 100
)

// Sweep runs one deregistration sweep (state.SweepRegistrations) over up to
// limit sets: bindings that have expired are removed, and a set left without
// any, or an unregistered user's record whose state has ended, is
// deregistered with the HSS, once for the whole set (SAR
// TIMEOUT_DEREGISTRATION, TS 29.228 §6.1.2), and ends as a user's
// deregistration does (endSet). A live set whose Reassert is due is
// reasserted (reassert). It returns how many sets it handled.
func (g *Registrar) Sweep(ctx context.Context, limit int) (int, error) {
	return state.SweepRegistrations(ctx, g.cfg.Store, g.cfg.Now(), limit, func(before, after *state.Registration) error {
		return g.swept(ctx, before, after)
	})
}

// swept handles one set a sweep changed. A failure that may pass, such as an
// HSS out of reach, is an error, so a sweep after the lease tries again; a
// permanent one is not (state.SweepRegistrations).
func (g *Registrar) swept(ctx context.Context, before, after *state.Registration) error {
	if len(after.Contacts) > 0 {
		if before.ReassertDue(g.cfg.Now()) {
			// The sweep may have pruned bindings too, which the
			// subscribers must hear of whatever the reassertion does.
			if len(after.Contacts) != len(before.Contacts) {
				g.cfg.Events.Changed(ctx, before, after, regevent.Expired)
			}
			return g.reassert(ctx, after)
		}
		// Some bindings expired, others remain: nothing to tell the HSS,
		// but the subscribers.
		g.cfg.Events.Changed(ctx, before, after, regevent.Expired)
		return nil
	}
	// The profile endSet may delete, and only if still this one
	// (DeleteProfileIf): a device that registers the set again after the
	// SAR saves its own, and endSet then finds the set live anyway.
	profile, err := g.cfg.Store.Profile(ctx, before.Key, g.cfg.Now())
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{
		UserName: before.Key.IMPI, PublicIdentities: []string{before.Key.IMPU}, AssignmentType: cx.TimeoutDeregistration,
	})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	o := cxclient.Classify(res)
	if err != nil {
		o = cxclient.ErrorOutcome(err)
	}
	switch {
	case o == cxclient.Success:
		g.count("registrar.expired")
	case permanent(o):
		g.count("registrar.expired_refused")
	default:
		g.count("registrar.expire_failed")
		return errors.New("registrar: SAR TIMEOUT_DEREGISTRATION failed: " + o.String())
	}
	cause := regevent.Expired
	if before.Rejected {
		// An RTR's end the sweep finishes (endSetNow).
		cause = regevent.Rejected
	}
	if err := g.cfg.Events.Ended(ctx, before, cause); err != nil {
		// The record keeps its lease: the sweep after it tries again.
		return err
	}
	ended, err := g.endSet(ctx, after, profile)
	if ended {
		g.endedByNetwork(ctx, before, profile)
	}
	return err
}

// permanent reports whether an SAR's outcome is one the HSS will not answer
// differently: the user is gone there, was never registered here, or is
// served by another S-CSCF now.
func permanent(o cxclient.Outcome) bool {
	switch o {
	case cxclient.UserUnknown, cxclient.IdentitiesDontMatch, cxclient.NotRegistered, cxclient.ServedElsewhere, cxclient.Rejected:
		return true
	}
	return false
}

// maxReassertTries is how many times sweeps tell the HSS again that this
// S-CSCF serves a set (reassert) before giving up: with reassertBackoff
// doubling, about half an hour after the first failure.
const maxReassertTries = 5

// reassert tells the HSS again that this S-CSCF serves reg's set (SAR
// REGISTRATION, TS 29.228 §6.1.2), which a deregistration's SAR that crossed
// a REGISTER's may have undone, and clears Reassert. A failure that may pass
// moves Reassert on by a doubled reassertBackoff, until maxReassertTries; a
// permanent one, or the last, gives up, counted, and the set's next
// re-registration tells the HSS anyway. Saves are conditional on the version
// the sweep claimed: a REGISTER that saved the set meanwhile told the HSS
// itself and left no Reassert.
func (g *Registrar) reassert(ctx context.Context, reg *state.Registration) error {
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{
		UserName: reg.Key.IMPI, PublicIdentities: []string{reg.Key.IMPU},
		AssignmentType: cx.Registration, UserDataAlreadyAvailable: cx.UserDataAlreadyAvailable,
	})
	var res cx.Result
	if saa != nil {
		res = saa.Result
	}
	o := cxclient.Classify(res)
	if err != nil {
		o = cxclient.ErrorOutcome(err)
	}
	next := reg.Clone()
	switch {
	case o == cxclient.Success:
		g.count("registrar.reasserted")
		next.Reassert, next.ReassertAttempts = time.Time{}, 0
	case !permanent(o) && reg.ReassertAttempts < maxReassertTries:
		g.count("registrar.reassert_failed")
		next.ReassertAttempts++
		next.Reassert = g.cfg.Now().Add(reassertBackoff << (next.ReassertAttempts - 1))
	default:
		g.count("registrar.reassert_abandoned")
		next.Reassert, next.ReassertAttempts = time.Time{}, 0
	}
	_, err = g.cfg.Store.SaveRegistration(ctx, next)
	if errors.Is(err, state.ErrConflict) || errors.Is(err, state.ErrNotFound) {
		return nil
	}
	return err
}

// sweepAll sweeps as many times as it takes to find fewer than limit sets
// due, so that a mass expiry drains in one run rather than limit per
// interval, and returns how many it handled.
func (g *Registrar) sweepAll(ctx context.Context, limit int) int {
	total := 0
	for {
		n, err := g.Sweep(ctx, limit)
		total += n
		if err != nil {
			// The errors name no identity (state.SweepRegistrations joins
			// the store's and swept's own).
			g.log.Warn("registrar: sweep", slog.Int("handled", n), slog.String("error", err.Error()))
		}
		if n < limit || ctx.Err() != nil {
			return total
		}
	}
}

// RunSweeps runs sweepAll every interval until ctx ends. Every instance runs
// it; the store lets one instance handle each set.
func (g *Registrar) RunSweeps(ctx context.Context, interval time.Duration, limit int) {
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	if limit <= 0 {
		limit = DefaultSweepLimit
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.sweepAll(ctx, limit)
	}
}
