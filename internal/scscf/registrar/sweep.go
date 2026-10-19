package registrar

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
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
// deregistration does (endSet). It returns how many sets it handled.
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
		// Some bindings expired, others remain: nothing to tell the HSS.
		return nil
	}
	// Read before the SAR, so that only this profile goes: a device that
	// registers the set again meanwhile saves one of its own.
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
	switch o {
	case cxclient.Success:
		g.count("registrar.expired")
	case cxclient.UserUnknown, cxclient.IdentitiesDontMatch, cxclient.NotRegistered, cxclient.ServedElsewhere, cxclient.Rejected:
		// The HSS will not answer differently: the user is gone there, was
		// never registered here, or is served by another S-CSCF now.
		g.count("registrar.expired_refused")
	default:
		g.count("registrar.expire_failed")
		return errors.New("registrar: SAR TIMEOUT_DEREGISTRATION failed: " + o.String())
	}
	return g.endSet(ctx, after, profile)
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
