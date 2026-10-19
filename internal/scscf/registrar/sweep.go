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

// Sweep runs one deregistration sweep (state.SweepRegistrations): bindings
// that have expired are removed, and a registration left without any, or an
// unregistered user's record whose state has ended, is deregistered with
// the HSS (SAR TIMEOUT_DEREGISTRATION, TS 29.228 §6.1.2) and deleted with,
// once no identity of its set has bindings left, the set's profile. It
// returns how many registrations it handled.
func (g *Registrar) Sweep(ctx context.Context, limit int) (int, error) {
	return state.SweepRegistrations(ctx, g.cfg.Store, g.cfg.Now(), limit, func(before, after *state.Registration) error {
		return g.swept(ctx, before, after)
	})
}

// swept handles one registration a sweep changed. A failure that may pass,
// such as an HSS out of reach, is an error, so a sweep after the lease tries
// again; a permanent one is not (state.SweepRegistrations).
func (g *Registrar) swept(ctx context.Context, before, after *state.Registration) error {
	if len(after.Contacts) > 0 {
		// Some bindings expired, others remain: nothing to tell the HSS.
		return nil
	}
	// Read before the SAR, so that only this profile goes: a device that
	// registers the set again meanwhile saves one of its own.
	profile, err := g.cfg.Store.Profile(ctx, before.ProfileKey(), g.cfg.Now())
	if err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	}
	saa, err := g.cfg.HSS.SAR(ctx, &cx.SAR{
		UserName: before.IMPI, PublicIdentities: []string{before.IMPU}, AssignmentType: cx.TimeoutDeregistration,
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
	case cxclient.UserUnknown, cxclient.IdentitiesDontMatch, cxclient.NotRegistered, cxclient.Rejected:
		// The HSS will not answer differently: the user is gone there, or
		// was never registered here.
		g.count("registrar.expired_refused")
	default:
		g.count("registrar.expire_failed")
		return errors.New("registrar: SAR TIMEOUT_DEREGISTRATION failed: " + o.String())
	}
	if profile == nil {
		return nil
	}
	return g.dropProfileIfIdle(ctx, before, profile.Received)
}

// dropProfileIfIdle deletes the profile of gone's set, if it is still the one
// received at received, unless another identity of the set still has
// bindings, as one whose save failed halfway might.
func (g *Registrar) dropProfileIfIdle(ctx context.Context, gone *state.Registration, received time.Time) error {
	others, err := g.cfg.Store.RegistrationsOf(ctx, gone.IMPI)
	if err != nil {
		return err
	}
	now := g.cfg.Now()
	for _, o := range others {
		if o.IMPU != gone.IMPU && o.DefaultIMPU == gone.DefaultIMPU && live(o, now) {
			return nil
		}
	}
	if err := g.cfg.Store.DeleteProfileIf(ctx, gone.ProfileKey(), received); err != nil && !errors.Is(err, state.ErrConflict) {
		return err
	}
	return nil
}

// RunSweeps sweeps every interval, as many times as it takes to find fewer
// than limit registrations due, until ctx ends. Every instance runs it; the
// store lets one instance handle each registration.
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
		for {
			n, err := g.Sweep(ctx, limit)
			if err != nil {
				// The errors name no identity (state.SweepRegistrations joins
				// the store's and swept's own).
				g.log.Warn("registrar: sweep", slog.Int("handled", n), slog.String("error", err.Error()))
			}
			if n < limit || ctx.Err() != nil {
				break
			}
		}
	}
}
