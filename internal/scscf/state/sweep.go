package state

import (
	"context"
	"errors"
	"time"
)

// SweepLease is how long the instance whose sweep claimed a registration left
// without contacts has to handle its deregistration before any sweep may try
// again: long enough for a SAR and a NOTIFY, short enough that one that fails,
// or an instance that stops midway, is retried soon.
const SweepLease = time.Minute

// TerminatedGrace is how long a subscription claimed by a sweep, or ended by
// the S-CSCF (Terminated), stays before a sweep deletes it: the time to send
// its final NOTIFY with NextNotify. It counts from the claim.
const TerminatedGrace = time.Minute

// SweepRegistrations removes the contacts that have expired at now from up to
// limit registrations, and calls handle for each registration it changed, with
// the registration before and after. after has no contacts when the last one
// expired, and the S-CSCF then deregisters the user (SAR TIMEOUT_DEREGISTRATION,
// TS 29.228 §6.1.2) as well as sending the reg event NOTIFY.
//
// Every instance may sweep at the same time. A registration is claimed by a
// save conditional on the version read, so only one instance wins it and calls
// handle; the others see ErrConflict and skip it. One left without contacts is
// claimed for SweepLease (Deregistering) and deleted once handle succeeds. If
// handle fails, as when the HSS cannot be reached, or the instance stops
// first, the registration stays, and a sweep after the lease claims it and
// calls handle again, with before as empty as after: the deregistration is
// retried until it succeeds, so the HSS is not left thinking the user is still
// registered here. The errors of handle are returned together with the number
// handled.
func SweepRegistrations(ctx context.Context, s Registrations, now time.Time, limit int, handle func(before, after *Registration) error) (int, error) {
	// A listing error that comes with registrations (an item that does not
	// decode) does not stop the others from being swept.
	regs, errs := s.ExpiringRegistrations(ctx, now, limit)
	n := 0
	for _, before := range regs {
		if len(before.Contacts) == 0 && before.Deregistering.After(now) {
			// Claimed by another instance, which is still within its lease.
			continue
		}
		next := before.Clone()
		if len(next.Prune(now)) == 0 && len(next.Contacts) > 0 {
			continue
		}
		if len(next.Contacts) == 0 {
			next.Deregistering = now.Add(SweepLease)
		}
		after, err := s.SaveRegistration(ctx, next)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, errors.Join(errs, err)
		}
		n++
		if err := handle(before, after); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		if len(after.Contacts) == 0 {
			if err := ignoreLost(s.DeleteRegistration(ctx, after)); err != nil {
				return n, errors.Join(errs, err)
			}
		}
	}
	return n, errs
}

// SweepSubscriptions ends up to limit subscriptions that have expired at now:
// each is claimed by saving it as Terminated, with an expiry TerminatedGrace
// ahead, conditional on the version read, so exactly one instance calls handle,
// which sends the final NOTIFY (RFC 6665 §4.2.2), and then deleted. A
// Terminated subscription whose expiry has passed, its grace over, is deleted
// without handle. It returns the number of subscriptions handled.
func SweepSubscriptions(ctx context.Context, s Subscriptions, now time.Time, limit int, handle func(*Subscription)) (int, error) {
	subs, errs := s.ExpiringSubscriptions(ctx, now, limit)
	n := 0
	for _, sub := range subs {
		if sub.Expires.After(now) {
			continue
		}
		if sub.Terminated {
			if err := ignoreLost(s.DeleteSubscription(ctx, sub)); err != nil {
				return n, errors.Join(errs, err)
			}
			continue
		}
		next := sub.Clone()
		next.Terminated = true
		next.Expires = now.Add(TerminatedGrace)
		claimed, err := s.SaveSubscription(ctx, next)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, errors.Join(errs, err)
		}
		n++
		handle(claimed)
		// handle may have used NextNotify, which changes the version.
		cur, err := s.Subscription(ctx, claimed.ID)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, errors.Join(errs, err)
		}
		if cur.Terminated {
			if err := ignoreLost(s.DeleteSubscription(ctx, cur)); err != nil {
				return n, errors.Join(errs, err)
			}
		}
	}
	return n, errs
}

// lost reports an error that means another instance got there first.
func lost(err error) bool { return errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) }

func ignoreLost(err error) error {
	if lost(err) {
		return nil
	}
	return err
}
