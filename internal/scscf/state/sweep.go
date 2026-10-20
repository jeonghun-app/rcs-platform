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

// TerminatedGrace is how long a subscription claimed by a sweep stays before
// another sweep sends its final NOTIFY in its place: the time for the
// claimer to send it with NextNotify. It counts from the claim.
const TerminatedGrace = time.Minute

// SweepRegistrations removes the contacts that have expired at now from up to
// limit registrations, and calls handle for each registration it changed, with
// the registration before and after. after has no contacts when the last one
// expired, and the S-CSCF then deregisters the user (SAR TIMEOUT_DEREGISTRATION,
// TS 29.228 §6.1.2) as well as sending the reg event NOTIFY. The record of an
// unregistered user is handled the same way once its Unregistered has come:
// before.Unregistered is set, and the S-CSCF ends that state with the HSS.
//
// Every instance may sweep at the same time. A registration is claimed by a
// save conditional on the version read, so only one instance wins it and calls
// handle; the others see ErrConflict and skip it. One left without contacts is
// claimed for SweepLease (Deregistering) and deleted once handle succeeds. If
// handle fails, as when the HSS cannot be reached, or the instance stops
// first, the registration stays, and a sweep after the lease claims it and
// calls handle again, with before as empty as after: the deregistration is
// retried until it succeeds, so the HSS is not left thinking the user is still
// registered here. handle therefore returns an error only for a failure that
// may pass, and nil for a permanent one, such as an SAA with
// DIAMETER_ERROR_USER_UNKNOWN (5001, TS 29.229 §6.2.2): the HSS will not
// answer differently, and an error would retry the SAR every lease. The
// errors of handle are returned together with the number handled.
//
// The order is what makes that retry complete: handle deletes the set's
// identities (DeleteIdentity) and its profile, and only then is the record
// deleted. Cut short between the two, the record still holds its lease, so
// the next sweep after it calls handle again, which finds what is left; an
// identity it never reaches still goes at its KeepUntil.
//
// A live registration whose Reassert is due is claimed the same way, Reassert
// moved one lease ahead, and handed to handle, whose before.ReassertDue tells
// it to tell the HSS again. The sweep does no more for it: handle saves after
// under its version, with Reassert and ReassertAttempts cleared once the HSS
// has taken the SAR, or else with the failure counted and Reassert moved on
// by a backoff, stopping by MaxReassertAttempts. A handle that only returns
// nil leaves Reassert one lease ahead, and the set is claimed again then.
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
		reassert := before.ReassertDue(now)
		if len(next.Prune(now)) == 0 && len(next.Contacts) > 0 && !reassert {
			continue
		}
		if len(next.Contacts) == 0 {
			next.Deregistering = now.Add(SweepLease)
			// Nothing is left to reassert: the set ends.
			next.Reassert, next.ReassertAttempts = time.Time{}, 0
		} else if reassert {
			// Claimed as a deregistration is: another sweep tries after the
			// lease if this one's handle does not move it.
			next.Reassert = now.Add(SweepLease)
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

// SweepSubscriptions ends up to limit subscriptions that have expired at
// now, and sends the final NOTIFY of those terminated whose NOTIFY nobody
// numbered: the instance that terminated one may have dropped it from a full
// queue, or stopped. Each is claimed by saving it as Terminated, with an
// expiry TerminatedGrace ahead, conditional on the version read, so one
// instance calls handle, which sends the final NOTIFY (RFC 6665 §4.2.2), at
// once or later; one expired that was not Terminated gets EndReason
// "timeout". A subscription whose final NOTIFY is numbered (NotifiedOf is
// FinalNotify) is deleted, now or by a later sweep, and one a handle did
// not get to is claimed again after the grace. It returns the number of
// subscriptions handled.
func SweepSubscriptions(ctx context.Context, s Subscriptions, now time.Time, limit int, handle func(*Subscription)) (int, error) {
	subs, errs := s.ExpiringSubscriptions(ctx, now, limit)
	n := 0
	for _, sub := range subs {
		if sub.Expires.After(now) {
			continue
		}
		if sub.Terminated && sub.NotifiedOf == FinalNotify {
			if err := ignoreLost(s.DeleteSubscription(ctx, sub)); err != nil {
				return n, errors.Join(errs, err)
			}
			continue
		}
		next := sub.Clone()
		if !sub.Terminated {
			next.Terminated, next.EndReason = true, "timeout"
		}
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
		if cur.NotifiedOf == FinalNotify {
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
