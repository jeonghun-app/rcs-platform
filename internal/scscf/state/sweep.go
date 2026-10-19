package state

import (
	"context"
	"errors"
	"time"
)

// TerminatedGrace is how long a subscription claimed by a sweep (Terminated)
// stays before any sweep deletes it, which leaves the instance that claimed it
// the time to send its final NOTIFY with NextNotify. It also cleans up after an
// instance that stopped between the claim and the delete.
const TerminatedGrace = time.Minute

// SweepRegistrations removes the contacts that have expired at now from up to
// limit registrations, and calls handle for each registration it changed, with
// the registration before and after; after has no contacts when the last one
// expired. The S-CSCF then does what a registration expiry needs (a SAR of
// type TIMEOUT_DEREGISTRATION when nothing is left, TS 29.228 §6.1.2, and the
// reg event NOTIFY).
//
// Every instance may sweep at the same time. A registration is claimed by a
// save conditional on the version read, so only one instance wins it and calls
// handle; the others see ErrConflict and skip it. A registration left without
// contacts is then deleted, conditional on the claimed version, so a REGISTER
// that arrived meanwhile is kept; one that an instance left behind, stopping
// between the two steps, is listed again and deleted by the next sweep. It
// returns the number of registrations handled.
func SweepRegistrations(ctx context.Context, s Registrations, now time.Time, limit int, handle func(before, after *Registration)) (int, error) {
	// A listing error that comes with registrations (an item that does not
	// decode) does not stop the others from being swept.
	regs, listErr := s.ExpiringRegistrations(ctx, now, limit)
	n := 0
	for _, before := range regs {
		if len(before.Contacts) == 0 {
			if err := ignoreLost(s.DeleteRegistration(ctx, before)); err != nil {
				return n, err
			}
			continue
		}
		next := before.Clone()
		if len(next.Prune(now)) == 0 {
			continue
		}
		after, err := s.SaveRegistration(ctx, next)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
		handle(before, after)
		if len(after.Contacts) == 0 {
			if err := ignoreLost(s.DeleteRegistration(ctx, after)); err != nil {
				return n, err
			}
		}
	}
	return n, listErr
}

// SweepSubscriptions ends up to limit subscriptions that have expired at now:
// each is claimed by saving it as Terminated, conditional on the version read,
// so exactly one instance calls handle, which sends the final NOTIFY (RFC 6665
// §4.2.2), and then deleted. A claimed subscription that is still there
// TerminatedGrace after its expiry is deleted without handle. It returns the
// number of subscriptions handled.
func SweepSubscriptions(ctx context.Context, s Subscriptions, now time.Time, limit int, handle func(*Subscription)) (int, error) {
	subs, listErr := s.ExpiringSubscriptions(ctx, now, limit)
	n := 0
	for _, sub := range subs {
		if sub.Terminated {
			if sub.Expires.Add(TerminatedGrace).Before(now) {
				if err := ignoreLost(s.DeleteSubscription(ctx, sub)); err != nil {
					return n, err
				}
			}
			continue
		}
		next := sub.Clone()
		next.Terminated = true
		claimed, err := s.SaveSubscription(ctx, next)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		n++
		handle(claimed)
		// handle may have used NextNotify, which changes the version.
		cur, err := s.Subscription(ctx, claimed.ID)
		if lost(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		if cur.Terminated {
			if err := ignoreLost(s.DeleteSubscription(ctx, cur)); err != nil {
				return n, err
			}
		}
	}
	return n, listErr
}

// lost reports an error that means another instance got there first.
func lost(err error) bool { return errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) }

func ignoreLost(err error) error {
	if lost(err) {
		return nil
	}
	return err
}
