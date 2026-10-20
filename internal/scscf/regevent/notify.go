package regevent

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func active(exp time.Duration) sip.SubscriptionState {
	ps := sip.Params{}
	ps.Set("expires", strconv.FormatInt(int64(exp/time.Second), 10))
	return sip.SubscriptionState{State: "active", Params: ps}
}

func terminated(reason string) sip.SubscriptionState {
	ss := sip.SubscriptionState{State: "terminated"}
	if reason != "" {
		ss.Params = sip.Params{}
		ss.Params.Set("reason", reason)
	}
	return ss
}

// Changed notifies the subscribers of a set that before became after, nil
// once the set has ended, because of cause (TS 24.229 §5.4.2.1.2). It
// returns at once: the NOTIFYs go out on their own, each within
// NotifyTimeout, so that the request that changed the set is answered first.
// When the set has ended, its subscriptions end with it: their NOTIFY says
// terminated, deactivated or rejected (RFC 3680 §6.3), and they are deleted.
func (n *Notifier) Changed(ctx context.Context, before, after *state.Registration, cause Cause) {
	set := after
	if set == nil {
		set = before
	}
	if set == nil {
		return
	}
	ctx = context.WithoutCancel(ctx)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		seen := map[string]bool{}
		for _, id := range set.Identities {
			subs, err := n.cfg.Store.SubscriptionsOf(ctx, id.IMPU)
			if err != nil {
				n.internalLog("listing subscriptions", err)
				continue
			}
			for _, sub := range subs {
				if seen[sub.ID] || sub.Terminated {
					continue
				}
				seen[sub.ID] = true
				if after == nil {
					n.notifyNext(ctx, sub, before, nil, cause, terminated(cause.reason()))
					n.end(ctx, sub)
					continue
				}
				left := sub.Expires.Sub(n.cfg.Now())
				n.notifyNext(ctx, sub, before, after, cause, active(max(left, 0)))
			}
		}
	}()
}

// notifyNext sends sub a NOTIFY with the next CSeq and reginfo version.
func (n *Notifier) notifyNext(ctx context.Context, sub *state.Subscription, before, after *state.Registration, cause Cause, ss sip.SubscriptionState) {
	cseq, version, err := n.cfg.Store.NextNotify(ctx, sub.ID)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return
	case errors.Is(err, state.ErrExhausted):
		// The counters ran out: the subscription ends, without a NOTIFY it
		// could not number.
		n.end(ctx, sub)
		return
	case err != nil:
		n.internalLog("counting a NOTIFY", err)
		return
	}
	n.notify(ctx, sub, cseq, version, before, after, cause, ss, n.cfg.Now())
}

// notify sends sub the NOTIFY numbered cseq of the set's state at version.
// A subscriber that is gone, says so (481), or does not answer ends the
// subscription (RFC 6665 §4.2.2); one that is busy keeps it, as the next
// NOTIFY carries the full state anyway.
func (n *Notifier) notify(ctx context.Context, sub *state.Subscription, cseq, version uint32, before, after *state.Registration, cause Cause, ss sip.SubscriptionState, now time.Time) {
	d, err := n.dialogOf(sub)
	if err != nil {
		n.internalLog("reading a subscription's dialog", err)
		return
	}
	d.LocalSeq = cseq - 1
	body, err := document(version, before, after, cause, now).Marshal()
	if err != nil {
		n.internalLog("writing reginfo", err)
		return
	}
	req, err := d.Notify(sip.Event{Type: "reg"}, ss, reginfo.ContentType, body, n.ids)
	if err != nil {
		n.internalLog("building a NOTIFY", err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, n.cfg.NotifyTimeout)
	defer cancel()
	res, err := n.cfg.Sender.Send(ctx, req)
	switch {
	case err == nil && res.StatusCode >= 200 && res.StatusCode < 300:
		n.count("regevent.notified")
	case err == nil && res.StatusCode != 481 && res.StatusCode != 408:
		n.count("regevent.notify_refused")
	case err != nil && !errors.Is(err, transport.ErrNoFlow) && !errors.Is(err, context.DeadlineExceeded):
		// The transport could not take it now (ErrQueueFull): the next
		// NOTIFY makes good.
		n.count("regevent.notify_failed")
	default:
		n.count("regevent.subscriber_gone")
		n.end(ctx, sub)
	}
}

// end deletes sub, read again for its version, which NextNotify changes.
func (n *Notifier) end(ctx context.Context, sub *state.Subscription) {
	for range saveAttempts {
		cur, err := n.cfg.Store.Subscription(ctx, sub.ID)
		if err != nil {
			return
		}
		err = n.cfg.Store.DeleteSubscription(ctx, cur)
		if !errors.Is(err, state.ErrConflict) {
			return
		}
	}
}

// Sweep ends up to limit subscriptions that have expired
// (state.SweepSubscriptions), each with a NOTIFY that says terminated,
// timeout (RFC 6665 §4.2.2), and returns how many it ended.
func (n *Notifier) Sweep(ctx context.Context, limit int) (int, error) {
	return state.SweepSubscriptions(ctx, n.cfg.Store, n.cfg.Now(), limit, func(sub *state.Subscription) {
		set, _ := n.liveSet(ctx, sub.IMPU, n.cfg.Now())
		n.notifyNext(ctx, sub, nil, set, Registered, terminated("timeout"))
	})
}
