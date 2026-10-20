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

// job is what a NOTIFY tells besides the state of the set, which it reads
// when it is sent.
type job struct {
	// before is the set before a change and cause the change: what before
	// had and the set has no more is listed as ended with cause's event.
	before *state.Registration
	cause  Cause
	// ended says the registrar ended the set: the NOTIFY tells of before's
	// end, whatever the store still has of a record being deleted.
	ended bool
	// first numbers it as the subscription's first NOTIFY, with the counters
	// the subscription was saved with, not NextNotify's.
	first bool
	// final makes it the subscription's last, terminated with reason ("" for
	// none), after which the subscription is deleted; bare sends it without
	// a body.
	final  bool
	reason string
	bare   bool
}

// Changed notifies the subscribers of a set that before became after, nil
// once the set has ended, because of cause (TS 24.229 §5.4.2.1.2). It
// returns at once: the NOTIFYs go out on the workers, each within
// NotifyTimeout, so that the request that changed the set is answered
// first. The subscriptions of every identity before or after has are told,
// so that one to an identity that left the set ends (#256 security review).
// When the set has ended, its subscriptions end with it: their NOTIFY says
// terminated, deactivated or rejected (RFC 6665 §4.1.3), and they are
// deleted.
func (n *Notifier) Changed(ctx context.Context, before, after *state.Registration, cause Cause) {
	changed := after
	if changed == nil {
		changed = before
	}
	if changed == nil {
		return
	}
	n.start(ctx, func(ctx context.Context) {
		seen := map[string]bool{}
		for _, impu := range identitiesBoth(before, after) {
			subs, err := n.cfg.Store.SubscriptionsOf(ctx, impu)
			if err != nil {
				n.internalLog("listing subscriptions", err)
				continue
			}
			for _, sub := range subs {
				if seen[sub.ID] || sub.Terminated {
					continue
				}
				seen[sub.ID] = true
				j := job{}
				// A subscription to another set, or to an earlier record of
				// this one, is only checked: it ends if it has lapsed.
				if sub.Set == changed.Key && sub.Incarnation == changed.Incarnation {
					j = job{before: before, cause: cause}
					if after == nil {
						j.ended, j.final, j.reason = true, true, cause.reason()
					}
				}
				n.start(ctx, func(ctx context.Context) { n.notifySub(ctx, sub, j) })
			}
		}
	})
}

// identitiesBoth are the identities of before and after, each once.
func identitiesBoth(before, after *state.Registration) []string {
	var out []string
	seen := map[string]bool{}
	for _, set := range []*state.Registration{before, after} {
		if set == nil {
			continue
		}
		for _, id := range set.Identities {
			if !seen[id.IMPU] {
				seen[id.IMPU] = true
				out = append(out, id.IMPU)
			}
		}
	}
	return out
}

// Why a subscription no longer holds (check).
const (
	lapsedIdentity = "identity_left"
	lapsedSet      = "no_binding"
	lapsedUE       = "ue_gone"
	lapsedPCSCF    = "pcscf_gone"
)

// check reports why sub no longer holds on set, its set's record at now,
// or "" if it does: its identity is still in the set, the set has a live
// binding, a UE's binding is live, and a P-CSCF still serves the set over a
// live binding, whatever the flow, which the next refresh asserts (#256
// security review: no subscriber goes on hearing of bindings it is not
// on). That set is sub's set, of sub's incarnation, the caller sees to.
func (n *Notifier) check(sub *state.Subscription, set *state.Registration, now time.Time) string {
	switch {
	case !hasIdentity(set, sub.IMPU):
		return lapsedIdentity
	case !anyLive(set, now):
		return lapsedSet
	case sub.Kind == state.SubscriberUE && sub.Binding != "" && !ueLive(set, sub.Binding, now):
		return lapsedUE
	case sub.Kind == state.SubscriberPCSCF:
		u, err := sip.ParseURI(sub.Subscriber)
		if err != nil || !onLivePath(set, u, now, true) {
			return lapsedPCSCF
		}
	}
	return ""
}

func anyLive(set *state.Registration, now time.Time) bool {
	for _, c := range set.Contacts {
		if !c.Expired(now) {
			return true
		}
	}
	return false
}

// notifySub sends sub a NOTIFY of its set as the store has it now, and so
// never a state older than one a NOTIFY with a lower number carried: the
// number is taken by NextNotify for the record's version read, which a
// later number's read cannot be below (#256 QA and code review). A read
// that fails sends nothing, rather than a document without the set, which a
// subscriber takes for its end (#256 code review); the next change or
// refresh brings the full state.
//
// The NOTIFY is the subscription's last if j says so or the subscription no
// longer holds: its record is gone or another incarnation, or check fails.
// Then it says terminated, deactivated, and has no body if it would tell
// the subscriber of a set that is not the one it was allowed to watch, or
// of bindings its P-CSCF is not on any more.
func (n *Notifier) notifySub(ctx context.Context, sub *state.Subscription, j job) {
	now := n.cfg.Now()
	var set *state.Registration
	if !j.ended {
		var err error
		set, err = n.cfg.Store.Registration(ctx, sub.Set)
		switch {
		case errors.Is(err, state.ErrNotFound):
			set = nil
		case err != nil:
			n.internalLog("reading a registration", err)
			return
		}
		if set != nil && set.Incarnation != sub.Incarnation {
			set = nil
		}
	}
	before := j.before
	if before != nil && (before.Key != sub.Set || before.Incarnation != sub.Incarnation) {
		before = nil
	}
	why := lapsedSet
	if set != nil {
		why = n.check(sub, set, now)
	}
	switch {
	case j.ended:
		// Changed told of the end of this very set, which before is.
	case why != "":
		n.count("regevent.lapsed")
		if !j.final {
			j.final, j.reason = true, "deactivated"
		}
		j.bare = j.bare || why == lapsedPCSCF || set == nil && before == nil
	}
	cseq, version := sub.CSeq, sub.ReginfoVersion
	if !j.first {
		var err error
		of := int64(state.FinalNotify)
		if !j.final {
			of = set.Version
		}
		cseq, version, err = n.cfg.Store.NextNotify(ctx, sub.ID, of)
		switch {
		case errors.Is(err, state.ErrNotFound):
			return
		case errors.Is(err, state.ErrStale):
			// A NOTIFY of a later state, or the last, has its number: this
			// one would tell less.
			n.count("regevent.notify_superseded")
			if j.final {
				n.end(ctx, sub)
			}
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
	}
	if n.send(ctx, sub, cseq, version, before, set, j, now) || j.final {
		n.end(ctx, sub)
	}
}

// send sends sub the NOTIFY numbered cseq of set's state at version, and
// reports whether the subscriber is gone: it answered with a code after
// which the notifier must remove the subscription (RFC 6665 §4.2.2), or
// 430, the edge's word for a flow that is gone (RFC 5626 §5.3; a UE that
// reconnected subscribes again over its new flow), or the transport has no
// flow to it, or it did not answer within NotifyTimeout. Any other answer,
// or a full queue, keeps it: the next NOTIFY carries the full state anyway.
func (n *Notifier) send(ctx context.Context, sub *state.Subscription, cseq, version uint32, before, set *state.Registration, j job, now time.Time) bool {
	d, err := n.dialogOf(sub)
	if err != nil {
		n.internalLog("reading a subscription's dialog", err)
		return false
	}
	d.LocalSeq = cseq - 1
	var b []byte
	ct := ""
	if !j.bare {
		b, err = body(version, before, set, j.cause, now)
		switch {
		case errors.Is(err, reginfo.ErrTooLarge):
			// Neither the full state nor what changed fits: the subscriber
			// misses this change.
			n.count("regevent.too_large")
			return false
		case err != nil:
			n.internalLog("writing reginfo", err)
			return false
		}
		ct = reginfo.ContentType
	}
	ss := terminated(j.reason)
	if !j.final {
		ss = active(max(sub.Expires.Sub(now), 0))
	}
	ev := sip.Event{Type: "reg"}
	if sub.EventID != "" {
		// RFC 6665 §4.5.2: the NOTIFY carries the SUBSCRIBE's id.
		ev.Params = sip.Params{}
		ev.Params.Set("id", sub.EventID)
	}
	req, err := d.Notify(ev, ss, ct, b, n.ids)
	if err != nil {
		n.internalLog("building a NOTIFY", err)
		return false
	}
	sendCtx, cancel := context.WithTimeout(ctx, n.cfg.NotifyTimeout)
	res, err := n.cfg.Sender.Send(sendCtx, req)
	cancel()
	switch {
	case err == nil && res.StatusCode >= 200 && res.StatusCode < 300:
		n.count("regevent.notified")
		return false
	case err == nil && !removes(res.StatusCode):
		n.count("regevent.notify_refused")
		return false
	case err != nil && !errors.Is(err, transport.ErrNoFlow) && !(errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil):
		// The transport could not take it now (ErrQueueFull), or the
		// notifier is stopping: the next NOTIFY makes good.
		n.count("regevent.notify_failed")
		return false
	}
	n.count("regevent.subscriber_gone")
	return true
}

// removes reports whether a NOTIFY answered code ends its subscription:
// RFC 6665 §4.2.2's list, 408 (no answer, as a timeout), and 430.
func removes(code int) bool {
	switch {
	case code == 404, code == 405, code == 408, code == 410, code == 416, code == 430,
		code >= 480 && code <= 485, code == 489, code == 501, code == 604:
		return true
	}
	return false
}

// end deletes sub, read again for its version, which NextNotify changes. It
// has a context of its own, bounded by NotifyTimeout: the caller's may have
// ended with the NOTIFY that timed out (#256 QA review).
func (n *Notifier) end(ctx context.Context, sub *state.Subscription) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), n.cfg.NotifyTimeout)
	defer cancel()
	for range saveAttempts {
		cur, err := n.cfg.Store.Subscription(ctx, sub.ID)
		if err != nil {
			if !errors.Is(err, state.ErrNotFound) {
				n.internalLog("reading a subscription", err)
			}
			return
		}
		err = n.cfg.Store.DeleteSubscription(ctx, cur)
		switch {
		case err == nil, errors.Is(err, state.ErrNotFound):
			return
		case !errors.Is(err, state.ErrConflict):
			n.internalLog("deleting a subscription", err)
			return
		}
	}
}

// Sweep ends up to limit subscriptions that have expired
// (state.SweepSubscriptions), each with a NOTIFY that says terminated,
// timeout (RFC 6665 §4.2.2), and returns how many it ended.
func (n *Notifier) Sweep(ctx context.Context, limit int) (int, error) {
	return state.SweepSubscriptions(ctx, n.cfg.Store, n.cfg.Now(), limit, func(sub *state.Subscription) {
		n.notifySub(ctx, sub, job{final: true, reason: "timeout"})
	})
}
