package regevent

import (
	"context"
	"errors"
	"strconv"
	"sync"
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
// returns at once: the NOTIFYs go out on the workers (schedule.go), so that
// the request that changed the set is answered first. The subscriptions of
// every identity before or after has are told, so that one to an identity
// that left the set ends (#256 security review).
//
// When the set has ended, its subscriptions end with it: each is first
// saved Terminated, with its reason and an expiry pendingEnd ahead, and
// then its final NOTIFY, which says terminated, deactivated or rejected
// (RFC 6665 §4.1.3), is queued. If the queue drops that NOTIFY, or the
// instance stops, a sweep sends it within seconds, so the end of a set is
// never lost (#256 security, code and QA reviews).
func (n *Notifier) Changed(ctx context.Context, before, after *state.Registration, cause Cause) {
	changed := after
	if changed == nil {
		changed = before
	}
	if changed == nil {
		return
	}
	n.enqueue(&task{ctx: ctx, run: func(ctx context.Context) func() {
		n.fanOut(ctx, before, after, changed, cause)
		return nil
	}})
}

// fanOut queues the NOTIFYs of Changed.
func (n *Notifier) fanOut(ctx context.Context, before, after, changed *state.Registration, cause Cause) {
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
					ended, err := n.terminate(ctx, sub, n.cfg.Now().Add(pendingEnd), j.reason, true)
					switch {
					case err != nil:
						// Its NOTIFY goes all the same, if the store lets
						// it be numbered.
						n.internalLog("terminating a subscription", err)
					case ended == nil:
						// Gone, or ending already.
						continue
					default:
						sub = ended
					}
				}
			}
			n.enqueueNotify(ctx, sub, j, nil)
		}
	}
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

// notifySub sends sub a NOTIFY of its set as the store has it now and
// waits for the answer (prepare).
func (n *Notifier) notifySub(ctx context.Context, sub *state.Subscription, j job) {
	if rest := n.prepare(ctx, sub, j); rest != nil {
		rest()
	}
}

// prepare makes the NOTIFY j to sub of its set as the store has it now, and
// returns what sends it and acts on the answer, or nil if there is nothing
// to send. It never carries a state older than one a NOTIFY with a lower
// number carried: the number is taken by NextNotify for the record's
// version read, which a later number's read cannot be below (#256 QA and
// code review). A read that fails sends nothing, rather than a document
// without the set, which a subscriber takes for its end (#256 code review);
// the next change or refresh brings the full state, and the next sweep an
// end.
//
// The NOTIFY is the subscription's last if j says so or the subscription no
// longer holds: its record is gone or another incarnation, or check fails.
// Then it says terminated, deactivated, and has no body if it would tell
// the subscriber of a set that is not the one it was allowed to watch, or
// of bindings its P-CSCF is not on any more. The end of a set read from a
// sweep, without the set before it, lists the watched identity alone,
// terminated.
func (n *Notifier) prepare(ctx context.Context, sub *state.Subscription, j job) func() {
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
			return nil
		}
		if set != nil && set.Incarnation != sub.Incarnation {
			set = nil
		}
	}
	// Changed gives a before only to the subscriptions of its record.
	before := j.before
	why := lapsedSet
	if set != nil {
		why = n.check(sub, set, now)
	}
	switch {
	case j.ended:
		// The registrar told of the end of this very set, which before is,
		// or a sweep sends that end in place of whoever saved it.
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
			return nil
		case errors.Is(err, state.ErrStale):
			// A NOTIFY of a later state, or the last, has its number: this
			// one would tell less.
			n.count("regevent.notify_superseded")
			if j.final {
				n.end(ctx, sub)
			}
			return nil
		case errors.Is(err, state.ErrExhausted):
			// The counters ran out: the subscription ends, without a NOTIFY it
			// could not number.
			n.end(ctx, sub)
			return nil
		case err != nil:
			n.internalLog("counting a NOTIFY", err)
			return nil
		}
	}
	req := n.build(sub, cseq, version, before, set, j, now)
	if req == nil {
		if j.final {
			n.end(ctx, sub)
		}
		return nil
	}
	return func() {
		if n.deliver(ctx, req) || j.final {
			n.end(ctx, sub)
		}
	}
}

// build makes sub's NOTIFY numbered cseq of set's state at version, nil if
// it cannot be made.
func (n *Notifier) build(sub *state.Subscription, cseq, version uint32, before, set *state.Registration, j job, now time.Time) *sip.Request {
	d, err := n.dialogOf(sub)
	if err != nil {
		n.internalLog("reading a subscription's dialog", err)
		return nil
	}
	d.LocalSeq = cseq - 1
	var b []byte
	ct := ""
	if !j.bare {
		if set == nil && before == nil {
			b, err = endOf(version, sub.IMPU, j.reason).Marshal()
		} else {
			b, err = body(version, before, set, j.cause, now)
		}
		switch {
		case errors.Is(err, reginfo.ErrTooLarge):
			// Neither the full state nor what changed fits: the subscriber
			// misses this change.
			n.count("regevent.too_large")
			return nil
		case err != nil:
			n.internalLog("writing reginfo", err)
			return nil
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
		return nil
	}
	return req
}

// deliver sends req and reports whether its subscriber is gone: it
// answered with a code after which the notifier must remove the
// subscription (RFC 6665 §4.2.2), or 430, the edge's word for a flow that
// is gone (RFC 5626 §5.3; a UE that reconnected subscribes again over its
// new flow), or the transport has no flow to it, or it did not answer
// within NotifyTimeout. Any other answer, or a full queue, keeps it: the
// next NOTIFY carries the full state anyway.
func (n *Notifier) deliver(ctx context.Context, req *sip.Request) bool {
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

// endOf is the end of the registration of impu, terminated without its
// contacts, for a set that ended and is no longer there to read: what a
// sweep sends in place of the instance that ended it.
func endOf(version uint32, impu, reason string) *reginfo.Info {
	return &reginfo.Info{Version: version, State: reginfo.Full, Registrations: []reginfo.Registration{
		{AOR: impu, ID: idOf("reg", impu), State: reginfo.Terminated},
	}}
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

// Sweep ends up to limit subscriptions that have expired, each with a
// NOTIFY that says terminated, timeout (RFC 6665 §4.2.2), and sends the
// final NOTIFY of those terminated whose NOTIFY nobody sent
// (state.SweepSubscriptions), with their reason. The NOTIFYs go on the
// workers, under the same bounds as any other; Sweep returns once they are
// answered, with how many it handled. One the queue drops is sent by a
// sweep after state.TerminatedGrace.
func (n *Notifier) Sweep(ctx context.Context, limit int) (int, error) {
	var wg sync.WaitGroup
	k, err := state.SweepSubscriptions(ctx, n.cfg.Store, n.cfg.Now(), limit, func(sub *state.Subscription) {
		wg.Add(1)
		n.enqueueNotify(ctx, sub, job{final: true, reason: sub.EndReason, ended: sub.SetEnded}, wg.Done)
	})
	wg.Wait()
	return k, err
}
