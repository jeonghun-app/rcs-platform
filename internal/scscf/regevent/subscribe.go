package regevent

import (
	"cmp"
	"context"
	"errors"
	mathrand "math/rand/v2"
	"slices"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
)

// saveAttempts bounds how often a refresh that lost to a NOTIFY's
// NextNotify, which changes the subscription's version, is read and applied
// again. NOTIFYs to one subscription come in bursts of a few, so the
// retries wait a little, with jitter, to let a burst pass (#256 QA review:
// three attempts lost about one refresh in 300 to ten changes at once).
const saveAttempts = 8

// Subscribe answers a SUBSCRIBE for the reg event (TS 24.229 §5.4.2.1.1)
// and returns the response, and for a SUBSCRIBE it accepted the NOTIFY to
// send once the response is on its way (RFC 6665 §4.2.1.2): call it then,
// with a context of its own. A SUBSCRIBE for another event is answered 489.
func (n *Notifier) Subscribe(ctx context.Context, req *sip.Request) (*sip.Response, func(context.Context)) {
	ev, err := req.Header.Event()
	if err != nil || ev.Type != "reg" {
		res := n.response(req, 489, "Bad Event", "")
		_ = res.Header.Set("Allow-Events", "reg")
		return res, nil
	}
	to, err := req.Header.To()
	if err != nil {
		return n.response(req, 400, "Bad To", ""), nil
	}
	if to.Tag() != "" {
		return n.refresh(ctx, req, ev)
	}
	return n.subscribe(ctx, req, ev)
}

// expiresOf is what a SUBSCRIBE asks for, capped, or the default.
func (n *Notifier) expiresOf(req *sip.Request) (time.Duration, error) {
	if !req.Header.Has("Expires") {
		return n.cfg.DefaultExpires, nil
	}
	s, err := req.Header.Expires()
	if err != nil {
		return 0, err
	}
	return min(time.Duration(s)*time.Second, n.cfg.MaxExpires), nil
}

// subscribe answers an initial SUBSCRIBE: the watched identity is the
// Request-URI's, and the subscriber the P-Asserted-Identity, which must be
// the Path a P-CSCF put on a live binding of its set, or one of the set's
// identities not barred (§5.4.2.1.1); anything else is 403, whether the
// identity is registered or not, so that the answer does not tell.
func (n *Notifier) subscribe(ctx context.Context, req *sip.Request, ev sip.Event) (*sip.Response, func(context.Context)) {
	now := n.cfg.Now()
	exp, err := n.expiresOf(req)
	if err != nil {
		return n.response(req, 400, "Bad Expires", ""), nil
	}
	impu, ok := identity.CanonicalIMPU(req.URI.String())
	pai, err := req.Header.PAssertedIdentity()
	if !ok || err != nil || len(pai) == 0 {
		return n.refused(req), nil
	}
	subscriber := pai[0].URI
	set, err := n.liveSet(ctx, impu, now)
	if err != nil {
		return n.unavailable(req, "reading a registration", err), nil
	}
	kind := kindOf(set, subscriber, now)
	if kind == "" || barred(set, impu) {
		// A barred identity has no state to watch: no NOTIFY lists it
		// (TS 24.229 §5.4.1.2.2).
		return n.refused(req), nil
	}
	tag, err := n.ids.Tag()
	if err != nil {
		return n.internal(req, "making a tag", err), nil
	}
	d, err := dialog.UAS(req, tag, n.cfg.Contact)
	if err != nil {
		return n.response(req, 400, "Bad Request", ""), nil
	}
	sub := &state.Subscription{
		ID: subscriptionID(d.ID()), IMPU: impu, Set: set.Key, Incarnation: set.Incarnation,
		Subscriber: subscriber.String(), Kind: kind, EventID: ev.ID(),
		Dialog: storedDialog(d), Expires: now.Add(exp), CSeq: 1, NotifiedOf: set.Version,
	}
	if kind == state.SubscriberUE {
		sub.Binding = ueBinding(set, req, now)
	}
	if exp == 0 {
		// A fetch (RFC 6665 §4.4.3): one NOTIFY, and no subscription.
		res := n.ok(req, tag, 0)
		return res, func(ctx context.Context) {
			n.notifySub(ctx, sub, job{first: true, final: true, reason: "timeout"})
		}
	}
	switch err := n.makeRoom(ctx, sub, set, now); {
	case errors.Is(err, errFull):
		n.count("regevent.refused_full")
		return n.response(req, 403, "Too many subscriptions", ""), nil
	case err != nil:
		return n.unavailable(req, "listing subscriptions", err), nil
	}
	saved, err := n.cfg.Store.SaveSubscription(ctx, sub)
	if err != nil {
		return n.unavailable(req, "saving a subscription", err), nil
	}
	n.count("regevent.subscribed")
	res := n.ok(req, tag, exp)
	return res, func(ctx context.Context) {
		// The set is read again, after the save: a change committed before
		// it did not find this subscription to notify (#256 QA review).
		n.notifySub(ctx, saved, job{first: true})
	}
}

// kindOf is what subscriber is to set: the P-CSCF over whose flow a live
// binding came, as its Path's first URI (§5.2.3), or the UE, one of the
// set's identities not barred (§5.4.2.1.1); "" for anyone else, or when
// set is nil.
func kindOf(set *state.Registration, subscriber sip.URI, now time.Time) string {
	if set == nil {
		return ""
	}
	if onLivePath(set, subscriber, now, false) {
		return state.SubscriberPCSCF
	}
	impu, ok := identity.CanonicalIMPU(subscriber.String())
	if !ok {
		return ""
	}
	for _, id := range set.Identities {
		if id.IMPU == impu && !id.Barred {
			return state.SubscriberUE
		}
	}
	return ""
}

// onLivePath reports whether u is the first Path URI of a live binding of
// set; anyUser compares without the user part, the flow token, so that it
// asks whether u's P-CSCF still serves the set over any of its flows.
func onLivePath(set *state.Registration, u sip.URI, now time.Time, anyUser bool) bool {
	if anyUser {
		u.User = ""
	}
	for _, c := range set.Contacts {
		if c.Expired(now) || len(c.Path) == 0 {
			continue
		}
		p, err := sip.ParseAddress(c.Path[0])
		if err != nil {
			continue
		}
		if anyUser {
			p.URI.User = ""
		}
		if p.URI.Equal(u) {
			return true
		}
	}
	return false
}

// ueKey names what a UE's subscription ends with: its device, by
// +sip.instance, or without one its contact URI; once no live binding of
// the set has it, none of the UE's contacts is active and its subscription
// is cancelled (§5.4.2.1.2).
func ueKey(c state.Contact) string {
	if c.InstanceID != "" {
		return "i|" + c.InstanceID
	}
	return "u|" + c.URI
}

// ueBinding is the ueKey of the live binding of set that req's Contact is,
// by +sip.instance or URI, or "" if none is: such a subscription ends with
// the set, not with a binding.
func ueBinding(set *state.Registration, req *sip.Request, now time.Time) string {
	cs, err := req.Header.Contact()
	if err != nil || len(cs) == 0 || cs[0].Star {
		return ""
	}
	inst, _ := cs[0].Instance()
	for _, c := range set.Contacts {
		if c.Expired(now) {
			continue
		}
		if inst != "" && c.InstanceID == inst {
			return ueKey(c)
		}
		if u, err := sip.ParseURI(c.URI); err == nil && u.Equal(cs[0].URI) {
			return ueKey(c)
		}
	}
	return ""
}

// ueLive reports whether a live binding of set has the ueKey key.
func ueLive(set *state.Registration, key string, now time.Time) bool {
	for _, c := range set.Contacts {
		if !c.Expired(now) && ueKey(c) == key {
			return true
		}
	}
	return false
}

// errFull refuses a subscription to a set that has MaxPerSet.
var errFull = errors.New("regevent: the set has as many subscriptions as it may")

// barred reports whether set has impu barred.
func barred(set *state.Registration, impu string) bool {
	for _, id := range set.Identities {
		if id.IMPU == impu {
			return id.Barred
		}
	}
	return false
}

// makeRoom makes room for sub among the live subscriptions to its set,
// ending the oldest, by expiry, that it pushes out: they are terminated at
// once and their NOTIFY, terminated, deactivated, without a body, goes on a
// worker.
//   - A subscriber keeps MaxPerSubscriber to an identity; a UE that many per
//     device, its binding (Binding), as every device of a user asserts the
//     same identity (#256 QA review).
//   - The UE's subscriptions to the set are at most MaxUEPerSet.
//   - All are at most MaxPerSet: a P-CSCF's pushes out the UE's, and with
//     none left it fails with errFull, so a P-CSCF is refused for its own
//     subscriptions only (#256 security and code reviews).
//
// The bounds are counted from a listing, without a transaction: SUBSCRIBEs
// handled at the same moment may each find the same room, so the bounds
// can be passed by as many as arrive together, and the next SUBSCRIBE of
// that subscriber, or to that set, brings them back. Their NOTIFYs stay
// bounded per set (SetConcurrency).
func (n *Notifier) makeRoom(ctx context.Context, sub *state.Subscription, set *state.Registration, now time.Time) error {
	var all []*state.Subscription
	for _, id := range set.Identities {
		subs, err := n.cfg.Store.SubscriptionsOf(ctx, id.IMPU)
		if err != nil {
			return err
		}
		for _, s := range subs {
			if !s.Terminated && s.Set == sub.Set && s.Incarnation == sub.Incarnation && !s.Expires.Before(now) {
				all = append(all, s)
			}
		}
	}
	slices.SortFunc(all, func(a, b *state.Subscription) int {
		return cmp.Or(a.Expires.Compare(b.Expires), cmp.Compare(a.ID, b.ID))
	})
	mine := func(s *state.Subscription) bool {
		return s.IMPU == sub.IMPU && s.Subscriber == sub.Subscriber && s.Kind == sub.Kind &&
			(sub.Kind != state.SubscriberUE || s.Binding == sub.Binding)
	}
	ue := func(s *state.Subscription) bool { return s.Kind == state.SubscriberUE }
	// pushOut ends the oldest that is, while there are more than keep.
	pushOut := func(is func(*state.Subscription) bool, keep int) error {
		for k := countOf(all, is); k > keep; k-- {
			i := slices.IndexFunc(all, is)
			old, err := n.terminate(ctx, all[i], now.Add(pendingEnd), "deactivated", false)
			if err != nil {
				return err
			}
			all = slices.Delete(all, i, i+1)
			if old != nil {
				n.count("regevent.replaced")
				n.enqueueNotify(ctx, old, job{final: true, reason: "deactivated", bare: true}, nil)
			}
		}
		return nil
	}
	if err := pushOut(mine, n.cfg.MaxPerSubscriber-1); err != nil {
		return err
	}
	var err error
	if sub.Kind == state.SubscriberUE {
		err = pushOut(ue, n.cfg.MaxUEPerSet-1)
	} else {
		// The UE's make room for a P-CSCF's, down to none.
		pcscf := len(all) - countOf(all, ue)
		err = pushOut(ue, max(n.cfg.MaxPerSet-1-pcscf, 0))
	}
	if err != nil {
		return err
	}
	if len(all) >= n.cfg.MaxPerSet {
		return errFull
	}
	return nil
}

func countOf(subs []*state.Subscription, is func(*state.Subscription) bool) int {
	k := 0
	for _, s := range subs {
		if is(s) {
			k++
		}
	}
	return k
}

// terminate marks sub Terminated, with reason as its final NOTIFY's and
// expires as its expiry, so that nothing but that NOTIFY is sent to it and
// it is deleted after it, or the first sweep after expires sends it, and
// returns it as saved: nil if it is gone or ending already. setEnded says
// that its set ended (state.Subscription).
func (n *Notifier) terminate(ctx context.Context, sub *state.Subscription, expires time.Time, reason string, setEnded bool) (*state.Subscription, error) {
	for range saveAttempts {
		next := sub.Clone()
		next.Terminated, next.Expires, next.EndReason, next.SetEnded = true, expires, reason, setEnded
		saved, err := n.cfg.Store.SaveSubscription(ctx, next)
		switch {
		case errors.Is(err, state.ErrNotFound):
			return nil, nil
		case !errors.Is(err, state.ErrConflict):
			return saved, err
		}
		// A NOTIFY counted meanwhile: read it again.
		switch sub, err = n.cfg.Store.Subscription(ctx, sub.ID); {
		case errors.Is(err, state.ErrNotFound):
			return nil, nil
		case err != nil:
			return nil, err
		case sub.Terminated:
			return nil, nil
		}
	}
	return nil, errors.New("regevent: a subscription kept changing")
}

// refresh answers a SUBSCRIBE in a subscription's dialog: a refresh, or with
// Expires 0 its end (RFC 6665 §4.1.2.2, §4.1.2.3). It must match a stored
// subscription's dialog and Event id, with a CSeq above the last (the lead's
// contract on #14: a repeat that reaches another instance is not applied
// twice), or it is 481, or 500 for the CSeq.
//
// The subscription must still watch its set (check). A P-CSCF's must also
// assert the Path of a live binding of the set, which becomes its
// subscriber: the P-CSCF asserts the Path of the user's latest
// registration, which a reconnection changes (#256 code review). A UE's is
// authorised by the dialog alone: the P-CSCF asserts no identity on a
// target refresh (TS 24.229 §5.2.6.3.5), and §5.4.2.1.1 accepts the UE's
// refresh while its identity is registered.
func (n *Notifier) refresh(ctx context.Context, req *sip.Request, ev sip.Event) (*sip.Response, func(context.Context)) {
	exp, err := n.expiresOf(req)
	if err != nil {
		return n.response(req, 400, "Bad Expires", ""), nil
	}
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	pai, err3 := req.Header.PAssertedIdentity()
	cseq, err4 := req.Header.CSeq()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return n.response(req, 400, "Bad Request", ""), nil
	}
	id := subscriptionID((&dialog.Dialog{CallID: req.Header.Get("Call-ID"), Local: to, Remote: from}).ID())
	for attempt := range saveAttempts {
		if attempt > 0 {
			n.count("regevent.refresh_conflict")
			select {
			case <-time.After(time.Duration(mathrand.IntN(2<<attempt)) * time.Millisecond):
			case <-ctx.Done():
				return n.unavailable(req, "saving a subscription", ctx.Err()), nil
			}
		}
		now := n.cfg.Now()
		sub, err := n.cfg.Store.Subscription(ctx, id)
		switch {
		case errors.Is(err, state.ErrNotFound):
			return n.noSubscription(req), nil
		case err != nil:
			return n.unavailable(req, "reading a subscription", err), nil
		case sub.Terminated || sub.NotifiedOf == state.FinalNotify || ev.ID() != sub.EventID:
			return n.noSubscription(req), nil
		}
		d, err := n.dialogOf(sub)
		if err != nil {
			return n.internal(req, "reading a subscription's dialog", err), nil
		}
		switch err := d.Accept(req); {
		case errors.Is(err, dialog.ErrOutOfOrder):
			return n.response(req, 500, "CSeq out of order", to.Tag()), nil
		case err != nil:
			return n.noSubscription(req), nil
		case cseq.Seq <= sub.Dialog.RemoteSeq:
			return n.response(req, 500, "CSeq not above the last", to.Tag()), nil
		}
		set, err := n.cfg.Store.Registration(ctx, sub.Set)
		if err != nil && !errors.Is(err, state.ErrNotFound) {
			return n.unavailable(req, "reading a registration", err), nil
		}
		if set == nil || n.check(sub, set, now) != "" {
			// It no longer watches what it was allowed to: it ends, without
			// a NOTIFY, and the subscriber is told so by the 481.
			n.end(ctx, sub)
			return n.noSubscription(req), nil
		}
		next := sub.Clone()
		if sub.Kind == state.SubscriberPCSCF {
			if len(pai) == 0 || !onLivePath(set, pai[0].URI, now, false) {
				return n.noSubscription(req), nil
			}
			next.Subscriber = pai[0].URI.String()
		}
		next.Dialog = storedDialog(d)
		next.Expires = now.Add(exp)
		j := job{}
		if exp == 0 {
			next.Terminated, next.Expires, next.EndReason = true, now.Add(pendingEnd), ""
			j = job{final: true}
		}
		saved, err := n.cfg.Store.SaveSubscription(ctx, next)
		switch {
		case errors.Is(err, state.ErrConflict):
			// A NOTIFY counted meanwhile: read it again.
			continue
		case errors.Is(err, state.ErrNotFound):
			return n.noSubscription(req), nil
		case err != nil:
			return n.unavailable(req, "saving a subscription", err), nil
		}
		res := n.ok(req, to.Tag(), exp)
		return res, func(ctx context.Context) { n.notifySub(ctx, saved, j) }
	}
	return n.unavailable(req, "saving a subscription", errors.New("kept changing")), nil
}

func (n *Notifier) noSubscription(req *sip.Request) *sip.Response {
	n.count("regevent.no_subscription")
	return n.response(req, 481, "Subscription does not exist", "")
}

func (n *Notifier) refused(req *sip.Request) *sip.Response {
	n.count("regevent.refused")
	return n.response(req, 403, "Forbidden", "")
}

// liveSet is the record of impu's set, nil if it has none live at now: the
// identity's pointer must name the record's incarnation and the record the
// identity, as a pointer written ahead of its record does not (state.Identity).
func (n *Notifier) liveSet(ctx context.Context, impu string, now time.Time) (*state.Registration, error) {
	id, err := n.cfg.Store.Identity(ctx, impu, now)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	set, err := n.cfg.Store.Registration(ctx, id.Set)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	}
	if set.Incarnation != id.Incarnation || !hasIdentity(set, impu) {
		return nil, nil
	}
	for _, c := range set.Contacts {
		if !c.Expired(now) {
			return set, nil
		}
	}
	return nil, nil
}

func (n *Notifier) response(req *sip.Request, code int, reason, tag string) *sip.Response {
	if tag == "" {
		tag, _ = n.ids.Tag()
	}
	res, err := sip.NewResponse(req, code, reason, tag)
	if err != nil {
		// A request the transaction layer accepted has what a response
		// needs; this cannot fail but on a broken generator.
		res, _ = sip.NewResponse(req, 500, "", "")
	}
	return res
}

func (n *Notifier) ok(req *sip.Request, tag string, exp time.Duration) *sip.Response {
	res := n.response(req, 200, "OK", tag)
	_ = res.Header.Set("Contact", sip.Address{URI: n.cfg.Contact}.String())
	_ = res.Header.Set("Expires", strconv.FormatInt(int64(exp/time.Second), 10))
	return res
}

func (n *Notifier) internal(req *sip.Request, what string, err error) *sip.Response {
	n.internalLog(what, err)
	return n.response(req, 500, "", "")
}

// unavailable answers a request the store failed: 500 with a Retry-After,
// so that the subscriber tries again soon (RFC 3261 §21.5.1) and does not
// take the failure for the end of its subscription.
func (n *Notifier) unavailable(req *sip.Request, what string, err error) *sip.Response {
	res := n.internal(req, what, err)
	_ = res.Header.Set("Retry-After", storeRetryAfter)
	return res
}

// internalLog logs a failure by its step and error, which name no identity.
func (n *Notifier) internalLog(what string, err error) {
	n.log.Error("regevent: internal failure", "step", what, "error", err.Error())
	n.count("regevent.internal_errors")
}
