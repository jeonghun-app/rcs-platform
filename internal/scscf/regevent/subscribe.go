package regevent

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
)

// saveAttempts bounds how often a subscription save that lost to a NOTIFY's
// NextNotify, which changes its version, is read and applied again.
const saveAttempts = 3

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
		return n.refresh(ctx, req)
	}
	return n.subscribe(ctx, req)
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
// identities (§5.4.2.1.1); anything else is 403, whether the identity is
// registered or not.
func (n *Notifier) subscribe(ctx context.Context, req *sip.Request) (*sip.Response, func(context.Context)) {
	now := n.cfg.Now()
	exp, err := n.expiresOf(req)
	if err != nil {
		return n.response(req, 400, "Bad Expires", ""), nil
	}
	impu, ok := identity.CanonicalIMPU(req.URI.String())
	pai, err := req.Header.PAssertedIdentity()
	if !ok || err != nil || len(pai) == 0 {
		n.count("regevent.refused")
		return n.response(req, 403, "Forbidden", ""), nil
	}
	subscriber := pai[0].URI
	set, f := n.liveSet(ctx, impu, now)
	if f != nil {
		return n.response(req, f.code, f.reason, ""), nil
	}
	if set == nil || !allowed(set, subscriber, now) {
		n.count("regevent.refused")
		return n.response(req, 403, "Forbidden", ""), nil
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
		ID: subscriptionID(d.ID()), IMPU: impu, Subscriber: subscriber.String(),
		Dialog: storedDialog(d), Expires: now.Add(exp), CSeq: 1,
	}
	if exp == 0 {
		// A fetch (RFC 6665 §4.4.3): one NOTIFY, and no subscription.
		res := n.ok(req, tag, 0)
		return res, func(ctx context.Context) {
			n.notify(ctx, sub, 1, 0, nil, set, Registered, terminated("timeout"), now)
		}
	}
	saved, err := n.cfg.Store.SaveSubscription(ctx, sub)
	if err != nil {
		return n.internal(req, "saving a subscription", err), nil
	}
	n.count("regevent.subscribed")
	res := n.ok(req, tag, exp)
	return res, func(ctx context.Context) {
		n.notify(ctx, saved, saved.CSeq, saved.ReginfoVersion, nil, set, Registered, active(exp), now)
	}
}

// allowed reports whether subscriber may watch set: the P-CSCF over whose
// flow a live binding came, as its Path's first URI (§5.2.3), or one of the
// set's identities, the UE itself.
func allowed(set *state.Registration, subscriber sip.URI, now time.Time) bool {
	for _, c := range set.Contacts {
		if c.Expired(now) || len(c.Path) == 0 {
			continue
		}
		if p, err := sip.ParseAddress(c.Path[0]); err == nil && p.URI.Equal(subscriber) {
			return true
		}
	}
	impu, ok := identity.CanonicalIMPU(subscriber.String())
	if !ok {
		return false
	}
	for _, id := range set.Identities {
		if id.IMPU == impu {
			return true
		}
	}
	return false
}

// refresh answers a SUBSCRIBE in a subscription's dialog: a refresh, or with
// Expires 0 its end (RFC 6665 §4.1.2.2, §4.1.2.3). It must match a stored
// subscription's dialog, in order, and its subscriber, or it is 481.
func (n *Notifier) refresh(ctx context.Context, req *sip.Request) (*sip.Response, func(context.Context)) {
	exp, err := n.expiresOf(req)
	if err != nil {
		return n.response(req, 400, "Bad Expires", ""), nil
	}
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	pai, err3 := req.Header.PAssertedIdentity()
	if err1 != nil || err2 != nil || err3 != nil {
		return n.response(req, 400, "Bad Request", ""), nil
	}
	id := subscriptionID((&dialog.Dialog{CallID: req.Header.Get("Call-ID"), Local: to, Remote: from}).ID())
	for range saveAttempts {
		now := n.cfg.Now()
		sub, err := n.cfg.Store.Subscription(ctx, id)
		switch {
		case errors.Is(err, state.ErrNotFound):
			return n.noSubscription(req), nil
		case err != nil:
			return n.internal(req, "reading a subscription", err), nil
		case sub.Terminated:
			return n.noSubscription(req), nil
		}
		if len(pai) == 0 || !sameURI(pai[0].URI, sub.Subscriber) {
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
		}
		next := sub.Clone()
		next.Dialog = storedDialog(d)
		next.Expires = now.Add(exp)
		ss := active(exp)
		if exp == 0 {
			next.Terminated, next.Expires = true, now.Add(state.TerminatedGrace)
			ss = terminated("")
		}
		saved, err := n.cfg.Store.SaveSubscription(ctx, next)
		switch {
		case errors.Is(err, state.ErrConflict):
			// A NOTIFY counted meanwhile: read it again.
			continue
		case errors.Is(err, state.ErrNotFound):
			return n.noSubscription(req), nil
		case err != nil:
			return n.internal(req, "saving a subscription", err), nil
		}
		res := n.ok(req, to.Tag(), exp)
		return res, func(ctx context.Context) {
			set, _ := n.liveSet(ctx, saved.IMPU, n.cfg.Now())
			n.notifyNext(ctx, saved, nil, set, Registered, ss)
			if saved.Terminated {
				n.end(ctx, saved)
			}
		}
	}
	return n.internal(req, "saving a subscription", errors.New("kept changing")), nil
}

func sameURI(u sip.URI, stored string) bool {
	s, err := sip.ParseURI(stored)
	return err == nil && s.Equal(u)
}

func (n *Notifier) noSubscription(req *sip.Request) *sip.Response {
	n.count("regevent.no_subscription")
	return n.response(req, 481, "Subscription does not exist", "")
}

// liveSet is the record of impu's set, nil if it has none live at now.
func (n *Notifier) liveSet(ctx context.Context, impu string, now time.Time) (*state.Registration, *failure) {
	id, err := n.cfg.Store.Identity(ctx, impu, now)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		n.internalLog("reading an identity", err)
		return nil, &failure{500, "Server Internal Error"}
	}
	set, err := n.cfg.Store.Registration(ctx, id.Set)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, nil
	case err != nil:
		n.internalLog("reading a registration", err)
		return nil, &failure{500, "Server Internal Error"}
	}
	for _, c := range set.Contacts {
		if !c.Expired(now) {
			return set, nil
		}
	}
	return nil, nil
}

type failure struct {
	code   int
	reason string
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

// internalLog logs a failure by its step and error, which name no identity.
func (n *Notifier) internalLog(what string, err error) {
	n.log.Error("regevent: internal failure", "step", what, "error", err.Error())
	n.count("regevent.internal_errors")
}
