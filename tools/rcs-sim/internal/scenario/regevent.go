package scenario

import (
	"context"
	"errors"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// noDeregister is why reg-event's network-deregister step is skipped on a
// stack that has given the scenario no way to deregister the client: until
// the HSS API's DELETE and scscf's RTR exist (#14), none has.
const noDeregister = "network deregistration not configured"

// regEvent is the reg-event scenario (#135 AC 3, RFC 3680, TS 24.229
// §5.1.1.3). The client subscribes to the reg event of its own IMPU, sees
// its contact active in the full state, sees a refresh raise the version,
// and sees its de-registration terminate its contact. Then it registers and
// subscribes again, has the network deregister it, and sees its contact
// end with the network's event. Each subscription's versions start at 0 and
// rise by one (RFC 3680 §5.1, §5.2). Error texts are fixed: nothing the
// network sent reaches a result line.
func regEvent(r *run) error {
	if r.cfg.SIP == nil {
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoSIP })
	}
	var c *sipClient
	if err := r.step("register", func(ctx context.Context) (map[string]int64, error) {
		var err error
		c, err = r.newSIPClient(ctx, *r.cfg.SIP, r.cfg.Self)
		return nil, sipError(err)
	}); err != nil {
		return err
	}
	var w *regWatch
	if err := r.step("subscribe", func(ctx context.Context) (map[string]int64, error) {
		var detail map[string]int64
		var err error
		w, detail, err = r.subscribeRegEvent(ctx, c)
		return detail, err
	}); err != nil {
		return err
	}
	if err := r.step("re-register", func(ctx context.Context) (map[string]int64, error) {
		reg, err := c.ua.Register(ctx)
		if err != nil {
			return nil, sipError(err)
		}
		n, own, skipped, err := w.untilChanged(ctx, refreshedBy(reg))
		detail := map[string]int64{"skipped": int64(skipped)}
		switch {
		case err != nil:
			return detail, err
		case n.State != "active":
			return detail, errors.New("the subscription is not active after the refresh")
		case !own.Active():
			return detail, errors.New("the client's contact is not active after the refresh")
		}
		detail["version"] = int64(n.Info.Version)
		return detail, nil
	}); err != nil {
		return err
	}
	if err := r.step("unregister", func(ctx context.Context) (map[string]int64, error) {
		if _, err := c.ua.Unregister(ctx); err != nil {
			return nil, sipError(err)
		}
		n, own, err := w.next(ctx)
		if err != nil {
			return nil, err
		}
		if own.Active() || own.Event != reginfo.Unregistered {
			return nil, errors.New("the client's contact did not end as unregistered")
		}
		// After the user's own de-registration the subscription ends as if
		// it had been refreshed with Expires 0 (TS 24.229 §5.4.1.4), so with
		// no reason, "timeout", or "deactivated" (subscribe again, RFC 6665
		// §4.1.3). "noresource" says the registration itself went away
		// without the user, an expiry for one, which is not what happened
		// here, so it fails: the team's decision on #216.
		return w.ended(n, "", "timeout", "deactivated")
	}); err != nil {
		return err
	}
	if r.cfg.Deregister == nil {
		return r.skip("network-deregister", noDeregister)
	}
	return r.step("network-deregister", func(ctx context.Context) (map[string]int64, error) {
		if _, err := c.ua.Register(ctx); err != nil {
			return nil, sipError(err)
		}
		w, detail, err := r.subscribeRegEvent(ctx, c)
		if err != nil {
			return detail, err
		}
		if err := r.cfg.Deregister(ctx, r.cfg.SIP.IMPU); err != nil {
			return nil, errors.New("the network deregistration could not be asked for")
		}
		n, own, err := w.next(ctx)
		if err != nil {
			return nil, err
		}
		// TS 24.229 §5.4.1.5 4) b): "unregistered", "deactivated" (the
		// client may register again) or "rejected" (it may not; RFC 3680
		// §4.7.1).
		switch {
		case own.Active():
			return nil, errors.New("the client's contact did not end with the network's deregistration")
		case own.Event != reginfo.Unregistered && own.Event != reginfo.Deactivated && own.Event != reginfo.Rejected:
			return nil, errors.New("the client's contact did not end as unregistered, deactivated or rejected")
		}
		// §5.4.1.5 sets the state to "terminated" and no reason; RFC 6665
		// §4.1.3 makes the reason optional, and these are the ones it has
		// for a subscription the notifier ended.
		return w.ended(n, "", "deactivated", "probation", "rejected", "timeout", "giveup", "noresource")
	})
}

// subscribeRegEvent subscribes c to the reg event of its IMPU and checks
// the first NOTIFY: active, the full state, version 0, the client's contact
// active. The subscription ends with the run.
func (r *run) subscribeRegEvent(ctx context.Context, c *sipClient) (*regWatch, map[string]int64, error) {
	sub, res, err := c.ua.SubscribeRegEvent(ctx)
	if err != nil {
		return nil, nil, sipError(err)
	}
	r.onEnd(func() {
		ctx, cancel := context.WithTimeout(context.Background(), r.cfg.StepTimeout)
		defer cancel()
		_, _ = sub.Unsubscribe(ctx)
	})
	w := &regWatch{impu: r.cfg.SIP.IMPU, contact: c.ua.ContactURI(), instance: "<" + r.cfg.SIP.InstanceID + ">", sub: sub}
	detail := map[string]int64{"status": int64(res.StatusCode)}
	n, own, err := w.next(ctx)
	switch {
	case err != nil:
		return w, detail, err
	case n.State != "active":
		return w, detail, errors.New("the subscription is not active")
	case n.Info.State != reginfo.Full:
		return w, detail, errors.New("the first NOTIFY is not the full state")
	case !own.Active():
		return w, detail, errors.New("the client's contact is not active")
	}
	detail["version"] = int64(n.Info.Version)
	return w, detail, nil
}

// untilChanged waits for the NOTIFY that tells of the change a REGISTER
// made, and returns it with the client's contact and how many came before
// it. A network may first send a NOTIFY of a state it has told already,
// the client's contact as it was and the version raised (#473 QA): one
// that refreshed does not accept and that repeats the last NOTIFY's
// contact is skipped, checked as next checks every NOTIFY. Any other is
// returned for the step to judge.
func (w *regWatch) untilChanged(ctx context.Context, refreshed func(reginfo.Contact) bool) (sipua.Notification, reginfo.Contact, int, error) {
	for skipped := 0; ; skipped++ {
		before := w.last
		n, own, err := w.next(ctx)
		if err != nil || refreshed(own) || !sameContact(own, before) {
			return n, own, skipped, err
		}
	}
}

// refreshedBy accepts the client's contact as the refresh reg made it: by
// the CSeq of the REGISTER that last changed it, when the NOTIFY gives one
// (RFC 3680 §5.1), or else by its "refreshed" event.
func refreshedBy(reg *sipua.Registration) func(reginfo.Contact) bool {
	var seq uint64
	if cseq, err := reg.Response.Header.CSeq(); err == nil {
		seq = uint64(cseq.Seq)
	}
	return func(own reginfo.Contact) bool {
		if own.CSeq != nil && seq != 0 {
			return own.Active() && *own.CSeq >= seq
		}
		return own.Active() && own.Event == reginfo.Refreshed
	}
}

// sameContact reports whether a and b tell the same of the client's
// contact: its state, its event and the CSeq of the REGISTER that last
// changed it.
func sameContact(a, b reginfo.Contact) bool {
	cseq := func(c reginfo.Contact) int64 {
		if c.CSeq == nil {
			return -1
		}
		return int64(*c.CSeq)
	}
	return a.State == b.State && a.Event == b.Event && cseq(a) == cseq(b)
}

// regWatch follows the NOTIFYs of one subscription. instance is the
// client's +sip.instance, as a contact parameter writes it.
type regWatch struct {
	impu, contact sip.URI
	instance      string
	sub           *sipua.Subscription
	version       uint32
	seen          bool
	// last is the client's contact as the last NOTIFY told it.
	last reginfo.Contact
}

// next waits for the next NOTIFY and returns it with the client's contact
// in it. internal/sip/reginfo has read the body, its version 32 bits. next
// checks what every NOTIFY must have besides: a reginfo body; a version of
// 0 in the first and one more each time after (RFC 3680 §5.1, §5.2); the
// client's contact under its AOR, which ByAOR compares canonically; and,
// the contact active, its registration active too, since a registration
// with a contact bound is active (§4.7.1).
func (w *regWatch) next(ctx context.Context) (sipua.Notification, reginfo.Contact, error) {
	var n sipua.Notification
	select {
	case n = <-w.sub.Notifications():
	case <-ctx.Done():
		return n, reginfo.Contact{}, errors.New("no NOTIFY came")
	}
	switch {
	case n.Err != nil:
		return n, reginfo.Contact{}, n.Err
	case n.Info == nil:
		return n, reginfo.Contact{}, errors.New("the NOTIFY has no reginfo")
	case !w.seen && n.Info.Version != 0:
		return n, reginfo.Contact{}, errors.New("the first reginfo version is not 0")
	case w.seen && n.Info.Version != w.version+1:
		return n, reginfo.Contact{}, errors.New("the reginfo version did not rise by one")
	}
	w.version, w.seen = n.Info.Version, true
	reg, ok := n.Info.ByAOR(w.impu)
	if !ok {
		return n, reginfo.Contact{}, errors.New("the reginfo does not list the client's contact")
	}
	own, ok := w.own(reg)
	switch {
	case !ok:
		return n, own, errors.New("the reginfo does not list the client's contact")
	case own.Active() && reg.State != reginfo.Active:
		return n, own, errors.New("the client's active contact is in a registration that is not active")
	}
	w.last = own
	return n, own, nil
}

// own is the client's contact in reg: at its URI, with its +sip.instance
// (a URI may be bound more than once, RFC 5626 §6), or else with no
// instance at all. A contact with another instance is another device's
// binding, never the client's (RFC 5626 §4.1, as sipua's isOurs has it).
func (w *regWatch) own(reg reginfo.Registration) (reginfo.Contact, bool) {
	var plain *reginfo.Contact
	for _, c := range reg.ByURI(w.contact) {
		inst, ok := c.Param("+sip.instance")
		switch {
		case ok && sipua.SameInstance(inst, w.instance):
			return c, true
		case !ok && plain == nil:
			plain = &c
		}
	}
	if plain == nil {
		return reginfo.Contact{}, false
	}
	return *plain, true
}

// ended checks the subscription after the client's contact has terminated.
// It ends once every registration in the document has (TS 24.229
// §5.4.2.1.2, §5.1.1.6.1), with one of reasons; while another one is
// active, a binding an earlier run left say, it goes on, and the detail
// counts the registrations still active ("others").
func (w *regWatch) ended(n sipua.Notification, reasons ...string) (map[string]int64, error) {
	detail := map[string]int64{"version": int64(n.Info.Version)}
	others := 0
	for _, reg := range n.Info.Registrations {
		if reg.State != reginfo.Terminated {
			others++
		}
	}
	if others > 0 {
		detail["others"] = int64(others)
		if n.State != "active" {
			return detail, errors.New("the subscription ended while a registration is still active")
		}
		return detail, nil
	}
	if n.State != "terminated" {
		return detail, errors.New("the subscription did not end with the last registration")
	}
	for _, reason := range reasons {
		if n.Reason == reason {
			return detail, nil
		}
	}
	return detail, errors.New("the subscription ended for a reason it should not")
}
