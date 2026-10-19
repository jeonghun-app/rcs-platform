package scenario

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// regEvent is the reg-event scenario (#135 AC 3, RFC 3680, TS 24.229
// §5.1.1.3): the client subscribes to the reg event of its own IMPU, sees
// its contact active in the full state, sees a refresh raise the version,
// and sees its de-registration terminate the contact and the
// subscription. Every NOTIFY's version must be one above the last.
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
	w := &regWatch{impu: r.cfg.SIP.IMPU.String(), contact: c.ua.ContactURI()}
	if err := r.step("subscribe", func(ctx context.Context) (map[string]int64, error) {
		sub, res, err := c.ua.SubscribeRegEvent(ctx)
		if err != nil {
			return nil, sipError(err)
		}
		w.sub = sub
		r.onEnd(func() {
			ctx, cancel := context.WithTimeout(context.Background(), r.cfg.StepTimeout)
			defer cancel()
			_, _ = sub.Unsubscribe(ctx)
		})
		n, err := w.next(ctx, "active", "active")
		detail := map[string]int64{"status": int64(res.StatusCode)}
		if err != nil {
			return detail, err
		}
		if n.Info.State != "full" {
			return detail, errors.New("the first NOTIFY is not the full state")
		}
		detail["version"] = int64(n.Info.Version)
		return detail, nil
	}); err != nil {
		return err
	}
	if err := r.step("re-register", func(ctx context.Context) (map[string]int64, error) {
		if _, err := c.ua.Register(ctx); err != nil {
			return nil, sipError(err)
		}
		n, err := w.next(ctx, "active", "active")
		if err != nil {
			return nil, err
		}
		return map[string]int64{"version": int64(n.Info.Version)}, nil
	}); err != nil {
		return err
	}
	return r.step("unregister", func(ctx context.Context) (map[string]int64, error) {
		if _, err := c.ua.Unregister(ctx); err != nil {
			return nil, sipError(err)
		}
		// A terminated Subscription-State ends the subscription with the
		// registration.
		n, err := w.next(ctx, "terminated", "terminated")
		if err != nil {
			return nil, err
		}
		return map[string]int64{"version": int64(n.Info.Version)}, nil
	})
}

// regWatch follows the NOTIFYs of one subscription.
type regWatch struct {
	impu    string
	contact sip.URI
	sub     *sipua.Subscription
	version uint64
	seen    bool
}

// next waits for the next NOTIFY and checks it: the Subscription-State
// wanted, the client's contact in the state wanted, and a version one above
// the last (RFC 3680 §5.3.1).
func (w *regWatch) next(ctx context.Context, subState, contactState string) (sipua.Notification, error) {
	var n sipua.Notification
	select {
	case n = <-w.sub.Notifications():
	case <-ctx.Done():
		return n, errors.New("no NOTIFY came")
	}
	switch {
	case n.Err != nil:
		return n, n.Err
	case n.State != subState:
		return n, fmt.Errorf("the NOTIFY's subscription state is %q, want %q", n.State, subState)
	case n.Info == nil:
		return n, errors.New("the NOTIFY has no reginfo")
	case w.seen && n.Info.Version != w.version+1:
		return n, fmt.Errorf("the reginfo version went from %d to %d, want one more", w.version, n.Info.Version)
	}
	w.version, w.seen = n.Info.Version, true
	found := false
	for _, reg := range n.Info.Registrations {
		if reg.AOR != w.impu {
			continue
		}
		for _, ct := range reg.Contacts {
			if u, err := sip.ParseURI(ct.URI); err == nil && u.Equal(w.contact) {
				found = true
				if ct.State != contactState {
					return n, fmt.Errorf("the client's contact is %q, want %q", ct.State, contactState)
				}
			}
		}
	}
	if !found {
		return n, errors.New("the reginfo does not list the client's contact")
	}
	return n, nil
}
