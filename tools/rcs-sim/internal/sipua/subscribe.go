package sipua

import (
	"context"
	"errors"
	"slices"
	"strconv"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Subscribe subscribes to the event package event at target, accepting the
// body type accept, for expires seconds (RFC 6665 §4.1.2), and returns the
// subscription with the SUBSCRIBE's final response. A non-2xx returns no
// subscription and a *StatusError. The first NOTIFY may come before the 2xx
// or after it. An expires of 0 fetches the state once (§4.1.2.1): the one
// NOTIFY, terminated, ends the subscription.
func (ua *UA) Subscribe(ctx context.Context, target sip.URI, event, accept string, expires int) (*Subscription, *sip.Response, error) {
	if event == "" || accept == "" || expires < 0 {
		return nil, nil, errors.New("sipua: a SUBSCRIBE needs an event, a body type and an expiry")
	}
	req, err := ua.NewRequest("SUBSCRIBE", target)
	if err != nil {
		return nil, nil, err
	}
	contact := sip.Contact{Address: sip.Address{URI: ua.contact.URI}}
	contact.URI.Params = slices.Clone(ua.contact.URI.Params)
	contact.URI.Params.SetFlag("ob")
	add(req, &err, "Contact", contact.String())
	add(req, &err, "Event", event)
	add(req, &err, "Accept", accept)
	add(req, &err, "Expires", strconv.Itoa(expires))
	if err != nil {
		return nil, nil, err
	}
	from, err := req.Header.From()
	if err != nil {
		return nil, nil, err
	}
	callID := req.Header.Get("Call-ID")
	cseq, _ := req.Header.CSeq()
	s := &Subscription{
		ua: ua, key: subscriptionKey(callID, from.Tag()), callID: callID, local: req.Header.Get("From"),
		event: event, target: target,
		notifications: make(chan Notification, queueLength), cseq: cseq.Seq, done: make(chan struct{}),
	}
	// Kept before the SUBSCRIBE goes, so a NOTIFY that overtakes its 2xx
	// finds it.
	ua.mu.Lock()
	ua.subs[s.key] = s
	ua.mu.Unlock()
	res, err := ua.Send(ctx, req)
	switch {
	case err != nil:
		ua.forgetSubscription(s)
		return nil, nil, err
	case res.StatusCode >= 300:
		ua.forgetSubscription(s)
		return nil, res, &StatusError{Method: "SUBSCRIBE", Code: res.StatusCode}
	}
	// The 2xx's Record-Route, reversed (RFC 3261 §12.1.2), stands in as the
	// route set until a NOTIFY gives its own.
	var routes []string
	if rr, err := res.Header.RecordRoute(); err == nil {
		for _, a := range slices.Backward(rr) {
			routes = append(routes, a.String())
		}
	}
	s.mu.Lock()
	if !s.notified {
		s.remote, s.routes, s.remoteTarget = res.Header.Get("To"), routes, contactOr(res, target)
	}
	s.mu.Unlock()
	return s, res, nil
}
