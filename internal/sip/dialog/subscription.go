package dialog

import (
	"errors"
	"slices"
	"strconv"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// Initial builds a request outside a dialog that may set one up (RFC 3261
// §8.1.1): method to target, from from with a new tag, to to, a new Call-ID
// made for host, CSeq 1, routes as its Route and contact as its Contact.
// Its top Via is the placeholder Request writes. A SUBSCRIBE's dialog is set
// up by its first NOTIFY (FromNotify, RFC 6665 §4.4.1).
func Initial(method string, target sip.URI, from, to sip.Address, routes []sip.Address, contact sip.URI, host string, ids sip.IDGenerator) (*sip.Request, error) {
	branch, err := ids.Branch()
	if err != nil {
		return nil, err
	}
	tag, err := ids.Tag()
	if err != nil {
		return nil, err
	}
	callID, err := ids.CallID(host)
	if err != nil {
		return nil, err
	}
	from.Params = slices.Clone(from.Params)
	from.Params.Set("tag", tag)
	to.Params = slices.Clone(to.Params)
	to.Params.Del("tag")
	req := &sip.Request{Method: method, URI: target}
	fields := [][2]string{
		{"Via", "SIP/2.0/TCP invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", from.String()},
		{"To", to.String()},
		{"Call-ID", callID},
		{"CSeq", "1 " + method},
	}
	for _, r := range routes {
		fields = append(fields, [2]string{"Route", r.String()})
	}
	fields = append(fields, [2]string{"Contact", sip.Address{URI: contact}.String()})
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// Subscribe builds this side's SUBSCRIBE in the dialog for event: a refresh
// for expires seconds, or with expires 0 the end of the subscription (RFC
// 6665 §4.1.2.2, §4.1.2.3).
func (d *Dialog) Subscribe(event sip.Event, expires uint32, ids sip.IDGenerator) (*sip.Request, error) {
	req, err := d.Request("SUBSCRIBE", ids)
	if err != nil {
		return nil, err
	}
	for _, f := range [][2]string{{"Event", event.String()}, {"Expires", strconv.FormatUint(uint64(expires), 10)}} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// Notify builds this side's NOTIFY in the dialog, the notifier's (RFC 6665
// §4.2.2): event as the SUBSCRIBE named it, its id included, the
// subscription's state, and body of contentType, if any.
func (d *Dialog) Notify(event sip.Event, state sip.SubscriptionState, contentType string, body []byte, ids sip.IDGenerator) (*sip.Request, error) {
	if (contentType == "") != (len(body) == 0) {
		return nil, errors.New("dialog: a NOTIFY body needs a content type, and only a body has one")
	}
	req, err := d.Request("NOTIFY", ids)
	if err != nil {
		return nil, err
	}
	fields := [][2]string{{"Event", event.String()}, {"Subscription-State", state.String()}}
	if contentType != "" {
		fields = append(fields, [2]string{"Content-Type", contentType})
	}
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	req.Body = body
	return req, nil
}
