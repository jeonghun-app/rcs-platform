// Package dialog keeps one side of a SIP dialog (RFC 3261 §12) and builds and
// checks the requests in it, for a service that is a user agent in a
// dialog rather than a proxy on its path: pcscf subscribing to the reg
// event of the users it serves, and scscf notifying them (RFC 6665, TS
// 24.229 §5.2.3, §5.4.2.1).
//
// A Dialog is plain data, so a service can keep it in memory or store it
// and carry on from another instance. It sends nothing itself: Request and
// the subscription helpers build requests the caller sends in a client
// transaction (transaction.Layer.Request) to NextHop, and Accept checks a
// request the caller received through its UAS before it answers. Route
// sets are used as RFC 3261 §12.2.1.1 says, for loose routers and strict
// ones alike.
package dialog

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

var (
	// ErrNotInDialog reports a request whose Call-ID or tags are not this
	// dialog's.
	ErrNotInDialog = errors.New("dialog: request not in this dialog")
	// ErrOutOfOrder reports a request whose CSeq is not above the last one
	// the other side sent, which RFC 3261 §12.2.2 answers 500.
	ErrOutOfOrder = errors.New("dialog: request out of order")
	// ErrNoDialog reports a message that cannot set up a dialog: no tag,
	// no Contact, or a header field that does not parse.
	ErrNoDialog = errors.New("dialog: message cannot set up a dialog")
)

// Dialog is the state of one side of a dialog (RFC 3261 §12.1).
type Dialog struct {
	CallID string
	// Local and Remote are the From and To of this side's requests, their
	// tags included.
	Local, Remote sip.Address
	// LocalTarget is this side's Contact, which a target refresh request
	// carries; RemoteTarget is the other side's, the Request-URI of this
	// side's requests.
	LocalTarget, RemoteTarget sip.URI
	// RouteSet is the route this side's requests take, first hop first.
	RouteSet []sip.Address
	// LocalSeq is the CSeq of this side's last request. RemoteSeq is that of
	// the other side's last request, when HasRemoteSeq says it has sent one.
	LocalSeq     uint32
	RemoteSeq    uint32
	HasRemoteSeq bool
}

// UAC is the dialog that a response with a To tag sets up for the request
// this side sent (RFC 3261 §12.1.2), an INVITE: its route set is the
// response's Record-Route reversed, its remote target the response's
// Contact. A subscription's dialog comes from its first NOTIFY instead
// (FromNotify).
func UAC(req *sip.Request, res *sip.Response) (*Dialog, error) {
	d, err := sent(req)
	if err != nil {
		return nil, err
	}
	if d.Remote, err = res.Header.To(); err != nil || d.Remote.Tag() == "" {
		return nil, fmt.Errorf("%w: To without a tag", ErrNoDialog)
	}
	if d.RemoteTarget, err = contact(&res.Header); err != nil {
		return nil, err
	}
	rr, err := res.Header.RecordRoute()
	if err != nil {
		return nil, fmt.Errorf("%w: malformed Record-Route", ErrNoDialog)
	}
	d.RouteSet = slices.Clone(rr)
	slices.Reverse(d.RouteSet)
	return d, nil
}

// FromNotify is the dialog that the first NOTIFY of a subscription sets up
// for the SUBSCRIBE this side sent: a subscription's dialog is created by
// that NOTIFY, whether it comes before the 2xx or after it, and its route
// set is the NOTIFY's, not the 2xx's (RFC 6665 §4.4.1). The subscriber takes
// it as a UAS takes a request: the route set is the NOTIFY's Record-Route in
// order and the remote target its Contact. The NOTIFY's CSeq is taken as
// the remote one.
func FromNotify(subscribe, notify *sip.Request) (*Dialog, error) {
	d, err := sent(subscribe)
	if err != nil {
		return nil, err
	}
	if d.Remote, err = notify.Header.From(); err != nil || d.Remote.Tag() == "" {
		return nil, fmt.Errorf("%w: From without a tag", ErrNoDialog)
	}
	if err := received(d, notify); err != nil {
		return nil, err
	}
	return d, nil
}

// UAS is the dialog that this side sets up by answering req with a response
// whose To tag is localTag and whose Contact is localTarget (RFC 3261
// §12.1.1): its route set is req's Record-Route in order, its remote target
// req's Contact.
func UAS(req *sip.Request, localTag string, localTarget sip.URI) (*Dialog, error) {
	if localTag == "" {
		return nil, fmt.Errorf("%w: no local tag", ErrNoDialog)
	}
	d := &Dialog{CallID: req.Header.Get("Call-ID"), LocalTarget: localTarget}
	var err error
	if d.Remote, err = req.Header.From(); err != nil || d.Remote.Tag() == "" {
		return nil, fmt.Errorf("%w: From without a tag", ErrNoDialog)
	}
	if d.Local, err = req.Header.To(); err != nil {
		return nil, fmt.Errorf("%w: malformed To", ErrNoDialog)
	}
	d.Local.Params.Set("tag", localTag)
	if d.CallID == "" {
		return nil, fmt.Errorf("%w: no Call-ID", ErrNoDialog)
	}
	if err := received(d, req); err != nil {
		return nil, err
	}
	return d, nil
}

// sent starts the dialog of a request this side sent: its Call-ID, From,
// Contact and CSeq.
func sent(req *sip.Request) (*Dialog, error) {
	d := &Dialog{CallID: req.Header.Get("Call-ID")}
	var err error
	if d.Local, err = req.Header.From(); err != nil || d.Local.Tag() == "" {
		return nil, fmt.Errorf("%w: From without a tag", ErrNoDialog)
	}
	if d.LocalTarget, err = contact(&req.Header); err != nil {
		return nil, err
	}
	cseq, err := req.Header.CSeq()
	if err != nil || d.CallID == "" {
		return nil, fmt.Errorf("%w: malformed CSeq or no Call-ID", ErrNoDialog)
	}
	d.LocalSeq = cseq.Seq
	return d, nil
}

// received takes the remote side of a dialog from a request it sent: the
// remote target, the route set and the CSeq.
func received(d *Dialog, req *sip.Request) error {
	var err error
	if d.RemoteTarget, err = contact(&req.Header); err != nil {
		return err
	}
	rr, err := req.Header.RecordRoute()
	if err != nil {
		return fmt.Errorf("%w: malformed Record-Route", ErrNoDialog)
	}
	d.RouteSet = slices.Clone(rr)
	cseq, err := req.Header.CSeq()
	if err != nil {
		return fmt.Errorf("%w: malformed CSeq", ErrNoDialog)
	}
	d.RemoteSeq, d.HasRemoteSeq = cseq.Seq, true
	return nil
}

// contact is the one Contact URI of a message that sets up a dialog or
// refreshes its target.
func contact(h *sip.Header) (sip.URI, error) {
	cs, err := h.Contact()
	if err != nil || len(cs) != 1 || cs[0].Star {
		return sip.URI{}, fmt.Errorf("%w: not one Contact", ErrNoDialog)
	}
	return cs[0].URI, nil
}

// LocalTag and RemoteTag are the dialog's tags.
func (d *Dialog) LocalTag() string  { return d.Local.Tag() }
func (d *Dialog) RemoteTag() string { return d.Remote.Tag() }

// ID is the dialog identifier (RFC 3261 §12): Call-ID and the two tags, in
// lower case since tags compare without it (§7.3.1), so that it can key a
// table.
func (d *Dialog) ID() string {
	return d.CallID + "\x00" + strings.ToLower(d.LocalTag()) + "\x00" + strings.ToLower(d.RemoteTag())
}

// targetRefresh reports whether method refreshes the remote target: INVITE
// (RFC 3261 §12.2), UPDATE (RFC 3311 §5.1), SUBSCRIBE and NOTIFY (RFC 6665
// §3.1, §3.2).
func targetRefresh(method string) bool {
	switch method {
	case "INVITE", "UPDATE", "SUBSCRIBE", "NOTIFY":
		return true
	}
	return false
}

// Accept checks that req, received from the other side, belongs to this
// dialog and is in order (RFC 3261 §12.2.2), and takes its CSeq and, for a
// target refresh request, its Contact. On an error d is unchanged:
// ErrNotInDialog is answered 481, ErrOutOfOrder 500 and ErrNoDialog 400.
func (d *Dialog) Accept(req *sip.Request) error {
	from, err1 := req.Header.From()
	to, err2 := req.Header.To()
	// Call-IDs compare exactly (RFC 3261 §8.1.1.4), tags, tokens, without
	// case (§7.3.1).
	if err1 != nil || err2 != nil || req.Header.Get("Call-ID") != d.CallID ||
		!strings.EqualFold(to.Tag(), d.LocalTag()) || !strings.EqualFold(from.Tag(), d.RemoteTag()) {
		return ErrNotInDialog
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return fmt.Errorf("%w: malformed CSeq", ErrNoDialog)
	}
	if d.HasRemoteSeq && cseq.Seq <= d.RemoteSeq {
		return ErrOutOfOrder
	}
	target := d.RemoteTarget
	if targetRefresh(req.Method) && req.Header.Has("Contact") {
		if target, err = contact(&req.Header); err != nil {
			return err
		}
	}
	d.RemoteSeq, d.HasRemoteSeq, d.RemoteTarget = cseq.Seq, true, target
	return nil
}

// NextHop is where this side's requests in the dialog go first: the first
// route, or the remote target when there is none (RFC 3261 §12.2.1.1).
func (d *Dialog) NextHop() sip.URI {
	if len(d.RouteSet) > 0 {
		return d.RouteSet[0].URI
	}
	return d.RemoteTarget
}

// Request builds this side's next request in the dialog (RFC 3261
// §12.2.1.1), with the next CSeq, which d keeps. Its top Via names the
// transport placeholder host "invalid" with a new branch; the transport
// writes its own sent-by when it sends it (RFC 3261 §18.1.1). A target
// refresh request carries LocalTarget as its Contact.
func (d *Dialog) Request(method string, ids sip.IDGenerator) (*sip.Request, error) {
	if d.LocalSeq == 1<<32-1 {
		return nil, errors.New("dialog: CSeq exhausted")
	}
	branch, err := ids.Branch()
	if err != nil {
		return nil, err
	}
	req := &sip.Request{Method: method, URI: d.RemoteTarget}
	routes := d.RouteSet
	// A strict router in the first route takes the Request-URI, and the
	// remote target goes last (§12.2.1.1).
	if len(routes) > 0 && !routes[0].URI.Params.Has("lr") {
		req.URI = routes[0].URI
		routes = append(slices.Clone(routes[1:]), sip.Address{URI: d.RemoteTarget})
	}
	seq := d.LocalSeq + 1
	fields := [][2]string{
		{"Via", "SIP/2.0/TCP invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", d.Local.String()},
		{"To", d.Remote.String()},
		{"Call-ID", d.CallID},
		{"CSeq", strconv.FormatUint(uint64(seq), 10) + " " + method},
	}
	for _, r := range routes {
		fields = append(fields, [2]string{"Route", r.String()})
	}
	if targetRefresh(method) {
		fields = append(fields, [2]string{"Contact", sip.Address{URI: d.LocalTarget}.String()})
	}
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	d.LocalSeq = seq
	return req, nil
}
