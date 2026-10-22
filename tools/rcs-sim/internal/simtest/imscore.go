package simtest

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// IMSCore stands in for pcscf, icscf and scscf together, as far as a
// registered client can tell, until they exist (#135): a registrar that
// authenticates with SIP Digest and keeps each IMPU's flow, and a proxy that
// routes every other request to the flow its Request-URI is registered on.
// It is a test double, not an IMS core: no iFC, no AS, no
// P-Asserted-Identity checks.
type IMSCore struct {
	// Addr is where clients connect, over TCP.
	Addr netip.AddrPort
	// Domain is the home domain, the Digest realm.
	Domain string
	// Rewrite, when set before any request, changes each request the core
	// forwards or sends, NOTIFYs included, as a faulty network element
	// would. It must not block: it runs on the reading goroutine of the
	// sender's connection for a request it forwards, and on the notifier's
	// goroutine for a NOTIFY, so two calls may run at once and a Rewrite
	// that keeps state must lock it.
	Rewrite func(*sip.Request)
	// RewriteResponse, when set before any request, changes each response
	// the core relays back for a request it forwarded, req, as a faulty
	// network element would. It runs on the transaction's goroutine and
	// must not block.
	RewriteResponse func(req *sip.Request, res *sip.Response)
	// NotifyAnswered, when set before any request, hears how each NOTIFY
	// the core sent ended: the subscriber's final response, or the error
	// that ended its transaction. It runs on the transaction's goroutine
	// and must not block. A test waits on it for a subscriber that must
	// drop a NOTIFY to have done so (#396).
	NotifyAnswered func(req *sip.Request, res *sip.Response, err error)
	// Forwarding, when set before any request, runs on the forwarding
	// goroutine just before the core passes a request on, and may hold
	// it there; CancelTaken runs once the core has answered a CANCEL and
	// either passed it on, once it has gone, or kept it for its INVITE. A
	// test pins with them that a CANCEL goes only after its INVITE (RFC
	// 3261 §9.1).
	Forwarding  func(*sip.Request)
	CancelTaken func()
	// answered, if set (export_test.go), runs once a REGISTER that changed
	// a registration has been answered.
	answered func(*sip.Request)
	// answering, if set (export_test.go), runs just before the 200 of a
	// REGISTER or a SUBSCRIBE is written; waiting, if set, runs on the
	// notifier's goroutine as each NOTIFY begins to wait for its gate.
	answering func(*sip.Request)
	waiting   func(gate <-chan struct{})
	// Offline, when set before any request, is what the core does with a
	// request to an IMPU that has no binding.
	Offline Offline
	// RepeatFirstNotify, when set before any request, has the core send
	// the first subscription's first NOTIFY twice, the state the same and
	// the version raised, as scscf may when an initial registration's
	// change reaches a subscription made after it (#473 QA).
	RepeatFirstNotify bool
	repeated          atomic.Bool

	t     testing.TB
	tr    *transport.Transport
	layer *transaction.Layer
	ds    *digest.Server
	users map[string]string
	ids   sip.IDGenerator

	mu       sync.Mutex
	bindings map[string]transport.FlowID
	// invites are the INVITEs the core forwarded and has no final answer
	// for yet, by their server transaction, for a CANCEL (RFC 3261 §16.10).
	invites map[*transaction.ServerTransaction]*forwardedInvite
	// t1 is the core's T1, for the 64*T1 it gives a CANCEL.
	t1 time.Duration
	// instances are each IMPU's last registered +sip.instance, and stored
	// the requests StoreAndForward holds for it, by aorKey.
	instances map[string]string
	stored    map[string][]*sip.Request
	// contacts are each IMPU's registered Contact URI, and subs the reg
	// event subscriptions to it (RFC 3680), by aorKey.
	contacts map[string]string
	// events are the event that last changed each IMPU's contact, which a
	// NOTIFY that does not change it writes again (RFC 3680 §4.7.1).
	events map[string]string
	subs   map[string][]*regSub
	// notifies sends NOTIFYs one at a time, in the order they were made,
	// off the reading goroutine.
	notifies chan func()
	stop     chan struct{}
	// silent marks the responses quietSender drops; silenced counts the
	// requests left unanswered so.
	silent   sync.Map
	silenced atomic.Int64
}

// quietSender is the stand-in's transaction layer's sender. It drops the
// responses silence marked, the way the platform's proxy ends a server
// transaction without sending anything (internal/sip/proxy).
type quietSender struct {
	transaction.Sender
	c *IMSCore
}

func (q quietSender) SendResponse(res *sip.Response, src transport.Source, opts ...transport.SendOption) error {
	if _, ok := q.c.silent.Load(res); ok {
		return nil
	}
	return q.Sender.SendResponse(res, src, opts...)
}

// silence ends tx without a response: it is given one quietSender never
// sends, so that it completes, and the layer's own 500 for a TU that never
// answers does not go either (RFC 4320 §4.2).
func (c *IMSCore) silence(tx *transaction.ServerTransaction, req *sip.Request) {
	tag, _ := c.ids.Tag()
	res, err := sip.NewResponse(req, 408, "", tag)
	if err != nil {
		return
	}
	c.silent.Store(res, true)
	c.silenced.Add(1)
	_ = tx.Respond(res)
}

// Silenced is how many requests the core has left unanswered after they
// timed out on their way to the callee.
func (c *IMSCore) Silenced() int { return int(c.silenced.Load()) }

// regSub is one subscription to an IMPU's reg event, from the notifier's
// side.
type regSub struct {
	impu, callID, from, tag string
	target                  sip.URI
	flow                    transport.FlowID
	cseq                    uint32
	version                 uint64
	// until is when the subscription expires, as granted: a NOTIFY says
	// what is left of it and never more (RFC 6665 §4.1.3).
	until time.Time
}

// left is what remains of s, in whole seconds, rounded up; c.mu is held.
func (s *regSub) left() uint64 {
	d := time.Until(s.until)
	if d <= 0 {
		return 0
	}
	return uint64((d + time.Second - 1) / time.Second)
}

// Offline is what IMSCore does with a request to an unregistered IMPU.
type Offline int

const (
	// Refuse answers 480 (TS 24.229 §5.4.3.3), what the platform does
	// today.
	Refuse Offline = iota
	// StoreAndForward answers 202 and delivers the request when the IMPU
	// registers again, as rcs-as's store-and-forward will.
	StoreAndForward
	// Drop answers 200 and loses the request, as a faulty element would.
	Drop
	// RefuseNotFound answers 404, a refusal other than the platform's.
	RefuseNotFound
	// StoreAndChange is StoreAndForward with the stored message's text
	// changed, as a faulty store would.
	StoreAndChange
)

// aorKey is how bindings are keyed: scheme, user and host (case folded),
// without parameters, for registration and routing alike.
func aorKey(u sip.URI) string {
	return sip.URI{Scheme: strings.ToLower(u.Scheme), User: u.User, Host: strings.ToLower(u.Host)}.String()
}

// keyOf is aorKey for an IMPU written out; "" if it does not parse.
func keyOf(impu string) string {
	u, err := sip.ParseURI(impu)
	if err != nil {
		return ""
	}
	return aorKey(u)
}

// StartIMSCore starts an IMSCore for domain whose users are IMPI to Digest
// password. t1, if given, is its transactions' T1 instead of RFC 3261's
// 500 ms, for tests that wait out a timer.
func StartIMSCore(t testing.TB, domain string, users map[string]string, t1 ...time.Duration) *IMSCore {
	t.Helper()
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: domain, NonceKey: bytes.Repeat([]byte("i"), digest.MinNonceKeySize),
		NonceCounts: digest.NewMemoryNonceCounts(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &IMSCore{
		Domain: domain, t: t, ds: ds, users: users,
		bindings: map[string]transport.FlowID{}, instances: map[string]string{}, stored: map[string][]*sip.Request{},
		invites:  map[*transaction.ServerTransaction]*forwardedInvite{},
		contacts: map[string]string{}, events: map[string]string{}, subs: map[string][]*regSub{}, notifies: make(chan func(), 256), stop: make(chan struct{}),
	}
	go func() {
		for {
			select {
			case f := <-c.notifies:
				f()
			case <-c.stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(c.stop) })
	// A flow that closes ends the requests sent over it at once, as the
	// platform's P-CSCF ends them (Proxy.FlowClosed, #234), rather than at
	// Timer B or F (#414). The layer exists before the core listens, so
	// before any flow can close.
	tr, err := transport.New(transport.Config{
		OnFlowClosed: func(id transport.FlowID, _ transport.FlowInfo) { c.layer.FlowClosed(id) },
	}, func(in transport.Inbound) { c.layer.Receive(in) })
	if err != nil {
		t.Fatal(err)
	}
	c.tr = tr
	var cfg transaction.Config
	c.t1 = transaction.DefaultT1
	if len(t1) > 0 {
		cfg.T1, c.t1 = t1[0], t1[0]
		// The layer answers 500 for a TU that has not answered within
		// NonInviteFinalTimeout, 128*T1 by default. A non-INVITE routed to
		// a callee that never answers is left unanswered once the
		// forwarded request's Timer F (64*T1) ends it, as the platform's
		// proxy leaves it (RFC 4320 §4.2, #363): the stand-in ends its
		// server transaction with an answer it does not send, and that
		// has to come before the layer's 500. With a T1 of milliseconds
		// the two timers were a fraction of a second apart, and a loaded
		// host let the 500 come first (#339). The safety net keeps the
		// margin a proxy's has instead, in time the work takes rather than
		// in T1.
		cfg.NonInviteFinalTimeout = 64*cfg.T1 + transaction.FinalTimeoutMargin
	}
	if c.layer, err = transaction.New(quietSender{Sender: tr, c: c}, c, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.layer.Close(); tr.Close() })
	if c.Addr, err = tr.Listen(transport.ListenerConfig{
		Network: transport.TCP, Addr: "127.0.0.1:0", ClientFacing: true,
		AdvertisedHost: "core.invalid", AdvertisedPort: 5060,
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// Registered reports whether impu has a binding.
func (c *IMSCore) Registered(impu string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.bindings[keyOf(impu)]
	return ok
}

// Instance is the +sip.instance impu last registered with, kept after it
// unregisters; "" if it never did.
func (c *IMSCore) Instance(impu string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.instances[keyOf(impu)]
}

// Expire drops impu's binding, as its expiry would: requests to it then
// get what Offline says until it registers again, and its reg event
// subscribers are told the contact expired (RFC 3680 §4.7.1), which ends
// their subscriptions.
func (c *IMSCore) Expire(impu string) { c.end(impu, "expired") }

// Deregister ends impu's registration from the network side, as the
// S-CSCF does on the HSS's Registration-Termination-Request (TS 24.229
// §5.4.1.5): its contact terminates with event, "deactivated" (the client
// may register again) or "rejected" (it may not), and so do the
// subscriptions to its reg event.
func (c *IMSCore) Deregister(impu, event string) { c.end(impu, event) }

func (c *IMSCore) end(impu, event string) {
	key := keyOf(impu)
	c.mu.Lock()
	_, bound := c.bindings[key]
	contact := c.contacts[key]
	delete(c.bindings, key)
	delete(c.contacts, key)
	delete(c.events, key)
	if bound {
		c.queueChangeLocked(regChange{key: key, contact: contact, event: event}, closedGate)
	}
	c.mu.Unlock()
}

// closedGate lets a NOTIFY go at once: one that answers no request.
var closedGate = func() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Request implements transaction.TU.
func (c *IMSCore) Request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	switch {
	case req.Method == "REGISTER":
		res, answered, deliver := c.register(tx)
		c.respond(tx, res)
		if answered != nil {
			answered()
		}
		if deliver != nil {
			go deliver()
		}
		c.mu.Lock()
		hook := c.answered
		c.mu.Unlock()
		if hook != nil && answered != nil {
			hook(req)
		}
	case req.Method == "SUBSCRIBE" && strings.EqualFold(eventPackage(req), "reg"):
		c.subscribe(tx)
	case req.Method == "CANCEL":
		c.cancel(tx)
	default:
		c.route(tx)
	}
}

// forwardedInvite is an INVITE the core forwarded: the CANCEL for it, the
// flow it went over, whether the originator has cancelled it, whether the
// INVITE has gone to the transaction layer, and whether the CANCEL has: it
// goes only after the INVITE (RFC 3261 §9.1), whichever comes first. end is
// the 64*T1 timer after the CANCEL, and over says the INVITE has its final
// answer; c.mu guards both.
type forwardedInvite struct {
	cancel                      *sip.Request
	flow                        transport.FlowID
	tx                          *transaction.ClientTransaction
	cancelled, sent, rung, gone bool
	end                         *time.Timer
	over                        bool
}

// cancelNow reports whether the CANCEL should go now, and if so marks it
// gone; c.mu must be held. It goes once the INVITE has gone and the callee
// has answered it provisionally (RFC 3261 §9.1), as the platform's proxy
// sends it.
func (f *forwardedInvite) cancelNow() bool {
	if f.cancelled && f.sent && f.rung && !f.gone {
		f.gone = true
		return true
	}
	return false
}

// sendCancel passes f's CANCEL on, off the calling goroutine, then calls
// then if it is not nil. An INVITE the callee does not end within 64*T1
// after it is ended by the core, as the platform's proxy ends it, and
// answered 487 (§9.1). As on the platform, the timer is armed before the
// CANCEL goes, and a final answer stops it: a 2xx that crossed the CANCEL
// keeps its transaction for its own 64*T1 (RFC 6026).
func (c *IMSCore) sendCancel(f *forwardedInvite, then func()) {
	go func() {
		c.mu.Lock()
		if !f.over {
			f.end = time.AfterFunc(64*c.t1, f.tx.Terminate)
		}
		c.mu.Unlock()
		_, _ = c.layer.Request(f.cancel, transport.Destination{Flow: f.flow}, func(*sip.Response, error) {})
		if then != nil {
			then()
		}
	}()
}

// cancel answers a CANCEL as a proxy does (RFC 3261 §16.10): 200, and the
// CANCEL goes on to the callee for the INVITE the core forwarded, whose
// final answer, normally 487, comes back through the INVITE. A CANCEL that
// matches no INVITE in progress gets 481 (§9.2).
func (c *IMSCore) cancel(tx *transaction.ServerTransaction) {
	req := tx.Request()
	code := 481
	var send *forwardedInvite
	if inv, ok := c.layer.InviteFor(req); ok {
		// It matches a live INVITE transaction: 200 (§9.2), whether or
		// not the INVITE still waits for its final answer.
		code = 200
		c.mu.Lock()
		if f := c.invites[inv]; f != nil {
			f.cancelled = true
			if f.cancelNow() {
				send = f
			}
		}
		c.mu.Unlock()
	}
	tag, _ := c.ids.Tag()
	if res, err := sip.NewResponse(req, code, "", tag); err == nil {
		c.respond(tx, res)
	}
	switch {
	case send != nil:
		c.sendCancel(send, c.CancelTaken)
	case c.CancelTaken != nil:
		c.CancelTaken()
	}
}

// cancelOf is the CANCEL of a forwarded INVITE (RFC 3261 §9.1): its
// Request-URI, top Via only, Route, From, To, Call-ID and CSeq number.
func cancelOf(invite *sip.Request) (*sip.Request, error) {
	cseq, err := invite.Header.CSeq()
	if err != nil {
		return nil, err
	}
	vias, err := invite.Header.Elements("Via")
	if err != nil || len(vias) == 0 {
		return nil, errors.New("simtest: an INVITE without a Via")
	}
	c := &sip.Request{Method: "CANCEL", URI: invite.URI}
	if err := c.Header.Add("Via", vias[0]); err != nil {
		return nil, err
	}
	for _, name := range []string{"Route", "From", "To", "Call-ID"} {
		for _, v := range invite.Header.Values(name) {
			if err := c.Header.Add(name, v); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range [][2]string{{"Max-Forwards", "70"}, {"CSeq", sip.CSeq{Seq: cseq.Seq, Method: "CANCEL"}.String()}} {
		if err := c.Header.Add(f[0], f[1]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Stray implements transaction.TU: an ACK to a 2xx goes to the flow its
// Request-URI names, like any request.
func (c *IMSCore) Stray(in transport.Inbound) {
	if req, ok := in.Message.(*sip.Request); ok && req.Method == "ACK" {
		if flow, ok := c.flowFor(req.URI); ok {
			fwd, err := c.forwarded(req)
			if err == nil {
				_, _ = c.tr.SendRequest(fwd, transport.Destination{Flow: flow}, transport.NoWait)
			}
		}
	}
}

// ServerFailed implements transaction.TU.
func (c *IMSCore) ServerFailed(*transaction.ServerTransaction, error) {}

func (c *IMSCore) respond(tx *transaction.ServerTransaction, res *sip.Response) {
	if res == nil {
		return
	}
	if req := tx.Request(); res.StatusCode == 200 && (req.Method == "REGISTER" || req.Method == "SUBSCRIBE") {
		c.mu.Lock()
		answering := c.answering
		c.mu.Unlock()
		if answering != nil {
			answering(req)
		}
	}
	_ = tx.Respond(res)
}

// register answers a REGISTER: 401 until it has Digest credentials that
// verify, then 200 with the binding, Require: outbound and a Service-Route.
// Expires: 0 removes the binding. The NOTIFYs of the change are queued
// with it, for the subscribers there are when it is made (#272), and go
// once the caller has sent the 200 and called answered. deliver, when not
// nil, sends what StoreAndForward held for the IMPU; the caller runs it
// once the 200 has gone, so the client is registered when the requests
// come.
func (c *IMSCore) register(tx *transaction.ServerTransaction) (res *sip.Response, answered, deliver func()) {
	req := tx.Request()
	tag, _ := c.ids.Tag()
	creds, err := digest.ParseCredentials(req.Header.Get("Authorization"))
	if err != nil || creds.Nonce == "" {
		res, _ := sip.NewResponse(req, 401, "", tag)
		ch, _ := c.ds.Challenge(digest.SHA256, false)
		res.Header.Add("WWW-Authenticate", ch.Header())
		return res, nil, nil
	}
	password, known := c.users[creds.Username]
	if !known || c.ds.Verify(context.Background(), "REGISTER", creds, digest.Password([]byte(password))) != nil {
		res, _ := sip.NewResponse(req, 403, "", tag)
		return res, nil, nil
	}
	to, err := req.Header.To()
	if err != nil {
		res, _ := sip.NewResponse(req, 400, "", tag)
		return res, nil, nil
	}
	expires, _ := req.Header.Expires()
	impu, key := to.URI.String(), aorKey(to.URI)
	res, _ = sip.NewResponse(req, 200, "", tag)
	change := &regChange{key: key, event: "registered"}
	var held []*sip.Request
	c.mu.Lock()
	if _, was := c.bindings[key]; was {
		change.event = "refreshed"
	}
	if expires == 0 {
		delete(c.bindings, key)
		change.contact, change.event = c.contacts[key], "unregistered"
		delete(c.contacts, key)
		delete(c.events, key)
	} else {
		c.events[key] = change.event
		c.bindings[key] = tx.Source().Flow
		if contacts, err := req.Header.Contact(); err == nil && len(contacts) > 0 {
			c.contacts[key] = contacts[0].URI.String()
			if inst, ok := contacts[0].Instance(); ok {
				c.instances[key] = inst
			}
		}
		change.contact = c.contacts[key]
		held = c.stored[key]
		delete(c.stored, key)
	}
	gate := make(chan struct{})
	c.queueChangeLocked(*change, gate)
	c.mu.Unlock()
	answered = func() { close(gate) }
	if len(held) > 0 {
		flow := tx.Source().Flow
		deliver = func() {
			for _, fwd := range held {
				_, _ = c.layer.Request(fwd, transport.Destination{Flow: flow}, func(*sip.Response, error) {})
			}
		}
	}
	if expires > 0 {
		if contacts, err := req.Header.Contact(); err == nil {
			for _, ct := range contacts {
				ct.Params.Set("expires", strconv.FormatUint(uint64(min(expires, 3600)), 10))
				res.Header.Add("Contact", ct.String())
			}
		}
		res.Header.Add("Require", "outbound")
		res.Header.Add("Service-Route", "<sip:orig@scscf.core.invalid;lr>")
		res.Header.Add("P-Associated-URI", "<"+impu+">")
	}
	return res, answered, deliver
}

// regChange is what changed an IMPU's registration, by its aorKey: its
// contact, and the event that changed it (RFC 3680 §4.7.1).
type regChange struct {
	key, contact, event string
}

// queueChangeLocked queues a NOTIFY for every subscriber of the IMPU's reg
// event (RFC 3680 §4.7), to go once gate is closed; c.mu is held, so the
// subscribers are those there are when the change is made, and the
// NOTIFYs are queued in the order of the changes. One that ends the
// registration, the IMPU's only one here, ends the subscriptions (TS
// 24.229 §5.4.2.1.2): with no reason after the user's de-registration,
// "noresource" after an expiry, and as the network ended it, "deactivated"
// or "rejected" (RFC 6665 §4.1.3).
func (c *IMSCore) queueChangeLocked(ch regChange, gate <-chan struct{}) {
	gone, terminated := true, "terminated"
	switch ch.event {
	case "unregistered":
	case "expired":
		terminated += ";reason=noresource"
	case "deactivated", "rejected":
		terminated += ";reason=" + ch.event
	default:
		gone = false
	}
	for _, s := range c.subs[ch.key] {
		state := "active;expires=" + strconv.FormatUint(s.left(), 10)
		if gone {
			state = terminated
		}
		c.notifyLocked(s, state, ch.contact, ch.event, !gone, gate)
	}
	if gone {
		delete(c.subs, ch.key)
	}
}

// subscribe answers a SUBSCRIBE to an IMPU's reg event (RFC 3680, TS
// 24.229 §5.4.2.1): 200, then a NOTIFY with the full state. Expires: 0
// ends the subscription with a final NOTIFY.
func (c *IMSCore) subscribe(tx *transaction.ServerTransaction) {
	req := tx.Request()
	tag, _ := c.ids.Tag()
	to, err1 := req.Header.To()
	contacts, err2 := req.Header.Contact()
	if err1 != nil || err2 != nil || len(contacts) == 0 {
		res, _ := sip.NewResponse(req, 400, "", tag)
		c.respond(tx, res)
		return
	}
	impu, key := sip.URI{Scheme: to.URI.Scheme, User: to.URI.User, Host: to.URI.Host}.String(), aorKey(to.URI)
	callID := req.Header.Get("Call-ID")
	expires, err := req.Header.Expires()
	if err != nil {
		// RFC 3680 §4.4's default.
		expires = 3761
	}
	c.mu.Lock()
	var s *regSub
	for _, old := range c.subs[key] {
		if old.callID == callID {
			s = old
		}
	}
	if s == nil && expires > 0 {
		s = &regSub{impu: impu, callID: callID, from: req.Header.Get("From"), tag: tag, target: contacts[0].URI, flow: tx.Source().Flow}
		c.subs[key] = append(c.subs[key], s)
	}
	if s != nil {
		s.until = time.Now().Add(time.Duration(expires) * time.Second)
	}
	if s != nil && expires == 0 {
		subs := c.subs[key][:0]
		for _, old := range c.subs[key] {
			if old != s {
				subs = append(subs, old)
			}
		}
		c.subs[key] = subs
	}
	if s == nil {
		c.mu.Unlock()
		res, _ := sip.NewResponse(req, 481, "", tag)
		c.respond(tx, res)
		return
	}
	// The contact as it stands, with the event that made it so (RFC 3680
	// §4.7.1, TS 24.229 §5.4.2.1.2 NOTE 10): the subscription's end does
	// not change the registration. Queued with the subscription, ahead of
	// any change after it, and sent after the 200.
	contact, registered := c.contacts[key]
	event := c.events[key]
	gate := make(chan struct{})
	switch {
	case expires == 0:
		c.notifyLocked(s, "terminated;reason=timeout", contact, event, registered, gate)
	default:
		c.notifyLocked(s, "active;expires="+strconv.FormatUint(uint64(expires), 10), contact, event, registered, gate)
		if c.RepeatFirstNotify && c.repeated.CompareAndSwap(false, true) {
			c.notifyLocked(s, "active;expires="+strconv.FormatUint(uint64(expires), 10), contact, event, registered, gate)
		}
	}
	c.mu.Unlock()
	res, _ := sip.NewResponse(req, 200, "", s.tag)
	res.Header.Add("Contact", "<sip:core.invalid:5060;transport=tcp>")
	res.Header.Add("Expires", strconv.FormatUint(uint64(expires), 10))
	c.respond(tx, res)
	close(gate)
}

// awaitGate waits until gate is closed, after the 200 of the request that
// made the NOTIFY, and reports false if the core stops first. waiting, the
// test hook, hears of the wait as it begins.
func (c *IMSCore) awaitGate(gate <-chan struct{}, waiting func(<-chan struct{})) bool {
	if waiting != nil {
		waiting(gate)
	}
	select {
	case <-gate:
		return true
	case <-c.stop:
		return false
	}
}

// notifyLocked queues a NOTIFY of s's next version: the IMPU's one
// contact, active with event, or terminated. It goes once gate is closed,
// after the 200 of the request that made it. c.mu is held, so NOTIFYs are
// queued in the order of the changes; the queue is long enough that this
// does not wait, and the notifier's goroutine never takes c.mu.
func (c *IMSCore) notifyLocked(s *regSub, state, contact, event string, active bool, gate <-chan struct{}) {
	waiting := c.waiting
	send := func() {
		if !c.awaitGate(gate, waiting) {
			return
		}
		branch, _ := c.ids.Branch()
		req := &sip.Request{Method: "NOTIFY", URI: s.target}
		s.cseq++
		regState, contactState := "active", "active"
		if !active {
			regState, contactState = "terminated", "terminated"
		}
		body := `<?xml version="1.0"?><reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="` + strconv.FormatUint(s.version, 10) + `" state="full">` +
			`<registration aor="` + xmlText(s.impu) + `" id="r1" state="` + regState + `">`
		if contact != "" {
			body += `<contact id="c1" state="` + contactState + `" event="` + event + `" expires="3600"><uri>` + xmlText(contact) + `</uri></contact>`
		}
		body += `</registration></reginfo>`
		s.version++
		for _, f := range [][2]string{
			{"Via", "SIP/2.0/TCP core.invalid;branch=" + branch},
			{"Max-Forwards", "70"},
			{"From", "<" + s.impu + ">;tag=" + s.tag},
			{"To", s.from},
			{"Call-ID", s.callID},
			{"CSeq", strconv.FormatUint(uint64(s.cseq), 10) + " NOTIFY"},
			{"Contact", "<sip:core.invalid:5060;transport=tcp>"},
			{"Event", "reg"},
			{"Subscription-State", state},
			{"Content-Type", "application/reginfo+xml"},
		} {
			if err := req.Header.Add(f[0], f[1]); err != nil {
				return
			}
		}
		req.Body = []byte(body)
		if c.Rewrite != nil {
			c.Rewrite(req)
		}
		done := make(chan struct{})
		if _, err := c.layer.Request(req, transport.Destination{Flow: s.flow}, func(res *sip.Response, err error) {
			if err != nil || res.StatusCode >= 200 {
				if c.NotifyAnswered != nil {
					c.NotifyAnswered(req, res, err)
				}
				select {
				case <-done:
				default:
					close(done)
				}
			}
		}); err != nil {
			return
		}
		// One at a time, so the versions reach the subscriber in order.
		select {
		case <-done:
		case <-c.stop:
		}
	}
	select {
	case c.notifies <- send:
	case <-c.stop:
	}
}

// eventPackage is the package of req's Event header, without its
// parameters (RFC 6665 §8.2.1).
func eventPackage(req *sip.Request) string {
	pkg, _, _ := strings.Cut(req.Header.Get("Event"), ";")
	return strings.TrimSpace(pkg)
}

// xmlText escapes s for an XML attribute or text node.
func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// flowFor is the flow uri is registered on. A tel URI is taken for the SIP
// IMPU with its number at the home domain, as an implicit set holds both
// (#282).
func (c *IMSCore) flowFor(uri sip.URI) (transport.FlowID, bool) {
	if uri.Scheme == "tel" {
		uri = sip.URI{Scheme: "sip", User: uri.User, Host: c.Domain}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	flow, ok := c.bindings[aorKey(uri)]
	return flow, ok
}

// route forwards a request to the flow its Request-URI is registered on,
// statefully: the answers come back through tx. An IMPU that is not
// registered gets what Offline says.
func (c *IMSCore) route(tx *transaction.ServerTransaction) {
	req := tx.Request()
	answer := func(code int) {
		tag, _ := c.ids.Tag()
		if res, err := sip.NewResponse(req, code, "", tag); err == nil {
			c.respond(tx, res)
		}
	}
	flow, ok := c.flowFor(req.URI)
	fwd, err := c.forwarded(req)
	switch {
	case err != nil:
		answer(500)
		return
	case !ok && (c.Offline == StoreAndForward || c.Offline == StoreAndChange) && req.Method == "MESSAGE":
		if c.Offline == StoreAndChange {
			fwd.Body = bytes.Replace(fwd.Body, []byte("pager-mode message"), []byte("pager-mode messagf"), 1)
		}
		c.mu.Lock()
		c.stored[aorKey(req.URI)] = append(c.stored[aorKey(req.URI)], fwd)
		c.mu.Unlock()
		answer(202)
		return
	case !ok && c.Offline == Drop:
		answer(200)
		return
	case !ok && c.Offline == RefuseNotFound:
		answer(404)
		return
	case !ok:
		answer(480)
		return
	}
	if c.Rewrite != nil {
		c.Rewrite(fwd)
	}
	// An INVITE in progress can be cancelled; its CANCEL is built now,
	// since the transport owns fwd once it is sent.
	var invite *forwardedInvite
	if req.Method == "INVITE" {
		if cancel, err := cancelOf(fwd); err == nil {
			invite = &forwardedInvite{cancel: cancel, flow: flow}
			c.mu.Lock()
			c.invites[tx] = invite
			c.mu.Unlock()
		}
	}
	// ended forgets the INVITE, which has its final answer, stops the
	// timer after its CANCEL, and reports whether the originator had
	// cancelled it.
	ended := func() bool {
		if invite == nil {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.invites, tx)
		invite.over = true
		if invite.end != nil {
			invite.end.Stop()
		}
		return invite.cancelled
	}
	// Off the reading goroutine: Request waits for room on the other flow.
	go func() {
		if c.Forwarding != nil {
			c.Forwarding(fwd)
		}
		ct, err := c.layer.Request(fwd, transport.Destination{Flow: flow}, func(res *sip.Response, err error) {
			if err != nil {
				cancelled := ended()
				// The far end never answered, or its flow went. A
				// non-INVITE that timed out is left unanswered, as the
				// platform's proxy leaves it (RFC 4320 §4.2 forbids the
				// 408): the originator's own transaction times out. An
				// INVITE gets its 408 (RFC 3261 §16.8). The rest is
				// answered as the platform answers it, the core standing
				// for its P-CSCF and S-CSCF both (#414).
				switch {
				case errors.Is(err, transaction.ErrTimeout) && req.Method != "INVITE":
					c.silence(tx, req)
				case cancelled && (errors.Is(err, transaction.ErrTimeout) || errors.Is(err, transaction.ErrTerminated) || errors.Is(err, transport.ErrNoFlow)):
					// A cancelled INVITE whose branch ended without a final
					// answer counts as the 487 its CANCEL asked for, as on
					// the platform: it was cancelled, not failed.
					answer(487)
				case errors.Is(err, transaction.ErrTimeout):
					answer(408)
				default:
					answer(failureCode(err))
				}
				return
			}
			if invite != nil && res.StatusCode < 200 {
				// The callee has the INVITE: a CANCEL may follow now.
				c.mu.Lock()
				invite.rung = true
				send := invite.cancelNow()
				c.mu.Unlock()
				if send {
					c.sendCancel(invite, nil)
				}
			}
			if res.StatusCode == 100 {
				return
			}
			if res.StatusCode >= 200 {
				ended()
			}
			back := res.Clone()
			if err := back.Header.RemoveFirstElement("Via"); err != nil {
				return
			}
			if c.RewriteResponse != nil {
				c.RewriteResponse(req, back)
			}
			_ = tx.Respond(back)
		})
		if err != nil {
			code := failureCode(err)
			if ended() {
				code = 487 // cancelled before it could go
			}
			tag, _ := c.ids.Tag()
			if res, e := sip.NewResponse(req, code, "", tag); e == nil {
				_ = tx.Respond(res)
			}
			return
		}
		if invite != nil {
			// A CANCEL that came before the INVITE went goes now, if the
			// callee has answered it provisionally already.
			c.mu.Lock()
			invite.sent, invite.tx = true, ct
			send := invite.cancelNow()
			c.mu.Unlock()
			if send {
				c.sendCancel(invite, nil)
			}
		}
	}()
}

// failureCode is the answer to a request the core could not get to the
// callee, as the platform gives it. A flow that is gone, whether before
// the request went or while it waited (ErrFlowClosed wraps ErrNoFlow), is
// the edge proxy's 430 (RFC 5626 §5.3.1), which reaches an endpoint as 480
// (§11.5; internal/sip/proxy keeps the 430 between its proxies only). Any
// other failure is a 503 for the one branch there (§16.9), which the
// proxy answers upstream as 500 (§16.7 step 6).
func failureCode(err error) int {
	if errors.Is(err, transport.ErrNoFlow) {
		return 480
	}
	return 500
}

// forwarded is req as a proxy sends it on (RFC 3261 §16.6): the core's own
// Routes taken off, Max-Forwards one less, and a Via of its own on top.
func (c *IMSCore) forwarded(req *sip.Request) (*sip.Request, error) {
	fwd := req.Clone()
	fwd.Header.Del("Route")
	if mf, err := fwd.Header.MaxForwards(); err == nil {
		if err := fwd.Header.Set("Max-Forwards", strconv.Itoa(max(mf-1, 0))); err != nil {
			return nil, err
		}
	}
	branch, err := c.ids.Branch()
	if err != nil {
		return nil, err
	}
	if err := fwd.Header.Prepend("Via", "SIP/2.0/TCP core.invalid;branch="+branch); err != nil {
		return nil, err
	}
	return fwd, nil
}
