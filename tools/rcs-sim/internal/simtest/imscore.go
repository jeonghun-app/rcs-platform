package simtest

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

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
	// would.
	Rewrite func(*sip.Request)

	t     testing.TB
	tr    *transport.Transport
	layer *transaction.Layer
	ds    *digest.Server
	users map[string]string
	ids   sip.IDGenerator

	mu       sync.Mutex
	bindings map[string]transport.FlowID
	// contacts are each IMPU's registered Contact URI, and subs the reg
	// event subscriptions to it (RFC 3680).
	contacts map[string]string
	subs     map[string][]*regSub
	// notifies sends NOTIFYs one at a time, in the order they were made,
	// off the reading goroutine.
	notifies chan func()
	stop     chan struct{}
}

// regSub is one subscription to an IMPU's reg event, from the notifier's
// side.
type regSub struct {
	impu, callID, from, tag string
	target                  sip.URI
	flow                    transport.FlowID
	cseq                    uint32
	version                 uint64
}

// StartIMSCore starts an IMSCore for domain whose users are IMPI to Digest
// password.
func StartIMSCore(t testing.TB, domain string, users map[string]string) *IMSCore {
	t.Helper()
	ds, err := digest.NewServer(digest.ServerConfig{
		Realm: domain, NonceKey: bytes.Repeat([]byte("i"), digest.MinNonceKeySize),
		NonceCounts: digest.NewMemoryNonceCounts(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := &IMSCore{
		Domain: domain, t: t, ds: ds, users: users, bindings: map[string]transport.FlowID{},
		contacts: map[string]string{}, subs: map[string][]*regSub{}, notifies: make(chan func(), 256), stop: make(chan struct{}),
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
	tr, err := transport.New(transport.Config{}, func(in transport.Inbound) { c.layer.Receive(in) })
	if err != nil {
		t.Fatal(err)
	}
	c.tr = tr
	c.layer = transaction.New(tr, c, transaction.Config{})
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
	_, ok := c.bindings[impu]
	return ok
}

// Expire drops impu's binding, as its expiry would: requests to it then
// get 480 until it registers again.
func (c *IMSCore) Expire(impu string) {
	c.mu.Lock()
	delete(c.bindings, impu)
	c.mu.Unlock()
}

// Request implements transaction.TU.
func (c *IMSCore) Request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	switch {
	case req.Method == "REGISTER":
		res, change := c.register(tx)
		c.respond(tx, res)
		if change != nil {
			c.registrationChanged(*change)
		}
	case req.Method == "SUBSCRIBE" && strings.EqualFold(eventPackage(req), "reg"):
		c.subscribe(tx)
	default:
		c.route(tx)
	}
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
	if res != nil {
		_ = tx.Respond(res)
	}
}

// register answers a REGISTER: 401 until it has Digest credentials that
// verify, then 200 with the binding, Require: outbound and a Service-Route.
// Expires: 0 removes the binding.
func (c *IMSCore) register(tx *transaction.ServerTransaction) (*sip.Response, *regChange) {
	req := tx.Request()
	tag, _ := c.ids.Tag()
	creds, err := digest.ParseCredentials(req.Header.Get("Authorization"))
	if err != nil || creds.Nonce == "" {
		res, _ := sip.NewResponse(req, 401, "", tag)
		ch, _ := c.ds.Challenge(digest.SHA256, false)
		res.Header.Add("WWW-Authenticate", ch.Header())
		return res, nil
	}
	password, known := c.users[creds.Username]
	if !known || c.ds.Verify(context.Background(), "REGISTER", creds, digest.Password([]byte(password))) != nil {
		res, _ := sip.NewResponse(req, 403, "", tag)
		return res, nil
	}
	to, err := req.Header.To()
	if err != nil {
		res, _ := sip.NewResponse(req, 400, "", tag)
		return res, nil
	}
	expires, _ := req.Header.Expires()
	impu := to.URI.String()
	res, _ := sip.NewResponse(req, 200, "", tag)
	change := &regChange{impu: impu, event: "registered"}
	c.mu.Lock()
	if _, was := c.bindings[impu]; was {
		change.event = "refreshed"
	}
	if expires == 0 {
		delete(c.bindings, impu)
		change.contact, change.event = c.contacts[impu], "unregistered"
		delete(c.contacts, impu)
	} else {
		c.bindings[impu] = tx.Source().Flow
		if contacts, err := req.Header.Contact(); err == nil && len(contacts) > 0 {
			c.contacts[impu] = contacts[0].URI.String()
		}
		change.contact = c.contacts[impu]
	}
	c.mu.Unlock()
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
	return res, change
}

// regChange is what a REGISTER changed in an IMPU's registration.
type regChange struct {
	impu, contact, event string
}

// registrationChanged notifies every subscriber of the IMPU's reg event
// (RFC 3680 §5.2); a de-registration ends the subscriptions.
func (c *IMSCore) registrationChanged(ch regChange) {
	gone := ch.event == "unregistered"
	c.mu.Lock()
	subs := c.subs[ch.impu]
	if gone {
		delete(c.subs, ch.impu)
	}
	c.mu.Unlock()
	state := "active;expires=600000"
	if gone {
		state = "terminated;reason=noresource"
	}
	for _, s := range subs {
		c.notify(s, state, ch.contact, ch.event, !gone)
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
	impu := sip.URI{Scheme: to.URI.Scheme, User: to.URI.User, Host: to.URI.Host}.String()
	callID := req.Header.Get("Call-ID")
	expires, err := req.Header.Expires()
	if err != nil {
		// RFC 3680 §6.4's default.
		expires = 3761
	}
	c.mu.Lock()
	var s *regSub
	for _, old := range c.subs[impu] {
		if old.callID == callID {
			s = old
		}
	}
	if s == nil && expires > 0 {
		s = &regSub{impu: impu, callID: callID, from: req.Header.Get("From"), tag: tag, target: contacts[0].URI, flow: tx.Source().Flow}
		c.subs[impu] = append(c.subs[impu], s)
	}
	if s != nil && expires == 0 {
		subs := c.subs[impu][:0]
		for _, old := range c.subs[impu] {
			if old != s {
				subs = append(subs, old)
			}
		}
		c.subs[impu] = subs
	}
	contact, registered := c.contacts[impu]
	c.mu.Unlock()
	if s == nil {
		res, _ := sip.NewResponse(req, 481, "", tag)
		c.respond(tx, res)
		return
	}
	res, _ := sip.NewResponse(req, 200, "", s.tag)
	res.Header.Add("Contact", "<sip:core.invalid:5060;transport=tcp>")
	res.Header.Add("Expires", strconv.FormatUint(uint64(expires), 10))
	c.respond(tx, res)
	switch {
	case expires == 0:
		c.notify(s, "terminated;reason=timeout", contact, "unregistered", registered)
	default:
		c.notify(s, "active;expires="+strconv.FormatUint(uint64(expires), 10), contact, "registered", registered)
	}
}

// notify queues a NOTIFY of s's next version: the IMPU's one contact,
// active with event, or terminated.
func (c *IMSCore) notify(s *regSub, state, contact, event string, active bool) {
	send := func() {
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

func (c *IMSCore) flowFor(uri sip.URI) (transport.FlowID, bool) {
	key := sip.URI{Scheme: uri.Scheme, User: uri.User, Host: uri.Host}.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	flow, ok := c.bindings[key]
	return flow, ok
}

// route forwards a request to the flow its Request-URI is registered on,
// statefully: the answers come back through tx. An IMPU that is not
// registered gets 480 (TS 24.229 §5.4.3.3).
func (c *IMSCore) route(tx *transaction.ServerTransaction) {
	req := tx.Request()
	flow, ok := c.flowFor(req.URI)
	if !ok {
		tag, _ := c.ids.Tag()
		res, _ := sip.NewResponse(req, 480, "", tag)
		c.respond(tx, res)
		return
	}
	fwd, err := c.forwarded(req)
	if err != nil {
		tag, _ := c.ids.Tag()
		res, _ := sip.NewResponse(req, 500, "", tag)
		c.respond(tx, res)
		return
	}
	if c.Rewrite != nil {
		c.Rewrite(fwd)
	}
	// Off the reading goroutine: Request waits for room on the other flow.
	go func() {
		_, err := c.layer.Request(fwd, transport.Destination{Flow: flow}, func(res *sip.Response, err error) {
			if err != nil || res.StatusCode == 100 {
				return
			}
			back := res.Clone()
			if err := back.Header.RemoveFirstElement("Via"); err != nil {
				return
			}
			_ = tx.Respond(back)
		})
		if err != nil {
			tag, _ := c.ids.Tag()
			if res, e := sip.NewResponse(req, 503, "", tag); e == nil {
				_ = tx.Respond(res)
			}
		}
	}()
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
