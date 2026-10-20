package simtest

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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
	// forwards, as a faulty network element would. It runs on the reading
	// goroutine of the sender's connection, so it must not block.
	Rewrite func(*sip.Request)
	// Offline, when set before any request, is what the core does with a
	// request to an IMPU that has no binding.
	Offline Offline

	t     testing.TB
	tr    *transport.Transport
	layer *transaction.Layer
	ds    *digest.Server
	users map[string]string
	ids   sip.IDGenerator

	mu       sync.Mutex
	bindings map[string]transport.FlowID
	// instances are each IMPU's last registered +sip.instance, and stored
	// the requests StoreAndForward holds for it, by aorKey.
	instances map[string]string
	stored    map[string][]*sip.Request
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
	}
	tr, err := transport.New(transport.Config{}, func(in transport.Inbound) { c.layer.Receive(in) })
	if err != nil {
		t.Fatal(err)
	}
	c.tr = tr
	var cfg transaction.Config
	if len(t1) > 0 {
		cfg.T1 = t1[0]
	}
	c.layer = transaction.New(tr, c, cfg)
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
// get what Offline says until it registers again.
func (c *IMSCore) Expire(impu string) {
	c.mu.Lock()
	delete(c.bindings, keyOf(impu))
	c.mu.Unlock()
}

// Request implements transaction.TU.
func (c *IMSCore) Request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	switch req.Method {
	case "REGISTER":
		c.respond(tx, c.register(tx))
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
func (c *IMSCore) register(tx *transaction.ServerTransaction) *sip.Response {
	req := tx.Request()
	tag, _ := c.ids.Tag()
	creds, err := digest.ParseCredentials(req.Header.Get("Authorization"))
	if err != nil || creds.Nonce == "" {
		res, _ := sip.NewResponse(req, 401, "", tag)
		ch, _ := c.ds.Challenge(digest.SHA256, false)
		res.Header.Add("WWW-Authenticate", ch.Header())
		return res
	}
	password, known := c.users[creds.Username]
	if !known || c.ds.Verify(context.Background(), "REGISTER", creds, digest.Password([]byte(password))) != nil {
		res, _ := sip.NewResponse(req, 403, "", tag)
		return res
	}
	to, err := req.Header.To()
	if err != nil {
		res, _ := sip.NewResponse(req, 400, "", tag)
		return res
	}
	expires, _ := req.Header.Expires()
	impu, key := to.URI.String(), aorKey(to.URI)
	res, _ := sip.NewResponse(req, 200, "", tag)
	var held []*sip.Request
	c.mu.Lock()
	if expires == 0 {
		delete(c.bindings, key)
	} else {
		c.bindings[key] = tx.Source().Flow
		if contacts, err := req.Header.Contact(); err == nil && len(contacts) > 0 {
			if inst, ok := contacts[0].Instance(); ok {
				c.instances[key] = inst
			}
		}
		held = c.stored[key]
		delete(c.stored, key)
	}
	c.mu.Unlock()
	if len(held) > 0 {
		// After the 2xx has gone, so the client knows it is registered.
		flow := tx.Source().Flow
		go func() {
			for _, fwd := range held {
				_, _ = c.layer.Request(fwd, transport.Destination{Flow: flow}, func(*sip.Response, error) {})
			}
		}()
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
	return res
}

func (c *IMSCore) flowFor(uri sip.URI) (transport.FlowID, bool) {
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
	case !ok && c.Offline == StoreAndForward && req.Method == "MESSAGE":
		c.mu.Lock()
		c.stored[aorKey(req.URI)] = append(c.stored[aorKey(req.URI)], fwd)
		c.mu.Unlock()
		answer(202)
		return
	case !ok && c.Offline == Drop:
		answer(200)
		return
	case !ok:
		answer(480)
		return
	}
	if c.Rewrite != nil {
		c.Rewrite(fwd)
	}
	// Off the reading goroutine: Request waits for room on the other flow.
	go func() {
		_, err := c.layer.Request(fwd, transport.Destination{Flow: flow}, func(res *sip.Response, err error) {
			if err != nil {
				// The far end never answered, or its flow went: the
				// originator hears it (RFC 3261 §16.7, §16.8).
				code := 500
				if errors.Is(err, transaction.ErrTimeout) {
					code = 408
				}
				answer(code)
				return
			}
			if res.StatusCode == 100 {
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
