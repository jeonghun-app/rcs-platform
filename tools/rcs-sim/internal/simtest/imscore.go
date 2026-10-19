package simtest

import (
	"bytes"
	"context"
	"net/netip"
	"strconv"
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
	// forwards, as a faulty network element would.
	Rewrite func(*sip.Request)

	t     testing.TB
	tr    *transport.Transport
	layer *transaction.Layer
	ds    *digest.Server
	users map[string]string
	ids   sip.IDGenerator

	mu       sync.Mutex
	bindings map[string]transport.FlowID
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
	c := &IMSCore{Domain: domain, t: t, ds: ds, users: users, bindings: map[string]transport.FlowID{}}
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
	impu := to.URI.String()
	res, _ := sip.NewResponse(req, 200, "", tag)
	c.mu.Lock()
	if expires == 0 {
		delete(c.bindings, impu)
	} else {
		c.bindings[impu] = tx.Source().Flow
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
	return res
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
