package sipas

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// waitFor bounds how long a test waits for rcs-as; a safety net, never a
// protocol timer.
const waitFor = 10 * time.Second

// The identities of the tests, all on .github/allowed-test-identifiers.txt.
const (
	domain = "ims.mnc001.mcc001.3gppnetwork.org"
	alice  = "tel:+15550100001"
	bob    = "tel:+15550100002"
	// aliceSIP is alice's SIP URI for her number (RFC 3261 §19.1.6).
	aliceSIP = "sip:+15550100001@" + domain + ";user=phone"
)

// fakeCore is scscf as rcs-as sees it: it sends rcs-as the requests the
// iFC route there, with the P-Asserted-Identity the core inserts, and
// takes the requests rcs-as originates, answering each with answer's
// status.
type fakeCore struct {
	t      *testing.T
	l      net.Listener
	got    chan *sip.Request
	answer atomic.Pointer[func(*sip.Request) int]
	// reply, when set, answers instead of answer: each response it
	// returns is sent, in order.
	reply atomic.Pointer[func(*sip.Request) []*sip.Response]
}

func newFakeCore(t *testing.T) *fakeCore {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeCore{t: t, l: l, got: make(chan *sip.Request, 64)}
	c.setAnswer(func(*sip.Request) int { return 200 })
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.serve(nc)
			}()
		}
	}()
	return c
}

func (c *fakeCore) setAnswer(f func(*sip.Request) int) { c.answer.Store(&f) }

func (c *fakeCore) setReply(f func(*sip.Request) []*sip.Response) { c.reply.Store(&f) }

// serve answers the requests on one connection rcs-as opened.
func (c *fakeCore) serve(nc net.Conn) {
	defer nc.Close()
	r := sip.NewReader(bufio.NewReader(nc), sip.Limits{})
	for {
		m, err := r.ReadMessage()
		if err != nil {
			return
		}
		req, ok := m.(*sip.Request)
		if !ok {
			continue
		}
		c.got <- req
		if req.Method == "ACK" {
			continue // nothing answers an ACK
		}
		var out []*sip.Response
		if f := c.reply.Load(); f != nil {
			out = (*f)(req)
		} else if code := (*c.answer.Load())(req); code != 0 {
			res, err := sip.NewResponse(req, code, "", "core1")
			if err != nil {
				return
			}
			out = []*sip.Response{res}
		}
		for _, res := range out {
			b, err := res.Bytes()
			if err != nil {
				return
			}
			if _, err := nc.Write(b); err != nil {
				return
			}
		}
	}
}

// nextOf is the next request rcs-as sent the core with method, skipping
// others.
func (c *fakeCore) nextOf(t *testing.T, method string) *sip.Request {
	t.Helper()
	for {
		if req := c.next(t); req.Method == method {
			return req
		}
	}
}

// uri is the core as rcs-as's Config.Core.
func (c *fakeCore) uri() sip.URI {
	u, err := sip.ParseURI("sip:" + c.l.Addr().String() + ";transport=tcp;lr")
	if err != nil {
		c.t.Fatal(err)
	}
	return u
}

// next is the next request rcs-as sent the core.
func (c *fakeCore) next(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case req := <-c.got:
		return req
	case <-time.After(waitFor):
		t.Fatal("the core received nothing")
		return nil
	}
}

// as is rcs-as's SIP side on loopback: a Server on a proxy and a transport
// listening on TCP.
type as struct {
	srv  *Server
	addr netip.AddrPort
}

// startAS serves e behind a Server whose core is core.
func startAS(t *testing.T, e Engine, core *fakeCore) *as {
	t.Helper()
	return startASWith(t, e, Config{Core: core.uri()})
}

// startASWith is startAS with cfg, whose Host, Listener and Contact it
// sets, and with the proxy's configuration changed by each of tune.
func startASWith(t *testing.T, e Engine, cfg Config, tune ...func(*proxy.Config)) *as {
	t.Helper()
	return startASOn(t, e, nil, cfg, transport.Config{}, tune...)
}

// The conference factory and host of the tests (ACS provisions the
// factory at the home domain).
const (
	confHost    = "conf." + domain
	confFactory = "sip:conf-factory@" + domain
)

// startASOn is startASWith with groups, on a transport configured by tc. A
// cfg without a conference factory or host gets the tests' own.
func startASOn(t *testing.T, e Engine, groups Groups, cfg Config, tc transport.Config, tune ...func(*proxy.Config)) *as {
	t.Helper()
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(tc, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			px.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	addr, err := tr.Listen(transport.ListenerConfig{Name: "core", Network: transport.TCP, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	self, err := sip.ParseURI("sip:" + addr.String() + ";transport=tcp")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Listener, cfg.Contact, cfg.HomeDomain = "127.0.0.1", "core", self, domain
	if cfg.ConferenceHost == "" {
		cfg.ConferenceHost = confHost
	}
	if cfg.ConferenceFactory.Host == "" {
		if cfg.ConferenceFactory, err = sip.ParseURI(confFactory); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pc := proxy.Config{Self: []sip.URI{self}, Router: srv}
	for _, f := range tune {
		f(&pc)
	}
	px, err := proxy.New(tr, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(px.Close)
	srv.Bind(e, groups, px.Layer(), tr)
	// Before the proxy and the transport, which carry its BYEs.
	t.Cleanup(srv.Close)
	p.Store(px)
	return &as{srv: srv, addr: addr}
}

// t1AtOnce is a proxy clock on which a timer of T1 fires at once, so that a
// 2xx to an INVITE is sent again as soon as it is sent, as when its ACK
// comes later than T1 (RFC 3261 §13.3.1.4). Timers of other lengths run as
// on the system clock.
type t1AtOnce struct{}

func (t1AtOnce) AfterFunc(d time.Duration, f func()) transaction.Timer {
	if d == transaction.DefaultT1 {
		d = 0
	}
	return time.AfterFunc(d, f)
}

// peer is the core's side of a connection to rcs-as, from which it sends
// the requests iFC route to rcs-as.
type peer struct {
	t  *testing.T
	nc net.Conn
	r  *sip.Reader

	mu sync.Mutex
	// sent holds the CSeq of each request the peer sent, by branch: a 2xx
	// retransmitted before its ACK may still come on that branch while a
	// later request waits for its own (#327), and must have that CSeq.
	sent map[string]sip.CSeq
}

// requests numbers every request a test sends, so no two share a branch
// or Call-ID.
var requests atomic.Int64

func (a *as) dial(t *testing.T) *peer {
	t.Helper()
	nc, err := net.Dial("tcp", a.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nc.Close() })
	return &peer{t: t, nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{}), sent: map[string]sip.CSeq{}}
}

// msg is a request the core sends rcs-as.
type msg struct {
	method, uri, toTag string
	fields             []string
	body               string
	// callID and cseq, when set, replace the request's own, for one in a
	// dialog.
	callID string
	cseq   int
	// from and to, when set, replace alice's From and bob's To.
	from, to string
}

// pager is alice's pager-mode MESSAGE to bob as scscf sends it to rcs-as:
// with her asserted identity, and a CPIM body.
func pager(body string) msg {
	return msg{method: "MESSAGE", uri: bob, body: body, fields: []string{
		"P-Asserted-Identity: <" + alice + ">", "Content-Type: message/cpim",
	}}
}

// cpimBody is a standalone message from alice (rcsjta's form).
func cpimBody(id, text string) string {
	return "From: <" + messaging.AnonymousURI + ">\r\nTo: <" + messaging.AnonymousURI + ">\r\n" +
		"NS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: " + id + "\r\nDateTime: 2026-03-04T05:06:07.000Z\r\n" +
		"imdn.Disposition-Notification: positive-delivery\r\n\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + text
}

// send sends m and returns its final response.
func (p *peer) send(m msg) *sip.Response {
	p.t.Helper()
	res, err := p.try(m)
	if err != nil {
		p.t.Fatalf("no response: %v", err)
	}
	return res
}

func (p *peer) try(m msg) (*sip.Response, error) {
	n := requests.Add(1)
	branch := fmt.Sprintf("z9hG4bK-sipas-%d", n)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", m.method, m.uri)
	fmt.Fprintf(&b, "Via: SIP/2.0/TCP 192.0.2.20:5060;branch=%s\r\n", branch)
	b.WriteString("Max-Forwards: 70\r\n")
	from, to := "From: <"+alice+">;tag=a1", "To: <"+bob+">"
	if m.toTag != "" {
		to += ";tag=" + m.toTag
	}
	if m.from != "" {
		from, to = "From: "+m.from, "To: "+m.to
	}
	b.WriteString(from + "\r\n" + to + "\r\n")
	callID, cseq := fmt.Sprintf("sipas-test-%d", n), max(m.cseq, 1)
	if m.callID != "" {
		callID = m.callID
	}
	fmt.Fprintf(&b, "Call-ID: %s\r\n", callID)
	fmt.Fprintf(&b, "CSeq: %d %s\r\n", cseq, m.method)
	for _, f := range m.fields {
		b.WriteString(f + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n%s", len(m.body), m.body)
	want := sip.CSeq{Seq: uint32(cseq), Method: m.method}
	p.sending(branch, want)
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(p.nc, b.String()); err != nil {
		return nil, err
	}
	if m.method == "ACK" {
		return nil, nil
	}
	return p.finalFor(branch, want)
}

// sending notes that a request with branch and cseq goes out.
func (p *peer) sending(branch string, cseq sip.CSeq) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent[branch] = cseq
}

// finalFor reads the final response to the request with branch and cseq.
// A 2xx to an earlier INVITE of the peer, sent again until its ACK arrives
// (RFC 3261 §13.3.1.4; #303, #327), is passed over; any other response to
// an earlier request, or one to no request of the peer, is an error, not a
// response to wait past.
func (p *peer) finalFor(branch string, cseq sip.CSeq) (*sip.Response, error) {
	for {
		msg, err := p.r.ReadMessage()
		if err != nil {
			return nil, err
		}
		res, ok := msg.(*sip.Response)
		if !ok {
			return nil, errors.New("got a request")
		}
		vias, err := res.Header.Via()
		if err != nil || len(vias) == 0 {
			return nil, fmt.Errorf("a %d without a Via: %v", res.StatusCode, err)
		}
		got, err := res.Header.CSeq()
		if err != nil {
			return nil, err
		}
		b := vias[0].Branch()
		p.mu.Lock()
		prev, earlier := p.sent[b]
		p.mu.Unlock()
		earlier = earlier && b != branch
		switch {
		case b == branch && got == cseq:
			if res.StatusCode >= 200 {
				return res, nil
			}
		case earlier && got != prev:
			return nil, fmt.Errorf("a %d on an earlier branch of this peer with CSeq %d %s, not the %d %s sent there", res.StatusCode, got.Seq, got.Method, prev.Seq, prev.Method)
		case earlier && res.StatusCode/100 == 2 && got.Method == "INVITE":
			// The one response sent again over TCP: a 2xx to an INVITE,
			// until its ACK (RFC 3261 §13.3.1.4, §17.2.2).
		case earlier:
			return nil, fmt.Errorf("a %d to an earlier %s of this peer, which is never sent again", res.StatusCode, got.Method)
		default:
			return nil, fmt.Errorf("a %d to no request of this peer: CSeq %d %s, branch %q", res.StatusCode, got.Seq, got.Method, b)
		}
	}
}

// forward sends req as the core would, after its own processing, and
// returns its final response.
func (p *peer) forward(req *sip.Request) (*sip.Response, error) {
	b, err := req.Bytes()
	if err != nil {
		return nil, err
	}
	vias, err := req.Header.Via()
	if err != nil || len(vias) == 0 {
		return nil, fmt.Errorf("a %s without a Via: %v", req.Method, err)
	}
	cseq, err := req.Header.CSeq()
	if err != nil {
		return nil, err
	}
	p.sending(vias[0].Branch(), cseq)
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := p.nc.Write(b); err != nil {
		return nil, err
	}
	return p.finalFor(vias[0].Branch(), cseq)
}

// fakeEngine records what it is given and answers with err.
type fakeEngine struct {
	mu         sync.Mutex
	got        []messaging.Origin
	registered []registration
	err        error
	done       chan struct{}
}

func (e *fakeEngine) Submit(_ context.Context, o messaging.Origin) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, o)
	return e.err
}

var errFakeLeg = errors.New("fake: no legs")

func (e *fakeEngine) OpenLeg(messaging.LegParams) (*messaging.Leg, error) { return nil, errFakeLeg }
func (e *fakeEngine) Offer(messaging.LegParams) (*messaging.Leg, error)   { return nil, errFakeLeg }
func (e *fakeEngine) InviteFailed(messaging.Invitation, error)            {}
func (e *fakeEngine) Invite(context.Context, messaging.Invitation)        {}

func (e *fakeEngine) UserRegistered(user string, newFlow bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.registered = append(e.registered, registration{user, newFlow})
}

type registration struct {
	user    string
	newFlow bool
}

func (e *fakeEngine) registrations() []registration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]registration(nil), e.registered...)
}

func (e *fakeEngine) origins() []messaging.Origin {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]messaging.Origin(nil), e.got...)
}

// #327: a peer takes for its request's answer only the final response
// with the request's branch and CSeq. A 2xx to one of its earlier INVITEs,
// which the connection may still carry until the ACK, is passed over; any
// other response to an earlier request, which TCP never sends again, or
// one to no request of the peer, is an error.
func TestAPeerTakesOnlyTheResponseToItsRequest(t *testing.T) {
	here, there := net.Pipe()
	t.Cleanup(func() { _ = here.Close(); _ = there.Close() })
	p := &peer{t: t, nc: here, r: sip.NewReader(bufio.NewReader(here), sip.Limits{}), sent: map[string]sip.CSeq{}}
	in := sip.NewReader(bufio.NewReader(there), sip.Limits{})
	// The far end reads one request and writes what reply makes of it.
	answer := func(reply func(req *sip.Request) []*sip.Response) {
		go func() {
			_ = there.SetDeadline(time.Now().Add(waitFor))
			m, err := in.ReadMessage()
			req, ok := m.(*sip.Request)
			if err != nil || !ok {
				return
			}
			for _, res := range reply(req) {
				b, err := res.Bytes()
				if err != nil {
					return
				}
				if _, err := there.Write(b); err != nil {
					return
				}
			}
		}()
	}
	respond := func(req *sip.Request, code int, reason string) *sip.Response {
		res, err := sip.NewResponse(req, code, reason, "b1")
		if err != nil {
			t.Error(err)
		}
		return res
	}
	in1 := func(method string, cseq int) msg {
		return msg{method: method, uri: bob, callID: "sipas-peer-test", cseq: cseq}
	}

	var invited, optioned *sip.Response
	answer(func(req *sip.Request) []*sip.Response {
		invited = respond(req, 200, "invited")
		return []*sip.Response{invited}
	})
	if res := p.send(in1("INVITE", 1)); res.Reason != "invited" {
		t.Fatalf("the INVITE: %d %s", res.StatusCode, res.Reason)
	}
	answer(func(req *sip.Request) []*sip.Response {
		optioned = respond(req, 200, "second")
		return []*sip.Response{invited, respond(req, 100, "Trying"), optioned}
	})
	if res := p.send(in1("OPTIONS", 2)); res.Reason != "second" {
		t.Fatalf("the OPTIONS took %d %s", res.StatusCode, res.Reason)
	}
	for name, stray := range map[string]func(req *sip.Request) *sip.Response{
		"an earlier OPTIONS's 200": func(*sip.Request) *sip.Response { return optioned },
		"the earlier INVITE's 200 with another CSeq": func(*sip.Request) *sip.Response {
			res := invited.Clone()
			_ = res.Header.Set("CSeq", "7 INVITE")
			return res
		},
		"another branch": func(req *sip.Request) *sip.Response {
			res := respond(req, 200, "stray")
			_ = res.Header.Set("Via", "SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-sipas-elsewhere")
			return res
		},
		"another CSeq": func(req *sip.Request) *sip.Response {
			res := respond(req, 200, "stray")
			_ = res.Header.Set("CSeq", "9 OPTIONS")
			return res
		},
	} {
		answer(func(req *sip.Request) []*sip.Response { return []*sip.Response{stray(req)} })
		if res, err := p.try(in1("OPTIONS", 3)); err == nil || !strings.Contains(err.Error(), "of this peer") {
			t.Errorf("%s: %v, %v", name, res, err)
		}
	}
}
