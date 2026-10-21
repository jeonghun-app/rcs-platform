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
	return startASOn(t, e, cfg, transport.Config{}, tune...)
}

// startASOn is startASWith on a transport configured by tc.
func startASOn(t *testing.T, e Engine, cfg Config, tc transport.Config, tune ...func(*proxy.Config)) *as {
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
	srv.Bind(e, px.Layer(), tr)
	// Before the proxy and the transport, which carry its BYEs.
	t.Cleanup(srv.Close)
	p.Store(px)
	return &as{srv: srv, addr: addr}
}

// peer is the core's side of a connection to rcs-as, from which it sends
// the requests iFC route to rcs-as.
type peer struct {
	t  *testing.T
	nc net.Conn
	r  *sip.Reader
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
	return &peer{t: t, nc: nc, r: sip.NewReader(bufio.NewReader(nc), sip.Limits{})}
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
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := io.WriteString(p.nc, b.String()); err != nil {
		return nil, err
	}
	if m.method == "ACK" {
		return nil, nil
	}
	for {
		msg, err := p.r.ReadMessage()
		if err != nil {
			return nil, err
		}
		res, ok := msg.(*sip.Response)
		if !ok {
			return nil, errors.New("got a request")
		}
		// Only the answer to this request: rcs-as retransmits an INVITE's
		// 2xx until the ACK reaches it (RFC 3261 §13.3.1.4), and on a
		// loaded host a retransmission can come after the ACK has gone,
		// where it would pass for the next request's answer (#290). A UAC
		// matches a response to its transaction; this one by CSeq.
		if !answers(res, branch, sip.CSeq{Seq: uint32(cseq), Method: m.method}) {
			continue
		}
		if res.StatusCode >= 200 {
			return res, nil
		}
	}
}

// answers reports whether res is the answer to the request whose top Via
// has branch and whose CSeq is want: a UAC matches a response to its
// transaction by the two (RFC 3261 §17.1.3), and a test peer takes nothing
// else for its request's answer (#290). The CSeq alone is not enough, as
// every call starts at 1: another call's retransmitted 2xx would pass.
func answers(res *sip.Response, branch string, want sip.CSeq) bool {
	vias, err := res.Header.Via()
	if err != nil || len(vias) == 0 || vias[0].Branch() != branch {
		return false
	}
	cs, err := res.Header.CSeq()
	return err == nil && cs == want
}

// forward sends req as the core would, after its own processing, and
// returns its final response.
func (p *peer) forward(req *sip.Request) (*sip.Response, error) {
	want, err := req.Header.CSeq()
	if err != nil {
		return nil, err
	}
	vias, err := req.Header.Via()
	if err != nil || len(vias) == 0 {
		return nil, errors.New("a request to forward needs a Via")
	}
	branch := vias[0].Branch()
	b, err := req.Bytes()
	if err != nil {
		return nil, err
	}
	_ = p.nc.SetDeadline(time.Now().Add(waitFor))
	if _, err := p.nc.Write(b); err != nil {
		return nil, err
	}
	for {
		msg, err := p.r.ReadMessage()
		if err != nil {
			return nil, err
		}
		// The answer to req only, as try takes (#290).
		if res, ok := msg.(*sip.Response); ok && res.StatusCode >= 200 && answers(res, branch, want) {
			return res, nil
		}
	}
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

// #290: the test peer takes the answer to its own request only, for a
// request it sends (try) and one it forwards as the core (forward). Before
// that answer comes a 2xx retransmitted after its ACK went, as under load:
// the dialog's earlier INVITE's, and another call's INVITE's, at CSeq 1 as
// every call starts (code review on #333).
func TestThePeerTakesTheAnswerToItsOwnRequest(t *testing.T) {
	request := func(method string, cseq int, callID string) string {
		return method + " " + bob + " SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bK-f" + callID + "\r\nMax-Forwards: 70\r\n" +
			"From: <" + alice + ">;tag=a1\r\nTo: <" + bob + ">;tag=b1\r\nCall-ID: " + callID + "\r\nCSeq: " + fmt.Sprint(cseq, " ", method) + "\r\nContent-Length: 0\r\n\r\n"
	}
	forward := func(raw string) func(*peer) (*sip.Response, error) {
		return func(p *peer) (*sip.Response, error) {
			m, err := sip.NewReader(bufio.NewReader(strings.NewReader(raw)), sip.Limits{}).ReadMessage()
			if err != nil {
				return nil, err
			}
			return p.forward(m.(*sip.Request))
		}
	}
	for _, c := range []struct {
		name                   string
		staleBranch, staleCSeq string // of the stale 2xx that comes first
		send                   func(*peer) (*sip.Response, error)
	}{
		{"try, the dialog's INVITE", "z9hG4bK-old", "2 INVITE", func(p *peer) (*sip.Response, error) {
			return p.try(msg{method: "UPDATE", uri: bob, toTag: "b1", callID: "c1", cseq: 3})
		}},
		{"try, another call", "z9hG4bK-other", "1 INVITE", func(p *peer) (*sip.Response, error) {
			return p.try(msg{method: "INVITE", uri: bob, callID: "c2", cseq: 1})
		}},
		{"forward, the dialog's INVITE", "z9hG4bK-old", "2 INVITE", forward(request("UPDATE", 3, "c1"))},
		{"forward, another call", "z9hG4bK-other", "1 INVITE", forward(request("INVITE", 1, "c2"))},
	} {
		t.Run(c.name, func(t *testing.T) {
			ours, theirs := net.Pipe()
			t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
			p := &peer{t: t, nc: ours, r: sip.NewReader(bufio.NewReader(ours), sip.Limits{})}
			go func() {
				br := bufio.NewReader(theirs)
				var via, cseq string
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case line == "\r\n":
						goto answer
					case strings.HasPrefix(line, "Via: "):
						via = strings.TrimSpace(line)
					case strings.HasPrefix(line, "CSeq: "):
						cseq = strings.TrimSpace(strings.TrimPrefix(line, "CSeq: "))
					}
				}
			answer:
				reply := func(via, cseq, body string) string {
					return "SIP/2.0 200 OK\r\n" + via + "\r\n" +
						"From: <" + alice + ">;tag=a1\r\nTo: <" + bob + ">;tag=b1\r\nCall-ID: c0\r\nCSeq: " + cseq + "\r\n" +
						"Content-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body
				}
				stale := reply("Via: SIP/2.0/TCP 192.0.2.20:5060;branch="+c.staleBranch, c.staleCSeq, "v=0\r\n")
				_, _ = io.WriteString(theirs, stale+reply(via, cseq, ""))
			}()
			res, err := c.send(p)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Body) != 0 {
				cs, _ := res.Header.CSeq()
				t.Fatalf("took the stale %v with %q for the request's answer", cs, res.Body)
			}
		})
	}
}
