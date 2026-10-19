package sipua

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	testPeer   = "sip:+15550100002@ims.example.com"
	testOffer  = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=message 7394 TCP/MSRP *\r\na=accept-types:message/cpim\r\na=setup:active\r\n"
	testAnswer = "v=0\r\no=- 2 2 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\nm=message 7394 TCP/MSRP *\r\na=accept-types:message/cpim\r\na=setup:passive\r\n"
	// The far end's Contact and the Record-Route the network adds,
	// topmost first: the S-CSCF last, nearest the far end.
	calleeContact = "<sip:callee@192.0.2.2:5060;transport=tcp>"
	recordRoute   = "<sip:scscf.example.com;lr>, <sip:pcscf.example.com;lr>"
)

// callee answers the stand-in's INVITEs as the far end: 180, then, when
// answer is set, 200 with the SDP answer. It keeps each transaction, so a
// test can send the 2xx again or another one, and the far end's side of the
// dialog for requests it sends.
type callee struct {
	s      *standIn
	tag    string
	answer bool
	// ringing hears each INVITE once its 180 is sent.
	ringing chan *transaction.ServerTransaction

	mu      sync.Mutex
	invite  *sip.Request
	flow    transport.FlowID
	ok      *sip.Response
	cseq    uint32
	sentLog []string
}

func newCallee(t *testing.T, s *standIn, answer bool) *callee {
	c := &callee{s: s, tag: "callee", answer: answer, ringing: make(chan *transaction.ServerTransaction, 4), cseq: 100}
	s.onInvite = func(tx *transaction.ServerTransaction) {
		req := tx.Request()
		c.mu.Lock()
		c.invite, c.flow = req.Clone(), tx.Source().Flow
		c.mu.Unlock()
		if res, err := sip.NewResponse(req, 180, "", c.tag); err == nil {
			tx.Respond(res)
			c.log("180")
		}
		c.ringing <- tx
		if c.answer {
			c.accept(t, tx, c.tag)
		}
	}
	return c
}

func (c *callee) log(what string) {
	c.mu.Lock()
	c.sentLog = append(c.sentLog, what)
	c.mu.Unlock()
}

// accept sends a 200 with the SDP answer, as the far end with tag.
func (c *callee) accept(t *testing.T, tx *transaction.ServerTransaction, tag string) {
	res, err := sip.NewResponse(tx.Request(), 200, "", tag)
	if err != nil {
		t.Errorf("callee: %v", err)
		return
	}
	res.Header.Add("Contact", calleeContact)
	res.Header.Add("Record-Route", recordRoute)
	res.Header.Add("Content-Type", "application/sdp")
	res.Body = []byte(testAnswer)
	c.mu.Lock()
	c.ok = res
	c.mu.Unlock()
	if err := tx.Respond(res); err != nil {
		if !c.s.closing.Load() {
			t.Errorf("callee: 200: %v", err)
		}
	}
	c.log("200 " + tag)
}

// request sends a request in the dialog from the far end's side.
func (c *callee) request(t *testing.T, method string, cseq uint32) *sip.Response {
	t.Helper()
	c.mu.Lock()
	inv, flow := c.invite, c.flow
	c.mu.Unlock()
	contacts, err := inv.Header.Contact()
	if err != nil || len(contacts) == 0 {
		t.Fatalf("INVITE Contact: %v", err)
	}
	branch, _ := c.s.ids.Branch()
	req := &sip.Request{Method: method, URI: contacts[0].URI}
	to := inv.Header.Get("From")
	from := inv.Header.Get("To") + ";tag=" + c.tag
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", from},
		{"To", to},
		{"Call-ID", inv.Header.Get("Call-ID")},
		{"CSeq", strconv.FormatUint(uint64(cseq), 10) + " " + method},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	return c.s.sendRequest(t, req, flow)
}

// inviteStandIn is a registered UA and a stand-in whose far end is c.
func inviteStandIn(t *testing.T, answer bool) (*standIn, *callee, *UA) {
	t.Helper()
	s := newStandIn(t, transport.TCP)
	c := newCallee(t, s, answer)
	ua := dial(t, s.config())
	register(t, ua)
	s.next(t)
	return s, c, ua
}

func call(t *testing.T, ua *UA) (*Dialog, *sip.Response, []*sip.Response) {
	t.Helper()
	req, err := ua.NewInvite(mustURI(t, testPeer), []byte(testOffer))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var progress []*sip.Response
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	d, res, err := ua.Invite(ctx, req, func(r *sip.Response) {
		mu.Lock()
		progress = append(progress, r)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	return d, res, progress
}

func (s *standIn) nextACK(t *testing.T) *sip.Request {
	t.Helper()
	select {
	case a := <-s.acks:
		return a
	case <-time.After(waitFor):
		t.Fatal("no ACK reached the stand-in")
		return nil
	}
}

func (s *standIn) nextMethod(t *testing.T, method string) received {
	t.Helper()
	for {
		r := s.next(t)
		if r.req.Method == method {
			return r
		}
	}
}

func routeHosts(t *testing.T, req *sip.Request) string {
	t.Helper()
	routes, err := req.Header.Route()
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, r := range routes {
		hosts = append(hosts, r.URI.Host)
	}
	return strings.Join(hosts, " ")
}

func TestAnInviteCarriesTheChatServiceAndPreferredIdentity(t *testing.T) {
	s, _, ua := inviteStandIn(t, true)
	call(t, ua)
	inv := s.nextMethod(t, "INVITE").req
	contacts, err := inv.Header.Contact()
	if err != nil || len(contacts) != 1 {
		t.Fatalf("Contact = %v, %v", contacts, err)
	}
	icsi, _ := contacts[0].Params.Get("+g.3gpp.icsi-ref")
	if icsi != ICSIChat || !contacts[0].URI.Params.Has("ob") {
		t.Errorf("Contact = %s, want the chat ICSI and ob (RFC 5626 §4.3)", contacts[0])
	}
	for name, want := range map[string]string{
		"Accept-Contact":       `*;+g.3gpp.icsi-ref="` + ICSIChat + `"`,
		"P-Preferred-Service":  "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session",
		"P-Preferred-Identity": "<" + testIMPU + ">",
		"Content-Type":         "application/sdp",
	} {
		if got := inv.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if string(inv.Body) != testOffer {
		t.Errorf("body = %q", inv.Body)
	}
}

func TestRegisterAndRequestsCarryTheRCSFeatureTagsAndIdentity(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	ua := dial(t, s.config())
	register(t, ua)
	reg := s.next(t).req
	contacts, _ := reg.Header.Contact()
	icsi, _ := contacts[0].Params.Get("+g.3gpp.icsi-ref")
	iari, _ := contacts[0].Params.Get("+g.3gpp.iari-ref")
	if icsi != ICSIChat+","+ICSIStandalone+","+ICSIStandaloneLarge || iari != IARIFileTransfer {
		t.Errorf("REGISTER Contact = %s, want the RCS services", contacts[0])
	}
	if reg.Header.Has("P-Preferred-Identity") {
		t.Error("REGISTER carries P-Preferred-Identity; TS 24.229 has it in other requests only")
	}
	req, err := ua.NewRequest("MESSAGE", mustURI(t, testPeer))
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("P-Preferred-Identity"); got != "<"+testIMPU+">" {
		t.Errorf("P-Preferred-Identity = %q", got)
	}
}

func TestAnInviteAnsweredIsACKedAlongTheRouteSet(t *testing.T) {
	s, c, ua := inviteStandIn(t, true)
	d, res, progress := call(t, ua)
	if d == nil || res.StatusCode != 200 || string(d.Answer().Body) != testAnswer {
		t.Fatalf("Invite = %v, %v", d, res)
	}
	// The stand-in's transaction layer sends 100 Trying at once, then the
	// far end rings.
	if n := len(progress); n == 0 || progress[n-1].StatusCode != 180 {
		t.Fatalf("%d provisional responses, the last not the 180", n)
	}
	ack := s.nextACK(t)
	inv := s.nextMethod(t, "INVITE").req
	invCSeq, _ := inv.Header.CSeq()
	ackCSeq, _ := ack.Header.CSeq()
	to, _ := ack.Header.To()
	invVia, _ := inv.Header.Via()
	ackVia, _ := ack.Header.Via()
	switch {
	case ack.URI.String() != mustURI(t, "sip:callee@192.0.2.2:5060;transport=tcp").String():
		t.Errorf("ACK Request-URI = %s, want the 2xx's Contact (RFC 3261 §12.2.1.1)", ack.URI)
	case routeHosts(t, ack) != "pcscf.example.com scscf.example.com":
		t.Errorf("ACK Route = %s, want the Record-Route reversed", routeHosts(t, ack))
	case ackCSeq.Seq != invCSeq.Seq || ackCSeq.Method != "ACK":
		t.Errorf("ACK CSeq = %v, INVITE %v", ackCSeq, invCSeq)
	case to.Tag() != c.tag:
		t.Errorf("ACK To tag = %q", to.Tag())
	case ackVia[0].Branch() == invVia[0].Branch():
		t.Error("the ACK to a 2xx reused the INVITE's branch; it is a new transaction (§13.2.2.4)")
	}
	if ack.Header.Get("Call-ID") != inv.Header.Get("Call-ID") {
		t.Error("ACK Call-ID differs")
	}
}

func TestARetransmitted2xxIsACKedAgain(t *testing.T) {
	s, c, ua := inviteStandIn(t, true)
	call(t, ua)
	s.nextACK(t)
	tx := <-c.ringing
	c.mu.Lock()
	ok := c.ok
	c.mu.Unlock()
	// RFC 6026 §7.1: the UAS sends the 2xx again until the ACK comes.
	if err := tx.Respond(ok); err != nil {
		t.Fatal(err)
	}
	s.nextACK(t)
}

func TestA2xxAfterTheTransactionEndedIsACKedAgain(t *testing.T) {
	// Once the INVITE transaction has gone (Timer M, RFC 6026 §7.2), a
	// retransmitted 2xx matches nothing and reaches the TU as a stray;
	// the dialog still ACKs it (RFC 3261 §13.2.2.4).
	s := newStandIn(t, transport.TCP)
	c := newCallee(t, s, true)
	clock := newFakeClock()
	cfg := s.config()
	cfg.Clock = clock
	ua := dial(t, cfg)
	register(t, ua)
	call(t, ua)
	s.nextACK(t)
	clock.advance(64*transaction.DefaultT1 + time.Second)
	tx := <-c.ringing
	c.mu.Lock()
	ok := c.ok
	c.mu.Unlock()
	if err := tx.Respond(ok); err != nil {
		t.Fatal(err)
	}
	s.nextACK(t)
}

func TestA2xxFromAnotherBranchIsACKedAndEnded(t *testing.T) {
	// RFC 3261 §13.2.2.4: a 2xx from another branch of a fork, with
	// another To tag, is ACKed and the call it set up ended with BYE.
	s, c, ua := inviteStandIn(t, true)
	call(t, ua)
	s.nextACK(t)
	tx := <-c.ringing
	c.accept(t, tx, "other-branch")
	ack := s.nextACK(t)
	if to, _ := ack.Header.To(); to.Tag() != "other-branch" {
		t.Fatalf("second ACK To tag = %q", to.Tag())
	}
	bye := s.nextMethod(t, "BYE").req
	if to, _ := bye.Header.To(); to.Tag() != "other-branch" {
		t.Fatalf("BYE To tag = %q, want the other branch's", to.Tag())
	}
}

func TestByeEndsTheDialog(t *testing.T) {
	s, c, ua := inviteStandIn(t, true)
	d, _, _ := call(t, ua)
	s.nextACK(t)
	res, err := d.Bye(context.Background())
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("Bye = %v, %v", res, err)
	}
	select {
	case <-d.Done():
	default:
		t.Fatal("the dialog did not end")
	}
	bye := s.nextMethod(t, "BYE").req
	c.mu.Lock()
	inv := c.invite
	c.mu.Unlock()
	invCSeq, _ := inv.Header.CSeq()
	byeCSeq, _ := bye.Header.CSeq()
	from, _ := bye.Header.From()
	invFrom, _ := inv.Header.From()
	to, _ := bye.Header.To()
	if byeCSeq.Seq != invCSeq.Seq+1 || from.Tag() != invFrom.Tag() || to.Tag() != c.tag || routeHosts(t, bye) != "pcscf.example.com scscf.example.com" {
		t.Fatalf("BYE CSeq %v, From tag %q, To tag %q, Route %s", byeCSeq, from.Tag(), to.Tag(), routeHosts(t, bye))
	}
	if _, err := d.Bye(context.Background()); !errors.Is(err, ErrDialogEnded) {
		t.Fatalf("second Bye = %v, want ErrDialogEnded", err)
	}
}

func TestAByeFromTheNetworkEndsTheDialog(t *testing.T) {
	s, c, ua := inviteStandIn(t, true)
	d, _, _ := call(t, ua)
	s.nextACK(t)
	if res := c.request(t, "BYE", 101); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
	select {
	case <-d.Done():
	case <-time.After(waitFor):
		t.Fatal("the dialog did not end")
	}
	// A request in a dialog that is over gets 481: the UA no longer knows
	// it (RFC 3261 §12.2.2).
	if res := c.request(t, "BYE", 102); res.StatusCode != 481 {
		t.Fatalf("BYE after the end answered %d", res.StatusCode)
	}
}

func TestAReInviteIsRefusedAndTheDialogStays(t *testing.T) {
	s, c, ua := inviteStandIn(t, true)
	d, _, _ := call(t, ua)
	s.nextACK(t)
	if res := c.request(t, "INVITE", 101); res.StatusCode != 488 {
		t.Fatalf("re-INVITE answered %d, want 488", res.StatusCode)
	}
	select {
	case <-d.Done():
		t.Fatal("a refused re-INVITE ended the dialog")
	default:
	}
	// Out of order: a CSeq below the re-INVITE's (RFC 3261 §12.2.2).
	if res := c.request(t, "BYE", 100); res.StatusCode != 500 {
		t.Fatalf("BYE with a lower CSeq answered %d, want 500", res.StatusCode)
	}
	if res := c.request(t, "BYE", 102); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
}

func TestARefusedInviteReturnsTheResponseAndNoDialog(t *testing.T) {
	s := newStandIn(t, transport.TCP)
	s.onInvite = func(tx *transaction.ServerTransaction) {
		if res, err := sip.NewResponse(tx.Request(), 486, "", "busy"); err == nil {
			tx.Respond(res)
		}
	}
	ua := dial(t, s.config())
	register(t, ua)
	req, _ := ua.NewInvite(mustURI(t, testPeer), []byte(testOffer))
	d, res, err := ua.Invite(context.Background(), req, nil)
	if err != nil || d != nil || res.StatusCode != 486 {
		t.Fatalf("Invite = %v, %v, %v", d, res, err)
	}
}

func TestCancellingAnInviteSendsCANCELAfterTheProvisional(t *testing.T) {
	// RFC 3261 §9.1: no CANCEL before a provisional response shows the
	// INVITE arrived. A bare-socket far end, which sends no 100 Trying of
	// its own, lets the caller give up first and rings only afterwards.
	r := newRawUAS(t)
	ua := dial(t, r.config(t))
	r.register(t, ua)
	ctx, cancel := context.WithCancel(context.Background())
	req, err := ua.NewInvite(mustURI(t, testPeer), []byte(testOffer))
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		res *sip.Response
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		_, res, err := ua.Invite(ctx, req, nil)
		done <- outcome{res, err}
	}()
	inv := r.expect(t, "INVITE")
	cancel()
	// A CANCEL sent at once would arrive now. This wait only catches that
	// mistake; a correct UA sends nothing until the 180.
	if m, ok := r.within(300 * time.Millisecond); ok {
		t.Fatalf("%s arrived before any provisional response", label(m))
	}
	r.respond(t, inv, 180)
	c := r.expect(t, "CANCEL")
	r.respond(t, c, 200)
	r.respond(t, inv, 487)
	r.expect(t, "ACK") // the transaction's, for the 487
	o := <-done
	if !errors.Is(o.err, context.Canceled) || o.res == nil || o.res.StatusCode != 487 {
		t.Fatalf("Invite = %v, %v; want 487 and the context's error", o.res, o.err)
	}
	iv, _ := inv.Header.Via()
	cv, _ := c.Header.Via()
	cs, _ := c.Header.CSeq()
	is, _ := inv.Header.CSeq()
	if cv[0].Branch() != iv[0].Branch() || cs.Seq != is.Seq || cs.Method != "CANCEL" || c.URI.String() != inv.URI.String() || c.Header.Get("To") != inv.Header.Get("To") {
		t.Fatalf("CANCEL does not match its INVITE (RFC 3261 §9.1): Via %s CSeq %v URI %s", cv[0], cs, c.URI)
	}
}

func TestA2xxThatCrossesTheCancelIsACKedAndEnded(t *testing.T) {
	// The far end answers the INVITE 200 when the CANCEL reaches it, as
	// one that had answered just before would: the 2xx and the CANCEL
	// cross (RFC 3261 §9.1).
	s := newStandIn(t, transport.TCP)
	c := newCallee(t, s, false)
	s.onCancel = func(inv *transaction.ServerTransaction) { c.accept(t, inv, c.tag) }
	ua := dial(t, s.config())
	register(t, ua)
	req, _ := ua.NewInvite(mustURI(t, testPeer), []byte(testOffer))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-c.ringing
		cancel()
	}()
	d, res, err := ua.Invite(ctx, req, nil)
	if d != nil || res == nil || res.StatusCode != 200 || !errors.Is(err, context.Canceled) {
		t.Fatalf("Invite = %v, %v, %v; want the 200, no dialog and the context's error", d, res, err)
	}
	s.nextACK(t)
	bye := s.nextMethod(t, "BYE").req
	if to, _ := bye.Header.To(); to.Tag() != c.tag {
		t.Fatalf("BYE To tag = %q", to.Tag())
	}
}

// rawUAS is a P-CSCF and far end on a bare socket, for what the stand-in's
// transaction layer would not allow: it sends no 100 Trying.
type rawUAS struct {
	ln   net.Listener
	conn net.Conn
	msgs chan sip.Message
}

func newRawUAS(t *testing.T) *rawUAS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return &rawUAS{ln: ln, msgs: make(chan sip.Message, 16)}
}

func (r *rawUAS) config(t *testing.T) Config {
	return Config{
		Network: transport.TCP, Proxy: netip.MustParseAddrPort(r.ln.Addr().String()), Domain: testDomain,
		IMPU: mustURI(t, testIMPU), InstanceID: testInstance,
	}
}

// register accepts the UA's connection, reads it from then on, and answers
// its REGISTER.
func (r *rawUAS) register(t *testing.T, ua *UA) {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := ua.Register(context.Background()); done <- err }()
	c, err := r.ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	r.conn = c
	go func() {
		rd := sip.NewReader(bufio.NewReader(c), sip.Limits{})
		for {
			m, err := rd.ReadMessage()
			if err != nil {
				close(r.msgs)
				return
			}
			r.msgs <- m
		}
	}()
	reg := r.expect(t, "REGISTER")
	res := mustResponse(t, reg, 200, "r1")
	contacts, _ := reg.Header.Contact()
	contacts[0].Params.Set("expires", "3600")
	res.Header.Add("Contact", contacts[0].String())
	r.write(t, res)
	if err := <-done; err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func (r *rawUAS) within(d time.Duration) (sip.Message, bool) {
	select {
	case m, ok := <-r.msgs:
		return m, ok
	case <-time.After(d):
		return nil, false
	}
}

func (r *rawUAS) expect(t *testing.T, method string) *sip.Request {
	t.Helper()
	m, ok := r.within(waitFor)
	req, isReq := m.(*sip.Request)
	if !ok || !isReq || req.Method != method {
		t.Fatalf("got %s, want %s", label(m), method)
	}
	return req
}

func (r *rawUAS) respond(t *testing.T, req *sip.Request, code int) {
	t.Helper()
	r.write(t, mustResponse(t, req, code, "callee"))
}

func (r *rawUAS) write(t *testing.T, m sip.Message) {
	t.Helper()
	b, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

func label(m sip.Message) string {
	switch m := m.(type) {
	case *sip.Request:
		return m.Method
	case *sip.Response:
		return strconv.Itoa(m.StatusCode)
	}
	return "nothing"
}
