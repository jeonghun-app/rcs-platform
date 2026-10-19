package sipua

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	callerContact = "<sip:caller@192.0.2.3:5060;transport=tcp>"
	// The Record-Route the network adds to a terminating INVITE, topmost
	// first: the called party's P-CSCF nearest it.
	callerRecordRoute = "<sip:pcscf.example.com;lr>, <sip:scscf.example.com;lr>"
)

// caller is the stand-in as the calling side of a chat: it sends an INVITE
// over the UA's flow and collects every response to it.
type caller struct {
	s      *standIn
	flow   transport.FlowID
	invite *sip.Request
	tag    string

	responses chan *sip.Response
	mu        sync.Mutex
	ok        *sip.Response
}

func (s *standIn) call(t *testing.T, flow transport.FlowID) *caller {
	t.Helper()
	callID, _ := s.ids.CallID("")
	return s.callWith(t, flow, callID)
}

// callWith is call with a given Call-ID and extra header fields.
func (s *standIn) callWith(t *testing.T, flow transport.FlowID, callID string, extra ...[2]string) *caller {
	t.Helper()
	c := &caller{s: s, flow: flow, tag: "caller", responses: make(chan *sip.Response, 32)}
	branch, _ := s.ids.Branch()
	req := &sip.Request{Method: "INVITE", URI: mustURI(t, testIMPU)}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", "<" + testPeer + ">;tag=" + c.tag},
		{"To", "<" + testIMPU + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 INVITE"},
		{"Contact", callerContact},
		{"Record-Route", callerRecordRoute},
		{"Content-Type", "application/sdp"},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range extra {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	req.Body = []byte(testOffer)
	c.invite = req
	if _, err := s.layer.Request(req, transport.Destination{Flow: flow}, func(res *sip.Response, err error) {
		if err == nil {
			select {
			case c.responses <- res:
			default:
				// A UA that never stops sending fails on the count, not
				// by blocking the stand-in.
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	return c
}

// next returns the next response to the INVITE that is not a 100.
func (c *caller) next(t *testing.T) *sip.Response {
	t.Helper()
	for {
		select {
		case res := <-c.responses:
			if res.StatusCode == 100 {
				continue
			}
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				c.mu.Lock()
				c.ok = res
				c.mu.Unlock()
			}
			return res
		case <-time.After(waitFor):
			t.Fatal("no response to the stand-in's INVITE")
			return nil
		}
	}
}

// none fails if a response other than a 100 is waiting.
func (c *caller) none(t *testing.T) {
	t.Helper()
	for {
		select {
		case res := <-c.responses:
			if res.StatusCode != 100 {
				t.Fatalf("unexpected %d", res.StatusCode)
			}
		default:
			return
		}
	}
}

// inDialog builds a request in the dialog from the caller's side.
func (c *caller) inDialog(t *testing.T, method string, cseq uint32) *sip.Request {
	t.Helper()
	c.mu.Lock()
	ok := c.ok
	c.mu.Unlock()
	contacts, err := ok.Header.Contact()
	if err != nil || len(contacts) == 0 {
		t.Fatalf("2xx Contact: %v", err)
	}
	branch, _ := c.s.ids.Branch()
	req := &sip.Request{Method: method, URI: contacts[0].URI}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"From", c.invite.Header.Get("From")},
		{"To", ok.Header.Get("To")},
		{"Call-ID", c.invite.Header.Get("Call-ID")},
		{"CSeq", strconv.FormatUint(uint64(cseq), 10) + " " + method},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	return req
}

// ack sends the ACK of the 2xx, which is no transaction.
func (c *caller) ack(t *testing.T) {
	t.Helper()
	if _, err := c.s.tr.SendRequest(c.inDialog(t, "ACK", 1), transport.Destination{Flow: c.flow}); err != nil {
		t.Fatal(err)
	}
}

// cancel sends CANCEL for the INVITE and returns its final response.
func (c *caller) cancel(t *testing.T) *sip.Response {
	t.Helper()
	h := &c.invite.Header
	vias, _ := h.Elements("Via")
	req := &sip.Request{Method: "CANCEL", URI: c.invite.URI}
	for _, f := range [][2]string{
		{"Via", vias[0]},
		{"Max-Forwards", "70"},
		{"From", h.Get("From")},
		{"To", h.Get("To")},
		{"Call-ID", h.Get("Call-ID")},
		{"CSeq", "1 CANCEL"},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	return c.s.sendRequest(t, req, c.flow)
}

// callee is a registered UA whose incoming calls arrive on calls.
func calleeUA(t *testing.T, clock *fakeClock) (*standIn, *UA, transport.FlowID, chan *IncomingCall) {
	t.Helper()
	s := newStandIn(t, transport.TCP)
	calls := make(chan *IncomingCall, 4)
	cfg := s.config()
	cfg.OnInvite = func(c *IncomingCall) { calls <- c }
	if clock != nil {
		cfg.Clock = clock
	}
	ua := dial(t, cfg)
	register(t, ua)
	return s, ua, s.next(t).src.Flow, calls
}

func waitConfirmed(t *testing.T, d *Dialog) {
	t.Helper()
	select {
	case <-d.Confirmed():
	case <-time.After(waitFor):
		t.Fatal("the ACK did not confirm the dialog")
	}
}

func nextCall(t *testing.T, calls chan *IncomingCall) *IncomingCall {
	t.Helper()
	select {
	case c := <-calls:
		return c
	case <-time.After(waitFor):
		t.Fatal("no incoming call")
		return nil
	}
}

func TestAnIncomingChatIsRungAcceptedAndConfirmed(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	in := nextCall(t, calls)
	if string(in.Request().Body) != testOffer {
		t.Fatalf("offer = %q", in.Request().Body)
	}
	if err := in.Ring(); err != nil {
		t.Fatal(err)
	}
	ringing := cl.next(t)
	rto, _ := ringing.Header.To()
	if rc, _ := ringing.Header.Contact(); len(rc) != 1 {
		t.Fatalf("180 Contact = %v: a response that sets up the dialog carries one (RFC 3261 §12.1.1)", rc)
	}
	if ringing.StatusCode != 180 || rto.Tag() == "" || ringing.Header.Get("Record-Route") != callerRecordRoute {
		t.Fatalf("180: %d, To tag %q, Record-Route %q", ringing.StatusCode, rto.Tag(), ringing.Header.Get("Record-Route"))
	}
	d, err := in.Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	ok := cl.next(t)
	oto, _ := ok.Header.To()
	contacts, _ := ok.Header.Contact()
	switch {
	case ok.StatusCode != 200 || string(ok.Body) != testAnswer || ok.Header.Get("Content-Type") != "application/sdp":
		t.Fatalf("200: %d %q", ok.StatusCode, ok.Body)
	case oto.Tag() != rto.Tag():
		t.Fatalf("the 200's To tag %q differs from the 180's %q (RFC 3261 §12.1.1)", oto.Tag(), rto.Tag())
	case ok.Header.Get("Record-Route") != callerRecordRoute:
		t.Fatalf("200 Record-Route = %q", ok.Header.Get("Record-Route"))
	case len(contacts) != 1 || !contacts[0].URI.Params.Has("ob"):
		t.Fatalf("200 Contact = %v", contacts)
	}
	select {
	case <-d.Confirmed():
		t.Fatal("confirmed before the ACK")
	default:
	}
	cl.ack(t)
	select {
	case <-d.Confirmed():
	case <-time.After(waitFor):
		t.Fatal("the ACK did not confirm the dialog")
	}
	if err := in.Reject(486); !errors.Is(err, ErrCallEnded) {
		t.Fatalf("Reject after Accept = %v", err)
	}
}

func TestTheCalledPartysByeFollowsTheRouteSetInOrder(t *testing.T) {
	// RFC 3261 §12.1.1: the called party's route set is the INVITE's
	// Record-Route as it is, and its remote target the INVITE's Contact.
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	in := nextCall(t, calls)
	d, err := in.Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	ok := cl.next(t)
	cl.ack(t)
	waitConfirmed(t, d)
	if res, err := d.Bye(context.Background()); err != nil || res.StatusCode != 200 {
		t.Fatalf("Bye = %v, %v", res, err)
	}
	bye := s.nextMethod(t, "BYE").req
	from, _ := bye.Header.From()
	to, _ := bye.Header.To()
	oto, _ := ok.Header.To()
	if bye.URI.String() != mustURI(t, "sip:caller@192.0.2.3:5060;transport=tcp").String() || routeHosts(t, bye) != "pcscf.example.com scscf.example.com" ||
		from.Tag() != oto.Tag() || to.Tag() != cl.tag || bye.Header.Get("Call-ID") != cl.invite.Header.Get("Call-ID") {
		t.Fatalf("BYE %s Route %s From tag %q To tag %q", bye.URI, routeHosts(t, bye), from.Tag(), to.Tag())
	}
}

func TestTheCallersByeEndsTheCalledPartysDialog(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	d, err := nextCall(t, calls).Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	cl.next(t)
	cl.ack(t)
	if res := s.sendRequest(t, cl.inDialog(t, "BYE", 2), flow); res.StatusCode != 200 {
		t.Fatalf("BYE answered %d", res.StatusCode)
	}
	select {
	case <-d.Done():
	case <-time.After(waitFor):
		t.Fatal("the dialog did not end")
	}
	// A re-INVITE in a dialog still up is refused; here it is over.
	if res := s.sendRequest(t, cl.inDialog(t, "INVITE", 3), flow); res.StatusCode != 481 {
		t.Fatalf("INVITE in the ended dialog answered %d, want 481", res.StatusCode)
	}
}

func TestAReInviteToTheCalledPartyIsRefused(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	d, _ := nextCall(t, calls).Accept([]byte(testAnswer))
	cl.next(t)
	cl.ack(t)
	if res := s.sendRequest(t, cl.inDialog(t, "INVITE", 2), flow); res.StatusCode != 488 {
		t.Fatalf("re-INVITE answered %d, want 488", res.StatusCode)
	}
	select {
	case <-d.Done():
		t.Fatal("the refused re-INVITE ended the dialog")
	default:
	}
}

func TestTheTwoHundredIsSentAgainUntilTheACK(t *testing.T) {
	// RFC 3261 §13.3.1.4: at T1, then doubling up to T2, over any
	// transport, until the ACK.
	clock := newFakeClock()
	s, ua, flow, calls := calleeUA(t, clock)
	cl := s.call(t, flow)
	d, err := nextCall(t, calls).Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	cl.next(t)
	for _, wait := range []time.Duration{transaction.DefaultT1, 2 * transaction.DefaultT1} {
		clock.armedFor(t, wait)
		clock.advance(wait)
		if res := cl.next(t); res.StatusCode != 200 {
			t.Fatalf("after %v: %d, want the 200 again", wait, res.StatusCode)
		}
	}
	cl.ack(t)
	select {
	case <-d.Confirmed():
	case <-time.After(waitFor):
		t.Fatal("the ACK did not confirm the dialog")
	}
	clock.advance(time.Minute)
	// A MESSAGE after it: any 200 sent meanwhile arrives first, on the
	// one connection.
	req, err := ua.NewRequest("MESSAGE", mustURI(t, testPeer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ua.Send(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	s.nextMethod(t, "MESSAGE")
	cl.none(t)
}

func TestNoACKEndsTheCalledPartysDialogWithBye(t *testing.T) {
	// RFC 3261 §13.3.1.4: no ACK in 64*T1, the dialog is ended with BYE.
	clock := newFakeClock()
	s, _, flow, calls := calleeUA(t, clock)
	cl := s.call(t, flow)
	d, err := nextCall(t, calls).Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	cl.next(t)
	clock.armedFor(t, transaction.DefaultT1)
	// Up to just short of 64*T1 in small steps: still up. Then the last
	// step: ended, exactly at 64*T1.
	const step = 100 * time.Millisecond
	for elapsed := time.Duration(0); elapsed < 64*transaction.DefaultT1-step; elapsed += step {
		clock.advance(step)
	}
	select {
	case <-d.Done():
		t.Fatal("the dialog ended before 64*T1")
	default:
	}
	// The BYE goes unanswered for now: the clock must not wait for it.
	hold := make(chan struct{})
	defer close(hold)
	s.mu.Lock()
	s.holdBye = hold
	s.mu.Unlock()
	advanced := make(chan struct{})
	go func() { clock.advance(step); close(advanced) }()
	select {
	case <-advanced:
	case <-time.After(waitFor):
		t.Fatal("the clock waited for the BYE's answer")
	}
	select {
	case <-d.Done():
	case <-time.After(waitFor):
		t.Fatal("the dialog did not end at 64*T1")
	}
	s.nextMethod(t, "BYE")
}

func TestARequiredExtensionIsRefusedWith420(t *testing.T) {
	// RFC 3261 §8.2.2.3; sipua supports none, 100rel and precondition
	// among them.
	s, _, flow, calls := calleeUA(t, nil)
	callID, _ := s.ids.CallID("")
	cl := s.callWith(t, flow, callID, [2]string{"Require", "100rel, precondition"})
	res := cl.next(t)
	if res.StatusCode != 420 || res.Header.Get("Unsupported") != "100rel, precondition" {
		t.Fatalf("answered %d, Unsupported %q", res.StatusCode, res.Header.Get("Unsupported"))
	}
	// A random To tag, as every tag must be (§19.3).
	if to, _ := res.Header.To(); len(to.Tag()) < 8 || to.Tag() == "rcs-sim" {
		t.Fatalf("To tag %q", to.Tag())
	}
	select {
	case <-calls:
		t.Fatal("OnInvite got an INVITE it cannot answer")
	default:
	}
}

func TestTheSameInviteByAnotherWayIs482(t *testing.T) {
	// A merged request (RFC 3261 §8.2.2.2): same Call-ID, From tag and
	// CSeq, another branch.
	s, _, flow, calls := calleeUA(t, nil)
	callID, _ := s.ids.CallID("")
	s.callWith(t, flow, callID)
	nextCall(t, calls)
	second := s.callWith(t, flow, callID)
	if res := second.next(t); res.StatusCode != 482 {
		t.Fatalf("the second copy answered %d, want 482", res.StatusCode)
	}
}

func TestTheCalledPartysByeWaitsForTheACK(t *testing.T) {
	// RFC 3261 §15: the called party's BYE waits until the ACK of its 200
	// has come (or 64*T1 have passed).
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	d, err := nextCall(t, calls).Accept([]byte(testAnswer))
	if err != nil {
		t.Fatal(err)
	}
	cl.next(t)
	byed := make(chan error, 1)
	go func() { _, err := d.Bye(context.Background()); byed <- err }()
	// A BYE sent before the ACK would be back by now; this wait only
	// catches that, a correct UA sends nothing until the ACK.
	select {
	case err := <-byed:
		t.Fatalf("Bye returned before the ACK: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cl.ack(t)
	if err := <-byed; err != nil {
		t.Fatal(err)
	}
	s.nextMethod(t, "BYE")
}

func TestACancelWithoutOnInviteGoesToOnRequest(t *testing.T) {
	// With no OnInvite, INVITEs and their CANCELs are OnRequest's alike.
	s := newStandIn(t, transport.TCP)
	got := make(chan string, 4)
	cfg := s.config()
	cfg.OnRequest = func(tx *transaction.ServerTransaction) {
		got <- tx.Request().Method
		code := 180
		if tx.Request().Method == "CANCEL" {
			code = 200
		}
		if res, err := sip.NewResponse(tx.Request(), code, "", "u"); err == nil {
			tx.Respond(res)
		}
	}
	ua := dial(t, cfg)
	register(t, ua)
	cl := s.call(t, s.next(t).src.Flow)
	if m := <-got; m != "INVITE" {
		t.Fatalf("OnRequest got %s", m)
	}
	cl.next(t)
	cl.cancel(t)
	select {
	case m := <-got:
		if m != "CANCEL" {
			t.Fatalf("OnRequest got %s, want the CANCEL", m)
		}
	case <-time.After(waitFor):
		t.Fatal("the CANCEL did not reach OnRequest")
	}
}

func TestRingAfterTheFinalResponseIsRefused(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	s.call(t, flow)
	in := nextCall(t, calls)
	if err := in.Reject(486); err != nil {
		t.Fatal(err)
	}
	if err := in.Ring(); !errors.Is(err, ErrCallEnded) {
		t.Fatalf("Ring after Reject = %v, want ErrCallEnded", err)
	}
}

func TestARejectedCallAnswersTheStatus(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	in := nextCall(t, calls)
	if err := in.Reject(486); err != nil {
		t.Fatal(err)
	}
	if res := cl.next(t); res.StatusCode != 486 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	if _, err := in.Accept(nil); !errors.Is(err, ErrCallEnded) {
		t.Fatalf("Accept after Reject = %v", err)
	}
	if err := in.Reject(200); err == nil {
		t.Fatal("Reject took a 2xx")
	}
}

func TestACancelBeforeTheAnswerEndsTheCallWith487(t *testing.T) {
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	in := nextCall(t, calls)
	if err := in.Ring(); err != nil {
		t.Fatal(err)
	}
	cl.next(t)
	if res := cl.cancel(t); res.StatusCode != 200 {
		t.Fatalf("CANCEL answered %d", res.StatusCode)
	}
	if res := cl.next(t); res.StatusCode != 487 {
		t.Fatalf("INVITE answered %d after CANCEL, want 487 (RFC 3261 §9.2)", res.StatusCode)
	}
	select {
	case <-in.Cancelled():
	default:
		t.Fatal("Cancelled is not closed")
	}
	if _, err := in.Accept([]byte(testAnswer)); !errors.Is(err, ErrCallEnded) {
		t.Fatalf("Accept after CANCEL = %v", err)
	}
}

func TestACancelAfterTheAnswerChangesNothing(t *testing.T) {
	// RFC 3261 §9.2: a CANCEL for an INVITE already answered gets 200 and
	// no other effect.
	s, _, flow, calls := calleeUA(t, nil)
	cl := s.call(t, flow)
	d, _ := nextCall(t, calls).Accept([]byte(testAnswer))
	cl.next(t)
	if res := cl.cancel(t); res.StatusCode != 200 {
		t.Fatalf("CANCEL answered %d", res.StatusCode)
	}
	cl.none(t)
	select {
	case <-d.Done():
		t.Fatal("the CANCEL ended the dialog")
	default:
	}
}

func TestACancelForNoInviteIs481(t *testing.T) {
	s, _, flow, _ := calleeUA(t, nil)
	cl := &caller{s: s, flow: flow, tag: "caller"}
	branch, _ := s.ids.Branch()
	callID, _ := s.ids.CallID("")
	req := &sip.Request{Method: "INVITE", URI: mustURI(t, testIMPU)}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/TCP standin.invalid;branch=" + branch},
		{"From", "<" + testPeer + ">;tag=caller"},
		{"To", "<" + testIMPU + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 INVITE"},
	} {
		req.Header.Add(f[0], f[1])
	}
	cl.invite = req
	if res := cl.cancel(t); res.StatusCode != 481 {
		t.Fatalf("CANCEL for no INVITE answered %d, want 481", res.StatusCode)
	}
}
