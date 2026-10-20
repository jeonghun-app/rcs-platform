package sipas

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

func delivery() messaging.Delivery {
	return messaging.Delivery{
		Recipient: bob, Sender: alice, SenderName: `Alice \u000aand Bob`, Mode: store.Standalone,
		Conversation: messaging.Conversation{ID: "c0nv1", Contribution: "c0ntr1", InReplyTo: "c0ntr0"},
		CPIM:         []byte(cpimBody("m1", "hi")),
	}
}

// A stored message goes to the core as a terminating request for its
// recipient, which the default profile does not send back to rcs-as
// (P-Served-User, docs/hss.md), with the sender asserted and its chosen
// name in From only.
func TestAStoredMessageGoesToTheCoreAsATerminatingRequest(t *testing.T) {
	core := newFakeCore(t)
	a := startAS(t, &fakeEngine{}, core)
	if err := a.srv.Pager(t.Context(), delivery()); err != nil {
		t.Fatal(err)
	}
	req := core.next(t)
	h := &req.Header
	for name, want := range map[string]string{
		"Route":                     "<" + core.uri().String() + ">",
		"To":                        "<" + bob + ">",
		"P-Asserted-Identity":       "<" + alice + ">",
		"P-Served-User":             "<" + bob + ">;sescase=term",
		"P-Asserted-Service":        messagingICSI,
		"Accept-Contact":            messagingAcceptTag,
		"Conversation-ID":           "c0nv1",
		"Contribution-ID":           "c0ntr1",
		"InReplyTo-Contribution-ID": "c0ntr0",
		"Content-Type":              "message/cpim",
		"CSeq":                      "1 MESSAGE",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if req.Method != "MESSAGE" || req.URI.String() != bob || string(req.Body) != cpimBody("m1", "hi") {
		t.Fatalf("%s %s with %q", req.Method, req.URI.String(), req.Body)
	}
	from, err := h.From()
	if err != nil || from.URI.String() != alice || from.DisplayName != `Alice \u000aand Bob` || from.Tag() == "" {
		t.Fatalf("From %+v, %v", from, err)
	}
	if pai, _ := h.PAssertedIdentity(); len(pai) != 1 || pai[0].DisplayName != "" {
		t.Fatalf("P-Asserted-Identity %+v carries a name", pai)
	}
	if strings := h.Values("Route"); len(strings) != 1 {
		t.Fatalf("Route %v", strings)
	}
}

func TestANotificationGoesThroughItsTrustedRoute(t *testing.T) {
	core, via := newFakeCore(t), newFakeCore(t)
	a := startAS(t, &fakeEngine{}, core)
	d := delivery()
	d.Notification, d.Route, d.SenderName = true, via.uri().String(), ""
	if err := a.srv.Pager(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	req := via.next(t)
	if got := req.Header.Get("Route"); got != "<"+via.uri().String()+">" {
		t.Fatalf("Route %q", got)
	}
	if from, _ := req.Header.From(); from.DisplayName != "" {
		t.Fatalf("From %+v", from)
	}
}

// What the recipient's side answered says what became of the message.
func TestAPagerAnswerSaysWhatBecameOfTheMessage(t *testing.T) {
	core := newFakeCore(t)
	a := startAS(t, &fakeEngine{}, core)
	for code, want := range map[int]error{
		200: nil, 202: nil,
		404: messaging.ErrUndeliverable, 604: messaging.ErrUndeliverable,
		408: messaging.ErrOffline, 430: messaging.ErrOffline, 480: messaging.ErrOffline, 503: messaging.ErrOffline,
		486: errPassing, 403: errPassing,
	} {
		core.setAnswer(func(*sip.Request) int { return code })
		err := a.srv.Pager(t.Context(), delivery())
		<-core.got
		switch {
		case want == nil && err != nil, want != nil && want != errPassing && !errors.Is(err, want):
			t.Errorf("%d: %v, want %v", code, err, want)
		case want == errPassing && (err == nil || errors.Is(err, messaging.ErrOffline) || errors.Is(err, messaging.ErrUndeliverable)):
			t.Errorf("%d: %v, want a failure to try again", code, err)
		}
	}
}

var errPassing = errors.New("a passing failure")

func TestAPagerThatCannotBeSentFindsTheRecipientOffline(t *testing.T) {
	core := newFakeCore(t)
	a := startAS(t, &fakeEngine{}, core)
	d := delivery()
	d.Route = "sip:scscf.elsewhere.example;transport=tcp;lr" // not resolvable here
	if err := a.srv.Pager(t.Context(), d); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("unresolvable next hop: %v", err)
	}
	// A core that nothing listens on: the request cannot be sent.
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.Route = "sip:" + gone.Addr().String() + ";transport=tcp;lr"
	_ = gone.Close()
	if err := a.srv.Pager(t.Context(), d); !errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("a next hop that refuses the connection: %v", err)
	}
	// A core that takes the request and never answers: the delivery's
	// context ends the wait.
	core.setAnswer(func(*sip.Request) int { return 0 })
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := a.srv.Pager(ctx, delivery()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unanswered: %v", err)
	}
}

func TestADeliveryWithoutAUsableAddressIsUndeliverable(t *testing.T) {
	a := startAS(t, &fakeEngine{}, newFakeCore(t))
	for name, d := range map[string]func(messaging.Delivery) messaging.Delivery{
		"recipient": func(d messaging.Delivery) messaging.Delivery { d.Recipient = "not a URI"; return d },
		"sender":    func(d messaging.Delivery) messaging.Delivery { d.Sender = "not a URI"; return d },
		"route":     func(d messaging.Delivery) messaging.Delivery { d.Route = "tel:+15550100002"; return d },
	} {
		if err := a.srv.Pager(t.Context(), d(delivery())); !errors.Is(err, messaging.ErrUndeliverable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSessionsAreNotServedYet(t *testing.T) {
	a := startAS(t, &fakeEngine{}, newFakeCore(t))
	if err := a.srv.Invite(t.Context(), messaging.Invitation{Recipient: bob, Peer: alice}); err == nil ||
		errors.Is(err, messaging.ErrNoSessions) || errors.Is(err, messaging.ErrOffline) {
		t.Fatalf("Invite = %v", err)
	}
}

// The security review's case on #242: a profile without the default one's
// P-Served-User exclusion sends rcs-as's own delivery back to it. rcs-as
// knows it by its From tag and refuses it with 482, instead of taking it
// for a new message and sending it again without end.
func TestADeliveryThatComesBackIsRefusedAsALoop(t *testing.T) {
	core := newFakeCore(t)
	e := &fakeEngine{}
	a := startAS(t, e, core)
	p := a.dial(t)
	bounced := make(chan int, 1)
	core.setAnswer(func(req *sip.Request) int {
		// What scscf would send on: rcs-as's AS URI and its own entry as
		// the Route, its Via on top.
		fwd := req.Clone()
		_ = fwd.Header.Set("Route", "<sip:"+a.addr.String()+";transport=tcp;lr>, <"+core.uri().String()+">")
		_ = fwd.Header.Prepend("Via", "SIP/2.0/TCP 192.0.2.30:5060;branch=z9hG4bK-scscf-loop")
		code := 0
		if res, err := p.forward(fwd); err == nil {
			code = res.StatusCode
		}
		bounced <- code
		return 482 // scscf passes rcs-as's answer back to it
	})
	err := a.srv.Pager(t.Context(), delivery())
	if code := <-bounced; code != 482 {
		t.Fatalf("the returning MESSAGE was answered %d", code)
	}
	if err == nil {
		t.Fatal("the looped delivery counts as delivered")
	}
	if got := e.origins(); len(got) != 0 {
		t.Fatalf("rcs-as took its own delivery as %d new messages", len(got))
	}
	// A client's own MESSAGE goes through as before.
	if res := p.send(pager(cpimBody("m2", "hi"))); res.StatusCode != 202 {
		t.Fatalf("a client's MESSAGE answered %d", res.StatusCode)
	}
}

// The transport's contract (#35) for what rcs-as sends, as the proxy
// follows it for what it forwards: a vanished flow is a recipient offline
// (430), a next hop without room a passing failure (503 with Retry-After),
// and the transport's error, which can name an address, stays out.
func TestASendFailureSaysWhatTheTransportReported(t *testing.T) {
	for err, want := range map[error]error{
		transport.ErrNoFlow:                            messaging.ErrOffline,
		fmt.Errorf("wrapped: %w", transport.ErrNoFlow): messaging.ErrOffline,
		transport.ErrQueueFull:                         errNextHopBusy,
		transport.ErrTooManyConnections:                errNextHopBusy,
		transport.ErrClosed:                            messaging.ErrOffline,
		errors.New("dial 192.0.2.9:5060: refused"):     messaging.ErrOffline,
	} {
		got := sendError(err)
		if !errors.Is(got, want) || errors.Is(got, err) {
			t.Errorf("sendError(%v) = %v, want %v without the transport's error", err, got, want)
		}
		if want == errNextHopBusy && errors.Is(got, messaging.ErrOffline) {
			t.Errorf("sendError(%v) is ErrOffline", err)
		}
	}
}
