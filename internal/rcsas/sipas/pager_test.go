package sipas

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
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
