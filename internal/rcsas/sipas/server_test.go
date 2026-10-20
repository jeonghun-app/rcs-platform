package sipas

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestAUserIsNamedInOneForm(t *testing.T) {
	for in, want := range map[string]string{
		"tel:+1-555-010-0001": alice,
		"tel:+15550100001":    alice,
		aliceSIP:              alice,
		"sip:+1-555-010-0001@IMS.example.net;user=phone":    alice,
		"sip:+15550100001@" + domain:                        "sip:+15550100001@" + domain,
		"sip:Bob@EXAMPLE.net":                               "sip:Bob@example.net",
		"sip:Bob@example.net;user=phone":                    "sip:Bob@example.net",
		"sip:%42ob@example.net":                             "sip:Bob@example.net",
		"sips:+15550100002@" + domain + ";user=phone;lr":    bob,
		"sip:+15550100002;ext=11@" + domain + ";user=phone": "sip:+15550100002;ext=11@" + domain,
	} {
		if got, ok := UserOf(in); !ok || got != want {
			t.Errorf("UserOf(%q) = %q, %t, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "not a URI", "tel:5550100", "sip:example.net", "http://example.net/"} {
		if got, ok := UserOf(in); ok {
			t.Errorf("UserOf(%q) = %q, want none", in, got)
		}
	}
}

// A pager-mode MESSAGE from the core goes into the engine as a standalone
// message from the asserted sender, both users named in one form, and is
// answered 202 Accepted (RFC 3428 §7).
func TestAPagerMessageIsSubmittedFromTheAssertedSender(t *testing.T) {
	e := &fakeEngine{}
	a := startAS(t, e, newFakeCore(t))
	m := pager(cpimBody("m1", "hi"))
	m.uri = "sip:+15550100002@" + domain + ";user=phone"
	m.fields = append([]string{"P-Asserted-Identity: \"Alice\" <" + aliceSIP + ">, <tel:+1-555-010-0001>"}, m.fields[1:]...)
	m.fields = append(m.fields, "Conversation-ID: c0nv1", "Contribution-ID: c0ntr1")
	res := a.dial(t).send(m)
	if res.StatusCode != 202 {
		t.Fatalf("answered %d", res.StatusCode)
	}
	got := e.origins()
	if len(got) != 1 {
		t.Fatalf("%d submitted", len(got))
	}
	o := got[0]
	if o.Sender != alice || o.Recipient != bob || o.Mode != store.Standalone || !o.Pager ||
		o.Conversation != (messaging.Conversation{ID: "c0nv1", Contribution: "c0ntr1"}) || string(o.CPIM) != cpimBody("m1", "hi") {
		t.Fatalf("origin %+v", o)
	}
	// Every asserted identity, as asserted, may name the sender in its
	// CPIM From.
	for _, id := range []string{aliceSIP, "tel:+1-555-010-0001"} {
		if !slices.Contains(o.Identities, id) {
			t.Errorf("identities %v lack %s", o.Identities, id)
		}
	}
}

func TestWhatRCSASCannotTakeIsRefusedWithItsStatus(t *testing.T) {
	busy := fmt.Errorf("fake: %w", store.ErrBusy)
	for name, c := range map[string]struct {
		m      func(msg) msg
		err    error
		code   int
		header [2]string
	}{
		"not CPIM": {m: func(m msg) msg { m.fields = []string{m.fields[0], "Content-Type: text/plain"}; return m }, code: 415,
			header: [2]string{"Accept", "message/cpim"}},
		"no asserted identity": {m: func(m msg) msg { m.fields = m.fields[1:]; return m }, code: 403},
		"asserted non-user":    {m: func(m msg) msg { m.fields[0] = "P-Asserted-Identity: <sip:example.net>"; return m }, code: 403},
		"recipient no user":    {m: func(m msg) msg { m.uri = "sip:" + domain; return m }, code: 404},
		"bad conversation": {m: func(m msg) msg {
			m.fields = append(m.fields, "Conversation-ID: <bad id>")
			return m
		}, code: 400},
		"too large":      {err: &messaging.Rejection{Reason: messaging.ReasonTooLarge}, code: 413},
		"wrong type":     {err: &messaging.Rejection{Reason: messaging.ReasonContentType}, code: 415},
		"malformed":      {err: &messaging.Rejection{Reason: messaging.ReasonMalformed}, code: 400},
		"malformed IMDN": {err: &messaging.Rejection{Reason: messaging.ReasonIMDNMalformed}, code: 400},
		"forged IMDN":    {err: &messaging.Rejection{Reason: messaging.ReasonIMDNForged}, code: 403},
		"queue full":     {err: &messaging.Rejection{Reason: messaging.ReasonQueueFull}, code: 403},
		"rate":           {err: &messaging.Rejection{Reason: messaging.ReasonRateLimited}, code: 403},
		"busy store":     {err: busy, code: 503, header: [2]string{"Retry-After", "1"}},
		"failed store":   {err: errors.New("fake: store down"), code: 500},
	} {
		t.Run(name, func(t *testing.T) {
			e := &fakeEngine{err: c.err}
			a := startAS(t, e, newFakeCore(t))
			m := pager(cpimBody("m1", "hi"))
			if c.m != nil {
				m = c.m(m)
			}
			res := a.dial(t).send(m)
			if res.StatusCode != c.code {
				t.Fatalf("answered %d, want %d", res.StatusCode, c.code)
			}
			if c.header[0] != "" && res.Header.Get(c.header[0]) != c.header[1] {
				t.Fatalf("%s: %q", c.header[0], res.Header.Get(c.header[0]))
			}
			if c.m != nil && len(e.origins()) != 0 {
				t.Fatal("a refused request reached the engine")
			}
		})
	}
}

func TestOtherRequestsAreAnsweredOrPassedOn(t *testing.T) {
	core := newFakeCore(t)
	e := &fakeEngine{}
	a := startAS(t, e, core)
	p := a.dial(t)
	if res := p.send(msg{method: "SUBSCRIBE", uri: bob}); res.StatusCode != 405 || res.Header.Get("Allow") != allowed {
		t.Fatalf("SUBSCRIBE answered %d, Allow %q", res.StatusCode, res.Header.Get("Allow"))
	}
	inDialog := pager(cpimBody("m1", "hi"))
	inDialog.toTag = "b1"
	if res := p.send(inDialog); res.StatusCode != 481 {
		t.Fatalf("MESSAGE in a dialog answered %d", res.StatusCode)
	}
	// OPTIONS goes on along the Route scscf put below its own entry.
	res := p.send(msg{method: "OPTIONS", uri: bob, fields: []string{"Route: <" + core.uri().String() + ">"}})
	if res.StatusCode != 200 {
		t.Fatalf("OPTIONS answered %d", res.StatusCode)
	}
	if got := core.next(t); got.Method != "OPTIONS" || got.URI.String() != bob {
		t.Fatalf("the core got %s %s", got.Method, got.URI.String())
	}
	if len(e.origins()) != 0 {
		t.Fatal("the engine was given a request")
	}
}

// The lead's case on #137: alice arrives once as tel:+1-555-… and once as
// sip:+1555…;user=phone, and holds one share of bob's queue, not two
// (threat model T10).
func TestAUserWrittenTwoWaysHoldsOneShare(t *testing.T) {
	core := newFakeCore(t)
	core.setAnswer(func(*sip.Request) int { return 480 }) // bob is offline: what is queued stays
	var a *as
	e, err := messaging.New(messaging.Config{
		MSRPHost: "127.0.0.1", MSRPPort: 2855, MaxQueueMessages: 4, QueueSenderShare: 2,
		SenderRate: messaging.Rate{PerMinute: -1},
	}, store.NewMemory(), deliverer{&a}, noMetrics{})
	if err != nil {
		t.Fatal(err)
	}
	a = startAS(t, e, core)
	// Closed before the transport, which carries the answers to the
	// deliveries it waits for.
	t.Cleanup(e.Close)
	p := a.dial(t)
	for i, id := range []string{"<tel:+1-555-010-0001>", "<" + aliceSIP + ">"} {
		m := pager(cpimBody(fmt.Sprint("m", i), "hi"))
		m.fields[0] = "P-Asserted-Identity: " + id
		if res := p.send(m); res.StatusCode != 202 {
			t.Fatalf("message %d as %s answered %d", i, id, res.StatusCode)
		}
	}
	m := pager(cpimBody("m2", "hi"))
	if res := p.send(m); res.StatusCode != 403 {
		t.Fatalf("a third message, past alice's share, answered %d", res.StatusCode)
	}
}

// deliverer is the engine's Deliverer before the Server exists.
type deliverer struct{ a **as }

func (d deliverer) Pager(ctx context.Context, v messaging.Delivery) error {
	return (*d.a).srv.Pager(ctx, v)
}

func (d deliverer) Invite(ctx context.Context, v messaging.Invitation) error {
	return (*d.a).srv.Invite(ctx, v)
}
