package sipas

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/imdn"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/store"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

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

// asserting replaces a request's P-Asserted-Identity with pai.
func asserting(pai string) func(msg) msg {
	return func(m msg) msg {
		m.fields[0] = "P-Asserted-Identity: " + pai
		return m
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
		// What pcscf asserts is one identity or one user's SIP and tel
		// pair (#208), nothing else (QA on #242).
		"three asserted": {m: asserting("<tel:+15550100001>, <sip:+15550100001@" + domain + ">, <" + aliceSIP + ">"), code: 403},
		"two tel URIs":   {m: asserting("<tel:+15550100001>, <tel:+1-555-010-0001>"), code: 403},
		"two SIP URIs":   {m: asserting("<sip:+15550100001@" + domain + ">, <" + aliceSIP + ">"), code: 403},
		"SIP and SIPS":   {m: asserting("<sips:+15550100001@" + domain + ">, <" + aliceSIP + ">"), code: 403},
		"two numbers":    {m: asserting("<sip:+15550100001@" + domain + ">, <tel:+15550100003>"), code: 403},

		"one a non-user": {m: asserting("<tel:+15550100001>, <sip:example.net>"), code: 403},
		// An empty Require has no option tag to name (QA on #242).
		"an empty Require": {m: func(m msg) msg { m.fields = append(m.fields, "Require:"); return m }, code: 400},
		"an extension rcs-as lacks": {m: func(m msg) msg { m.fields = append(m.fields, "Require: x-qa-unknown"); return m }, code: 420,
			header: [2]string{"Unsupported", "x-qa-unknown"}},
		"recipient no user": {m: func(m msg) msg { m.uri = "sip:" + domain; return m }, code: 404},
		"bad conversation": {m: func(m msg) msg {
			m.fields = append(m.fields, "Conversation-ID: <bad id>")
			return m
		}, code: 400},
		"too large": {err: &messaging.Rejection{Reason: messaging.ReasonTooLarge}, code: 413},
		// The client sent message/cpim already: no Accept (QA on #242).
		"wrong type":     {err: &messaging.Rejection{Reason: messaging.ReasonContentType}, code: 415, header: [2]string{"Accept", ""}},
		"malformed":      {err: &messaging.Rejection{Reason: messaging.ReasonMalformed}, code: 400},
		"malformed IMDN": {err: &messaging.Rejection{Reason: messaging.ReasonIMDNMalformed}, code: 400},
		"forged IMDN":    {err: &messaging.Rejection{Reason: messaging.ReasonIMDNForged}, code: 403},
		"queue full":     {err: &messaging.Rejection{Reason: messaging.ReasonQueueFull}, code: 403},
		"rate":           {err: &messaging.Rejection{Reason: messaging.ReasonRateLimited}, code: 403},
		"busy store":     {err: busy, code: 500, header: [2]string{"Retry-After", "1"}},
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

// The lead's case on #137, and the code review's on #242: alice arrives in
// every form pcscf may assert (#208) or a client may choose by its
// P-Preferred-Identity, and holds one share of bob's queue, not one per
// form (threat model T10).
func TestAUserWrittenEveryWayHoldsOneShare(t *testing.T) {
	core := newFakeCore(t)
	core.setAnswer(func(*sip.Request) int { return 480 }) // bob is offline: what is queued stays
	a, _ := startEngine(t, core, messaging.Config{MaxQueueMessages: 6, QueueSenderShare: 2})
	p := a.dial(t)
	// Three of six, alice's share, then a refusal, whichever form comes.
	forms := []string{
		"<tel:+1-555-010-0001>",
		"<sip:+15550100001@" + domain + ">, <tel:+15550100001>",
		"<" + aliceSIP + ">",
		"<sip:+15550100001@" + strings.ToUpper(domain) + ">",
	}
	for i, id := range forms {
		m := pager(cpimBody(fmt.Sprint("m", i), "hi"))
		m.fields[0] = "P-Asserted-Identity: " + id
		want := 202
		if i == 3 {
			want = 403
		}
		if res := p.send(m); res.StatusCode != want {
			t.Fatalf("message %d as %s answered %d, want %d", i, id, res.StatusCode, want)
		}
	}
}

// The code review's case on #242: alice is asserted in SIP form first, as
// pcscf does for a SIP identity, and writes to bob's number; bob's client
// sends its delivery notification to alice's number, as rcsjta does
// (ImdnManager), or to the SIP From rcs-as wrote, asserted in SIP form too.
// Either way it finds the message, and goes on to alice.
func TestADeliveryNotificationFindsItsMessageWhateverTheForms(t *testing.T) {
	core := newFakeCore(t)
	a, _ := startEngine(t, core, messaging.Config{})
	p := a.dial(t)
	for i, to := range []string{"tel:+15550100001", "sip:+15550100001@" + domain} {
		id := fmt.Sprint("m", i)
		m := pager(cpimBody(id, "hi"))
		m.uri = "tel:+15550100002"
		m.fields[0] = "P-Asserted-Identity: <sip:+15550100001@" + domain + ">, <tel:+15550100001>"
		if res := p.send(m); res.StatusCode != 202 {
			t.Fatalf("alice's message answered %d", res.StatusCode)
		}
		if got := core.next(t); got.URI.String() != bob {
			t.Fatalf("delivered to %s", got.URI.String())
		}
		n := imdn.Notification{MessageID: id, DateTime: "2026-03-04T05:06:07.000Z", Kind: imdn.DeliveryNotification, Status: imdn.Delivered}
		cm, err := n.Message(imdn.Envelope{
			From: cpim.Address{URI: messaging.AnonymousURI}, To: cpim.Address{URI: messaging.AnonymousURI},
			MessageID: "r" + id, DateTime: time.Date(2026, 3, 4, 5, 6, 8, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		body, err := cm.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		r := pager(string(body))
		r.uri = to
		r.fields[0] = "P-Asserted-Identity: <sip:+15550100002@" + domain + ">, <tel:+15550100002>"
		if res := p.send(r); res.StatusCode != 202 {
			t.Fatalf("bob's notification to %s answered %d", to, res.StatusCode)
		}
		if got := core.next(t); got.URI.String() != alice || !strings.Contains(string(got.Body), "<delivered>") {
			t.Fatalf("the notification went to %s: %q", got.URI.String(), got.Body)
		}
	}
}

// startEngine serves the real engine, on the memory store, behind a Server
// whose core is core.
func startEngine(t *testing.T, core *fakeCore, cfg messaging.Config) (*as, *messaging.Engine) {
	t.Helper()
	var a *as
	cfg.MSRPHost, cfg.MSRPPort, cfg.HomeDomain = "127.0.0.1", 2855, domain
	cfg.SenderRate = messaging.Rate{PerMinute: -1}
	e, err := messaging.New(cfg, store.NewMemory(), deliverer{&a}, noMetrics{})
	if err != nil {
		t.Fatal(err)
	}
	a = startAS(t, e, core)
	// Closed before the transport, which carries the answers to the
	// deliveries it waits for.
	t.Cleanup(e.Close)
	return a, e
}

// deliverer is the engine's Deliverer before the Server exists.
type deliverer struct{ a **as }

func (d deliverer) Pager(ctx context.Context, v messaging.Delivery) error {
	return (*d.a).srv.Pager(ctx, v)
}

func (d deliverer) Invite(ctx context.Context, v messaging.Invitation) error {
	return (*d.a).srv.Invite(ctx, v)
}

// notifier is the group chat focus's Notifier: the Server, once started.
// While skip is above zero, it drops that many updates, as a change made on
// another task would reach no subscription here.
type notifier struct {
	a    **as
	skip *atomic.Int32
}

func (n notifier) RosterChanged(ctx context.Context, u group.RosterUpdate) {
	for n.skip != nil {
		v := n.skip.Load()
		if v <= 0 {
			break
		}
		if n.skip.CompareAndSwap(v, v-1) {
			return
		}
	}
	(*n.a).srv.RosterChanged(ctx, u)
}

// #298: a pager MESSAGE as rcsjta sends it, without conversation headers,
// or as a client that names only its Contribution-ID, is taken; the engine
// gives the latter its pair's Conversation-ID (conversation_test.go).
func TestAPagerMessageWithoutAConversationIDIsTaken(t *testing.T) {
	e := &fakeEngine{}
	a := startAS(t, e, newFakeCore(t))
	p := a.dial(t)
	plain := pager(cpimBody("m1", "hi"))
	contribution := pager(cpimBody("m2", "hi"))
	contribution.fields = append(contribution.fields, "Contribution-ID: c0ntr1")
	for _, m := range []msg{plain, contribution} {
		if res := p.send(m); res.StatusCode != 202 {
			t.Fatalf("answered %d", res.StatusCode)
		}
	}
	got := e.origins()
	if len(got) != 2 || got[0].Conversation != (messaging.Conversation{}) ||
		got[1].Conversation != (messaging.Conversation{Contribution: "c0ntr1"}) {
		t.Fatalf("origins %+v", got)
	}
}
